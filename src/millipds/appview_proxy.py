import logging
import time

import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)

@authenticated
async def static_appview_proxy(request: web.Request):
	lxm = request.path.rpartition("/")[2].partition("?")[0]
	# TODO: verify valid lexicon method?
	logger.info(f"proxying lxm {lxm}")
	db = get_db(request)
	signing_key = db.signing_key_pem_by_did(request["authed_did"])
	authn = {
		"Authorization": "Bearer "
		+ jwt.encode(
			{
				"iss": request["authed_did"],
				"aud": db.config["bsky_appview_did"],
				"lxm": lxm,
				"exp": int(time.time()) + 60 * 60 * 24,  # 24h
			},
			signing_key,
			algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
		)
	}  # TODO: cache this!
	appview_pfx = db.config["bsky_appview_pfx"]
	if request.method == "GET":
		async with get_client(request).get(
			appview_pfx + request.path, params=request.query, headers=authn
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "POST":
		request_body = await request.read()  # TODO: streaming?
		async with get_client(request).post(
			appview_pfx + request.path, data=request_body, headers=(authn|{"Content-Type": request.content_type})
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "PUT":
		raise NotImplementedError("TODO")
