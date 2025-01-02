from typing import Optional
import logging
import time

import jwt
from aiohttp import web

from . import crypto
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)


@authenticated
async def service_proxy(request: web.Request, service: Optional[str] = None):
	"""
	If `service` is None, default to bsky appview (per details in db config)
	"""
	lxm = request.path.rpartition("/")[2].partition("?")[0]
	# TODO: verify valid lexicon method?
	logger.info(f"proxying lxm {lxm}")
	db = get_db(request)
	if service:
		service_did, _, fragment = service.partition("#")
		fragment = "#" + fragment
		did_doc = await get_did_resolver(request).resolve_with_db_cache(
			db, service_did
		)
		if did_doc is None:
			return web.HTTPInternalServerError(
				text=f"unable to resolve service {service!r}"
			)
		for service_info in did_doc.get("service", []):
			if service_info.get("id") == fragment:
				service_route = service_info["serviceEndpoint"]
				break
		else:
			return web.HTTPBadRequest(
				text=f"unable to resolve service {service!r}"
			)
	else:  # fall thru to assuming bsky appview
		service_did = db.config["bsky_appview_did"]
		service_route = db.config["bsky_appview_pfx"]

	signing_key = db.signing_key_pem_by_did(request["authed_did"])
	auth_headers = {
		"Authorization": "Bearer "
		+ jwt.encode(
			{
				"iss": request["authed_did"],
				"aud": service_did,
				"lxm": lxm,
				"exp": int(time.time()) + 5 * 60,  # 5 mins
			},
			signing_key,
			algorithm=crypto.jwt_signature_alg_for_pem(signing_key),
		)
	}  # TODO: cache this?
	if request.method == "GET":
		async with get_client(request).get(
			service_route + request.path,
			params=request.query,
			headers=auth_headers,
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "POST":
		request_body = await request.read()  # TODO: streaming?
		async with get_client(request).post(
			service_route + request.path,
			data=request_body,
			headers=(auth_headers | {"Content-Type": request.content_type}),
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "PUT":  # are xrpc requests ever PUT?
		raise NotImplementedError("TODO: PUT")
	else:
		raise NotImplementedError("TODO")
