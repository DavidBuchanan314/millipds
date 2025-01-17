import logging

import jwt
import cbrrr
import json
import secrets
import time
import urllib.parse

from aiohttp import web

from . import database
from . import html_templates
from .app_util import *
from . import static_config
from . import util

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# we need to use a weaker-than-usual CSP to let the CSS and form submission work
WEBUI_HEADERS = {
	"Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
}


# example: https://shiitake.us-east.host.bsky.network/.well-known/oauth-protected-resource
@routes.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: web.Request):
	cfg = get_db(request).config
	return web.json_response(
		{
			"resource": cfg["pds_pfx"],
			"authorization_servers": [
				cfg["pds_pfx"]
			],  # we are our own auth server
			"scopes_supported": [],
			"bearer_methods_supported": ["header"],
			"resource_documentation": "https://atproto.com",
		}
	)


# example: https://bsky.social/.well-known/oauth-authorization-server
@routes.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: web.Request):
	# XXX: most of these values are currently bogus!!! I copy pasted bsky's one
	# TODO: fill in alg_supported lists based on what pyjwt actually supports
	# perhaps via jwt.api_jws.get_default_algorithms().keys(), but we'd want to exclude the symmetric ones
	cfg = get_db(request).config
	pfx = cfg["pds_pfx"]
	return web.json_response(
		{
			"issuer": pfx,
			"scopes_supported": [
				"atproto",
				"transition:generic",
				"transition:chat.bsky",
			],
			"subject_types_supported": ["public"],
			"response_types_supported": ["code"],
			"response_modes_supported": ["query", "fragment", "form_post"],
			"grant_types_supported": ["authorization_code", "refresh_token"],
			"code_challenge_methods_supported": ["S256"],
			"ui_locales_supported": ["en-US"],
			"display_values_supported": ["page", "popup", "touch"],
			"authorization_response_iss_parameter_supported": True,
			"request_object_signing_alg_values_supported": [
				"RS256",
				"RS384",
				"RS512",
				"PS256",
				"PS384",
				"PS512",
				"ES256",
				"ES256K",
				"ES384",
				"ES512",
				"none",
			],
			"request_object_encryption_alg_values_supported": [],
			"request_object_encryption_enc_values_supported": [],
			"request_parameter_supported": True,
			"request_uri_parameter_supported": True,
			"require_request_uri_registration": True,
			"jwks_uri": pfx + "/oauth/jwks",
			"authorization_endpoint": pfx + "/oauth/authorize",
			"token_endpoint": pfx + "/oauth/token",
			"token_endpoint_auth_methods_supported": [
				"none",
				"private_key_jwt",
			],
			"token_endpoint_auth_signing_alg_values_supported": [
				"RS256",
				"RS384",
				"RS512",
				"PS256",
				"PS384",
				"PS512",
				"ES256",
				"ES256K",
				"ES384",
				"ES512",
			],
			"revocation_endpoint": pfx + "/oauth/revoke",
			"introspection_endpoint": pfx + "/oauth/introspect",
			"pushed_authorization_request_endpoint": pfx + "/oauth/par",
			"require_pushed_authorization_requests": True,
			"dpop_signing_alg_values_supported": [
				"RS256",
				"RS384",
				"RS512",
				"PS256",
				"PS384",
				"PS512",
				"ES256",
				"ES256K",
				"ES384",
				"ES512",
			],
			"client_id_metadata_document_supported": True,
		}
	)


# this is where a client will redirect to during the auth flow.
# they'll see a webpage asking them to login
@routes.get("/oauth/authorize")
async def oauth_authorize_get(request: web.Request):
	now = int(time.time())
	db = get_db(request)

	session_token = request.cookies.get("millipds-oauth-session")
	row = db.con.execute(
		"""
			SELECT user_id FROM oauth_session_cookie
			WHERE token=? AND expires_at>?
		""",
		(session_token, now),
	).fetchone()
	if row is None:
		# no active oauth cookie session
		return web.HTTPTemporaryRedirect(
			"/oauth/authenticate?"
			+ urllib.parse.urlencode({"next": request.path_qs})
		)
	user_id = row[0]

	# if we reached here, either there was an existing session, or the user
	# just created a new one and got redirected back again

	client_id_param = request.query.get("client_id")
	request_uri_param = request.query.get("request_uri")

	# retreive the PAR we stashed earlier
	row = db.con.execute(
		"""
			SELECT value FROM oauth_par
			WHERE uri=? AND expires_at>?
		""",
		(request_uri_param, now),
	).fetchone()
	if row is None:
		return web.Response(
			text=html_templates.error_page(
				"bad request_uri parameter. it should've been set by the client that sent you here."
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)
	authorization_request = cbrrr.decode_dag_cbor(row[0])
	logger.info(authorization_request)

	# XXX: why is the client_id sent in the request params in the first place anyway? seems like redundant information
	if (
		not client_id_param
		or authorization_request.get("client_id") != client_id_param
	):
		return web.Response(
			text=html_templates.error_page(
				"client_id in URL does not match authorization request."
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)

	try:
		client_id_doc = await util.get_json_with_limit(
			get_client(request), client_id_param, 0x10000
		)  # 64k limit
		logger.info(client_id_doc)
		if not isinstance(client_id_doc, dict):
			raise TypeError("expected client_id_doc to be dict")
	except:
		return web.Response(
			text=html_templates.error_page(
				"failed to retrieve client_id document."
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)

	if client_id_doc.get("client_id") != client_id_param:
		return web.Response(
			text=html_templates.error_page(
				"client_id document does not contain its own client_id"
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)

	did, handle = db.con.execute(
		"SELECT did, handle FROM user WHERE id=?", (user_id,)
	).fetchone()
	# TODO: check id hint in auth request matches!

	scopes = set(authorization_request.get("scope", "").split(" "))
	# TODO: look at the requested scopes, see if the user already granted them,
	# display UI as appropriate

	return web.Response(
		text=html_templates.authz_page(
			handle=handle, client_id=client_id_param, scopes=list(scopes)
		),
		content_type="text/html",
		headers=WEBUI_HEADERS,
	)


@routes.post("/oauth/authorize")
async def oauth_authorize_post(request: web.Request):
	now = int(time.time())
	db = get_db(request)

	# TODO: don't duplicate code between here and the GET handler
	session_token = request.cookies.get("millipds-oauth-session")
	row = db.con.execute(
		"""
			SELECT user_id FROM oauth_session_cookie
			WHERE token=? AND expires_at>?
		""",
		(session_token, now),
	).fetchone()
	if row is None:
		# no active oauth cookie session
		# this should be pretty rare - session expired between the initial GET and the form submission
		return web.HTTPTemporaryRedirect(
			"/oauth/authenticate?"
			+ urllib.parse.urlencode({"next": request.path_qs})
		)

	# TODO: redirect back to app?
	return web.Response(
		text="TODO",
		content_type="text/html",
		headers=WEBUI_HEADERS,
	)


@routes.get("/oauth/authenticate")
async def oauth_authenticate_get(request: web.Request):
	return web.Response(
		text=html_templates.authn_page(
			identifier_hint="todo.invalid"
		),  # this includes a login form that POSTs to the same endpoint
		content_type="text/html",
		headers=WEBUI_HEADERS,
	)


@routes.post("/oauth/authenticate")
async def oauth_authenticate_post(request: web.Request):
	form = await request.post()
	logging.info(form)

	db = get_db(request)
	form_identifier = form.get("identifier", "")
	form_password = form.get("password", "")

	try:
		user_id, did, handle = db.verify_account_login(
			form_identifier, form_password
		)
		# login succeeded, let's start a new cookie session
		session_token = secrets.token_hex()
		session_value = {}
		now = int(time.time())
		db.con.execute(
			"""
				INSERT INTO oauth_session_cookie (
					token, user_id, value, created_at, expires_at
				) VALUES (?, ?, ?, ?, ?)
			""",
			(
				session_token,
				user_id,
				cbrrr.encode_dag_cbor(session_value),
				now,
				now + static_config.OAUTH_COOKIE_EXP,
			),
		)
		# we can't use a 301/302 redirect because we need to produce a GET
		next = request.query.get("next", "")
		# TODO: !!!important!!! assert next is a relative URL, or absolutify it somehow
		res = web.Response(
			text=html_templates.redirect(next),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)
		res.set_cookie(
			name="millipds-oauth-session",
			value=session_token,
			max_age=static_config.OAUTH_COOKIE_EXP,
			path="/oauth/authorize",  # the only page that needs to see it
			secure=True,  # prevents token from leaking over plaintext channels
			httponly=True,  # prevents XSS from being able to steal tokens
			samesite="Strict",  # mitigates CSRF
		)
		return res
	except:
		return web.Response(
			text=html_templates.authn_page(
				identifier_hint=form_identifier,
				error_msg="incorrect identifier or password",
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)


DPOP_NONCE = "placeholder_nonce_value"  # this needs to get rotated! (does it matter that it's global?)


def dpop_protected(handler):
	async def dpop_handler(request: web.Request):
		dpop = request.headers.get("dpop")
		if dpop is None:
			raise web.HTTPBadRequest(text="missing dpop")

		# we're not verifying yet, we just want to pull out the jwk from the header
		unverified = jwt.api_jwt.decode_complete(
			dpop, options={"verify_signature": False}
		)
		jwk_data = unverified["header"]["jwk"]
		jwk = jwt.PyJWK.from_dict(jwk_data)

		# actual signature verification happens here:
		decoded: dict = jwt.decode(dpop, key=jwk)

		logger.info(decoded)
		logger.info(request.url)

		# TODO: verify iat?, iss?

		if request.method != decoded["htm"]:
			raise web.HTTPBadRequest(text="dpop: bad htm")

		if str(request.url) != decoded["htu"]:
			logger.info(f"{request.url!r} != {decoded['htu']!r}")
			raise web.HTTPBadRequest(
				text="dpop: bad htu (if your application is reverse-proxied, make sure the Host header is getting set properly)"
			)

		if decoded.get("nonce") != DPOP_NONCE:
			raise web.HTTPBadRequest(
				body=json.dumps(
					{
						"error": "use_dpop_nonce",
						"error_description": "Authorization server requires nonce in DPoP proof",
					}
				),
				headers={
					"DPoP-Nonce": DPOP_NONCE,
					"Content-Type": "application/json",
				},  # if we don't put it here, the client will never see it
			)

		request["dpop_jwk"] = cbrrr.encode_dag_cbor(
			jwk_data
		)  # for easy comparison in db etc.
		request["dpop_jti"] = decoded[
			"jti"
		]  # XXX: should replay prevention happen here?
		request["dpop_iss"] = decoded["iss"]

		res: web.Response = await handler(request)
		res.headers["DPoP-Nonce"] = (
			DPOP_NONCE  # TODO: make sure this always gets set even under error conditions?
		)
		return res

	return dpop_handler


@routes.post("/oauth/par")
@dpop_protected
async def oauth_pushed_authorization_request(request: web.Request):
	# NOTE: rfc9126 says this is posted as form data, but this is atproto-flavoured oauth
	request_json = await request.json()
	logger.info(request_json)

	# idk if this is required
	assert request_json["client_id"] == request["dpop_iss"]

	now = int(time.time())
	par_uri = "urn:ietf:params:oauth:request_uri:req-" + secrets.token_hex()

	# NOTE: we don't do any verification of the auth request itself, we just associate it with a URI for later retreival.
	get_db(request).con.execute(
		"""
			INSERT INTO oauth_par (
				uri, dpop_jwk, value, created_at, expires_at
			) VALUES (?, ?, ?, ?, ?)
		""",
		(
			par_uri,
			request["dpop_jwk"],
			cbrrr.encode_dag_cbor(request_json),
			now,
			now + static_config.OAUTH_PAR_EXP,
		),
	)

	return web.json_response(
		{
			"request_uri": par_uri,
			"expires_in": static_config.OAUTH_PAR_EXP,
		}
	)
