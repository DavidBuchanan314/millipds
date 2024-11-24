import logging

import jwt
import cbrrr

from aiohttp import web

from . import database

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# example: https://shiitake.us-east.host.bsky.network/.well-known/oauth-protected-resource
@routes.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: web.Request):
	cfg = get_db(request).config
	return web.json_response({
		"resource": cfg["pds_pfx"],
		"authorization_servers": [ cfg["pds_pfx"] ], # we are our own auth server
		"scopes_supported": [],
		"bearer_methods_supported": [ "header" ],
		"resource_documentation": "https://atproto.com"
	})


# example: https://bsky.social/.well-known/oauth-authorization-server
@routes.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: web.Request):
	# XXX: most of these values are currently bogus!!! I copy pasted bsky's one
	# TODO: fill in alg_supported lists based on what pyjwt actually supports
	# perhaps via jwt.api_jws.get_default_algorithms().keys(), but we'd want to exclude the symmetric ones
	cfg = get_db(request).config
	pfx = cfg["pds_pfx"]
	return web.json_response({
		"issuer": pfx,
		"scopes_supported": ["atproto", "transition:generic", "transition:chat.bsky"],
		"subject_types_supported": ["public"],
		"response_types_supported": ["code"],
		"response_modes_supported": ["query", "fragment", "form_post"],
		"grant_types_supported": ["authorization_code", "refresh_token"],
		"code_challenge_methods_supported": ["S256"],
		"ui_locales_supported": ["en-US"],
		"display_values_supported": ["page", "popup", "touch"],
		"authorization_response_iss_parameter_supported": True,
		"request_object_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],
		"request_object_encryption_alg_values_supported": [],
		"request_object_encryption_enc_values_supported": [],
		"request_parameter_supported": True,
		"request_uri_parameter_supported": True,
		"require_request_uri_registration": True,
		"jwks_uri": pfx + "/oauth/jwks",
		"authorization_endpoint": pfx + "/oauth/authorize",
		"token_endpoint": pfx + "/oauth/token",
		"token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
		"token_endpoint_auth_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],
		"revocation_endpoint": pfx + "/oauth/revoke",
		"introspection_endpoint": pfx + "/oauth/introspect",
		"pushed_authorization_request_endpoint": pfx + "/oauth/par",
		"require_pushed_authorization_requests": True,
		"dpop_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],
		"client_id_metadata_document_supported": True
	})

@routes.get("/oauth/authorize")
async def oauth_authorize(request: web.Request):
	return web.Response(
		text="<h1>TODO: login</h1>",
		content_type="text/html"
	)


def dpop_protected(handler):
	def dpop_handler(request: web.Request):
		dpop = request.headers.get("dpop")
		if dpop is None:
			raise web.HTTPUnauthorized(
				text="missing dpop"
			)

		# we're not verifying yet, we just want to pull out the jwk from the header
		unverified = jwt.api_jwt.decode_complete(dpop, options={"verify_signature": False})
		jwk_data = unverified["header"]["jwk"]
		jwk = jwt.PyJWK.from_dict(jwk_data)
		decoded = jwt.decode(dpop, key=jwk) # actual signature verification happens here

		logger.info(decoded)
		logger.info(request.url)

		# TODO: verify iat?, iss?

		if request.method != decoded["htm"]:
			raise web.HTTPUnauthorized(
				text="dpop: bad htm"
			)

		if str(request.url) != decoded["htu"]:
			logger.info(f"{request.url!r} != {decoded['htu']!r}")
			raise web.HTTPUnauthorized(
				text="dpop: bad htu (if your application is reverse-proxied, make sure the Host header is getting set properly)"
			)

		request["dpop_jwk"] = cbrrr.encode_dag_cbor(jwk_data) # for easy comparison in db etc.
		request["dpop_jti"] = decoded["jti"] # XXX: should replay prevention happen here?
		request["dpop_iss"] = decoded["iss"]

		return handler(request)

	return dpop_handler


@routes.post("/oauth/par")
@dpop_protected
async def oauth_par(request: web.Request):
	data = await request.json() # TODO: doesn't rfc9126 say it's posted as form data?
	logging.info(data)

	assert(data["client_id"] == request["dpop_iss"]) # idk if this is required

	# TODO: rest of owl
	return web.json_response({
		"TODO": "TODO"
	})


# these helpers are useful for conciseness and type hinting
# XXX: copy-pasted from service.py to avoid circular imports (should maybe put these in their own file)
def get_db(req: web.Request) -> database.Database:
	return req.app["MILLIPDS_DB"]
