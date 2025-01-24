from typing import Tuple
import logging

import jwt
import cbrrr
import json
import secrets
import time
import hashlib
import base64
import urllib.parse
import uuid

from aiohttp import web
from cryptography.fernet import Fernet

from . import html_templates
from .app_util import *
from . import static_config
from . import util
from .util import definitely, NoneError
from . import crypto
from .auth_bearer import symmetric_token_auth, auth_required

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

# we need to use a weaker-than-usual CSP to let the CSS and form submission work
WEBUI_HEADERS = {
	"Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
}

# used to AEAD-encrypt oauth `code` data.
# ciphertexts have short TTL so the key does not need to persist.
code_fernet = Fernet(Fernet.generate_key())


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
			"response_modes_supported": [
				"query",
				"fragment",
			],  # , "form_post"],  # TODO
			"grant_types_supported": ["authorization_code", "refresh_token"],
			"code_challenge_methods_supported": ["S256"],
			"ui_locales_supported": ["en-US"],
			"display_values_supported": ["page", "popup", "touch"],
			"authorization_response_iss_parameter_supported": True,
			"request_object_signing_alg_values_supported": [
				# "RS256",
				# "RS384",
				# "RS512",
				# "PS256",
				# "PS384",
				# "PS512",
				# "ES256",
				# "ES256K",
				# "ES384",
				# "ES512",  # TODO
				"none",
			],
			"request_object_encryption_alg_values_supported": [],
			"request_object_encryption_enc_values_supported": [],
			"request_parameter_supported": True,
			"request_uri_parameter_supported": True,
			"require_request_uri_registration": True,
			"jwks_uri": pfx + "/oauth/jwks",  # TODO
			"authorization_endpoint": pfx + "/oauth/authorize",
			"token_endpoint": pfx + "/oauth/token",
			"token_endpoint_auth_methods_supported": [
				"none",
				# "private_key_jwt", # TODO
			],
			# "token_endpoint_auth_signing_alg_values_supported": [
			# "RS256",
			# "RS384",
			# "RS512",
			# "PS256",
			# "PS384",
			# "PS512",
			# "ES256",
			# "ES256K",
			# "ES384",
			# "ES512",
			# ], # TODO
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


def pretty_error_page(msg: str) -> web.HTTPBadRequest:
	return web.HTTPBadRequest(
		text=html_templates.error_page(msg),
		content_type="text/html",
		headers=WEBUI_HEADERS,
	)


def get_auth_request(request: web.Request) -> Tuple[dict, bytes]:
	"""
	pull a previously PAR'd auth request from db, and check it isn't expired.
	reads request_uri query parameter.
	Also returns the DPoP jwk thumbprint it was created with.
	"""

	try:
		value, dpop_jkt, expires_at = definitely(
			get_db(request)
			.con.execute(
				"SELECT value, dpop_jkt, expires_at FROM oauth_par WHERE uri=?",
				(request.query.get("request_uri"),),
			)
			.fetchone()
		)
	except NoneError:
		raise pretty_error_page("unrecognized request_uri.")

	# we check for expiry on the python-side so we can give friendly errors
	if expires_at < time.time():
		raise pretty_error_page("authorization request expired. try again?")

	return cbrrr.decode_dag_cbor(value), dpop_jkt


def get_or_initiate_oauth_session(request: web.Request, login_hint: str) -> int:
	"""
	Get the user id if the currently auth'd user.
	If there is no valid session, raise a redirect to the login page.
	"""

	user_id = (
		get_db(request)
		.con.execute(
			"""
				SELECT user_id FROM oauth_session_cookie
				WHERE token=? AND expires_at>?
			""",
			(request.cookies.get("millipds-oauth-session"), int(time.time())),
		)
		.get
	)
	if user_id is None:
		# no active oauth cookie session
		raise web.HTTPTemporaryRedirect(
			"/oauth/authenticate?"
			+ urllib.parse.urlencode(
				{
					"login_hint": login_hint,
					"next": request.path_qs,
				}
			)
		)
	return user_id


# this is where a client will redirect to during the auth flow.
# they'll see a webpage asking them to login
@routes.get("/oauth/authorize")
@routes.post(
	"/oauth/authorize"
)  # we might get here via POST, if the user just granted some new scopes
async def oauth_authorize_get(request: web.Request):
	db = get_db(request)

	client_id_param = request.query.get("client_id")

	authorization_request, dpop_jkt = get_auth_request(request)
	logger.info(authorization_request)

	login_hint = authorization_request.get("login_hint", "")
	user_id = get_or_initiate_oauth_session(request, login_hint)
	# if we reached here, either there was an existing session, or the user
	# just created a new one and got redirected back again

	# XXX: why is the client_id sent in the request params in the first place anyway? seems like redundant information
	if (
		not client_id_param
		or authorization_request.get("client_id") != client_id_param
	):
		raise pretty_error_page(
			"client_id in URL does not match authorization request."
		)

	# fetch the client metadata doc
	try:
		client_metadata = await util.get_json_with_limit(
			get_client(request), client_id_param, 0x10000, allow_redirects=False
		)  # 64k limit
		logger.info(client_metadata)
		if not isinstance(client_metadata, dict):
			raise TypeError("expected client_metadata to be dict")
	except:
		raise pretty_error_page("client_id document retrieval failed.")

	if client_metadata.get("client_id") != client_id_param:
		raise pretty_error_page(
			"client_id document does not contain its own client_id"
		)

	# at this point onwards, `client_id` can be trusted to be correct/consistent
	client_id = client_id_param

	did, handle = db.con.execute(
		"SELECT did, handle FROM user WHERE id=?", (user_id,)
	).fetchone()
	# TODO: check id hint in auth request matches!

	wanted_scopes = set(authorization_request.get("scope", "").split(" "))

	# check if someone just POSTed some more grants
	if request.method == "POST":
		form = await request.post()
		logging.info(form)
		freshly_granted_scopes = form["scope"].split(" ")
		grant_client_id = form["client_id"]
		# do we really need to put client_id in the form in the first place?
		if grant_client_id != client_id:
			raise web.HTTPBadRequest(text="client_id mismatch")
		grant_time = int(time.time())
		db.con.executemany(
			"""
				INSERT OR IGNORE INTO oauth_grants (
					user_id, client_id, scope, granted_at
				) VALUES (?, ?, ?, ?)
			""",
			[
				(user_id, grant_client_id, scope, grant_time)
				for scope in freshly_granted_scopes
			],
		)

	already_granted_scopes = set(
		scope
		for scope, *_ in db.con.execute(
			"SELECT scope FROM oauth_grants WHERE user_id=? AND client_id=?",
			(user_id, client_id),
		).fetchall()
	)
	missing_scopes = wanted_scopes - already_granted_scopes

	if missing_scopes:
		# TODO: improve the web UI to show the user which scopes were previously granted, if applicable
		logger.info(f"missing scopes: {missing_scopes}")
		return web.Response(
			text=html_templates.authz_page(
				handle=handle, client_id=client_id, scopes=list(wanted_scopes)
			),
			content_type="text/html",
			headers=WEBUI_HEADERS,
		)

	# else, everything checks out.
	# generate the auth tokens, encrypt them into the auth code, and redirect the user back to the app!

	# use the same jti for both tokens, so revoking one revokes both
	payload_common = {
		"aud": db.config["pds_did"],
		"sub": did,
		"iat": int(time.time()),
		"jti": str(uuid.uuid4()),
		"cnf": {
			"jkt": dpop_jkt,
		},
	}
	access_jwt = jwt.encode(
		payload_common
		| {
			"scope": authorization_request["scope"],
			"exp": payload_common["iat"] + static_config.ACCESS_EXP,
		},
		db.config["jwt_access_secret"],
		"HS256",
	)

	# made-up scope to distinguish the one generated during password auth
	refresh_jwt = jwt.encode(
		payload_common
		| {
			"scope": "com.atproto.refresh:oauth",
			"refresh_scope": authorization_request["scope"],
			"exp": payload_common["iat"] + static_config.REFRESH_EXP,
		},
		db.config["jwt_access_secret"],
		"HS256",
	)

	code = code_fernet.encrypt(
		cbrrr.encode_dag_cbor(
			{
				"client_id": client_id,
				"code_challenge": authorization_request["code_challenge"],
				"code_challenge_method": authorization_request[
					"code_challenge_method"
				],
				"dpop_jkt": dpop_jkt,
				"token_response": {
					"access_token": access_jwt,
					"token_type": "DPoP",
					"expires_in": static_config.ACCESS_EXP,
					"refresh_token": refresh_jwt,
					"scope": authorization_request["scope"],
					"sub": did,
				},
			}
		)
	).decode()

	SEPARATORS = {"fragment": "#", "query": "?"}
	if separator := SEPARATORS.get(authorization_request["response_mode"]):
		return web.HTTPSeeOther(
			authorization_request["redirect_uri"]
			+ separator
			+ urllib.parse.urlencode(
				{
					"iss": db.config["pds_pfx"],
					"state": authorization_request["state"],
					"code": code,
				}
			)
		)
	# TODO: support form_post?
	else:
		return pretty_error_page("unsupported response_mode")


@routes.get("/oauth/authenticate")
async def oauth_authenticate_get(request: web.Request):
	return web.Response(
		text=html_templates.authn_page(
			identifier_hint=request.query.get("login_hint", "")
		),  # this includes a login form that POSTs to the same endpoint
		content_type="text/html",
		headers=WEBUI_HEADERS,
	)


@routes.post("/oauth/authenticate")
async def oauth_authenticate_post(request: web.Request):
	form = await request.post()
	logger.info(form)

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
		# this check could be relaxed, but it *has* to be a relative URL
		next = request.query.get("next", "")
		if not next.startswith("/oauth/"):
			raise web.HTTPBadRequest(text="unsupported redirect target")
		# we can't use a 301/302 redirect because we want to produce a GET
		res = web.HTTPSeeOther(next)
		res.set_cookie(
			name="millipds-oauth-session",
			value=session_token,
			max_age=static_config.OAUTH_COOKIE_EXP,
			path="/oauth/authorize",  # the only page that needs to see it
			secure=True,  # prevents token from leaking over plaintext channels
			httponly=True,  # prevents XSS from being able to steal tokens
			samesite="Lax",  # Partial CSRF mitigation
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


def dpop_required(handler):
	async def dpop_handler(request: web.Request):
		if request.get("verified_dpop_jkt") is None:
			raise web.HTTPBadRequest(text="missing dpop")
		return await handler(request)

	return dpop_handler


@routes.post("/oauth/token")
@dpop_required
async def oauth_token_post(request: web.Request):
	form: dict = await request.json()
	logger.info(form)

	grant_type = form.get("grant_type")

	if grant_type == "authorization_code":
		code_payload = cbrrr.decode_dag_cbor(
			code_fernet.decrypt(token=form["code"], ttl=60)
		)
		logger.info(code_payload)

		# TODO: what do I do with redirect_uri?

		if form.get("client_id") != code_payload["client_id"]:
			raise web.HTTPBadRequest(text="client_id mismatch")

		if request["verified_dpop_jkt"] != code_payload["dpop_jkt"]:
			raise web.HTTPBadRequest(text="dpop mismatch")

		if code_payload["code_challenge_method"] != "S256":
			raise web.HTTPBadRequest(text="bad code_challenge_method")

		expected_code_challenge = (
			base64.urlsafe_b64encode(
				hashlib.sha256(form["code_verifier"].encode("ascii")).digest()
			)
			.rstrip(b"=")
			.decode()
		)
		if expected_code_challenge != code_payload["code_challenge"]:
			raise web.HTTPBadRequest(text="bad code_verifier")

		return web.json_response(code_payload["token_response"])

	elif grant_type == "refresh_token":
		# TODO: check client_id matches?
		symmetric_token_auth(request, "dpop", form.get("refresh_token"))
		if "com.atproto.refresh:oauth" not in request["authed_scopes"]:
			raise web.HTTPBadRequest(text="not a refresh token")
		# TODO: revoke old token, issue new one...
	else:
		raise web.HTTPBadRequest(text="unsupported grant_type")


@routes.post("/oauth/revoke")
@dpop_required
async def oauth_revoke_post(request: web.Request):
	# TODO!!!!
	logger.error("oauth token revocation not implemented!!!!")
	return web.Response()


@routes.post("/oauth/par")
@dpop_required
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
				uri, dpop_jkt, value, created_at, expires_at
			) VALUES (?, ?, ?, ?, ?)
		""",
		(
			par_uri,
			request["verified_dpop_jkt"],
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


DPOP_NONCE = "placeholder_nonce_value"  # this needs to get rotated! (does it matter that it's global?)


@web.middleware
async def dpop_middlware(request: web.Request, handler):
	# passthru any non-dpop requests
	if (dpop := request.headers.get("dpop")) is None:
		return await handler(request)

	# we're not verifying yet, we just want to pull out the jwk from the header
	unverified = jwt.api_jwt.decode_complete(
		dpop, options={"verify_signature": False}
	)
	jwk_data = unverified["header"]["jwk"]
	jwk = jwt.PyJWK.from_dict(jwk_data)
	jkt = crypto.jwk_thumbprint(jwk)

	# actual signature verification happens here:
	decoded: dict = jwt.decode(dpop, key=jwk)

	logger.info(decoded)
	logger.info(request.url)

	# TODO: verify iat?

	if request.method != decoded["htm"]:
		raise web.HTTPBadRequest(text="dpop: bad htm")

	if str(request.url) != decoded["htu"]:
		logger.info(f"{request.url!r} != {decoded['htu']!r}")
		raise web.HTTPBadRequest(
			text="dpop: bad htu (if your application is reverse-proxied, make sure the Host header is getting set properly)"
		)

	if decoded.get("nonce") != DPOP_NONCE:
		res = util.atproto_json_http_error(
			web.HTTPBadRequest,
			"use_dpop_nonce",
			"Authorization server requires nonce in DPoP proof",
		)
		res.headers["DPoP-Nonce"] = DPOP_NONCE
		raise res

	# TODO: check for jti reuse!!! (and revoke the one we're using here)

	request["verified_dpop_jkt"] = (
		jkt  # certifies that the dpop is valid for this particular jkt
	)
	request["dpop_jti"] = decoded["jti"]  # do we really need to pass this thru?
	request["dpop_iss"] = decoded["iss"]

	res: web.Response = await handler(request)
	# TODO: make sure this always gets set even under error conditions?
	res.headers["DPoP-Nonce"] = DPOP_NONCE
	return res


@routes.get("/xrpc/com.atproto.server.listAppPasswords")
@auth_required({"transition:generic"})
async def list_app_passwords(request: web.Request):
	"""
	Since millipds does not support app passwords, and bsky.app does not support
	revoking oauth scopes/sessions, we reuse the app password APIs for the latter
	"""
	db = get_db(request)
	user_id = db.con.execute(
		"SELECT id FROM user WHERE did=?", (request["authed_did"],)
	).get
	return web.json_response(
		{
			"passwords": [
				{
					"name": json.dumps([client_id, scope], indent=4),
					"createdAt": util.unix_to_iso_string(granted_at),
				}
				for client_id, scope, granted_at in db.con.execute(
					"SELECT client_id, scope, granted_at FROM oauth_grants WHERE user_id=?",
					(user_id,),
				).fetchall()
			]
		}
	)


@routes.post("/xrpc/com.atproto.server.revokeAppPassword")
@auth_required({"transition:generic"})
async def revoke_app_password(request: web.Request):
	body = await request.json()
	client_id, scope = json.loads(body["name"])
	get_db(request).con.execute(
		"""
		DELETE FROM oauth_grants WHERE
		user_id=(SELECT id FROM user WHERE did=?) AND client_id=? AND scope=?
		""",
		(request["authed_did"], client_id, scope),
	)
	return web.Response()
