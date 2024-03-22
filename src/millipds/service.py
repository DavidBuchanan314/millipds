from typing import Optional
import importlib.metadata
import logging
import asyncio
import aiohttp_cors
import time
import os

import aiohttp
from aiohttp import web
import jwt

from . import static_config
from . import database

routes = web.RouteTableDef()


@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
	# TODO: if service proxying header is present, do service proxying!
	# if request.headers.get("atproto-proxy"):
	# pass

	# else, normal response
	return await handler(request)


# inject permissive CORS headers unconditionally
# async def prepare_cors_headers(request, response: web.Response):
# response.headers["Access-Control-Allow-Origin"] = "*"
# response.headers["Access-Control-Allow-Headers"] = "atproto-accept-labelers,authorization"  # TODO: tighten?
# response.headers["Access-Control-Allow-Methods"] = "GET,HEAD,PUT,PATCH,POST,DELETE"


@routes.get("/")
async def hello(request: web.Request):
	version = importlib.metadata.version("millipds")
	msg = f"""Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds"""
	return web.Response(text=msg)


# we should not be implementing bsky-specific logic here!
@routes.get("/xrpc/app.bsky.actor.getPreferences")
async def actor_get_preferences(request: web.Request):
	return web.json_response({"preferences": []})  # dummy response


@routes.get("/xrpc/com.atproto.identity.resolveHandle")
async def identity_resolve_handle(request: web.Request):
	# TODO: forward to appview(?) if we can't answer?
	handle = request.query.get("handle")
	if not isinstance(handle, str):
		print(handle)
		raise web.HTTPBadRequest(text="missing or invalid handle")
	did = get_db(request).did_by_handle(handle)
	if not did:
		raise web.HTTPNotFound(text="no user by that handle exists on this PDS")
	return web.json_response({"did": did})


@routes.get("/xrpc/com.atproto.server.describeServer")
async def server_describe_server(request: web.Request):
	return web.json_response(
		{
			"did": get_db(request).config["pds_did"],
			"availableUserDomains": [],
		}
	)


# TODO: ratelimit this!!!
@routes.post("/xrpc/com.atproto.server.createSession")
async def server_create_session(request: web.Request):
	# extract the args
	json: dict = await request.json()
	identifier = json.get("identifier")
	password = json.get("password")
	if not (isinstance(identifier, str) and isinstance(password, str)):
		raise web.HTTPBadRequest(text="invalid identifier or password")

	# do authentication
	db = get_db(request)
	try:
		did, handle, pw_hash, _ = db.get_account(did_or_handle=identifier)
	except KeyError:
		raise web.HTTPUnauthorized(text="user not found")
	try:
		db.pw_hasher.verify(pw_hash, password)
	except:
		raise web.HTTPUnauthorized(text="incorrect identifier or password")

	# prepare access tokens
	unix_seconds_now = int(time.time())
	access_jwt = jwt.encode(
		{
			"scope": "com.atproto.access",
			"aud": db.config["pds_did"],
			"sub": did,
			"iat": unix_seconds_now,
			"exp": unix_seconds_now + 60 * 60 * 24,  # 24h
		},
		db.config["jwt_access_secret"],
		"HS256",
	)

	refresh_jwt = jwt.encode(
		{
			"scope": "com.atproto.refresh",
			"aud": db.config["pds_did"],
			"sub": did,
			"iat": unix_seconds_now,
			"exp": unix_seconds_now + 60 * 60 * 24 * 90,  # 90 days!
		},
		db.config["jwt_access_secret"],
		"HS256",
	)

	return web.json_response(
		{
			"did": did,
			"handle": handle,
			"accessJwt": access_jwt,
			"refreshJwt": refresh_jwt,
		}
	)


def authenticated(handler):
	def authentication_handler(request: web.Request):
		# extract the auth token
		auth = request.headers.get("Authorization")
		if auth is None:
			raise web.HTTPUnauthorized(
				text="authentication required (this may be a bug, I'm erring on the side of caution for now)"
			)
		if not auth.startswith("Bearer "):
			raise web.HTTPUnauthorized(text="invalid auth type")
		token = auth.removeprefix("Bearer ")

		# validate it TODO: this needs rigorous testing, I'm not 100% sure I'm
		# verifying all the things that need verifying
		db = get_db(request)
		try:
			payload: dict = jwt.decode(
				jwt=token,
				key=db.config["jwt_access_secret"],
				algorithms=["HS256"],
				audience=db.config["pds_did"],
				require=["exp", "scope"],  # consider iat?
				strict_aud=True,
			)
		except jwt.exceptions.PyJWTError:
			raise web.HTTPUnauthorized(text="invalid jwt")

		# if we reached this far, the payload must've been signed by us
		if payload.get("scope") != "com.atproto.access":
			raise web.HTTPUnauthorized(text="invalid jwt scope")

		subject: str = payload.get("sub", "")
		if not subject.startswith("did:"):
			raise web.HTTPUnauthorized(text="invalid jwt: invalid subject")
		request["did"] = subject
		return handler(request)

	return authentication_handler


@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
	return web.json_response(
		{
			"handle": get_db(request).handle_by_did(request["did"]),  # ew
			"did": request["did"],
			"email": "nunya@business.invalid",  # this and below are just here for testing lol
			"emailConfirmed": True,
			"didDoc": {},
		}
	)


@routes.get("/xrpc/com.atproto.sync.listRepos")
async def sync_list_repos(request: web.Request):  # TODO: pagination
	return web.json_response(
		{
			"repos": [
				{
					"did": did,
					"head": head.encode("base32"),
					"rev": rev,
				}
				for did, head, rev in get_db(request).list_repos()
			]
		}
	)


@authenticated
async def static_appview_proxy(request: web.Request):
	db = get_db(request)
	did, _, _, signing_key = db.get_account(request["did"])
	authn = {
		"Authorization": "Bearer "
		+ jwt.encode(
			{
				"iss": did,
				"aud": db.config["bsky_appview_did"],
				"exp": int(time.time()) + 60 * 60 * 24,  # 24h
			},
			signing_key,
			algorithm="ES256",
		)  # TODO: ES256K compat?
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
			appview_pfx + request.path, data=request_body, headers=authn
		) as r:
			body_bytes = await r.read()  # TODO: streaming?
			return web.Response(
				body=body_bytes, content_type=r.content_type, status=r.status
			)  # XXX: allowlist safe content types!
	elif request.method == "PUT":
		raise NotImplementedError("TODO")


def construct_app(routes, db: database.Database) -> web.Application:
	app = web.Application(middlewares=[atproto_service_proxy_middleware])
	app["MILLIPDS_DB"] = db
	app["MILLIPDS_AIOHTTP_CLIENT"] = (
		aiohttp.ClientSession()
	)  # should this be dependency-injected?
	app.add_routes(routes)

	# list of routes to proxy to the appview - hopefully not needed in the future
	app.add_routes(
		[
			# web.get ("/xrpc/app.bsky.actor.getPreferences", static_appview_proxy),
			# web.post("/xrpc/app.bsky.actor.putPreferences", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.getProfile", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.searchActorsTypeahead", static_appview_proxy),
			web.get("/xrpc/app.bsky.labeler.getServices", static_appview_proxy),
			web.get(
				"/xrpc/app.bsky.notification.listNotifications", static_appview_proxy
			),
			web.post("/xrpc/app.bsky.notification.updateSeen", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getLists", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getFollows", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getFollowers", static_appview_proxy),
			web.get(
				"/xrpc/app.bsky.graph.getSuggestedFollowsByActor", static_appview_proxy
			),
			web.post("/xrpc/app.bsky.graph.muteActor", static_appview_proxy),
			web.post("/xrpc/app.bsky.graph.unmuteActor", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getTimeline", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getAuthorFeed", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getActorFeeds", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getFeed", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getFeedGenerator", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getFeedGenerators", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getPostThread", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getPosts", static_appview_proxy),
			web.get("/xrpc/app.bsky.feed.getLikes", static_appview_proxy),
			web.get(
				"/xrpc/app.bsky.unspecced.getPopularFeedGenerators",
				static_appview_proxy,
			),
		]
	)
	# app.on_response_prepare.append(prepare_cors_headers)

	cors = aiohttp_cors.setup(
		app,
		defaults={
			"*": aiohttp_cors.ResourceOptions(
				allow_credentials=True, expose_headers="*", allow_headers="*"
			)
		},
	)

	for route in app.router.routes():
		cors.add(route)

	return app


def get_db(req: web.Request) -> database.Database:
	"""
	Helper function to retreive the db instance associated with a request
	"""
	return req.app["MILLIPDS_DB"]


def get_client(req: web.Request) -> aiohttp.ClientSession:
	return req.app["MILLIPDS_AIOHTTP_CLIENT"]


async def run(db: database.Database, sock_path: Optional[str], host: str, port: int):
	"""
	This gets invoked via millipds.__main__.py
	"""

	app = construct_app(routes, db)
	runner = web.AppRunner(app, access_log_format=static_config.HTTP_LOG_FMT)
	await runner.setup()

	if sock_path is None:
		site = web.TCPSite(runner, host=host, port=port)
	else:
		site = web.UnixSite(runner, path=sock_path)

	await site.start()

	if sock_path:
		# give group access to the socket (so that nginx can access it via a shared group)
		# see https://github.com/aio-libs/aiohttp/issues/4155#issuecomment-693979753
		import grp

		try:
			sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid
			os.chown(sock_path, os.geteuid(), sock_gid)
		except KeyError:
			logging.warn(
				f"Failed to set socket group - group {static_config.GROUPNAME!r} not found."
			)
		except PermissionError:
			logging.warn(
				f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?"
			)

		os.chmod(sock_path, 0o770)

	while True:
		await asyncio.sleep(3600)  # sleep forever
