from typing import Optional
import importlib.metadata
import logging
import asyncio
import aiohttp_cors
import time
import os

from aiohttp import web
import jwt

from . import static_config
from . import database

routes = web.RouteTableDef()


@routes.get("/")
async def hello(request: web.Request):
	version = importlib.metadata.version("millipds")
	msg = f"""Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds"""
	return web.Response(text=msg)


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
		raise web.HTTPBadRequest("invalid identifier or password")

	# do authentication
	db = get_db(request)
	try:
		did, handle, pw_hash = db.get_account(did_or_handle=identifier)
	except KeyError:
		raise web.HTTPUnauthorized("user not found")
	if not db.pw_hasher.verify(pw_hash, password):
		raise web.HTTPUnauthorized("incorrect identifier or password")

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


def construct_app(routes, db: database.Database) -> web.Application:
	app = web.Application()
	app["MILLIPDS_DB"] = db
	app.add_routes(routes)

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
