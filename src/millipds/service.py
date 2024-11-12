from typing import Optional
import importlib.metadata
import logging
import asyncio
import aiohttp_cors
import time
import io
import os
import hashlib

import apsw
import aiohttp
from aiohttp import web
import jwt

import cbrrr

from . import static_config
from . import database
from . import repo_ops

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
	# TODO: if service proxying header is present, do service proxying!
	# https://atproto.com/specs/xrpc#service-proxying
	# (this implies having a DID resolver!!!) (probably with a cache!)
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
	msg = f"""
                          ,dPYb, ,dPYb,                           8I
                          IP'`Yb IP'`Yb                           8I
                     gg   I8  8I I8  8I  gg                       8I
                     ""   I8  8' I8  8'  ""                       8I
  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,      ,gggg,8I     ,gg,
 ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P"  "Yb    dP"  "Y8I   ,8'8,
 I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i  i8'    ,8I  ,8'  Yb
,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8' ,d8,   ,d8b,,8'_   8)
8P'   8I   8I   `Y88P""Y88P'"Y888P'"Y888P""Y8PI8 YY88888PP"Y8888P"`Y8P' "YY8P8P
                                              I8
                                              I8
                                              I8
                                              I8
                                              I8
                                              I8


Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds"""

	return web.Response(text=msg)


# not a spec'd endpoint, but the reference impl has this too
@routes.get("/xrpc/_health")
async def health(request: web.Request):
	return web.json_response({
		"version": importlib.metadata.version("millipds")
	})

# we should not be implementing bsky-specific logic here!
@routes.get("/xrpc/app.bsky.actor.getPreferences")
async def actor_get_preferences(request: web.Request):
	return web.json_response({"preferences": []})  # dummy response

@routes.post("/xrpc/app.bsky.actor.putPreferences")
async def actor_put_preferences(request: web.Request):
	# TODO: actually implement this
	return web.Response()

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
		did, handle = db.verify_account_login(
			did_or_handle=identifier, password=password
		)
	except KeyError:
		raise web.HTTPUnauthorized(text="user not found")
	except ValueError:
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
		request["authed_did"] = subject
		return handler(request)

	return authentication_handler


@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
	return web.json_response(
		{
			"handle": get_db(request).handle_by_did(request["authed_did"]),
			"did": request["authed_did"],
			"email": "tfw_no@email.invalid",  # this and below are just here for testing lol
			"emailConfirmed": True,
			#"didDoc": {},
		}
	)

async def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:
	if req_json["repo"] != request["authed_did"]:
		raise web.HTTPUnauthorized(text="not authed for that repo")
	res, firehose_res = repo_ops.apply_writes(get_db(request), request["authed_did"], req_json["writes"])
	# TODO: emit firehose!!
	return res


@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
	return web.json_response(await apply_writes_and_emit_firehose(request, await request.json()))

@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
	orig: dict = await request.json()
	req = {
		"repo": orig["repo"],
		"validate": orig.get("validate"),
		"swapCommit": orig.get("swapCommit"),
		"writes": [{
			"$type": "com.atproto.repo.applyWrites#create",
			"collection": orig["collection"],
			"rkey": orig.get("rkey"),
			"validate": orig.get("validate"),
			"value": orig["record"]
		}]
	}
	res = await apply_writes_and_emit_firehose(request, req)
	return web.json_response({
		"commit": res["commit"],
		"uri": res["results"][0]["uri"],
		"cid": res["results"][0]["cid"],
		"validationStatus": res["results"][0]["validationStatus"]
	})

@routes.post("/xrpc/com.atproto.repo.putRecord")
@authenticated
async def repo_put_record(request: web.Request):
	orig: dict = await request.json()
	req = {
		"repo": orig["repo"],
		"validate": orig.get("validate"),
		"swapCommit": orig.get("swapCommit"),
		"writes": [{
			"$type": "com.atproto.repo.applyWrites#update",
			"collection": orig["collection"],
			"rkey": orig["rkey"],
			"validate": orig.get("validate"),
			"swapRecord": orig.get("swapRecord"),
			"value": orig["record"]
		}]
	}
	res = await apply_writes_and_emit_firehose(request, req)
	return web.json_response({
		"commit": res["commit"],
		"uri": res["results"][0]["uri"],
		"cid": res["results"][0]["cid"],
		"validationStatus": res["results"][0]["validationStatus"]
	})

@routes.post("/xrpc/com.atproto.repo.deleteRecord")
@authenticated
async def repo_delete_record(request: web.Request):
	orig: dict = await request.json()
	req = {
		"repo": orig["repo"],
		"validate": orig.get("validate"),
		"swapCommit": orig.get("swapCommit"),
		"writes": [{
			"$type": "com.atproto.repo.applyWrites#delete",
			"collection": orig["collection"],
			"rkey": orig["rkey"],
			"validate": orig.get("validate"),
			"swapRecord": orig.get("swapRecord"),
			"value": orig["record"]
		}]
	}
	res = await apply_writes_and_emit_firehose(request, req)
	return web.json_response({
		"commit": res["commit"]
	})


@routes.post("/xrpc/com.atproto.repo.uploadBlob")
@authenticated
async def repo_upload_blob(request: web.Request):
	mime = request.headers.get("content-type", "application/octet-stream")
	BLOCK_SIZE = 0x10000 # 64k for now, might tweak this upwards, for perf?
	db = get_db(request)
	# TODO: should I start a fresh transaction here? will it block other writers for the duration?
	db.con.execute(
		"INSERT INTO blob (repo, refcount) VALUES ((SELECT id FROM user WHERE did=?), 0)",
		(request["authed_did"],)
	)
	blob_id = db.con.last_insert_rowid()
	length_read = 0
	part_idx = 0
	hasher = hashlib.sha256()
	while True:
		try:
			chunk = await request.content.readexactly(BLOCK_SIZE)
		except asyncio.IncompleteReadError as e:
			chunk = e.partial
		if not chunk: # zero-length final chunk
			break
		length_read += len(chunk)
		hasher.update(chunk)
		db.con.execute(
			"INSERT INTO blob_part (blob, idx, data) VALUES (?, ?, ?)",
			(blob_id, part_idx, chunk)
		)
		part_idx += 1
		if len(chunk) < BLOCK_SIZE:
			break
	digest = hasher.digest()
	cid = cbrrr.CID(cbrrr.CID.CIDV1_RAW_SHA256_32_PFX + digest)
	try:
		db.con.execute("UPDATE blob SET cid=? WHERE id=?", (bytes(cid), blob_id))
	except apsw.ConstraintError:
		# this means the blob already existed, we need to clean up the duplicate
		# TODO: if we were using transactions this could happen automagically
		db.con.execute("DELETE FROM blob_part WHERE blob=?", (blob_id,)) # TODO: could also make this happen in a delete hook?
		db.con.execute("DELETE FROM blob WHERE id=?", (blob_id,))
		logger.info("uploaded blob already existed, dropping duplicate")

	return web.json_response({
		"blob": {
			"$type": "blob",
			"ref": {
				"$link": cid.encode()
			},
			"mimeType": mime, # note: not stored, merely reflected
			"size": length_read
		}
	})


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


@routes.get("/xrpc/com.atproto.sync.getRepo")
async def sync_get_repo(request: web.Request):
	# TODO: "since"
	# TODO: make this async/streaming!!! (important!!!)
	did = request.query.get("did")
	if not isinstance(did, str):
		raise web.HTTPBadRequest(text="no did specified")
	db = get_db(request)
	res = web.StreamResponse()
	res.content_type = "application/vnd.ipld.car"
	await res.prepare(request)
	car = io.BytesIO()
	db.get_repo(did, car)
	await res.write(car.getvalue())  # writing all in one chunk is useless!!!
	await res.write_eof()
	return res


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

	# list of routes to proxy to the appview - hopefully not needed in the future (we'll derive the list from lexicons? and/or maybe service-proxying would be used?) https://github.com/bluesky-social/atproto/discussions/2350#discussioncomment-11193778
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
			web.get("/xrpc/app.bsky.graph.getActorStarterPacks", static_appview_proxy),
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
			web.get("/xrpc/app.bsky.feed.getActorLikes", static_appview_proxy),
			web.get(
				"/xrpc/app.bsky.unspecced.getPopularFeedGenerators",
				static_appview_proxy,
			),

			web.get("/xrpc/chat.bsky.convo.listConvos", static_appview_proxy)
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
		logger.info(f"listening on http://{host}:{port}")
		site = web.TCPSite(runner, host=host, port=port)
	else:
		logger.info(f"listening on {sock_path}")
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
			logger.warning(
				f"Failed to set socket group - group {static_config.GROUPNAME!r} not found."
			)
		except PermissionError:
			logger.warning(
				f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?"
			)

		os.chmod(sock_path, 0o770)

	while True:
		await asyncio.sleep(3600)  # sleep forever
