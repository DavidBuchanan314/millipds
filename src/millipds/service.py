from typing import Optional, Set, Tuple
import importlib.metadata
import logging
import asyncio
import aiohttp_cors
import time
import os
import io
import json
import hashlib

import apsw
import aiohttp
from aiohttp import web
import jwt

import cbrrr

from . import static_config
from . import database
from . import repo_ops
from . import oauth
from . import util

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

https://github.com/DavidBuchanan314/millipds
"""

	return web.Response(text=msg)




# not a spec'd endpoint, but the reference impl has this too
@routes.get("/xrpc/_health")
async def health(request: web.Request):
	version = importlib.metadata.version("millipds")
	return web.json_response({
		"version": f"millipds v{version}"
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
	if handle is None:
		return web.HTTPBadRequest(text="missing or invalid handle")
	did = get_db(request).did_by_handle(handle)
	if not did:
		return web.HTTPNotFound(text="no user by that handle exists on this PDS")
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
	try:
		req_json: dict = await request.json()
	except json.JSONDecodeError:
		return web.HTTPBadRequest(text="expected JSON")

	identifier = req_json.get("identifier")
	password = req_json.get("password")
	if not (isinstance(identifier, str) and isinstance(password, str)):
		return web.HTTPBadRequest(text="invalid identifier or password")

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


@routes.post("/xrpc/com.atproto.identity.updateHandle")
@authenticated
async def identity_update_handle(request: web.Request):
	req_json: dict = await request.json()
	handle = req_json.get("handle")
	if handle is None:
		return web.HTTPBadRequest(text="missing or invalid handle")
	# TODO: actually validate it, and update the db!!!
	# (I'm writing this half-baked version just so I can send firehose #identity events)
	with get_db(request).new_con() as con:
		# TODO: refactor to avoid duplicated logic between here and apply_writes
		firehose_seq = con.execute("SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose").fetchone()[0]
		firehose_bytes = cbrrr.encode_dag_cbor({
			"t": "#identity",
			"op": 1
		}) + cbrrr.encode_dag_cbor({
			"seq": firehose_seq,
			"did": request["authed_did"],
			"time": util.iso_string_now(),
			"handle": handle
		})
		con.execute(
			"INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",
			(firehose_seq, 0, firehose_bytes) # TODO: put sensible timestamp here...
		)
	await firehose_broadcast(request, (firehose_seq, firehose_bytes))
	return web.Response()


@routes.get("/xrpc/com.atproto.server.getSession")
@authenticated
async def server_get_session(request: web.Request):
	return web.json_response(
		{
			"handle": get_db(request).handle_by_did(request["authed_did"]),
			"did": request["authed_did"],
			"email": "tfw_no@email.invalid",  # this and below are just here for testing lol
			"emailConfirmed": True,
			#"didDoc": {}, # iiuc this is only used for entryway usecase?
		}
	)

async def firehose_broadcast(request: web.Request, msg: Tuple[int, bytes]):
	async with get_firehose_queues_lock(request): # hm, everything in here is synchronous so we could drop the lock
		for queue in get_firehose_queues(request):
			try:
				queue.put_nowait(msg)
			except asyncio.QueueFull: # this implies the client wasn't reading our messages fast enough
				while not queue.empty(): # flush what's left of the queue
					queue.get_nowait()
				queue.put_nowait(None) # signal end-of-stream
				get_firehose_queues(request).remove(queue) # don't give this queue any more events


async def apply_writes_and_emit_firehose(request: web.Request, req_json: dict) -> dict:
	if req_json["repo"] != request["authed_did"]:
		raise web.HTTPUnauthorized(text="not authed for that repo")
	res, firehose_seq, firehose_bytes = repo_ops.apply_writes(
		get_db(request),
		request["authed_did"],
		req_json["writes"],
		req_json.get("swapCommit")
	)
	await firehose_broadcast(request, (firehose_seq, firehose_bytes))
	return res


@routes.post("/xrpc/com.atproto.repo.applyWrites")
@authenticated
async def repo_apply_writes(request: web.Request):
	return web.json_response(await apply_writes_and_emit_firehose(request, await request.json()))

@routes.post("/xrpc/com.atproto.repo.createRecord")
@authenticated
async def repo_create_record(request: web.Request):
	orig: dict = await request.json()
	res = await apply_writes_and_emit_firehose(request, {
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
	})
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
	res = await apply_writes_and_emit_firehose(request, {
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
	})
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
	res = await apply_writes_and_emit_firehose(request, {
		"repo": orig["repo"],
		"validate": orig.get("validate"),
		"swapCommit": orig.get("swapCommit"),
		"writes": [{
			"$type": "com.atproto.repo.applyWrites#delete",
			"collection": orig["collection"],
			"rkey": orig["rkey"],
			"validate": orig.get("validate"),
			"swapRecord": orig.get("swapRecord"),
		}]
	})
	return web.json_response({
		"commit": res["commit"]
	})


@routes.get("/xrpc/com.atproto.repo.describeRepo")
async def repo_describe_repo(request: web.Request):
	if "repo" not in request.query:
		return web.HTTPBadRequest(text="missing repo")
	did_or_handle = request.query["repo"]
	with get_db(request).new_con(readonly=True) as con:
		user_id, did, handle = con.execute(
			"SELECT id, did, handle FROM user WHERE did=? OR handle=?",
			(did_or_handle, did_or_handle),
		).fetchone()

		return web.json_response({
			"handle": handle,
			"did": did,
			"didDoc": {}, # TODO
			"collections": [
				row[0] for row in
				con.execute(
					"SELECT DISTINCT(nsid) FROM record WHERE repo=?",
					(user_id,)
				) # TODO: is this query efficient? do we want an index?
			],
			"handleIsCorrect": True # TODO
		})


@routes.get("/xrpc/com.atproto.repo.getRecord")
async def repo_get_record(request: web.Request):
	if "repo" not in request.query:
		return web.HTTPBadRequest(text="missing repo")
	if "collection" not in request.query:
		return web.HTTPBadRequest(text="missing collection")
	if "rkey" not in request.query:
		return web.HTTPBadRequest(text="missing rkey")
	did_or_handle = request.query["repo"]
	collection = request.query["collection"]
	rkey = request.query["rkey"]
	cid_in = request.query.get("cid")
	db = get_db(request)
	row = db.con.execute(
		"SELECT cid, value FROM record WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?) AND nsid=? AND rkey=?",
		(did_or_handle, did_or_handle, collection, rkey)
	).fetchone()
	if row is None:
		return await static_appview_proxy(request) # forward to appview
		#return web.HTTPNotFound(text="record not found")
	cid_out, value = row
	cid_out = cbrrr.CID(cid_out)
	if cid_in is not None:
		if cbrrr.CID.decode(cid_in) != cid_out:
			return web.HTTPNotFound(text="record not found with matching CID")
	return web.json_response({
		"uri": f"at://{did_or_handle}/{collection}/{rkey}", # TODO rejig query to get the did out always,
		"cid": cid_out.encode(),
		"value": cbrrr.decode_dag_cbor(value, atjson_mode=True)
	})


@routes.get("/xrpc/com.atproto.repo.listRecords")
async def repo_list_records(request: web.Request):
	if "repo" not in request.query:
		return web.HTTPBadRequest(text="missing repo")
	if "collection" not in request.query:
		return web.HTTPBadRequest(text="missing collection")
	limit = int(request.query.get("limit", 50))
	if limit < 1 or limit > 100:
		return web.HTTPBadRequest(text="limit out of range")
	reverse = request.query.get("reverse") == "true"
	cursor = request.query.get("cursor", "" if reverse else "\xff")
	did_or_handle = request.query["repo"]
	collection = request.query["collection"]
	records = []
	db = get_db(request)
	for rkey, cid, value in db.con.execute(
		f"""
			SELECT rkey, cid, value
			FROM record
			WHERE repo=(SELECT id FROM user WHERE did=? OR handle=?)
				AND nsid=? AND rkey{">" if reverse else "<"}?
			ORDER BY rkey {"ASC" if reverse else "DESC"}
			LIMIT ?
		""",
		(did_or_handle, did_or_handle, collection, cursor, limit)
	):
		records.append({
			"uri": f"at://{did_or_handle}/{collection}/{rkey}", # TODO rejig query to get the did out always
			"cid": cbrrr.CID(cid).encode(),
			"value": cbrrr.decode_dag_cbor(value, atjson_mode=True)
		})
	return web.json_response({
		"records": records
	} | ({
		"cursor": rkey
	} if len(records) == limit else {}))


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

@routes.get("/xrpc/com.atproto.sync.getBlob")
async def sync_get_blob(request: web.Request):
	with get_db(request).new_con(readonly=True) as con:
		blob_id = con.execute(
			"SELECT blob.id FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND cid=? AND refcount>0",
			(request.query["did"], bytes(cbrrr.CID.decode(request.query["cid"]))) # TODO: check params exist first, give nicer error
		).fetchone()
		if blob_id is None:
			return web.HTTPNotFound(text="blob not found")
		res = web.StreamResponse()
		res.content_type = "application/octet-stream"
		await res.prepare(request)
		for blob_part, *_ in con.execute( # TODO: would bad things happen to the db if a client started reading and then blocked?
			"SELECT data FROM blob_part WHERE blob=? ORDER BY idx",
			(blob_id[0],)
		):
			await res.write(blob_part)
		await res.write_eof()
		return res


# TODO: this is mostly untested!!!
@routes.get("/xrpc/com.atproto.sync.getBlocks")
async def sync_get_blocks(request: web.Request):
	did = request.query.get("did")
	if did is None:
		return web.HTTPBadRequest(text="no did specified")
	try:
		cids = [bytes(cbrrr.CID.decode(cid)) for cid in request.query.getall("cids")]
	except ValueError:
		return web.HTTPBadRequest(text="invalid cid")
	db = get_db(request)
	row = db.con.execute("SELECT id FROM user WHERE did=?", (did,)).fetchone()
	if row is None:
		return web.HTTPNotFound(text="did not found")
	user_id = row[0]
	res = web.StreamResponse()
	res.content_type = "application/vnd.ipld.car"
	await res.prepare(request)
	await res.write(util.serialize_car_header())
	for cid in cids:
		# we don't use executemany so as not to hog the db
		for value, *_ in db.con.execute(
			"""
				SELECT commit_bytes FROM user WHERE head=? AND id=?
				UNION SELECT value FROM mst WHERE cid=? AND repo=?
				UNION SELECT value FROM record WHERE cid=? AND repo=?
			""",
			(cid, user_id) * 3
		):
			await res.write(util.serialize_car_entry(cid, value))
	await res.write_eof()
	return res


@routes.get("/xrpc/com.atproto.sync.getLatestCommit")
async def sync_get_latest_commit(request: web.Request):
	did = request.query.get("did")
	if did is None:
		return web.HTTPBadRequest(text="no did specified")
	row = get_db(request).con.execute(
		"SELECT rev, head FROM user WHERE did=?",
		(did,)
	).fetchone()
	if row is None:
		return web.HTTPNotFound(text="did not found")
	rev, head = row
	return web.json_response({
		"cid": cbrrr.CID(head).encode(),
		"rev": rev
	})


@routes.get("/xrpc/com.atproto.sync.getRecord")
async def sync_get_record(request: web.Request):
	if "did" not in request.query:
		return web.HTTPBadRequest(text="missing did")
	if "collection" not in request.query:
		return web.HTTPBadRequest(text="missing collection")
	if "rkey" not in request.query:
		return web.HTTPBadRequest(text="missing rkey")

	# we don't stream the response because it should be compact-ish
	car = repo_ops.get_record(
		get_db(request),
		request.query["did"],
		request.query["collection"] + "/" + request.query["rkey"]
	)

	if car is None:
		return web.HTTPNotFound(text="did or record not found")
	
	return web.Response(
		body=car,
		content_type="application/vnd.ipld.car"
	)


@routes.get("/xrpc/com.atproto.sync.getRepoStatus")
async def sync_get_repo_status(request: web.Request):
	did = request.query.get("did")
	if did is None:
		return web.HTTPBadRequest(text="no did specified")
	row = get_db(request).con.execute(
		"SELECT rev FROM user WHERE did=?",
		(did,)
	).fetchone()
	if row is None:
		return web.HTTPNotFound(text="did not found")
	return web.json_response({
		"did": did,
		"active": True,
		"rev": row[0]
	})


@routes.get("/xrpc/com.atproto.sync.getRepo")
async def sync_get_repo(request: web.Request):
	did = request.query.get("did")
	if did is None:
		return web.HTTPBadRequest(text="no did specified")
	since = request.query.get("since", "") # empty string is "lowest" possible value wrt string comparison

	# TODO: do bad things happen if a client holds the connection open for a long time?
	with get_db(request).new_con(readonly=True) as con: # make sure we have a consistent view of the repo
		try:
			user_id, head, commit_bytes = con.execute(
				"SELECT id, head, commit_bytes FROM user WHERE did=?",
				(did,)
			).fetchone()
		except TypeError: # from trying to unpack None
			return web.HTTPNotFound(text="repo not found")

		res = web.StreamResponse()
		res.content_type = "application/vnd.ipld.car"
		await res.prepare(request)
		await res.write(util.serialize_car_header(head))
		await res.write(util.serialize_car_entry(head, commit_bytes))

		for mst_cid, mst_value in con.execute(
			"SELECT cid, value FROM mst WHERE repo=? AND since>?",
			(user_id, since)
		):
			await res.write(util.serialize_car_entry(mst_cid, mst_value))

		for record_cid, record_value in con.execute(
			"SELECT cid, value FROM record WHERE repo=? AND since>?",
			(user_id, since)
		):
			await res.write(util.serialize_car_entry(record_cid, record_value))

	await res.write_eof()
	return res

@routes.get("/xrpc/com.atproto.sync.listBlobs")
async def sync_list_blobs(request: web.Request):
	did = request.query.get("did")
	if did is None:
		return web.HTTPBadRequest(text="no did specified")
	since = request.query.get("since", "") # empty string is "lowest" possible value wrt string comparison
	limit = int(request.query.get("limit", 500))
	if limit < 1 or limit > 1000:
		return web.HTTPBadRequest(text="limit out of range")
	cursor = int(request.query.get("cursor", 0))

	cids = []
	for id_, cid in get_db(request).con.execute(
		"SELECT blob.id, cid FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND refcount>0 AND since>? AND blob.id>? ORDER BY blob.id LIMIT ?",
		(did, since, cursor, limit)
	):
		cids.append(cbrrr.CID(cid).encode())
	
	return web.json_response({
		"cids": cids
	} | ({
		"cursor": id_
	} if len(cids) == limit else {}))


@routes.get("/xrpc/com.atproto.sync.listRepos")
async def sync_list_repos(request: web.Request):  # TODO: pagination
	return web.json_response(
		{
			"repos": [
				{
					"did": did,
					"head": head.encode("base32"),
					"rev": rev,
					"active": True
				}
				for did, head, rev in get_db(request).list_repos()
			]
		}
	)


TOOSLOW_MSG = (
	cbrrr.encode_dag_cbor({"op": -1}) +
	cbrrr.encode_dag_cbor({
		"error": "ConsumerTooSlow",
		"message": "you're not reading my events fast enough :("
	})
)

FUTURECURSOR_MSG = (
	cbrrr.encode_dag_cbor({"op": -1}) +
	cbrrr.encode_dag_cbor({
		"error": "FutureCursor",
		"message": "woah, are you from the future?"
	})
)

# https://atproto.com/specs/event-stream
# XXX: this whole implementation is extremely janky right now, and I think has a race condition in the
# cutover between backfilling and live-tailing. I just wanted to start federating™
@routes.get("/xrpc/com.atproto.sync.subscribeRepos")
async def sync_subscribe_repos(request: web.Request):
	logger.info(f"NEW FIREHOSE CLIENT {request.remote} {request.headers.get('x-forwarded-for')} {request.query}")
	ws = web.WebSocketResponse()
	try:
		await ws.prepare(request) # TODO: should this be outside of try?

		last_sent_seq = None
		if "cursor" in request.query:
			# TODO: try to limit number of concurrent backfillers? (it's more expensive than livetailing)
			cursor = int(request.query["cursor"])
			db = get_db(request)
			while True:
				# we read one at a time to force gaps between reads - could be a perf win to read in small batches
				# TODO: what happens if the reader is slow, falling outside of the backfill window?
				row = db.con.execute(
					"SELECT seq, msg FROM firehose WHERE seq>? ORDER BY seq LIMIT 1",
					(cursor,)
				).fetchone()
				if row is None:
					# XXX: we could drop messages arriving between the db read, and setting up our livetail queue
					# I think we can solve this by having some sort of ringbuffer that always holds the last N
					# messages, which we check *after* setting up the queue.
					# or maybe we should do an extra db read after setting up the queue? maybe we could be reading a stale snapshot of the db though.
					break
				cursor, msg = row
				await ws.send_bytes(msg)
				last_sent_seq = cursor

			if last_sent_seq is None:
				current_seq = db.con.execute("SELECT IFNULL(MAX(seq), 0) FROM firehose").fetchone()[0]
				if cursor > current_seq:
					await ws.send_bytes(FUTURECURSOR_MSG)
					await ws.close()
					return ws
				# else if cursor == current_seq, fall thru to livetailing (someone was reconnecting where they left off)
	except ConnectionResetError: # TODO: other types of error???
		await ws.close()
		return ws

	queue: asyncio.Queue[Optional[Tuple[int, bytes]]] = asyncio.Queue(static_config.FIREHOSE_QUEUE_SIZE)
	async with get_firehose_queues_lock(request):
		get_firehose_queues(request).add(queue)

	try:
		# live-tailing
		while True:
			msg = await queue.get() # TODO: client may have closed the connection, but we'll hang here if there are no new events coming through. I think this is fine, although it makes the logs a little confusing.
			if msg is None:
				await ws.send_bytes(TOOSLOW_MSG)
				break
			seq, msg_bytes = msg
			# if seq < cursor, raise FutureCursor?
			# TODO: more cutover logic here
			await ws.send_bytes(msg_bytes)
	except ConnectionResetError:
		pass
	finally:
		async with get_firehose_queues_lock(request):
			get_firehose_queues(request).discard(queue) # may have already been removed due to tooslow

	await ws.close()
	return ws

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
			appview_pfx + request.path, data=request_body, headers=(authn|{"Content-Type": request.content_type})
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
	app["MILLIPDS_FIREHOSE_QUEUES"] = set()
	app["MILLIPDS_FIREHOSE_QUEUES_LOCK"] = asyncio.Lock()
	app.add_routes(routes)
	app.add_routes(oauth.routes)

	# list of routes to proxy to the appview - hopefully not needed in the future (we'll derive the list from lexicons? and/or maybe service-proxying would be used?) https://github.com/bluesky-social/atproto/discussions/2350#discussioncomment-11193778
	app.add_routes(
		[
			# web.get ("/xrpc/app.bsky.actor.getPreferences", static_appview_proxy),
			# web.post("/xrpc/app.bsky.actor.putPreferences", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.getProfile", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.getProfiles", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.getSuggestions", static_appview_proxy),
			web.get("/xrpc/app.bsky.actor.searchActorsTypeahead", static_appview_proxy),
			web.get("/xrpc/app.bsky.labeler.getServices", static_appview_proxy),
			web.get(
				"/xrpc/app.bsky.notification.listNotifications", static_appview_proxy
			),
			web.post("/xrpc/app.bsky.notification.updateSeen", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getList", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getLists", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getFollows", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getFollowers", static_appview_proxy),
			web.get("/xrpc/app.bsky.graph.getStarterPack", static_appview_proxy),
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
			web.get("/xrpc/app.bsky.feed.getListFeed", static_appview_proxy),
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


# these helpers are useful for conciseness and type hinting
def get_db(req: web.Request) -> database.Database:
	return req.app["MILLIPDS_DB"]

def get_client(req: web.Request) -> aiohttp.ClientSession:
	return req.app["MILLIPDS_AIOHTTP_CLIENT"]

def get_firehose_queues(req: web.Request) -> Set[asyncio.Queue[Optional[Tuple[int, bytes]]]]:
	return req.app["MILLIPDS_FIREHOSE_QUEUES"]

def get_firehose_queues_lock(req: web.Request) -> asyncio.Lock:
	return req.app["MILLIPDS_FIREHOSE_QUEUES_LOCK"]


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
