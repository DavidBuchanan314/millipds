import logging
import hashlib

from aiohttp import web
import cbrrr
import apsw

from . import repo_ops
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

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
		return await service_proxy(request) # forward to appview
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
