from typing import Optional, Tuple
import logging
import asyncio

from aiohttp import web
import cbrrr

from . import static_config
from . import repo_ops
from . import util
from .app_util import *

logger = logging.getLogger(__name__)

routes = web.RouteTableDef()


@routes.get("/xrpc/com.atproto.sync.getBlob")
async def sync_get_blob(request: web.Request):
	with get_db(request).new_con(readonly=True) as con:
		blob_id = con.execute(
			"SELECT blob.id FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND cid=? AND refcount>0",
			(
				request.query["did"],
				bytes(cbrrr.CID.decode(request.query["cid"])),
			),  # TODO: check params exist first, give nicer error
		).fetchone()
		if blob_id is None:
			raise web.HTTPNotFound(text="blob not found")
		res = web.StreamResponse(
			headers={
				"Content-Disposition": f'attachment; filename="{request.query["cid"]}.bin"'
			}
		)
		res.content_type = "application/octet-stream"
		await res.prepare(request)
		for (
			blob_part,
			*_,
		) in con.execute(  # TODO: would bad things happen to the db if a client started reading and then blocked?
			"SELECT data FROM blob_part WHERE blob=? ORDER BY idx",
			(blob_id[0],),
		):
			await res.write(blob_part)
		await res.write_eof()
		return res


# TODO: this is mostly untested!!!
@routes.get("/xrpc/com.atproto.sync.getBlocks")
async def sync_get_blocks(request: web.Request):
	did = request.query.get("did")
	if did is None:
		raise web.HTTPBadRequest(text="no did specified")
	try:
		cids = [
			bytes(cbrrr.CID.decode(cid)) for cid in request.query.getall("cids")
		]
	except ValueError:
		raise web.HTTPBadRequest(text="invalid cid")
	db = get_db(request)
	row = db.con.execute("SELECT id FROM user WHERE did=?", (did,)).fetchone()
	if row is None:
		raise web.HTTPNotFound(text="did not found")
	user_id = row[0]
	res = web.StreamResponse()
	res.content_type = "application/vnd.ipld.car"
	await res.prepare(request)
	await res.write(util.serialize_car_header())
	for cid in cids:
		# we don't use executemany so as not to hog the db
		row = db.con.execute(
			"""
				SELECT commit_bytes FROM user WHERE head=? AND id=?
				UNION SELECT value FROM mst WHERE cid=? AND repo=?
				UNION SELECT value FROM record WHERE cid=? AND repo=?
			""",
			(cid, user_id) * 3,
		).fetchone()
		if row is None:
			continue  # hmm, we can't 404 because we already send the response headers
		await res.write(util.serialize_car_entry(cid, row[0]))
	await res.write_eof()
	return res


@routes.get("/xrpc/com.atproto.sync.getLatestCommit")
async def sync_get_latest_commit(request: web.Request):
	did = request.query.get("did")
	if did is None:
		raise web.HTTPBadRequest(text="no did specified")
	row = (
		get_db(request)
		.con.execute("SELECT rev, head FROM user WHERE did=?", (did,))
		.fetchone()
	)
	if row is None:
		raise web.HTTPNotFound(text="did not found")
	rev, head = row
	return web.json_response({"cid": cbrrr.CID(head).encode(), "rev": rev})


@routes.get("/xrpc/com.atproto.sync.getRecord")
async def sync_get_record(request: web.Request):
	if "did" not in request.query:
		raise web.HTTPBadRequest(text="missing did")
	if "collection" not in request.query:
		raise web.HTTPBadRequest(text="missing collection")
	if "rkey" not in request.query:
		raise web.HTTPBadRequest(text="missing rkey")

	# we don't stream the response because it should be compact-ish
	car = repo_ops.get_record(
		get_db(request),
		request.query["did"],
		request.query["collection"] + "/" + request.query["rkey"],
	)

	if car is None:
		raise web.HTTPNotFound(text="did not found")

	return web.Response(body=car, content_type="application/vnd.ipld.car")


@routes.get("/xrpc/com.atproto.sync.getRepoStatus")
async def sync_get_repo_status(request: web.Request):
	did = request.query.get("did")
	if did is None:
		raise web.HTTPBadRequest(text="no did specified")
	row = (
		get_db(request)
		.con.execute("SELECT rev FROM user WHERE did=?", (did,))
		.fetchone()
	)
	if row is None:
		raise web.HTTPNotFound(text="did not found")
	return web.json_response({"did": did, "active": True, "rev": row[0]})


@routes.get("/xrpc/com.atproto.sync.getRepo")
async def sync_get_repo(request: web.Request):
	did = request.query.get("did")
	if did is None:
		raise web.HTTPBadRequest(text="no did specified")
	since = request.query.get(
		"since", ""
	)  # empty string is "lowest" possible value wrt string comparison

	# TODO: do bad things happen if a client holds the connection open for a long time?
	with get_db(request).new_con(
		readonly=True
	) as con:  # make sure we have a consistent view of the repo
		try:
			user_id, head, commit_bytes = con.execute(
				"SELECT id, head, commit_bytes FROM user WHERE did=?", (did,)
			).fetchone()
		except TypeError:  # from trying to unpack None
			raise web.HTTPNotFound(text="repo not found")

		res = web.StreamResponse()
		res.content_type = "application/vnd.ipld.car"
		await res.prepare(request)
		await res.write(util.serialize_car_header(head))
		await res.write(util.serialize_car_entry(head, commit_bytes))

		for mst_cid, mst_value in con.execute(
			"SELECT cid, value FROM mst WHERE repo=? AND since>?",
			(user_id, since),
		):
			await res.write(util.serialize_car_entry(mst_cid, mst_value))

		for record_cid, record_value in con.execute(
			"SELECT cid, value FROM record WHERE repo=? AND since>?",
			(user_id, since),
		):
			await res.write(util.serialize_car_entry(record_cid, record_value))

	await res.write_eof()
	return res


@routes.get("/xrpc/com.atproto.sync.listBlobs")
async def sync_list_blobs(request: web.Request):
	did = request.query.get("did")
	if did is None:
		raise web.HTTPBadRequest(text="no did specified")
	since = request.query.get(
		"since", ""
	)  # empty string is "lowest" possible value wrt string comparison
	limit = int(request.query.get("limit", 500))
	if limit < 1 or limit > 1000:
		raise web.HTTPBadRequest(text="limit out of range")
	cursor = int(request.query.get("cursor", 0))

	cids = []
	for id_, cid in get_db(request).con.execute(
		"SELECT blob.id, cid FROM blob INNER JOIN user ON blob.repo=user.id WHERE did=? AND refcount>0 AND since>? AND blob.id>? ORDER BY blob.id LIMIT ?",
		(did, since, cursor, limit),
	):
		cids.append(cbrrr.CID(cid).encode())

	return web.json_response(
		{"cids": cids} | ({"cursor": id_} if len(cids) == limit else {})
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
					"active": True,
				}
				for did, head, rev in get_db(request).list_repos()
			]
		}
	)


TOOSLOW_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
	{
		"error": "ConsumerTooSlow",
		"message": "you're not reading my events fast enough :(",
	}
)

FUTURECURSOR_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
	{"error": "FutureCursor", "message": "woah, are you from the future?"}
)


# https://atproto.com/specs/event-stream
# XXX: this whole implementation is extremely janky right now, and I think has a race condition in the
# cutover between backfilling and live-tailing. I just wanted to start federating™
@routes.get("/xrpc/com.atproto.sync.subscribeRepos")
async def sync_subscribe_repos(request: web.Request):
	logger.info(
		f"NEW FIREHOSE CLIENT {request.remote} {request.headers.get('x-forwarded-for')} {request.query}"
	)
	ws = web.WebSocketResponse()
	try:
		await ws.prepare(request)  # TODO: should this be outside of try?

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
					(cursor,),
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
				current_seq = db.con.execute(
					"SELECT IFNULL(MAX(seq), 0) FROM firehose"
				).fetchone()[0]
				if cursor > current_seq:
					await ws.send_bytes(FUTURECURSOR_MSG)
					await ws.close()
					return ws
				# else if cursor == current_seq, fall thru to livetailing (someone was reconnecting where they left off)
	except ConnectionResetError:  # TODO: other types of error???
		await ws.close()
		return ws

	queue: asyncio.Queue[Optional[Tuple[int, bytes]]] = asyncio.Queue(
		static_config.FIREHOSE_QUEUE_SIZE
	)
	async with get_firehose_queues_lock(request):
		get_firehose_queues(request).add(queue)

	try:
		# live-tailing
		while True:
			msg = await queue.get()  # TODO: client may have closed the connection, but we'll hang here if there are no new events coming through. I think this is fine, although it makes the logs a little confusing.
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
			get_firehose_queues(request).discard(
				queue
			)  # may have already been removed due to tooslow

	await ws.close()
	return ws
