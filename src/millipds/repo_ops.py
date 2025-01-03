"""
Theory: all MST-wrangling should happen in here, but all SQL happens in database.py

(in the interrim we'll do raw SQL in here, and refactor later...)

actuallyyyyyyy I think I changed my mind. given the sheer volume of SQL involved, and
its tight coupling to the actual commit logic, I think it makes the most sense to have it right here.

I'm never planning on replacing sqlite with anything else, so the tight coupling is fine.
"""

import io
from typing import List, TypedDict, Literal, TYPE_CHECKING, Optional, Tuple, Set

if TYPE_CHECKING:
	from typing import NotRequired  # not suppored <= py3.10
import apsw
import aiohttp.web
import base64

import cbrrr

from atmst.blockstore import OverlayBlockStore, MemoryBlockStore
from atmst.mst.node_store import NodeStore
from atmst.mst.node_wrangler import NodeWrangler
from atmst.mst.node_walker import NodeWalker
from atmst.mst.diff import mst_diff, record_diff, DeltaType
from atmst.mst import proof

from .database import Database, DBBlockStore
from . import util
from . import crypto

import logging

logger = logging.getLogger(__name__)


# record plus full merkle path as CAR (or nonexistence proof)
def get_record(db: Database, did: str, path: str) -> Optional[bytes]:
	with db.new_con(readonly=True) as con:
		row = con.execute(
			"SELECT id, head, commit_bytes FROM user WHERE did=?", (did,)
		).fetchone()

		if row is None:
			logger.info("did not found")
			return None

		user_id, head, commit_bytes = row
		car = io.BytesIO()
		car.write(util.serialize_car_header(head))
		car.write(util.serialize_car_entry(head, commit_bytes))

		commit = cbrrr.decode_dag_cbor(commit_bytes)

		bs = DBBlockStore(con, did)
		ns = NodeStore(bs)

		record_cid, proof_cids = proof.find_rpath_and_build_proof(
			ns, commit["data"], path
		)
		for cid in proof_cids:
			cid_bytes = bytes(cid)
			car.write(
				util.serialize_car_entry(cid_bytes, bs.get_block(cid_bytes))
			)

		if record_cid is None:
			return car.getvalue()

		# we don't have a neat abstraction for fetching records yet...
		record_cid_bytes = bytes(record_cid)
		record, *_ = con.execute(
			"SELECT value FROM record WHERE repo=? AND cid=?",
			(user_id, record_cid_bytes),
		).fetchone()
		car.write(util.serialize_car_entry(record_cid_bytes, record))

		return car.getvalue()


# https://github.com/bluesky-social/atproto/blob/main/lexicons/com/atproto/repo/applyWrites.json
if TYPE_CHECKING:
	WriteOp = TypedDict(
		"WriteOp",
		{
			"$type": Literal[
				"com.atproto.repo.applyWrites#create",
				"com.atproto.repo.applyWrites#update",
				"com.atproto.repo.applyWrites#delete",
			],
			"collection": str,
			"rkey": NotRequired[str],  # required for update, delete
			"validate": NotRequired[bool],
			"swapRecord": NotRequired[str],
			"value": NotRequired[
				dict | str
			],  # not required for delete - str is for base64-encoded dag-cbor
		},
	)


# This is perhaps the most complex function in the whole codebase.
# There's probably some scope for refactoring, but I like the "directness" of it.
# The work it does is inherently complex, i.e. the atproto MST record commit logic
# The MST logic itself is hidden away inside the `atmst` module.
def apply_writes(
	db: Database, repo: str, writes: List["WriteOp"], swap_commit: Optional[str]
) -> Tuple[dict, int, bytes]:
	# one big transaction (we could perhaps work in two phases, prepare (via read-only conn) then commit?)
	with db.new_con() as con:
		db_bs = DBBlockStore(con, repo)
		mem_bs = MemoryBlockStore()
		bs = OverlayBlockStore(mem_bs, db_bs)
		ns = NodeStore(bs)
		wrangler = NodeWrangler(ns)
		user_id, prev_commit, signing_key_pem, head = con.execute(
			"SELECT id, commit_bytes, signing_key, head FROM user WHERE did=?",
			(repo,),
		).fetchone()
		if swap_commit is not None:
			if cbrrr.CID.decode(swap_commit) != cbrrr.CID(head):
				raise aiohttp.web.HTTPBadRequest(
					text="swapCommit did not match current head"
				)  # XXX: probably the wrong way to signal this error lol
		prev_commit = cbrrr.decode_dag_cbor(prev_commit)
		prev_commit_root: cbrrr.CID = prev_commit["data"]
		tid_now = util.tid_now()

		record_cbors: dict[cbrrr.CID, bytes] = {}

		# step 0: apply writes into the MST
		# TODO: should I forbid touching the same record more than once?
		prev_root = prev_commit_root
		results = []  # for result of applyWrites
		for op in writes:
			optype = op["$type"]
			# TODO: rkey validation!
			rkey = op.get("rkey") or tid_now
			path = op["collection"] + "/" + rkey
			prev_cid = NodeWalker(ns, prev_root).find_rpath(path)
			if optype in [
				"com.atproto.repo.applyWrites#create",
				"com.atproto.repo.applyWrites#update",
			]:
				if optype == "com.atproto.repo.applyWrites#create":
					if prev_cid is not None:
						raise aiohttp.web.HTTPBadRequest(
							text="record already exists"
						)
				elif op.get("swapRecord"):  # only applies to #update
					if cbrrr.CID.decode(op["swapRecord"]) != prev_cid:
						raise aiohttp.web.HTTPBadRequest(
							text="swapRecord did not match"
						)

				if isinstance(op["value"], dict):  # normal
					value_cbor = cbrrr.encode_dag_cbor(
						op["value"], atjson_mode=True
					)
				elif isinstance(
					op["value"], str
				):  # base64 dag-cbor record extension
					value_cbor = base64.b64decode(op["value"])
				else:
					raise Exception("invalid record value type")

				value_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(value_cbor)
				record_cbors[value_cid] = value_cbor
				next_root = wrangler.put_record(prev_root, path, value_cid)
				results.append(
					{
						"$type": optype + "Result",
						"uri": f"at://{repo}/{path}",
						"cid": value_cid.encode(),
						"validationStatus": "unknown",  # we are not currently aware of the concept of a lexicon!
					}
				)
			elif optype == "com.atproto.repo.applyWrites#delete":
				if op.get("swapRecord"):
					if cbrrr.CID.decode(op["swapRecord"]) != prev_cid:
						raise aiohttp.web.HTTPBadRequest(
							text="swapRecord did not match"
						)
				next_root = wrangler.del_record(prev_root, path)
				if prev_root == next_root:
					raise aiohttp.web.HTTPBadRequest(
						text="no such record"
					)  # TODO: better error signalling!!!
				results.append(
					{"$type": "com.atproto.repo.applyWrites#deleteResult"}
				)
			else:
				raise ValueError("invalid applyWrites type")
			prev_root = next_root
		next_commit_root = prev_root

		logger.info(
			f"mst root {prev_commit_root.encode()} -> {next_commit_root.encode()}"
		)

		# step 1: diff the mst
		created, deleted = mst_diff(ns, prev_commit_root, next_commit_root)

		# step 2: persist record changes
		# (and also build ops list and gather proofs for firehose)
		# nb: this ops list may be more "efficient" than that of the input writes list
		# if e.g. a record was created and then immediately deleted, or modified multiple times.
		new_record_cids = []
		firehose_ops = []
		firehose_blobs = set()
		deletion_proof_cids = set()
		for delta in record_diff(ns, created, deleted):
			if delta.prior_value:
				# needed for blob decref
				prior_value = con.execute(
					"SELECT value FROM record WHERE repo=? AND nsid=? AND rkey=?",
					(user_id,) + util.split_path(delta.path),
				).fetchone()[0]
			if delta.delta_type == DeltaType.CREATED:
				new_record_cids.append(delta.later_value)
				firehose_ops.append(
					{
						"cid": delta.later_value,
						"path": delta.path,
						"action": "create",
					}
				)
				new_value = record_cbors[delta.later_value]
				firehose_blobs |= blob_incref_all(
					con, user_id, new_value, tid_now
				)
				con.execute(
					"INSERT INTO record (repo, nsid, rkey, cid, since, value) VALUES (?, ?, ?, ?, ?, ?)",
					(user_id,)
					+ util.split_path(delta.path)
					+ (bytes(delta.later_value), tid_now, new_value),
				)
			elif delta.delta_type == DeltaType.UPDATED:
				new_record_cids.append(delta.later_value)
				firehose_ops.append(
					{
						"cid": delta.later_value,
						"path": delta.path,
						"action": "update",
					}
				)
				new_value = record_cbors[delta.later_value]
				firehose_blobs |= blob_incref_all(
					con, user_id, new_value, tid_now
				)  # important to incref before decref
				blob_decref_all(con, user_id, prior_value)
				con.execute(
					"UPDATE record SET cid=?, since=?, value=? WHERE repo=? AND nsid=? AND rkey=?",
					(bytes(delta.later_value), tid_now, new_value, user_id)
					+ util.split_path(delta.path),
				)
			elif delta.delta_type == DeltaType.DELETED:
				# for creates and updates, the proof cids are already in `created`
				# - but deletion proofs are less obvious
				deletion_proof_cids.update(
					proof.build_exclusion_proof(
						ns, next_commit_root, delta.path
					)
				)
				firehose_ops.append(
					{"cid": None, "path": delta.path, "action": "delete"}
				)
				blob_decref_all(con, user_id, prior_value)
				con.execute(
					"DELETE FROM record WHERE repo=? AND nsid=? AND rkey=?",
					(user_id,) + util.split_path(delta.path),
				)
			else:
				raise Exception("unreachable")

		# step 3: persist MST changes (we have to do this *after* record_diff because it might need to read some old blocks from the db)
		con.executemany(
			"DELETE FROM mst WHERE repo=? AND cid=?",
			[(user_id, cid) for cid in map(bytes, deleted)],
		)
		con.executemany(
			"INSERT INTO mst (repo, cid, since, value) VALUES (?, ?, ?, ?)",
			[
				(user_id, cid, tid_now, bs.get_block(cid))
				for cid in map(bytes, created)
			],
		)

		# prepare the signed commit object
		commit_obj = {
			"version": 3,
			"did": repo,
			"data": next_commit_root,
			"rev": tid_now,
			"prev": None,
		}
		commit_obj["sig"] = crypto.raw_sign(
			crypto.privkey_from_pem(signing_key_pem),
			cbrrr.encode_dag_cbor(commit_obj),
		)
		commit_bytes = cbrrr.encode_dag_cbor(commit_obj)
		commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)

		# persist commit object
		con.execute(
			"UPDATE user SET commit_bytes=?, head=?, rev=? WHERE did=?",
			(commit_bytes, bytes(commit_cid), tid_now, repo),
		)

		car = io.BytesIO()
		cw = util.CarWriter(car, commit_cid)
		cw.write_block(commit_cid, commit_bytes)
		for mst_cid in created | deletion_proof_cids:
			cw.write_block(mst_cid, bs.get_block(bytes(mst_cid)))
		for record_cid in new_record_cids:
			cw.write_block(record_cid, record_cbors[record_cid])

		firehose_seq = con.execute(
			"SELECT IFNULL(MAX(seq), 0) + 1 FROM firehose"
		).fetchone()[0]
		firehose_body = {
			"ops": firehose_ops,
			"seq": firehose_seq,
			"rev": tid_now,
			"since": prev_commit["rev"],
			"prev": None,
			"repo": repo,
			"time": util.iso_string_now(),
			"blobs": list(firehose_blobs),
			"blocks": car.getvalue(),
			"commit": commit_cid,
			"rebase": False,  # deprecated but still required
			"tooBig": False,  # TODO: actually check lol
		}
		firehose_bytes = cbrrr.encode_dag_cbor(
			{"t": "#commit", "op": 1}
		) + cbrrr.encode_dag_cbor(firehose_body)
		con.execute(
			"INSERT INTO firehose (seq, timestamp, msg) VALUES (?, ?, ?)",
			(
				firehose_seq,
				0,
				firehose_bytes,
			),  # TODO: put sensible timestamp here...
		)

		applywrites_res = {
			"commit": {"cid": commit_cid.encode(), "rev": tid_now},
			"results": results,
		}

		return applywrites_res, firehose_seq, firehose_bytes


# and also set `since`, if previously unset
# NB: both of these will incref/decref the same blob multiple times, if a record contains the same blob multiple times.
# this is mildly sub-optimal perf-wise but it keeps the code simple.
# (why would you reference the same blob multiple times anyway?)
def blob_incref_all(
	con: apsw.Connection, user_id: int, record_bytes: bytes, tid: str
) -> Set[cbrrr.CID]:
	new_blobs = set()
	for ref in util.enumerate_blob_cids(cbrrr.decode_dag_cbor(record_bytes)):
		new_blobs.add(ref)
		blob_incref(con, user_id, ref, tid)
	return new_blobs


def blob_decref_all(con: apsw.Connection, user_id: int, record_bytes: bytes):
	for ref in util.enumerate_blob_cids(cbrrr.decode_dag_cbor(record_bytes)):
		blob_decref(con, user_id, ref)


def blob_incref(con: apsw.Connection, user_id: int, ref: cbrrr.CID, tid: str):
	# also set `since` if this is the first time a blob has ever been ref'd
	con.execute(
		"UPDATE blob SET refcount=refcount+1, since=IFNULL(since, ?) WHERE blob.repo=? AND blob.cid=?",
		(tid, user_id, bytes(ref)),
	)
	changes = con.changes()  # number of updated rows

	if changes == 1:
		return  # happy path

	if changes == 0:  # could happen if e.g. user didn't upload blob first
		raise ValueError("tried to incref a blob that doesn't exist")

	# changes > 1 (should be impossible given UNIQUE constraints)
	raise ValueError("welp, that's not supposed to happen")


def blob_decref(con: apsw.Connection, user_id: int, ref: cbrrr.CID):
	blob_id, refcount = con.execute(
		"UPDATE blob SET refcount=refcount-1 WHERE blob.repo=? AND blob.cid=? RETURNING id, refcount",
		(user_id, bytes(ref)),
	).fetchone()

	assert con.changes() == 1
	assert refcount >= 0

	if refcount == 0:
		con.execute(
			"DELETE FROM blob_part WHERE blob=?", (blob_id,)
		)  # TODO: could also make this happen in a delete hook?
		con.execute("DELETE FROM blob WHERE id=?", (blob_id,))
