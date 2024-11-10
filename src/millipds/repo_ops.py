"""
Theory: all MST-wrangling should happen in here, but all SQL happens in database.py

(in the interrim we'll do raw SQL in here, and refactor later...)
"""

from typing import List, TypedDict, Literal, NotRequired
from .database import Database
from . import util
from . import crypto

import logging
logger = logging.getLogger(__name__)

import cbrrr

from atmst.blockstore import BlockStore, OverlayBlockStore, MemoryBlockStore
from atmst.mst.node_store import NodeStore
from atmst.mst.node_wrangler import NodeWrangler
from atmst.mst.node_walker import NodeWalker
from atmst.mst.node import MSTNode
from atmst.mst.diff import mst_diff, record_diff, DeltaType

# https://github.com/bluesky-social/atproto/blob/main/lexicons/com/atproto/repo/applyWrites.json
WriteOp = TypedDict("WriteOp", {
	"$type": Literal["com.atproto.repo.applyWrites#create", "com.atproto.repo.applyWrites#update", "com.atproto.repo.applyWrites#delete"],
	"collection": str,
	"rkey": NotRequired[str],
	"value": dict
})

def apply_writes(db: Database, repo: str, writes: List[WriteOp]):
	# TODO: is apsw's context manager async-safe???
	with db.con: # one big transaction (we could perhaps work in two phases, prepare (via read-only conn) then commit?)
		db_bs = db.get_blockstore(repo)
		mem_bs = MemoryBlockStore()
		bs = OverlayBlockStore(mem_bs, db_bs)
		ns = NodeStore(bs)
		wrangler = NodeWrangler(ns)
		user_id, prev_commit, signing_key_pem = db.con.execute("SELECT id, commit_bytes, signing_key FROM user WHERE did=?", (repo,)).fetchone()
		prev_commit = cbrrr.decode_dag_cbor(prev_commit)
		prev_commit_root = prev_commit["data"]
		tid_now = util.tid_now()

		record_cbors: dict[cbrrr.CID, bytes] = {}

		# step 0: apply writes into the MST
		# TODO: should I forbid touching the same record more than once?
		prev_root = prev_commit_root
		results = [] # for result of applyWrites
		for op in writes:
			optype = op["$type"]
			# TODO: rkey validation!
			if optype in ["com.atproto.repo.applyWrites#create", "com.atproto.repo.applyWrites#update"]:
				rkey = op.get("rkey") or tid_now
				path = op["collection"] + "/" + rkey
				if optype == "com.atproto.repo.applyWrites#create":
					if NodeWalker(ns, prev_root).find_value(path):
						raise Exception("record already exists")
				value_cbor = cbrrr.encode_dag_cbor(op["value"], atjson_mode=True)
				value_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(value_cbor)
				record_cbors[value_cid] = value_cbor
				next_root = wrangler.put_record(prev_root, path, value_cid)
				results.append({
					"$type": optype + "Result",
					"uri": f"at://{repo}/{path}",
					"cid": value_cid.encode()
				})
			elif optype == "com.atproto.repo.applyWrites#delete":
				next_root = wrangler.del_record(prev_root, op["collection"] + "/" + op["rkey"])
				if prev_root == next_root:
					raise Exception("no such record") # TODO: better error signalling!!!
				results.append({
					"$type": "com.atproto.repo.applyWrites#deleteResult"
				})
			else:
				raise ValueError("invalid applyWrites type")
			prev_root = next_root
		next_commit_root = prev_root

		logger.info(f"mst root {prev_commit_root.encode()} -> {next_commit_root.encode()}")

		# step 1: diff the mst
		created, deleted = mst_diff(ns, prev_commit_root, next_commit_root)

		# step 2: persist MST changes
		db.con.executemany(
			"DELETE FROM mst WHERE repo=? AND cid=?",
			[(user_id, cid) for cid in map(bytes, deleted)]
		)
		db.con.executemany(
			"INSERT INTO mst (repo, cid, since, value) VALUES (?, ?, ?, ?)",
			[(user_id, cid, tid_now, bs.get_block(cid)) for cid in map(bytes, created)]
		)

		# step 3: persist record changes
		# TODO: also build ops list for firehose
		for delta in record_diff(ns, created, deleted):
			if delta.delta_type == DeltaType.CREATED:
				db.con.execute(
					"INSERT INTO record (repo, path, cid, since, value) VALUES (?, ?, ?, ?, ?)",
					(user_id, delta.key, bytes(delta.later_value), tid_now, record_cbors[delta.later_value])
				)
			elif delta.delta_type == DeltaType.UPDATED:
				db.con.execute(
					"UPDATE record SET cid=?, since=?, value=? WHERE repo=? AND path=?",
					(bytes(delta.later_value), tid_now, record_cbors[delta.later_value], user_id, delta.key)
				)
			elif delta.delta_type == DeltaType.DELETED:
				db.con.execute(
					"DELETE FROM WHERE repo=? AND path=?",
					(user_id, delta.key)
				)
			else:
				raise Exception("unreachable")
		
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
			cbrrr.encode_dag_cbor(commit_obj)
		)
		commit_bytes = cbrrr.encode_dag_cbor(commit_obj)
		commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)

		# persist commit object
		db.con.execute(
			"UPDATE user SET commit_bytes=?, head=?, rev=? WHERE did=?",
			(commit_bytes, bytes(commit_cid), tid_now, repo)
		)

		# TODO: create firehose event
		# TODO: persist firehose event

		applywrites_res = {
			"commit": {
				"cid": commit_cid.encode(),
				"rev": tid_now
			},
			"results": results
		}

		return applywrites_res, "TODO"


