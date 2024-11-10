"""
Ideally, all SQL statements are contained within this file.

Password hashing also happens in here, because it doesn't make much sense to do
it anywhere else.
"""

from typing import Optional, Dict, List, Tuple, BinaryIO
from functools import cached_property
import secrets
import logging
import io

import argon2  # maybe this should come from .crypto?
import apsw
import apsw.bestpractice

import cbrrr
from atmst.blockstore import BlockStore, OverlayBlockStore, MemoryBlockStore
from atmst.mst.node_store import NodeStore
from atmst.mst.node_wrangler import NodeWrangler
from atmst.mst.node import MSTNode
from atmst.mst.diff import mst_diff, record_diff

from . import static_config
from . import util
from . import crypto

logger = logging.getLogger(__name__)

# https://rogerbinns.github.io/apsw/bestpractice.html
apsw.bestpractice.apply(apsw.bestpractice.recommended)

class DBBlockStore(BlockStore):
	"""
	Adapt the db for consumption by the atmst library
	"""

	def __init__(self, db: "Database", repo: str) -> None:
		self.db = db
		# TODO: implement and use db instance method!
		self.user_id = self.db.con.execute("SELECT id FROM user WHERE did=?", (repo,)).fetchone()[0]

	def get_block(self, key: bytes) -> bytes:
		# TODO: implement and use db instance method!
		row = self.db.con.execute(
			"SELECT value FROM mst WHERE repo=? AND cid=?", (self.user_id, key)
		).fetchone()
		if row is None:
			raise KeyError("block not found in db")
		return row[0]

	def del_block(self, key: bytes) -> None:
		raise NotImplementedError("TODO?")
	
	def put_block(self, key: bytes, value: bytes) -> None:
		raise NotImplementedError("TODO?")


class Database:
	def __init__(self, path: str = static_config.MAIN_DB_PATH) -> None:
		util.mkdirs_for_file(path)
		self.con = apsw.Connection(path)
		self.pw_hasher = argon2.PasswordHasher()

		try:
			if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
				raise Exception("unrecognised db version (TODO: db migrations?!)")

		except apsw.SQLError as e:  # no such table, so lets create it
			if not "no such table" in str(e):
				raise
			with self.con:
				self._init_central_tables()

	def _init_central_tables(self):
		logger.info("initing central tables")
		self.con.execute(
			"""
			CREATE TABLE config(
				db_version INTEGER NOT NULL,
				pds_pfx TEXT,
				pds_did TEXT,
				bsky_appview_pfx TEXT,
				bsky_appview_did TEXT,
				jwt_access_secret TEXT NOT NULL
			)
			"""
		)

		self.con.execute(
			"""
			INSERT INTO config(
				db_version,
				jwt_access_secret
			) VALUES (?, ?)
			""",
			(static_config.MILLIPDS_DB_VERSION, secrets.token_hex()),
		)

		self.con.execute(
			"""
			CREATE TABLE user(
				id INTEGER PRIMARY KEY NOT NULL,
				did TEXT NOT NULL,
				handle TEXT NOT NULL,
				prefs BLOB NOT NULL,
				pw_hash TEXT NOT NULL,
				signing_key TEXT NOT NULL,
				head BLOB NOT NULL,
				rev TEXT NOT NULL,
				commit_bytes BLOB NOT NULL
			)
			"""
		)

		self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")
		self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")

		self.con.execute(
			"""
			CREATE TABLE firehose(
				seq INTEGER PRIMARY KEY NOT NULL,
				timestamp INTEGER NOT NULL,
				msg BLOB NOT NULL
			)
			"""
		)

		# repo storage stuff
		self.con.execute(
			"""
			CREATE TABLE mst(
				repo INTEGER NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, cid)
			)
			"""
		)
		self.con.execute("CREATE INDEX mst_since ON mst(since)")

		self.con.execute(
			"""
			CREATE TABLE record(
				repo INTEGER NOT NULL,
				path TEXT NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, path)
			)
			"""
		)
		self.con.execute("CREATE INDEX record_since ON record(since)")

		# nb: blobs are partitioned per-repo
		# TODO: think carefully about refcount/since interaction?
		# TODO: when should blob GC happen? after each commit?
		self.con.execute(
			"""
			CREATE TABLE blob(
				repo INTEGER NOT NULL,
				cid BLOB NOT NULL,
				refcount INTEGER NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, cid)
			)
			"""
		)
		self.con.execute("CREATE INDEX blob_isrefd ON blob(refcount, refcount > 0)") # dunno how useful this is
		self.con.execute("CREATE INDEX blob_since ON blob(since)")

	def update_config(
		self,
		pds_pfx: Optional[str] = None,
		pds_did: Optional[str] = None,
		bsky_appview_pfx: Optional[str] = None,
		bsky_appview_did: Optional[str] = None,
	):
		with self.con:
			if pds_pfx is not None:
				self.con.execute("UPDATE config SET pds_pfx=?", (pds_pfx,))
			if pds_did is not None:
				self.con.execute("UPDATE config SET pds_did=?", (pds_did,))
			if bsky_appview_pfx is not None:
				self.con.execute(
					"UPDATE config SET bsky_appview_pfx=?", (bsky_appview_pfx,)
				)
			if bsky_appview_did is not None:
				self.con.execute(
					"UPDATE config SET bsky_appview_did=?", (bsky_appview_did,)
				)

		try:
			del self.config  # invalidate the cached value
		except AttributeError:
			pass

	@cached_property
	def config(self) -> Dict[str, object]:
		config_fields = (
			"db_version",
			"pds_pfx",
			"pds_did",
			"bsky_appview_pfx",
			"bsky_appview_did",
			"jwt_access_secret",
		)

		cfg = self.con.execute(
			f"SELECT {', '.join(config_fields)} FROM config"
		).fetchone()

		# TODO: consider using a properly typed dataclass rather than a dict
		# see also https://docs.python.org/3/library/typing.html#typing.TypedDict
		return dict(zip(config_fields, cfg))

	def config_is_initialised(self) -> bool:
		return all(v is not None for v in self.config.values())

	def print_config(self, redact_secrets: bool = True) -> None:
		maxlen = max(map(len, self.config))
		for k, v in self.config.items():
			if redact_secrets and "secret" in k:
				v = "[REDACTED]"
			print(f"{k:<{maxlen}} : {v!r}")

	def create_account(
		self,
		did: str,
		handle: str,
		password: str,
		privkey: crypto.ec.EllipticCurvePrivateKey,
	) -> None:
		pw_hash = self.pw_hasher.hash(password)
		privkey_pem = crypto.privkey_to_pem(privkey)
		logger.info(f"creating account for did={did}, handle={handle}")

		# create an initial commit for an empty MST, as an atomic transaction
		with self.con:
			tid = util.tid_now()
			empty_mst = MSTNode.empty_root()
			initial_commit = {
				"did": did,  # TODO: did normalisation, somewhere?
				"version": static_config.ATPROTO_REPO_VERSION_3,
				"data": empty_mst.cid,
				"rev": tid,
				"prev": None,
			}
			initial_commit["sig"] = crypto.raw_sign(
				privkey, cbrrr.encode_dag_cbor(initial_commit)
			)
			commit_bytes = cbrrr.encode_dag_cbor(initial_commit)
			commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)
			self.con.execute(
				"""
				INSERT INTO user(
					did,
					handle,
					prefs,
					pw_hash,
					signing_key,
					head,
					rev,
					commit_bytes
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					did,
					handle,
					b"{}",
					pw_hash,
					privkey_pem,
					bytes(commit_cid),
					tid,
					commit_bytes,
				),
			)
			user_id = self.con.last_insert_rowid()
			self.con.execute(
				"INSERT INTO mst(repo, cid, since, value) VALUES (?, ?, ?, ?)",
				(user_id, bytes(empty_mst.cid), tid, empty_mst.serialised),
			)
			#util.mkdirs_for_file(repo_path)
			#UserDatabase.init_tables(self.con, did, repo_path, tid)
		#self.con.execute("DETACH spoke")

	def verify_account_login(
		self, did_or_handle: str, password: str
	) -> Tuple[str, str, str, str]:
		row = self.con.execute(
			"SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?",
			(did_or_handle, did_or_handle),
		).fetchone()
		if row is None:
			raise KeyError("no account found for did")
		did, handle, pw_hash = row
		try:
			self.pw_hasher.verify(pw_hash, password)
		except argon2.exceptions.VerifyMismatchError:
			raise ValueError("invalid password")
		return did, handle

	def did_by_handle(self, handle: str) -> Optional[str]:
		row = self.con.execute(
			"SELECT did FROM user WHERE handle=?", (handle,)
		).fetchone()
		if row is None:
			return None
		return row[0]

	def handle_by_did(self, did: str) -> Optional[str]:
		row = self.con.execute("SELECT handle FROM user WHERE did=?", (did,)).fetchone()
		if row is None:
			return None
		return row[0]

	def signing_key_pem_by_did(self, did: str) -> Optional[str]:
		row = self.con.execute(
			"SELECT signing_key FROM user WHERE did=?", (did,)
		).fetchone()
		if row is None:
			return None
		return row[0]

	def list_repos(self) -> List[Tuple[str, cbrrr.CID, str]]:  # TODO: pagination
		return [
			(did, cbrrr.CID(head), rev)
			for did, head, rev in self.con.execute(
				"SELECT did, head, rev FROM user"
			).fetchall()
		]

	def get_repo(self, did: str, stream: BinaryIO):
		# TODO: make this async?
		# TODO: "since"
		# TODO: maybe use a brand new read-only db connection?

		with self.con: # make sure we have a consistent view of the repo
			user_id, head, commit_bytes = self.con.execute(
				"SELECT id, head, commit_bytes FROM user WHERE did=?",
				(did,)
			).fetchone()
			head = cbrrr.CID(head)
			cw = util.CarWriter(stream, head)
			cw.write_block(head, commit_bytes)

			for mst_cid, mst_value in self.con.execute(
				"SELECT cid, value FROM mst WHERE repo=?",
				(user_id,)
			):
				cw.write_block(cbrrr.CID(mst_cid), mst_value)

			for record_cid, record_value in self.con.execute(
				"SELECT cid, value FROM record WHERE repo=?",
				(user_id,)
			):
				cw.write_block(cbrrr.CID(record_cid), record_value)

	def get_blockstore(self, did: str) -> "Database":
		return DBBlockStore(self, did)


if 0: # this is dead code now but I'm leaving the WIP commit logic for reference
	class UserDatabase:
		def get_repo(self, stream: BinaryIO):
			# TODO: make this async?
			# TODO: "since"
			# TODO: there might be some atomicity/consistency issues here!

			head, commit_bytes = self.wcon.execute(
				"SELECT head, commit_bytes FROM user WHERE did=?", (self.did,)
			).fetchone()
			head = cbrrr.CID(head)
			cw = util.CarWriter(stream, head)
			cw.write_block(head, commit_bytes)

			for mst_cid, mst_value in self.rcon.execute("SELECT cid, value FROM mst"):
				cw.write_block(cbrrr.CID(mst_cid), mst_value)

			for record_cid, record_value in self.rcon.execute(
				"SELECT cid, value FROM record"
			):
				cw.write_block(cbrrr.CID(record_cid), record_value)

		def create_record(self, path: str, record):
			# this'll eventually be an "applywrites", once I refactor.
			# TODO: make this async????? (nahhhh)

			# prepare the new commit
			bs = OverlayBlockStore(MemoryBlockStore(), UserDBBlockStore(self.rcon))
			ns = NodeStore(bs)  # TODO: make a NodeStore with global LRU cache?
			wrangler = NodeWrangler(ns)
			privkey_pem, prev_head, prev_commit_bytes = self.wcon.execute(
				"SELECT signing_key, head, commit_bytes FROM user WHERE did=?", (self.did,)
			)
			privkey = crypto.privkey_from_pem(privkey_pem)
			prev_commit = cbrrr.decode_dag_cbor(prev_commit_bytes)

			record_bytes = cbrrr.encode_dag_cbor(record)
			record_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(record_bytes)

			# wrangle the MST
			prev_root = prev_commit["data"]
			new_root = wrangler.put_record(prev_root, path, record_cid)
			mst_created, mst_deleted = mst_diff(ns, prev_root, new_root)
			record_deltas = list(record_diff(ns, mst_created, mst_deleted))

			# construct the commit object
			tid = util.tid_now()
			commit_obj = {
				"did": self.did,  # TODO: did normalisation, somewhere?
				"version": static_config.ATPROTO_REPO_VERSION_3,
				"data": new_root,
				"rev": tid,
				"prev": None,  # deprecated but still required to be present
			}
			commit_obj["sig"] = crypto.raw_sign(privkey, cbrrr.encode_dag_cbor(commit_obj))
			commit_bytes = cbrrr.encode_dag_cbor(commit_obj)
			commit_cid = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(commit_bytes)

			# gather the MST blocks
			# TODO: consider being more liberal about which mst blocks are included
			car = io.BytesIO()
			cw = util.CarWriter(car, commit_cid)
			cw.write_block(commit_cid, commit_bytes)
			for mst_cid in mst_created:
				cw.write_block(mst_cid, bs.get_block(bytes(mst_cid)))
			cw.write_block(
				record_cid, record_bytes
			)  # TODO: build this alongside apply_writes

			# transaction should probably start here
			firehose_body = {
				"ops": [
					{"cid": record_cid, "path": path, "action": "create"}
				],  # TODO construct this from record_delta
				"seq": 0,  # TODO
				"rev": tid,
				"since": prev_commit["rev"],
				"prev": None,
				"repo": self.did,
				"time": util.iso_string_now(),
				"blobs": [],  # TODO!!!
				"blocks": car.getvalue(),
				"commit": commit_cid,
				"rebase": False,  # deprecated but still required
				"tooBig": False,  # TODO: actually check lol
			}

			# TODO: draw the rest of the owl
			try:
				with self.wcon: # transaction for write
					self.wcon.execute("ATTACH ? AS spoke", (self.path,))

					self.wcon.executemany("INSERT INTO spoke.mst(cid, since, value) VALUES (?, ?, ?)", [
						(bytes(cid), tid, bs.get_block(cid))
						for cid in mst_created
					])

					self.wcon.executemany("DELETE FROM spoke.mst WHERE cid=?", [
						(bytes(cid),)
						for cid in mst_deleted
					])

					self.wcon.execute("INSERT INTO spoke.record(path, cid, since, value) VALUES (?, ?, ?, ?)", (
						path, record_cid, tid, record_bytes
					))
			finally:
				self.wcon.execute("DETACH spoke")
