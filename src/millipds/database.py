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
				did TEXT PRIMARY KEY NOT NULL,
				handle TEXT NOT NULL,
				prefs BLOB NOT NULL,
				pw_hash TEXT NOT NULL,
				repo_path TEXT NOT NULL,
				signing_key TEXT NOT NULL,
				head BLOB NOT NULL,
				rev TEXT NOT NULL,
				commit_bytes BLOB NOT NULL
			)
			"""
		)

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
		repo_path = (
			f"{static_config.REPOS_DIR}/{util.did_to_safe_filename(did)}.sqlite3"
		)
		logger.info(f"creating account for did={did}, handle={handle} at {repo_path}")

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
					repo_path,
					signing_key,
					head,
					rev,
					commit_bytes
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					did,
					handle,
					b"{}",
					pw_hash,
					repo_path,
					privkey_pem,
					bytes(commit_cid),
					tid,
					commit_bytes,
				),
			)
			util.mkdirs_for_file(repo_path)
			UserDatabase.init_tables(self.con, did, repo_path, tid)
		self.con.execute("DETACH spoke")

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

	def get_user_db(self, did: str) -> "UserDatabase":
		# TODO: cache the UserDatabase instance (reuse db connections)
		row = self.con.execute(
			"SELECT repo_path FROM user WHERE did=?", (did,)
		).fetchone()
		if row is None:
			raise KeyError("user not found")
		path = row[0]
		return UserDatabase(self.con, did, path)


class UserDBBlockStore(BlockStore):
	"""
	Adapt the db for consumption by the atmst library
	"""

	def __init__(self, udb: "UserDatabase") -> None:
		self.udb = udb

	def get_block(self, key: bytes) -> bytes:
		row = self.udb.rcon.execute(
			"SELECT value FROM mst WHERE cid=?", (key,)
		).fetchone()
		if row is None:
			raise KeyError("block not found in db")
		return row[0]


class UserDatabase:
	def __init__(self, wcon: apsw.Connection, did: str, path: str) -> None:
		self.wcon = wcon  # writes go via the hub database connection, using ATTACH
		self.did = did
		# we use a separate connection for reads (in theory, for better
		# concurrent accesses, but uh, we're not doing those yet)
		self.rcon = apsw.Connection(
			path
		)  # , flags=apsw.SQLITE_OPEN_READONLY) # looks like being literally read only is incompatible with WAL, but we're readonly in spirit

		db_version, db_did = self.rcon.execute(
			"SELECT db_version, did FROM repo"
		).fetchone()
		if db_version != static_config.MILLIPDS_DB_VERSION:
			raise ValueError("unsupported DB version (TODO: migrations?)")
		if db_did != did:
			raise ValueError("user db did mismatch")

	@staticmethod
	def init_tables(wcon: apsw.Connection, did: str, path: str, tid: str) -> None:
		wcon.execute("ATTACH ? AS spoke", (path,))

		wcon.execute(
			"""
			CREATE TABLE spoke.repo(
				db_version INTEGER NOT NULL,
				did TEXT NOT NULL
			)
			"""
		)

		wcon.execute(
			"INSERT INTO spoke.repo(db_version, did) VALUES (?, ?)",
			(static_config.MILLIPDS_DB_VERSION, did),
		)

		wcon.execute(
			"""
			CREATE TABLE spoke.mst(
				cid BLOB PRIMARY KEY NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL
			)
			"""
		)
		wcon.execute("CREATE INDEX spoke.mst_since ON mst(since)")
		empty_root = MSTNode.empty_root()
		wcon.execute(
			"INSERT INTO spoke.mst(cid, since, value) VALUES (?, ?, ?)",
			(bytes(empty_root.cid), tid, empty_root.serialised),
		)

		wcon.execute(
			"""
			CREATE TABLE spoke.record(
				path TEXT PRIMARY KEY NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL
			)
			"""
		)
		wcon.execute("CREATE INDEX spoke.record_since ON record(since)")

		wcon.execute(
			"""
			CREATE TABLE spoke.blob(
				cid BLOB PRIMARY KEY NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL
			)
			"""
		)
		wcon.execute("CREATE INDEX spoke.blob_since ON blob(since)")

		# nb: caller is responsible for running "DETACH spoke", after the end
		# of the transaction

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
		# TODO: make this async?????

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
