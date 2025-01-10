"""
Ideally, all SQL statements are contained within this file.

Password hashing also happens in here, because it doesn't make much sense to do
it anywhere else.
"""

from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging

import argon2  # maybe this should come from .crypto?
import apsw
import apsw.bestpractice

import cbrrr
from atmst.blockstore import BlockStore
from atmst.mst.node import MSTNode

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

	def __init__(self, db: apsw.Connection, repo: str) -> None:
		self.db = db
		self.user_id = self.db.execute(
			"SELECT id FROM user WHERE did=?", (repo,)
		).fetchone()[0]

	def get_block(self, key: bytes) -> bytes:
		row = self.db.execute(
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
		logger.info(f"opening database at {path}")
		self.path = path
		if "/" in path:
			util.mkdirs_for_file(path)
		self.con = self.new_con()
		self.pw_hasher = argon2.PasswordHasher()

		config_exists = self.con.execute(
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='config'"
		).fetchone()[0]

		if config_exists:
			if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
				raise Exception(
					"unrecognised db version (TODO: db migrations?!)"
				)
		else:
			with self.con:
				self._init_tables()

	def new_con(self, readonly=False):
		"""
		https://rogerbinns.github.io/apsw/cursor.html
		"Cursors on the same Connection are not isolated from each other.
		Anything done on one cursor is immediately visible to all other Cursors
		on the same connection. This still applies if you start transactions.
		Connections are isolated from each other with cursors on other
		connections not seeing changes until they are committed."

		therefore we frequently spawn new connections when we need an isolated cursor
		"""
		return apsw.Connection(
			self.path,
			flags=(
				apsw.SQLITE_OPEN_READONLY
				if readonly
				else apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
			),
		)

	def _init_tables(self):
		logger.info("initing tables")
		self.con.execute(
			"""
			CREATE TABLE config(
				db_version INTEGER NOT NULL,
				pds_pfx TEXT,
				pds_did TEXT,
				bsky_appview_pfx TEXT,
				bsky_appview_did TEXT,
				jwt_access_secret TEXT NOT NULL
			) STRICT
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

		# TODO: head and rev are redundant, technically (rev contained within commit_bytes)
		self.con.execute(
			"""
			CREATE TABLE user(
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				did TEXT NOT NULL,
				handle TEXT NOT NULL,
				prefs BLOB NOT NULL,
				pw_hash TEXT NOT NULL,
				signing_key TEXT NOT NULL,
				head BLOB NOT NULL,
				rev TEXT NOT NULL,
				commit_bytes BLOB NOT NULL
			) STRICT
			"""
		)

		self.con.execute("CREATE UNIQUE INDEX user_by_did ON user(did)")
		self.con.execute("CREATE UNIQUE INDEX user_by_handle ON user(handle)")

		self.con.execute(
			"""
			CREATE TABLE firehose(
				seq INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp INTEGER NOT NULL,
				msg BLOB NOT NULL
			) STRICT
			"""
		)
		# TODO: index on timestamp for efficient purging of old events.

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
			) STRICT, WITHOUT ROWID
			"""
		)
		# should maybe be (repo, since) instead?
		self.con.execute("CREATE INDEX mst_since ON mst(since)")

		self.con.execute(
			"""
			CREATE TABLE record(
				repo INTEGER NOT NULL,
				nsid TEXT NOT NULL,
				rkey TEXT NOT NULL,
				cid BLOB NOT NULL,
				since TEXT NOT NULL,
				value BLOB NOT NULL,
				FOREIGN KEY (repo) REFERENCES user(id),
				PRIMARY KEY (repo, nsid, rkey)
			) STRICT, WITHOUT ROWID
			"""
		)
		# should maybe be (repo, since) instead? maybe also (repo, nsid, since)?
		self.con.execute("CREATE INDEX record_since ON record(since)")

		# nb: blobs are partitioned per-repo
		# TODO: think carefully about refcount/since interaction?
		# TODO: when should blob GC happen? after each commit? (nah, that would behave badly with e.g. concurrent browser sessions)
		# NOTE: blobs have null cid when they're midway through being uploaded,
		# and they have null "since" when they haven't been committed yet
		# TODO: store length explicitly?
		self.con.execute(
			"""
			CREATE TABLE blob(
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				repo INTEGER NOT NULL,
				cid BLOB,
				refcount INTEGER NOT NULL,
				since TEXT,
				FOREIGN KEY (repo) REFERENCES user(id)
			) STRICT
			"""
		)
		self.con.execute(
			"CREATE INDEX blob_isrefd ON blob(refcount, refcount > 0)"
		)  # dunno how useful this is
		self.con.execute("CREATE UNIQUE INDEX blob_repo_cid ON blob(repo, cid)")
		self.con.execute("CREATE INDEX blob_since ON blob(since)")

		self.con.execute(
			"""
			CREATE TABLE blob_part(
				blob INTEGER NOT NULL,
				idx INTEGER NOT NULL,
				data BLOB NOT NULL,
				PRIMARY KEY (blob, idx),
				FOREIGN KEY (blob) REFERENCES blob(id)
			) STRICT, WITHOUT ROWID
			"""
		)

		# we cache failures too, represented as a null doc (with shorter TTL)
		# timestamps are unix timestamp ints, in seconds
		self.con.execute(
			"""
			CREATE TABLE did_cache(
				did TEXT PRIMARY KEY NOT NULL,
				doc BLOB,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			) STRICT, WITHOUT ROWID
			"""
		)

		# likewise, a null did represents a failed resolution
		self.con.execute(
			"""
			CREATE TABLE handle_cache(
				handle TEXT PRIMARY KEY NOT NULL,
				did TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			) STRICT, WITHOUT ROWID
			"""
		)

		# this is only for the tokens *we* issue, dpop jti will be tracked separately
		# there's no point remembering that an expired token was revoked, and we'll garbage-collect these periodically
		self.con.execute(
			"""
			CREATE TABLE revoked_token(
				did TEXT NOT NULL,
				jti TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				PRIMARY KEY (did, jti)
			) STRICT, WITHOUT ROWID
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
					b'{"preferences":[]}',
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

	def verify_account_login(
		self, did_or_handle: str, password: str
	) -> Tuple[str, str]:
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
		row = self.con.execute(
			"SELECT handle FROM user WHERE did=?", (did,)
		).fetchone()
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

	def list_repos(
		self,
	) -> List[Tuple[str, cbrrr.CID, str]]:  # TODO: pagination
		return [
			(did, cbrrr.CID(head), rev)
			for did, head, rev in self.con.execute(
				"SELECT did, head, rev FROM user"
			).fetchall()
		]

	def get_blockstore(self, did: str) -> "Database":
		return DBBlockStore(self, did)
