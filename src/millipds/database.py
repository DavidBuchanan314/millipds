"""
Ideally, all SQL statements are contained within this file.

Password hashing also happens in here, because it doesn't make much sense to do
it anywhere else.
"""

from typing import Optional, Dict, List, Tuple
from functools import cached_property
import secrets
import logging

from argon2 import PasswordHasher  # maybe this should come from .crypto?
import apsw
import apsw.bestpractice

from cbrrr import CID
from atmst.blockstore import BlockStore

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
		self.pw_hasher = PasswordHasher()

		try:
			if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
				raise Exception("unrecognised db version (TODO: db migrations?!)")

		except apsw.SQLError as e:  # no such table, so lets create it
			if "no such table" not in str(e):
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
				head BLOB,
				rev TEXT
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
		with self.con:
			self.con.execute(
				"""
				INSERT INTO user(
					did,
					handle,
					prefs,
					pw_hash,
					repo_path,
					signing_key
				) VALUES (?, ?, ?, ?, ?, ?)
				""",
				(did, handle, b"{}", pw_hash, repo_path, privkey_pem),
			)
			util.mkdirs_for_file(repo_path)
			UserDatabase.init_tables(self.con, did, repo_path)
		self.con.execute("DETACH spoke")

	def get_account(self, did_or_handle: str) -> Tuple[str, str, str]:
		row = self.con.execute(
			"SELECT did, handle, pw_hash FROM user WHERE did=? OR handle=?",
			(did_or_handle, did_or_handle),
		).fetchone()
		if row is None:
			raise KeyError("no account found for did")
		did, handle, pw_hash = row
		return did, handle, pw_hash

	def list_repos(self) -> List[Tuple[str, CID, str]]:  # TODO: pagination
		return [
			(did, CID(head), rev)
			for did, head, rev in self.con.execute(
				"SELECT did, head, rev FROM user WHERE head IS NOT NULL AND rev IS NOT NULL"
			).fetchall()
		]


class UserDBBlockStore(BlockStore):
	pass  # TODO


class UserDatabase:
	def __init__(self, wcon: apsw.Connection, did: str, path: str) -> None:
		self.wcon = wcon  # writes go via the hub database connection, using ATTACH
		self.rcon = apsw.Connection(path, flags=apsw.SQLITE_OPEN_READONLY)

		# TODO: check db version and did match

	@staticmethod
	def init_tables(wcon: apsw.Connection, did: str, path: str) -> None:
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

		# TODO: the other tables

		# nb: caller is responsible for running "DETACH spoke", after the end
		# of the transaction
