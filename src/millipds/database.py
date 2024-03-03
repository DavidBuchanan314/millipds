"""
Ideally, all SQL statements are contained within this file
"""

from typing import Optional, Dict
from functools import cached_property
import secrets

import apsw

from . import static_config
from . import util

class Database:
	def __init__(self, path: str=static_config.MAIN_DB_PATH) -> None:
		util.mkdirs_for_file(path)
		self.con = apsw.Connection(path)

		try:
			if self.config["db_version"] != static_config.MILLIPDS_DB_VERSION:
				raise Exception("unrecognised db version (TODO: db migrations?!)")

		except apsw.SQLError as e: # no such table, so lets create it
			if "no such table" not in str(e):
				raise
			with self.con:
				self._init_central_tables()

	def _init_central_tables(self):
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
			INSERT INTO config (
				db_version,
				jwt_access_secret
			) VALUES (?, ?)
			""",
			( static_config.MILLIPDS_DB_VERSION, secrets.token_hex() )
		)

		self.con.execute(
			"""
			CREATE TABLE user(
				did TEXT PRIMARY KEY NOT NULL,
				prefs BLOB NOT NULL,
				pw_hash TEXT NOT NULL,
				repo_path TEXT NOT NULL,
				signing_key TEXT NOT NULL
			)
			"""
		)

		self.con.execute(
			"""
			CREATE TABLE firehose(
				seq INTEGER PRIMARY KEY NOT NULL,
				timestamp INTEGER NOT NULL,
				msg BLOB NOT NULL
			)
			"""
		)

	def update_config(self,
		pds_pfx: Optional[str]=None,
		pds_did: Optional[str]=None,
		bsky_appview_pfx: Optional[str]=None,
		bsky_appview_did: Optional[str]=None,
	):
		with self.con:
			if pds_pfx is not None:
				self.con.execute("UPDATE config SET pds_pfx=?", (pds_pfx,))
			if pds_did is not None:
				self.con.execute("UPDATE config SET pds_did=?", (pds_did,))
			if bsky_appview_pfx is not None:
				self.con.execute("UPDATE config SET bsky_appview_pfx=?", (bsky_appview_pfx,))
			if bsky_appview_did is not None:
				self.con.execute("UPDATE config SET bsky_appview_did=?", (bsky_appview_did,))
		
		del self.config # invalidate the cached value

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

	def print_config(self, redact_secrets: bool=True) -> None:
		maxlen = max(map(len, self.config))
		for k, v in self.config.items():
			if redact_secrets and "secret" in k:
				v = "[REDACTED]"
			print(f"{k:<{maxlen}} : {v!r}")
