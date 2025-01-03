# TODO: some smarter way of handling migrations

import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config


def migrate(con: apsw.Connection):
	version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

	assert version_now == 1

	con.execute(
		"""
		CREATE TABLE did_cache(
			did TEXT PRIMARY KEY NOT NULL,
			doc BLOB,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		) STRICT, WITHOUT ROWID
		"""
	)

	con.execute(
		"""
		CREATE TABLE handle_cache(
			handle TEXT PRIMARY KEY NOT NULL,
			did TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		) STRICT, WITHOUT ROWID
		"""
	)

	con.execute("UPDATE config SET db_version=2")


if __name__ == "__main__":
	with apsw.Connection(static_config.MAIN_DB_PATH) as con:
		migrate(con)

	print("v1 -> v2 Migration successful")
