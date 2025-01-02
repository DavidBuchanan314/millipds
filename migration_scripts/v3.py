# TODO: some smarter way of handling migrations

import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config


def migrate(con: apsw.Connection):
	version_now, *_ = con.execute("SELECT db_version FROM config").fetchone()

	assert version_now == 2

	con.execute(
		"""
		CREATE TABLE revoked_token(
			did TEXT NOT NULL,
			jti TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY (did, jti)
		) STRICT, WITHOUT ROWID
		"""
	)

	con.execute("UPDATE config SET db_version=3")


if __name__ == "__main__":
	with apsw.Connection(static_config.MAIN_DB_PATH) as con:
		migrate(con)

	print("v2 -> v3 Migration successful")
