# TODO: some smarter way of handling migrations

import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

from millipds import static_config


def migrate(con: apsw.Connection):
	version_now = con.execute("SELECT db_version FROM config").fetchone()[0]

	assert version_now == 3

	# Get current pds_pfx value to use as default for auth_pfx
	pds_pfx = con.execute("SELECT pds_pfx FROM config").fetchone()[0]

	# Add auth_pfx column
	con.execute("ALTER TABLE config ADD COLUMN auth_pfx TEXT")

	# Set auth_pfx to pds_pfx for existing installations
	con.execute("UPDATE config SET auth_pfx=?", (pds_pfx,))

	con.execute("UPDATE config SET db_version=4")


if __name__ == "__main__":
	with apsw.Connection(static_config.MAIN_DB_PATH) as con:
		migrate(con)

	print("v3 -> v4 Migration successful")
