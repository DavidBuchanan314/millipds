"""millipds CLI

Usage:
  millipds init <hostname> [--dev|--sandbox]
  millipds config [--pds_pfx=URL] [--pds_did=DID] [--bsky_appview_pfx=URL] [--bsky_appview_did=DID]
  millipds run [--sock_path=PATH] [--listen_host=HOST] [--listen_port=PORT]
  millipds (-h | --help)
  millipds --version

Init:
  Initialise the database. Must be done before any other commands will work.
  This also sets the config options to their defaults.

  hostname            The public-facing hostname of this PDS, e.g. "bsky.social"
  --dev               Pre-set config options for local dev/testing
  --sandbox           Pre-set config options to work with the bsky "sandbox" network. Otherwise, default to bsky prod.

Config:
  Any options not specified will be left at their previous values. Once changes
  have been made (or even if they haven't), the new config will be printed.

  --pds_pfx=URL           The HTTP URL prefix that this PDS is publicly accessible at (e.g. mypds.example)
  --pds_did=DID           This PDS's DID (e.g. did:web:mypds.example)
  --bsky_appview_pfx=URL  AppView URL prefix e.g. "https://api.bsky-sandbox.dev"
  --bsky_appview_did=DID  AppView DID e.g. did:web:api.bsky-sandbox.dev

Run:
  Launch the service (in the foreground)

  --sock_path=PATH    UNIX domain socket to listen on (supersedes host and port options if specified)
  --listen_host=HOST  Hostname to listen on [default: 127.0.0.1]
  --listen_port=PORT  TCP port to listen on [default: 8123]

General options:
  -h --help           Show this screen.
  --version           Show version.
"""

from docopt import docopt
import importlib.metadata
import asyncio

from . import service
from . import database

"""
This is the entrypoint for the `millipds` command (declared in project.scripts)
"""
def main():
	args = docopt(
		__doc__,
		version=f"millipds version {importlib.metadata.version('millipds')}"
	)

	db = database.Database()

	if args["init"]:
		if db.config_is_initialised():
			print(
				"Already initialised! Use the `config` command to make changes,"
				" or manually delete the db and try again."
			)
			return
		if args["--dev"]:
			db.update_config(
				pds_pfx=f'http://{args["<hostname>"]}:{args["--listen_port"]}',
				pds_did=f'did:web:{args["<hostname>"]}',
				bsky_appview_pfx="http://appview.test",
				bsky_appview_did="did:web:appview.test",
			)
		elif args["--sandbox"]:
			db.update_config(
				pds_pfx=f'https://{args["<hostname>"]}',
				pds_did=f'did:web:{args["<hostname>"]}',
				bsky_appview_pfx="https://api.bsky-sandbox.dev",
				bsky_appview_did="did:web:api.bsky-sandbox.dev",
			)
		else:
			db.update_config(
				pds_pfx=f'https://{args["<hostname>"]}',
				pds_did=f'did:web:{args["<hostname>"]}',
				bsky_appview_pfx="https://api.bsky.app",
				bsky_appview_did="did:web:api.bsky.app",
			)
		assert(db.config_is_initialised())
		db.print_config()
		return
	
	if not db.config_is_initialised():
		print("Config uninitialised! Try the `init` command")
		return

	if args["config"]:
		db.update_config(
			pds_pfx=args["--pds_pfx"],
			pds_did=args["--pds_did"],
			bsky_appview_pfx=args["--bsky_appview_pfx"],
			bsky_appview_did=args["--bsky_appview_did"],
		)
		db.print_config()
	elif args["run"]:
		asyncio.run(service.run(
			sock_path=args["--sock_path"],
			host=args["--listen_host"],
			port=int(args["--listen_port"])
		))
	else:
		print("CLI arg parse error?!")

"""
This is the entrypoint for python3 -m millipds
"""
if __name__ == "__main__":
	main()
