"""millipds CLI

Usage:
  millipds init <hostname> [--sandbox]
  millipds config [--appview_url=URL] [--appview_did=DID]
  millipds run [--sock_path=PATH] [--listen_host=HOST] [--listen_port=PORT]
  millipds (-h | --help)
  millipds --version

Init:
  Initialise the database. Must be done before any other commands will work.
  This also sets the config options to their defaults.

  hostname            The public-facing hostname of this PDS, e.g. "bsky.social"
  --sandbox           Set config options to work with the bsky "sandbox" network. Otherwise, default to bsky prod.

Config:
  Any options not specified will be left at their previous values. Once changes
  have been made (or even if they haven't), the new config will be printed.

  --appview_url=URL   AppView URL prefix e.g. "https://api.bsky-sandbox.dev"

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

"""
This is the entrypoint for the `millipds` command (declared in project.scripts)
"""
def main():
	args = docopt(__doc__, version=f"millipds version {importlib.metadata.version('millipds')}")

	if args["init"]:
		print("TODO INIT", args)
	elif args["config"]:
		print("TODO CONFIG", args)
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
