"""millipds CLI

Usage:
  millipds init <hostname> [--dev | --sandbox]
  millipds config [--pds_pfx=URL] [--pds_did=DID] [--bsky_appview_pfx=URL] [--bsky_appview_did=DID]
  millipds account create <did> <handle> [--unsafe_password=PW] [--signing_key=PEM]
  millipds run [--sock_path=PATH] [--listen_host=HOST] [--listen_port=PORT]
  millipds util keygen [--p256 | --k256]
  millipds util print_pubkey <pem>
  millipds util plcgen --genesis_json=PATH --rotation_key=PEM --handle=HANDLE --pds_host=URL --repo_pubkey=DIDKEY
  millipds util plcsign --unsigned_op=PATH --rotation_key=PEM [--prev_op=PATH]
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

  Do not change the config while the PDS is running (TODO: enforce this in code (or make sure it's harmless?))

  --pds_pfx=URL           The HTTP URL prefix that this PDS is publicly accessible at (e.g. mypds.example)
  --pds_did=DID           This PDS's DID (e.g. did:web:mypds.example)
  --bsky_appview_pfx=URL  AppView URL prefix e.g. "https://api.bsky-sandbox.dev"
  --bsky_appview_did=DID  AppView DID e.g. did:web:api.bsky-sandbox.dev

Account Create:
  Create a new user account on the PDS. Bring your own DID and corresponding
  handle - millipds will not (yet?) attempt to validate either.
  You'll be prompted for a password interactively.

  --unsafe_password=PW  Specify password non-iteractively, for use in test scripts etc.
  --signing_key=PEM     Path to a PEM file

Run:
  Launch the service (in the foreground)

  --sock_path=PATH    UNIX domain socket to listen on (supersedes host and port options if specified)
  --listen_host=HOST  Hostname to listen on [default: 127.0.0.1]
  --listen_port=PORT  TCP port to listen on [default: 8123]

Util Keygen:
  Generate a signing key, save it to a PEM, and print its path to stdout.

  --p256    NISTP256 key format (default)
  --k256    secp256k1 key format

General options:
  -h --help           Show this screen.
  --version           Show version.
"""

import importlib.metadata
import asyncio
import logging
import json
import base64
import hashlib
import urllib.parse
from getpass import getpass

from docopt import docopt

import cbrrr

from . import service
from . import database
from . import crypto
from . import util


logging.basicConfig(level=logging.DEBUG)  # TODO: make this configurable?


def main():
	"""
	This is the entrypoint for the `millipds` command (declared in project.scripts)
	"""

	args = docopt(
		__doc__, version=f"millipds version {importlib.metadata.version('millipds')}"
	)

	if args["init"]:
		db = database.Database()
		if db.config_is_initialised():
			print(
				"Already initialised! Use the `config` command to make changes,"
				" or manually delete the db and try again."
			)
			return
		if args["--dev"]: # like prod but http://
			db.update_config(
				pds_pfx=f'http://{args["<hostname>"]}',
				pds_did=f'did:web:{urllib.parse.quote(args["<hostname>"])}',
				bsky_appview_pfx="https://api.bsky.app",
				bsky_appview_did="did:web:api.bsky.app",
			)
		elif args["--sandbox"]: # now-defunct, need to figure out how to point at local infra
			db.update_config(
				pds_pfx=f'https://{args["<hostname>"]}',
				pds_did=f'did:web:{urllib.parse.quote(args["<hostname>"])}',
				bsky_appview_pfx="https://api.bsky-sandbox.dev",
				bsky_appview_did="did:web:api.bsky-sandbox.dev",
			)
		else:  # "prod" presets
			db.update_config(
				pds_pfx=f'https://{args["<hostname>"]}',
				pds_did=f'did:web:{urllib.parse.quote(args["<hostname>"])}',
				bsky_appview_pfx="https://api.bsky.app",
				bsky_appview_did="did:web:api.bsky.app",
			)
		assert db.config_is_initialised()
		db.print_config()
		return
	elif args["util"]:
		if args["keygen"]: # TODO: deprecate in favour of openssl?
			if args["--k256"]:
				privkey = crypto.keygen_k256() # openssl ecparam -name secp256k1 -genkey -noout
			else: # default
				privkey = crypto.keygen_p256() # openssl ecparam -name prime256v1 -genkey -noout
			print(crypto.privkey_to_pem(privkey), end="")
		elif args["print_pubkey"]:
			with open(args["<pem>"]) as pem:
				pem_data = pem.read()
			try:
				pubkey = crypto.privkey_from_pem(pem_data).public_key()
			except ValueError:
				pubkey = crypto.pubkey_from_pem(pem_data)
			print(crypto.encode_pubkey_as_did_key(pubkey))
		elif args["plcgen"]:
			with open(args["--rotation_key"]) as pem:
				rotation_key = crypto.privkey_from_pem(pem.read())
			if not args["--repo_pubkey"].startswith("did:key:z"):
				raise ValueError("invalid did:key")
			genesis = {
				"type": "plc_operation",
				"rotationKeys": [ crypto.encode_pubkey_as_did_key(rotation_key.public_key()) ],
				"verificationMethods": { "atproto": args["--repo_pubkey"] },
				"alsoKnownAs": [ "at://" + args["--handle"] ],
				"services": {
					"atproto_pds": {
						"type": "AtprotoPersonalDataServer",
						"endpoint": args["--pds_host"]
					}
				},
				"prev": None,
			}
			genesis["sig"] = crypto.plc_sign(rotation_key, genesis)
			genesis_digest = hashlib.sha256(cbrrr.encode_dag_cbor(genesis)).digest()
			plc = "did:plc:" + base64.b32encode(genesis_digest)[:24].lower().decode()
			with open(args["--genesis_json"], "w") as out:
				json.dump(genesis, out, indent=4)
			print(plc)
		elif args["plcsign"]:
			with open(args["--unsigned_op"]) as op_json:
				op = json.load(op_json)
			with open(args["--rotation_key"]) as pem:
				rotation_key = crypto.privkey_from_pem(pem.read())
			if args["--prev_op"]:
				with open(args["--prev_op"]) as op_json:
					prev_op = json.load(op_json)
				op["prev"] = cbrrr.CID.cidv1_dag_cbor_sha256_32_from(cbrrr.encode_dag_cbor(prev_op)).encode()
			del op["sig"] # remove any existing sig
			op["sig"] = crypto.plc_sign(rotation_key, op)
			print(json.dumps(op, indent=4))
		else:
			print("invalid util subcommand")
		return

	# everything after this point requires an already-inited db
	db = database.Database()
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
	elif args["account"]:
		if args["create"]:
			pw = args["--unsafe_password"]
			if pw:
				print(
					"WARNING: passing a password as a CLI arg is not recommended, for security"
				)
			else:
				pw = getpass("Password for new account: ")
				if getpass("Confirm password: ") != pw:
					print("error: password mismatch")
					return
			pem_path = args["--signing_key"]
			if pem_path:
				privkey = crypto.privkey_from_pem(open(pem_path).read())
			else:
				privkey = crypto.keygen_p256()
			db.create_account(
				did=args["<did>"],
				handle=args["<handle>"],
				password=pw,
				privkey=privkey,
			)
		else:
			print("invalid account subcommand")
	elif args["run"]:
		asyncio.run(
			service.run(
				db=db,
				sock_path=args["--sock_path"],
				host=args["--listen_host"],
				port=int(args["--listen_port"]),
			)
		)
	else:
		print("CLI arg parse error?!")


"""
This is the entrypoint for python3 -m millipds
"""
if __name__ == "__main__":
	main()
