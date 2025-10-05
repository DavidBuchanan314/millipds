"""Tests for split Authorization Server / Resource Server configuration."""

import asyncio
import dataclasses
import tempfile
import urllib.parse

import aiohttp
import pytest

from millipds import crypto, database, service
from tests.conftest import (
	TEST_DID,
	TEST_HANDLE,
	TEST_PASSWORD,
	TEST_PRIVKEY,
	VALID_LOGINS,
	service_run_and_capture_port,
)


@dataclasses.dataclass
class SplitPDSInfo:
	endpoint: str  # Single server endpoint
	pds_host: str  # PDS Host header value
	auth_host: str  # Auth Host header value
	db: database.Database


@pytest.fixture
async def split_pds(aiolib):
	"""Create a test PDS instance with split AS/RS hostnames.

	Uses a single server but different Host headers to simulate split hostnames.
	"""
	queue = asyncio.Queue()

	with tempfile.TemporaryDirectory() as tempdir:
		async with aiohttp.ClientSession() as client:
			db_path = f"{tempdir}/millipds-0000.db"
			db = database.Database(path=db_path)

			# Start server
			run_task = asyncio.create_task(
				service_run_and_capture_port(
					queue,
					db=db,
					client=client,
					sock_path=None,
					host="localhost",
					port=0,
				)
			)
			queue_get = asyncio.create_task(queue.get())
			done, pending = await asyncio.wait(
				(queue_get, run_task),
				return_when=asyncio.FIRST_COMPLETED,
			)
			if run_task in done:
				raise run_task.exception()  # type: ignore[misc]

			port = queue_get.result()

			# Configure with split hostnames (same port, different hosts)
			pds_host = "pds.localhost"
			auth_host = "auth.localhost"

			db.update_config(
				pds_pfx=f"http://{pds_host}",
				pds_did=f"did:web:{urllib.parse.quote(pds_host)}",
				auth_pfx=f"http://{auth_host}",
				bsky_appview_pfx="https://api.bsky.app",
				bsky_appview_did="did:web:api.bsky.app",
			)

			db.create_account(
				did=TEST_DID,
				handle=TEST_HANDLE,
				password=TEST_PASSWORD,
				privkey=TEST_PRIVKEY,
			)

			try:
				yield SplitPDSInfo(
					endpoint=f"http://localhost:{port}",
					pds_host=pds_host,
					auth_host=auth_host,
					db=db,
				)
			finally:
				db.con.close()
				run_task.cancel()
				try:
					await run_task
				except asyncio.CancelledError:
					pass


async def test_split_as_rs_oauth_metadata(s, split_pds):
	"""Test that OAuth metadata endpoints are only accessible on correct hosts."""
	# AS metadata should be accessible on auth host
	async with s.get(
		split_pds.endpoint + "/.well-known/oauth-authorization-server",
		headers={"Host": split_pds.auth_host},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert "issuer" in data

	# AS metadata should NOT be accessible on PDS host
	async with s.get(
		split_pds.endpoint + "/.well-known/oauth-authorization-server",
		headers={"Host": split_pds.pds_host},
	) as r:
		assert r.status == 404

	# RS metadata should be accessible on PDS host
	async with s.get(
		split_pds.endpoint + "/.well-known/oauth-protected-resource",
		headers={"Host": split_pds.pds_host},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["resource"] == split_pds.db.config["pds_pfx"]
		assert split_pds.db.config["auth_pfx"] in data["authorization_servers"]

	# RS metadata should NOT be accessible on auth host
	async with s.get(
		split_pds.endpoint + "/.well-known/oauth-protected-resource",
		headers={"Host": split_pds.auth_host},
	) as r:
		assert r.status == 404


async def test_split_as_rs_oauth_endpoints(s, split_pds):
	"""Test that OAuth endpoints are only accessible on auth host."""
	# /oauth/authorize should work on auth host
	async with s.get(
		split_pds.endpoint + "/oauth/authorize",
		headers={"Host": split_pds.auth_host},
	) as r:
		assert r.status == 200
		text = await r.text()
		assert "html" in text.lower()  # Should return HTML login page

	# /oauth/authorize should NOT work on PDS host
	async with s.get(
		split_pds.endpoint + "/oauth/authorize",
		headers={"Host": split_pds.pds_host},
	) as r:
		assert r.status == 404


async def test_split_as_rs_xrpc_endpoints(s, split_pds):
	"""Test that XRPC endpoints are only accessible on PDS host."""
	# XRPC endpoints should work on PDS host
	async with s.get(
		split_pds.endpoint + "/xrpc/com.atproto.server.describeServer",
		headers={"Host": split_pds.pds_host},
	) as r:
		assert r.status == 200

	# XRPC endpoints should NOT work on auth host
	async with s.get(
		split_pds.endpoint + "/xrpc/com.atproto.server.describeServer",
		headers={"Host": split_pds.auth_host},
	) as r:
		assert r.status == 404


async def test_split_as_rs_session_creation(s, split_pds):
	"""Test that session creation works on PDS host."""
	# createSession should work on PDS host
	async with s.post(
		split_pds.endpoint + "/xrpc/com.atproto.server.createSession",
		json=VALID_LOGINS[0],
		headers={"Host": split_pds.pds_host},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["did"] == TEST_DID
		assert "accessJwt" in data

	# createSession should NOT work on auth host
	async with s.post(
		split_pds.endpoint + "/xrpc/com.atproto.server.createSession",
		json=VALID_LOGINS[0],
		headers={"Host": split_pds.auth_host},
	) as r:
		assert r.status == 404
