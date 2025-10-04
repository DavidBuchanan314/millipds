"""Shared pytest fixtures for millipds integration tests."""

import asyncio
import dataclasses
import tempfile
import unittest.mock
import urllib.parse

import aiohttp
import aiohttp.web
import pytest

from millipds import crypto, database, service


@dataclasses.dataclass
class PDSInfo:
	endpoint: str
	db: database.Database


# Test account constants
TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"
TEST_HANDLE = "local.dev.retr0.id"
TEST_PASSWORD = "test_password_123"
TEST_PRIVKEY = crypto.keygen_p256()

VALID_LOGINS = [
	{"identifier": TEST_HANDLE, "password": TEST_PASSWORD},
	{"identifier": TEST_DID, "password": TEST_PASSWORD},
]


old_web_tcpsite_start = aiohttp.web.TCPSite.start


def make_capture_random_bound_port_web_tcpsite_start(queue: asyncio.Queue):
	async def mock_start(site: aiohttp.web.TCPSite, *args, **kwargs):
		nonlocal queue
		await old_web_tcpsite_start(site, *args, **kwargs)
		await queue.put(site._server.sockets[0].getsockname()[1])

	return mock_start


async def service_run_and_capture_port(queue: asyncio.Queue, **kwargs):
	mock_start = make_capture_random_bound_port_web_tcpsite_start(queue)
	with unittest.mock.patch.object(
		aiohttp.web.TCPSite, "start", new=mock_start
	):
		await service.run(**kwargs)


@pytest.fixture
async def test_pds(aiolib):
	"""Create a test PDS instance with a test account."""
	queue = asyncio.Queue()
	with tempfile.TemporaryDirectory() as tempdir:
		async with aiohttp.ClientSession() as client:
			db_path = f"{tempdir}/millipds-0000.db"
			db = database.Database(path=db_path)

			hostname = "localhost:0"
			db.update_config(
				pds_pfx=f"http://{hostname}",
				pds_did=f"did:web:{urllib.parse.quote(hostname)}",
				bsky_appview_pfx="https://api.bsky.app",
				bsky_appview_did="did:web:api.bsky.app",
			)

			service_run_task = asyncio.create_task(
				service_run_and_capture_port(
					queue,
					db=db,
					client=client,
					sock_path=None,
					host="localhost",
					port=0,
				)
			)
			queue_get_task = asyncio.create_task(queue.get())
			done, pending = await asyncio.wait(
				(queue_get_task, service_run_task),
				return_when=asyncio.FIRST_COMPLETED,
			)
			if done == service_run_task:
				raise service_run_task.exception()
			else:
				port = queue_get_task.result()

			hostname = f"localhost:{port}"
			db.update_config(
				pds_pfx=f"http://{hostname}",
				pds_did=f"did:web:{urllib.parse.quote(hostname)}",
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
				yield PDSInfo(
					endpoint=f"http://{hostname}",
					db=db,
				)
			finally:
				db.con.close()
				service_run_task.cancel()
				try:
					await service_run_task
				except asyncio.CancelledError:
					pass


@pytest.fixture
async def s(aiolib):
	"""Create an HTTP client session."""
	async with aiohttp.ClientSession() as s:
		yield s


@pytest.fixture
def pds_host(test_pds) -> str:
	"""Get the PDS endpoint URL."""
	return test_pds.endpoint


@pytest.fixture
async def auth_headers(s, pds_host):
	"""Get valid authentication headers."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=VALID_LOGINS[0],
	) as r:
		r = await r.json()
	token = r["accessJwt"]
	return {"Authorization": "Bearer " + token}


@pytest.fixture
async def populated_pds_host(s, pds_host, auth_headers):
	"""Create a PDS with sample records."""
	for i in range(10):
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.applyWrites",
			headers=auth_headers,
			json={
				"repo": TEST_DID,
				"writes": [
					{
						"$type": "com.atproto.repo.applyWrites#create",
						"action": "create",
						"collection": "app.bsky.feed.like",
						"rkey": f"{i}-{j}",
						"value": {"blah": "test record"},
					}
					for j in range(30)
				],
			},
		) as r:
			assert r.status == 200
	return pds_host
