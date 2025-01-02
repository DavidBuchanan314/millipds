import os
import asyncio
import tempfile
import urllib.parse
import unittest.mock
import pytest
import dataclasses
import aiohttp
import aiohttp.web

from millipds import service
from millipds import database
from millipds import crypto


@dataclasses.dataclass
class PDSInfo:
	endpoint: str
	db: database.Database


old_web_tcpsite_start = aiohttp.web.TCPSite.start


def make_capture_random_bound_port_web_tcpsite_startstart(queue: asyncio.Queue):
	async def mock_start(site: aiohttp.web.TCPSite, *args, **kwargs):
		nonlocal queue
		await old_web_tcpsite_start(site, *args, **kwargs)
		await queue.put(site._server.sockets[0].getsockname()[1])

	return mock_start


async def service_run_and_capture_port(queue: asyncio.Queue, **kwargs):
	mock_start = make_capture_random_bound_port_web_tcpsite_startstart(queue)
	with unittest.mock.patch.object(
		aiohttp.web.TCPSite, "start", new=mock_start
	):
		await service.run(**kwargs)


if 0:
	TEST_DID = "did:web:alice.test"
	TEST_HANDLE = "alice.test"
	TEST_PASSWORD = "alice_pw"
else:
	TEST_DID = "did:plc:bwxddkvw5c6pkkntbtp2j4lx"
	TEST_HANDLE = "local.dev.retr0.id"
	TEST_PASSWORD = "lol"
TEST_PRIVKEY = crypto.keygen_p256()


@pytest.fixture
async def test_pds(aiolib):
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
				raise service_run_task.execption()
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
	async with aiohttp.ClientSession() as s:
		yield s


@pytest.fixture
def pds_host(test_pds) -> str:
	return test_pds.endpoint


async def test_hello_world(s, pds_host):
	async with s.get(pds_host + "/") as r:
		r = await r.text()
		print(r)
		assert "Hello" in r


async def test_describeServer(s, pds_host):
	async with s.get(pds_host + "/xrpc/com.atproto.server.describeServer") as r:
		print(await r.json())


async def test_createSession_no_args(s, pds_host):
	# no args
	async with s.post(pds_host + "/xrpc/com.atproto.server.createSession") as r:
		assert r.status != 200


invalid_logins = [
	{"identifier": [], "password": TEST_PASSWORD},
	{"identifier": "example.invalid", "password": "wrongPassword123"},
	{"identifier": TEST_HANDLE, "password": "wrongPassword123"},
]


@pytest.mark.parametrize("login_data", invalid_logins)
async def test_invalid_logins(s, pds_host, login_data):
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=login_data,
	) as r:
		assert r.status != 200


valid_logins = [
	{"identifier": TEST_HANDLE, "password": TEST_PASSWORD},
	{"identifier": TEST_DID, "password": TEST_PASSWORD},
]


@pytest.mark.parametrize("login_data", valid_logins)
async def test_valid_logins(s, pds_host, login_data):
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=login_data,
	) as r:
		r = await r.json()
		assert r["did"] == TEST_DID
		assert r["handle"] == TEST_HANDLE
		assert "accessJwt" in r
		assert "refreshJwt" in r

	token = r["accessJwt"]
	auth_headers = {"Authorization": "Bearer " + token}

	# good auth
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers=auth_headers,
	) as r:
		print(await r.json())
		assert r.status == 200

	# bad auth
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + token[:-1]},
	) as r:
		print(await r.text())
		assert r.status != 200

	# bad auth
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearest"},
	) as r:
		print(await r.text())
		assert r.status != 200


async def test_sync_getRepo(s, pds_host):
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepo",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200


@pytest.fixture
async def auth_headers(s, pds_host):
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=valid_logins[0],
	) as r:
		r = await r.json()
	token = r["accessJwt"]
	return {"Authorization": "Bearer " + token}


@pytest.fixture
async def populated_pds_host(s, pds_host, auth_headers):
	# same thing as test_repo_applyWrites, for now
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
			print(await r.json())
			assert r.status == 200
	return pds_host


async def test_repo_applyWrites(s, pds_host, auth_headers):
	# TODO: test more than just "create"!
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
			print(await r.json())
			assert r.status == 200


async def test_repo_uploadBlob(s, pds_host, auth_headers):
	blob = os.urandom(0x100000)

	for _ in range(2):  # test reupload is nop
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.uploadBlob",
			headers=auth_headers | {"content-type": "blah"},
			data=blob,
		) as r:
			res = await r.json()
			print(res)
			assert r.status == 200

	# getBlob should still 404 because refcount==0
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]},
	) as r:
		assert r.status == 404

	# get the blob refcount >0
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"myblob": res},
		},
	) as r:
		print(await r.json())
		assert r.status == 200

	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]},
	) as r:
		downloaded_blob = await r.read()
		assert downloaded_blob == blob

	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepo",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200
		open("repo.car", "wb").write(await r.read())


async def test_sync_getRepo_not_found(s, pds_host):
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepo",
		params={"did": "did:web:nonexistent.invalid"},
	) as r:
		assert r.status == 404


async def test_sync_getRecord_nonexistent(s, populated_pds_host):
	# nonexistent DID should still 404
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": "did:web:nonexistent.invalid",
			"collection": "app.bsky.feed.post",
			"rkey": "nonexistent",
		},
	) as r:
		assert r.status == 404

	# but extant DID with nonexistent record should 200, with exclusion proof CAR
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": "nonexistent",
		},
	) as r:
		assert r.status == 200
		assert r.content_type == "application/vnd.ipld.car"
		proof_car = await r.read()
		assert proof_car  # nonempty
		# TODO: make sure the proof is valid


async def test_sync_getRecord_existent(s, populated_pds_host):
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": TEST_DID,
			"collection": "app.bsky.feed.like",
			"rkey": "1-1",
		},
	) as r:
		assert r.status == 200
		assert r.content_type == "application/vnd.ipld.car"
		proof_car = await r.read()
		assert proof_car  # nonempty
		# TODO: make sure the proof is valid, and contains the record
		assert b"test record" in proof_car


async def test_seviceauth(s, test_pds, auth_headers):
	async with s.get(
		test_pds.endpoint + "/xrpc/com.atproto.server.getServiceAuth",
		headers=auth_headers,
		params={
			"aud": test_pds.db.config["pds_did"],
			"lxm": "com.atproto.server.getSession",
		},
	) as r:
		assert r.status == 200
		token = (await r.json())["token"]

	# test if the token works
	async with s.get(
		test_pds.endpoint + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + token},
	) as r:
		assert r.status == 200
		await r.json()


async def test_refreshSession(s, pds_host):
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=valid_logins[0],
	) as r:
		assert r.status == 200
		r = await r.json()
		orig_session_token = r["accessJwt"]
		orig_refresh_token = r["refreshJwt"]

	# can't refresh using the session token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_session_token},
	) as r:
		assert r.status != 200

	# correctly refresh using the refresh token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_refresh_token},
	) as r:
		assert r.status == 200
		r = await r.json()
		new_session_token = r["accessJwt"]
		new_refresh_token = r["refreshJwt"]

	# test if the new session token works
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + new_session_token},
	) as r:
		assert r.status == 200
		await r.json()

	# test that the old session token is invalid
	# XXX: in the future we might relax this behaviour
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + orig_session_token},
	) as r:
		assert r.status != 200

	# test that the old refresh token is invalid
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_refresh_token},
	) as r:
		assert r.status != 200


async def test_deleteSession(s, pds_host):
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=valid_logins[0],
	) as r:
		assert r.status == 200
		r = await r.json()
		session_token = r["accessJwt"]
		refresh_token = r["refreshJwt"]

	# sanity-check that the session token currently works
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status == 200
		await r.json()

	# can't delete using the session token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.deleteSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status != 200

	# can delete using the refresh token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.deleteSession",
		headers={"Authorization": "Bearer " + refresh_token},
	) as r:
		assert r.status == 200

	# test that the session token is invalid now
	# XXX: in the future we might relax this behaviour
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status != 200

	# test that the refresh token is invalid too
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + refresh_token},
	) as r:
		assert r.status != 200
