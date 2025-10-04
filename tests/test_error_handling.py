"""Error handling and validation tests."""

import pytest

from tests.conftest import TEST_DID


async def test_repo_getRecord_missing_params(s, pds_host):
	"""Test getRecord with missing required parameters."""
	# Missing repo
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={"collection": "app.bsky.feed.post", "rkey": "test"},
	) as r:
		assert r.status == 400
		text = await r.text()
		assert "repo" in text.lower()

	# Missing collection
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={"repo": TEST_DID, "rkey": "test"},
	) as r:
		assert r.status == 400
		text = await r.text()
		assert "collection" in text.lower()

	# Missing rkey
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={"repo": TEST_DID, "collection": "app.bsky.feed.post"},
	) as r:
		assert r.status == 400
		text = await r.text()
		assert "rkey" in text.lower()


async def test_repo_listRecords_missing_params(s, pds_host):
	"""Test listRecords with missing required parameters."""
	# Missing repo
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={"collection": "app.bsky.feed.post"},
	) as r:
		assert r.status == 400

	# Missing collection
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={"repo": TEST_DID},
	) as r:
		assert r.status == 400


async def test_repo_describeRepo_missing_param(s, pds_host):
	"""Test describeRepo with missing repo parameter."""
	async with s.get(pds_host + "/xrpc/com.atproto.repo.describeRepo") as r:
		assert r.status == 400


async def test_sync_getLatestCommit_missing_did(s, pds_host):
	"""Test getLatestCommit without DID parameter."""
	async with s.get(pds_host + "/xrpc/com.atproto.sync.getLatestCommit") as r:
		assert r.status == 400
		text = await r.text()
		assert "did" in text.lower()


async def test_sync_getRepoStatus_missing_did(s, pds_host):
	"""Test getRepoStatus without DID parameter."""
	async with s.get(pds_host + "/xrpc/com.atproto.sync.getRepoStatus") as r:
		assert r.status == 400


async def test_sync_listBlobs_missing_did(s, pds_host):
	"""Test listBlobs without DID parameter."""
	async with s.get(pds_host + "/xrpc/com.atproto.sync.listBlobs") as r:
		assert r.status == 400


async def test_sync_getRecord_missing_params(s, pds_host):
	"""Test sync.getRecord with missing parameters."""
	# Missing did
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={"collection": "app.bsky.feed.post", "rkey": "test"},
	) as r:
		assert r.status == 400

	# Missing collection
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={"did": TEST_DID, "rkey": "test"},
	) as r:
		assert r.status == 400

	# Missing rkey
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={"did": TEST_DID, "collection": "app.bsky.feed.post"},
	) as r:
		assert r.status == 400


async def test_repo_applyWrites_unauthorized(s, pds_host, auth_headers):
	"""Test applyWrites to a repo you don't own."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": "did:plc:someoneelse",
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": "test",
					"value": {"text": "unauthorized"},
				}
			],
		},
	) as r:
		assert r.status == 401


async def test_repo_createRecord_no_auth(s, pds_host):
	"""Test createRecord without authentication."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "no auth"},
		},
	) as r:
		assert r.status == 401


async def test_repo_getRecord_cid_mismatch(s, pds_host, auth_headers):
	"""Test getRecord with CID that doesn't match."""
	# Create a record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "cid test"},
		},
	) as r:
		data = await r.json()
		rkey = data["uri"].split("/")[-1]

	# Try to get with wrong CID
	fake_cid = "bafyreihw3s6ndtjf5xpnpakz6dpqxsg4eay6j3sppxkl33s3q2c7c6qp6i"
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
			"cid": fake_cid,
		},
	) as r:
		assert r.status == 404
		text = await r.text()
		assert "CID" in text or "cid" in text


async def test_invalid_json_request(s, pds_host, auth_headers):
	"""Test endpoints with invalid JSON."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers | {"content-type": "application/json"},
		data=b"not valid json{",
	) as r:
		assert r.status != 200


async def test_repo_uploadBlob_no_auth(s, pds_host):
	"""Test blob upload without authentication."""
	import os

	blob = os.urandom(1000)
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers={"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		assert r.status == 401


async def test_sync_getBlob_not_found(s, pds_host):
	"""Test getBlob with non-existent CID."""
	fake_cid = "bafkreihw3s6ndtjf5xpnpakz6dpqxsg4eay6j3sppxkl33s3q2c7c6qp6i"
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": fake_cid},
	) as r:
		assert r.status == 404
