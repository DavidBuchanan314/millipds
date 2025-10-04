"""Sync protocol and firehose tests."""

import pytest

from tests.conftest import TEST_DID


async def test_sync_getRepo(s, pds_host):
	"""Test basic repository retrieval."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepo",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200
		assert r.content_type == "application/vnd.ipld.car"
		car_data = await r.read()
		assert len(car_data) > 0


async def test_sync_getRepo_not_found(s, pds_host):
	"""Test getRepo with non-existent DID."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepo",
		params={"did": "did:web:nonexistent.invalid"},
	) as r:
		assert r.status == 404


async def test_sync_getRecord_nonexistent(s, populated_pds_host):
	"""Test getRecord with non-existent DID and record."""
	# Nonexistent DID should 404
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": "did:web:nonexistent.invalid",
			"collection": "app.bsky.feed.post",
			"rkey": "nonexistent",
		},
	) as r:
		assert r.status == 404

	# Existent DID with nonexistent record should 200 with exclusion proof CAR
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
		assert len(proof_car) > 0


async def test_sync_getRecord_existent(s, populated_pds_host):
	"""Test getRecord with existing record."""
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
		assert len(proof_car) > 0
		assert b"test record" in proof_car


async def test_sync_getLatestCommit(s, pds_host):
	"""Test getLatestCommit endpoint."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getLatestCommit",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert "rev" in data
		assert "cid" in data


async def test_sync_getLatestCommit_not_found(s, pds_host):
	"""Test getLatestCommit with non-existent DID."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getLatestCommit",
		params={"did": "did:web:nonexistent.invalid"},
	) as r:
		assert r.status == 404


async def test_sync_getRepoStatus(s, pds_host):
	"""Test getRepoStatus endpoint."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepoStatus",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["did"] == TEST_DID
		assert data["active"] is True
		assert "rev" in data


async def test_sync_getRepoStatus_not_found(s, pds_host):
	"""Test getRepoStatus with non-existent DID."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRepoStatus",
		params={"did": "did:web:nonexistent.invalid"},
	) as r:
		assert r.status == 404


async def test_sync_listRepos(s, pds_host):
	"""Test listRepos endpoint."""
	async with s.get(pds_host + "/xrpc/com.atproto.sync.listRepos") as r:
		assert r.status == 200
		data = await r.json()
		assert "repos" in data
		assert len(data["repos"]) >= 1
		# Our test account should be in the list
		dids = [repo["did"] for repo in data["repos"]]
		assert TEST_DID in dids


async def test_repo_listRecords(s, populated_pds_host, auth_headers):
	"""Test listRecords with pagination."""
	# List records without pagination
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert "records" in data
		# We created 10*30 = 300 records, default limit is 50
		assert len(data["records"]) == 50
		assert "cursor" in data

	# List with custom limit
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
			"limit": "10",
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert len(data["records"]) == 10

	# List with cursor pagination
	first_cursor = data["cursor"]
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
			"limit": "10",
			"cursor": first_cursor,
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert len(data["records"]) == 10
		# Should be different records
		assert data["cursor"] != first_cursor


async def test_repo_listRecords_reverse(s, populated_pds_host):
	"""Test listRecords with reverse parameter."""
	# Test that reverse mode works (tests pagination direction)
	async with s.get(
		populated_pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
			"limit": "5",
			"reverse": "true",
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert len(data["records"]) == 5
		# Verify we got valid records
		assert all("uri" in rec for rec in data["records"])


async def test_repo_listRecords_invalid_limit(s, pds_host):
	"""Test listRecords with invalid limit values."""
	# Limit too low
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
			"limit": "0",
		},
	) as r:
		assert r.status == 400

	# Limit too high
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.listRecords",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.like",
			"limit": "1000",
		},
	) as r:
		assert r.status == 400


async def test_sync_listBlobs(s, pds_host, auth_headers):
	"""Test listBlobs endpoint."""
	import os

	# Upload some blobs and reference them
	blob_cids = []
	for i in range(3):
		blob = os.urandom(0x1000)
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.uploadBlob",
			headers=auth_headers | {"content-type": "application/octet-stream"},
			data=blob,
		) as r:
			res = await r.json()
			blob_cids.append(res["blob"]["ref"]["$link"])

		# Reference it in a record
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.createRecord",
			headers=auth_headers,
			json={
				"repo": TEST_DID,
				"collection": "app.bsky.feed.post",
				"record": {"text": f"blob {i}", "embed": res},
			},
		) as r:
			assert r.status == 200

	# List blobs
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.listBlobs",
		params={"did": TEST_DID},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert "cids" in data
		assert len(data["cids"]) >= 3


async def test_sync_listBlobs_pagination(s, pds_host, auth_headers):
	"""Test listBlobs with pagination."""
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.listBlobs",
		params={
			"did": TEST_DID,
			"limit": "1",
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		if len(data["cids"]) > 0:  # Only if there are blobs
			assert len(data["cids"]) == 1
			if "cursor" in data:
				# Test pagination with cursor
				async with s.get(
					pds_host + "/xrpc/com.atproto.sync.listBlobs",
					params={
						"did": TEST_DID,
						"limit": "1",
						"cursor": data["cursor"],
					},
				) as r2:
					assert r2.status == 200
