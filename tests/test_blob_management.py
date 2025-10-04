"""Blob storage and reference counting tests."""

import os

import pytest

from tests.conftest import TEST_DID


async def test_repo_uploadBlob(s, pds_host, auth_headers):
	"""Test blob upload."""
	blob = os.urandom(0x100000)

	for _ in range(2):  # Test reupload is idempotent
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.uploadBlob",
			headers=auth_headers | {"content-type": "application/octet-stream"},
			data=blob,
		) as r:
			res = await r.json()
			assert r.status == 200
			assert "blob" in res
			assert "ref" in res["blob"]

	# getBlob should 404 because refcount==0
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": res["blob"]["ref"]["$link"]},  # type: ignore[possibly-unbound]
	) as r:
		assert r.status == 404


async def test_blob_lifecycle(s, pds_host, auth_headers):
	"""Test blob reference counting and retrieval."""
	blob = os.urandom(0x50000)

	# Upload blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "image/jpeg"},
		data=blob,
	) as r:
		assert r.status == 200
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	# Blob should not be retrievable (refcount=0)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 404

	# Reference the blob in a record (refcount -> 1)
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "post with image", "embed": res},
		},
	) as r:
		assert r.status == 200
		post_data = await r.json()
		post_rkey = post_data["uri"].split("/")[-1]

	# Now the blob should be retrievable
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 200
		downloaded_blob = await r.read()
		assert downloaded_blob == blob

	# Delete the record (refcount -> 0, blob should be deleted)
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.deleteRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": post_rkey,
		},
	) as r:
		assert r.status == 200

	# Blob should be gone now
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 404


async def test_blob_multiple_references(s, pds_host, auth_headers):
	"""Test blob with multiple references."""
	blob = os.urandom(0x10000)

	# Upload blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "image/png"},
		data=blob,
	) as r:
		assert r.status == 200
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	# Create two records referencing the same blob
	post_rkeys = []
	for i in range(2):
		async with s.post(
			pds_host + "/xrpc/com.atproto.repo.createRecord",
			headers=auth_headers,
			json={
				"repo": TEST_DID,
				"collection": "app.bsky.feed.post",
				"record": {"text": f"post {i} with blob", "embed": res},
			},
		) as r:
			assert r.status == 200
			data = await r.json()
			post_rkeys.append(data["uri"].split("/")[-1])

	# Blob should be retrievable (refcount=2)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 200

	# Delete first record (refcount -> 1)
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.deleteRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": post_rkeys[0],
		},
	) as r:
		assert r.status == 200

	# Blob should still be retrievable
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 200

	# Delete second record (refcount -> 0)
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.deleteRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": post_rkeys[1],
		},
	) as r:
		assert r.status == 200

	# Blob should now be gone
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 404


async def test_blob_update_changes_references(s, pds_host, auth_headers):
	"""Test that updating a record with a different blob changes refcounts."""
	blob1 = os.urandom(0x8000)
	blob2 = os.urandom(0x8000)

	# Upload both blobs
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "image/jpeg"},
		data=blob1,
	) as r:
		res1 = await r.json()
		blob1_cid = res1["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "image/jpeg"},
		data=blob2,
	) as r:
		res2 = await r.json()
		blob2_cid = res2["blob"]["ref"]["$link"]

	# Create record with blob1
	rkey = "blob-update-test"
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.putRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
			"record": {"text": "with blob1", "embed": res1},
		},
	) as r:
		assert r.status == 200

	# blob1 should be retrievable, blob2 should not
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob1_cid},
	) as r:
		assert r.status == 200

	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob2_cid},
	) as r:
		assert r.status == 404

	# Update record to use blob2 instead
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.putRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
			"record": {"text": "with blob2", "embed": res2},
		},
	) as r:
		assert r.status == 200

	# Now blob2 should be retrievable, blob1 should be gone
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob1_cid},
	) as r:
		assert r.status == 404

	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob2_cid},
	) as r:
		assert r.status == 200
		downloaded = await r.read()
		assert downloaded == blob2
