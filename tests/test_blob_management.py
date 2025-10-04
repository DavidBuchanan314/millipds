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


async def test_blob_range_request_basic(s, pds_host, auth_headers):
	"""Test basic HTTP range request on blob."""
	# Create a blob that spans multiple parts (>64KB)
	blob = os.urandom(0x30000)  # 192KB

	# Upload blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		assert r.status == 200
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	# Reference the blob in a record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "post with large blob", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Test full blob retrieval includes Accept-Ranges header
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 200
		assert r.headers.get("Accept-Ranges") == "bytes"
		assert "Content-Range" not in r.headers
		full_blob = await r.read()
		assert full_blob == blob

	# Test range request for middle section
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=1000-2999"},
	) as r:
		assert r.status == 206
		assert r.headers.get("Accept-Ranges") == "bytes"
		assert r.headers.get("Content-Range") == f"bytes 1000-2999/{len(blob)}"
		assert int(r.headers.get("Content-Length", 0)) == 2000
		partial_blob = await r.read()
		assert len(partial_blob) == 2000
		assert partial_blob == blob[1000:3000]


async def test_blob_range_request_from_start(s, pds_host, auth_headers):
	"""Test range request from start of blob."""
	blob = os.urandom(0x20000)  # 128KB

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request first 1000 bytes
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=0-999"},
	) as r:
		assert r.status == 206
		assert r.headers.get("Content-Range") == f"bytes 0-999/{len(blob)}"
		partial_blob = await r.read()
		assert len(partial_blob) == 1000
		assert partial_blob == blob[0:1000]


async def test_blob_range_request_to_end(s, pds_host, auth_headers):
	"""Test range request from offset to end of blob."""
	blob = os.urandom(0x25000)  # 148KB

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request from byte 100000 to end
	start = 100000
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": f"bytes={start}-"},
	) as r:
		assert r.status == 206
		assert (
			r.headers.get("Content-Range")
			== f"bytes {start}-{len(blob) - 1}/{len(blob)}"
		)
		partial_blob = await r.read()
		assert len(partial_blob) == len(blob) - start
		assert partial_blob == blob[start:]


async def test_blob_range_request_suffix(s, pds_host, auth_headers):
	"""Test suffix range request (last N bytes)."""
	blob = os.urandom(0x18000)  # 96KB

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request last 5000 bytes
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=-5000"},
	) as r:
		assert r.status == 206
		assert (
			r.headers.get("Content-Range")
			== f"bytes {len(blob) - 5000}-{len(blob) - 1}/{len(blob)}"
		)
		partial_blob = await r.read()
		assert len(partial_blob) == 5000
		assert partial_blob == blob[-5000:]


async def test_blob_range_request_invalid(s, pds_host, auth_headers):
	"""Test invalid range requests return 416."""
	blob = os.urandom(0x10000)  # 64KB

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request range beyond blob size
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": f"bytes={len(blob)}-{len(blob) + 1000}"},
	) as r:
		assert r.status == 416
		assert r.headers.get("Content-Range") == f"bytes */{len(blob)}"

	# Request invalid range (start > end)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=5000-1000"},
	) as r:
		assert r.status == 416


async def test_blob_range_request_spanning_parts(s, pds_host, auth_headers):
	"""Test range request that spans multiple blob_parts."""
	# Create blob that's exactly 3 parts (192KB)
	blob = os.urandom(0x30000)

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request range spanning from part 0 into part 2
	# (0x10000 = 65536 is the part boundary)
	start = 0x8000  # Middle of part 0
	end = 0x18000 - 1  # Middle of part 1
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": f"bytes={start}-{end}"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == end - start + 1
		assert partial_blob == blob[start : end + 1]


async def test_blob_range_request_within_single_part(s, pds_host, auth_headers):
	"""Test range request entirely within a single blob_part."""
	# Create small blob (single part)
	blob = os.urandom(0x8000)  # 32KB

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Request small range within the single part
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=100-199"},
	) as r:
		assert r.status == 206
		assert r.headers.get("Content-Range") == f"bytes 100-199/{len(blob)}"
		partial_blob = await r.read()
		assert len(partial_blob) == 100
		assert partial_blob == blob[100:200]


async def test_blob_zero_length(s, pds_host, auth_headers):
	"""Test uploading and downloading a zero-length blob."""
	blob = b""

	# Upload zero-length blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		assert r.status == 200
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]
		assert res["blob"]["size"] == 0

	# Reference the blob in a record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "post with empty blob", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Download the zero-length blob
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
	) as r:
		assert r.status == 200
		assert r.headers.get("Accept-Ranges") == "bytes"
		assert r.headers.get("Content-Length") == "0"
		downloaded_blob = await r.read()
		assert downloaded_blob == b""


async def test_blob_range_request_part_boundary(s, pds_host, auth_headers):
	"""Test range requests exactly on 64KB part boundaries."""
	# Create blob that's exactly 3 parts (192KB = 3 * 64KB)
	blob = os.urandom(0x30000)

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Test: Request exactly one part (part 1: bytes 65536-131071)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65536-131071"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 65536
		assert partial_blob == blob[65536:131072]

	# Test: Request starting exactly at part boundary
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65536-"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert partial_blob == blob[65536:]

	# Test: Request ending exactly at part boundary
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=0-65535"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 65536
		assert partial_blob == blob[0:65536]


async def test_blob_range_request_part_boundary_off_by_one(
	s, pds_host, auth_headers
):
	"""Test range requests off-by-one around 64KB part boundaries."""
	# Create blob that's exactly 2 parts (128KB)
	blob = os.urandom(0x20000)

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Test: Request one byte before boundary to one byte after
	# (65535-65537 crosses from part 0 to part 1)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65535-65537"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 3
		assert partial_blob == blob[65535:65538]

	# Test: Request ending one byte before boundary
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=0-65534"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 65535
		assert partial_blob == blob[0:65535]

	# Test: Request starting one byte after boundary
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65537-"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert partial_blob == blob[65537:]

	# Test: Request ending one byte after boundary
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=0-65536"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 65537
		assert partial_blob == blob[0:65537]


async def test_blob_range_request_single_byte_at_boundary(
	s, pds_host, auth_headers
):
	"""Test requesting single bytes at part boundaries."""
	# Create blob that's exactly 2 parts (128KB)
	blob = os.urandom(0x20000)

	# Upload and reference blob
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.uploadBlob",
		headers=auth_headers | {"content-type": "application/octet-stream"},
		data=blob,
	) as r:
		res = await r.json()
		blob_cid = res["blob"]["ref"]["$link"]

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "test", "embed": res},
		},
	) as r:
		assert r.status == 200

	# Test: Request last byte of part 0
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65535-65535"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 1
		assert partial_blob == blob[65535:65536]

	# Test: Request first byte of part 1
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getBlob",
		params={"did": TEST_DID, "cid": blob_cid},
		headers={"Range": "bytes=65536-65536"},
	) as r:
		assert r.status == 206
		partial_blob = await r.read()
		assert len(partial_blob) == 1
		assert partial_blob == blob[65536:65537]
