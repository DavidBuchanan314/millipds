"""Repository operation tests (CRUD on records)."""

import base64

import cbrrr
import pytest

from tests.conftest import TEST_DID


async def test_repo_applyWrites_create(s, pds_host, auth_headers):
	"""Test creating records via applyWrites."""
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
			data = await r.json()
			assert "commit" in data
			assert "results" in data


async def test_repo_applyWrites_create_duplicate(s, pds_host, auth_headers):
	"""Test that creating an existing record fails."""
	rkey = "duplicate-test"

	# Create the record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": {"text": "original"},
				}
			],
		},
	) as r:
		assert r.status == 200

	# Try to create it again - should fail
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": {"text": "duplicate"},
				}
			],
		},
	) as r:
		assert r.status == 400
		text = await r.text()
		assert "already exists" in text


async def test_repo_applyWrites_update(s, pds_host, auth_headers):
	"""Test updating records via applyWrites."""
	rkey = "update-test"

	# Create initial record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": {"text": "original text"},
				}
			],
		},
	) as r:
		assert r.status == 200

	# Update the record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#update",
					"action": "update",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": {"text": "updated text"},
				}
			],
		},
	) as r:
		assert r.status == 200

	# Verify the update
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["value"]["text"] == "updated text"


async def test_repo_applyWrites_delete(s, pds_host, auth_headers):
	"""Test deleting records via applyWrites."""
	rkey = "delete-test"

	# Create record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": {"text": "to be deleted"},
				}
			],
		},
	) as r:
		assert r.status == 200

	# Delete the record
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#delete",
					"action": "delete",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
				}
			],
		},
	) as r:
		assert r.status == 200

	# Verify deletion - getRecord will proxy to appview (401) when not found locally
	# Use sync.getRecord instead which returns an exclusion proof
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
		},
	) as r:
		# Should return 200 with an exclusion proof CAR
		assert r.status == 200
		proof = await r.read()
		assert len(proof) > 0  # Has proof data


async def test_repo_applyWrites_delete_nonexistent(s, pds_host, auth_headers):
	"""Test that deleting a non-existent record fails."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#delete",
					"action": "delete",
					"collection": "app.bsky.feed.post",
					"rkey": "nonexistent",
				}
			],
		},
	) as r:
		assert r.status == 400
		text = await r.text()
		assert "no such record" in text


async def test_repo_applyWrites_base64_cbor(s, pds_host, auth_headers):
	"""Test applyWrites with base64-encoded CBOR values."""
	rkey = "base64-cbor-test"
	value = {"text": "encoded as cbor"}
	cbor_bytes = cbrrr.encode_dag_cbor(value)
	b64_cbor = base64.b64encode(cbor_bytes).decode()

	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.applyWrites",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"writes": [
				{
					"$type": "com.atproto.repo.applyWrites#create",
					"action": "create",
					"collection": "app.bsky.feed.post",
					"rkey": rkey,
					"value": b64_cbor,  # base64 string instead of object
				}
			],
		},
	) as r:
		assert r.status == 200

	# Verify the record was created correctly
	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.getRecord",
		params={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["value"]["text"] == "encoded as cbor"


async def test_repo_createRecord(s, pds_host, auth_headers):
	"""Test the createRecord endpoint."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "created via createRecord"},
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert "uri" in data
		assert "cid" in data


async def test_repo_putRecord(s, pds_host, auth_headers):
	"""Test the putRecord endpoint (create or update)."""
	rkey = "put-test"

	# Create via putRecord
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.putRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
			"record": {"text": "initial via put"},
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		first_cid = data["cid"]

	# Update via putRecord
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.putRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
			"record": {"text": "updated via put"},
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		second_cid = data["cid"]
		assert first_cid != second_cid


async def test_repo_deleteRecord(s, pds_host, auth_headers):
	"""Test the deleteRecord endpoint."""
	# Create a record first
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.createRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"record": {"text": "to be deleted via deleteRecord"},
		},
	) as r:
		assert r.status == 200
		data = await r.json()
		# Extract rkey from URI: at://did/collection/rkey
		rkey = data["uri"].split("/")[-1]

	# Delete it
	async with s.post(
		pds_host + "/xrpc/com.atproto.repo.deleteRecord",
		headers=auth_headers,
		json={
			"repo": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
		},
	) as r:
		assert r.status == 200

	# Verify it's gone using sync.getRecord (returns exclusion proof)
	async with s.get(
		pds_host + "/xrpc/com.atproto.sync.getRecord",
		params={
			"did": TEST_DID,
			"collection": "app.bsky.feed.post",
			"rkey": rkey,
		},
	) as r:
		assert r.status == 200
		proof = await r.read()
		assert len(proof) > 0  # Has exclusion proof


async def test_updateHandle(s, pds_host, auth_headers):
	"""Test handle updates."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.identity.updateHandle",
		headers=auth_headers,
		json={"handle": "juliet.test"},
	) as r:
		assert r.status == 200

	async with s.get(
		pds_host + "/xrpc/com.atproto.repo.describeRepo",
		params={"repo": TEST_DID},
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["handle"] == "juliet.test"
