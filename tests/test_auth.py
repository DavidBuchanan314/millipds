"""Authentication and authorization tests."""

import pytest

from tests.conftest import TEST_DID, TEST_HANDLE, TEST_PASSWORD, VALID_LOGINS


async def test_hello_world(s, pds_host):
	"""Test the root endpoint returns a greeting."""
	async with s.get(pds_host + "/") as r:
		text = await r.text()
		assert "Hello" in text


async def test_describeServer(s, pds_host):
	"""Test the server description endpoint."""
	async with s.get(pds_host + "/xrpc/com.atproto.server.describeServer") as r:
		assert r.status == 200
		data = await r.json()
		assert "availableUserDomains" in data


async def test_createSession_no_args(s, pds_host):
	"""Test session creation fails without arguments."""
	async with s.post(pds_host + "/xrpc/com.atproto.server.createSession") as r:
		assert r.status != 200


@pytest.mark.parametrize(
	"login_data",
	[
		{"identifier": [], "password": TEST_PASSWORD},
		{"identifier": "example.invalid", "password": "wrongPassword123"},
		{"identifier": TEST_HANDLE, "password": "wrongPassword123"},
	],
)
async def test_invalid_logins(s, pds_host, login_data):
	"""Test various invalid login attempts."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=login_data,
	) as r:
		assert r.status != 200


@pytest.mark.parametrize("login_data", VALID_LOGINS)
async def test_valid_logins(s, pds_host, login_data):
	"""Test valid login with both handle and DID."""
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=login_data,
	) as r:
		data = await r.json()
		assert r.status == 200
		assert data["did"] == TEST_DID
		assert data["handle"] == TEST_HANDLE
		assert "accessJwt" in data
		assert "refreshJwt" in data

	token = data["accessJwt"]
	auth_headers = {"Authorization": "Bearer " + token}

	# Test valid auth
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers=auth_headers,
	) as r:
		assert r.status == 200
		data = await r.json()
		assert data["did"] == TEST_DID

	# Test invalid token (truncated)
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + token[:-1]},
	) as r:
		assert r.status != 200

	# Test malformed auth header
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearest"},
	) as r:
		assert r.status != 200


async def test_serviceauth(s, test_pds, auth_headers):
	"""Test service authentication token generation."""
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

	# Test if the service auth token works
	async with s.get(
		test_pds.endpoint + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + token},
	) as r:
		assert r.status == 200
		await r.json()


async def test_refreshSession(s, pds_host):
	"""Test session refresh flow."""
	# Create initial session
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=VALID_LOGINS[0],
	) as r:
		assert r.status == 200
		data = await r.json()
		orig_session_token = data["accessJwt"]
		orig_refresh_token = data["refreshJwt"]

	# Can't refresh using the session token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_session_token},
	) as r:
		assert r.status != 200

	# Correctly refresh using the refresh token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_refresh_token},
	) as r:
		assert r.status == 200
		data = await r.json()
		new_session_token = data["accessJwt"]
		new_refresh_token = data["refreshJwt"]

	# Test if the new session token works
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + new_session_token},
	) as r:
		assert r.status == 200
		await r.json()

	# Test that the old session token is invalid
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + orig_session_token},
	) as r:
		assert r.status != 200

	# Test that the old refresh token is invalid
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + orig_refresh_token},
	) as r:
		assert r.status != 200


async def test_deleteSession(s, pds_host):
	"""Test session deletion/logout."""
	# Create session
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.createSession",
		json=VALID_LOGINS[0],
	) as r:
		assert r.status == 200
		data = await r.json()
		session_token = data["accessJwt"]
		refresh_token = data["refreshJwt"]

	# Sanity-check that the session token currently works
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status == 200
		await r.json()

	# Can't delete using the session token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.deleteSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status != 200

	# Can delete using the refresh token
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.deleteSession",
		headers={"Authorization": "Bearer " + refresh_token},
	) as r:
		assert r.status == 200

	# Test that the session token is invalid now
	async with s.get(
		pds_host + "/xrpc/com.atproto.server.getSession",
		headers={"Authorization": "Bearer " + session_token},
	) as r:
		assert r.status != 200

	# Test that the refresh token is invalid too
	async with s.post(
		pds_host + "/xrpc/com.atproto.server.refreshSession",
		headers={"Authorization": "Bearer " + refresh_token},
	) as r:
		assert r.status != 200
