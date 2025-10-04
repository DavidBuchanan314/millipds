"""Database layer tests."""

import tempfile

import pytest

from millipds import crypto, database


def test_did_by_handle_found():
	"""Test did_by_handle with existing handle."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		test_did = "did:plc:test123"
		test_handle = "alice.test"
		db.create_account(
			did=test_did,
			handle=test_handle,
			password="password",
			privkey=crypto.keygen_p256(),
		)

		result = db.did_by_handle(test_handle)
		assert result == test_did


def test_did_by_handle_not_found():
	"""Test did_by_handle with non-existent handle."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		result = db.did_by_handle("nonexistent.test")
		assert result is None


def test_handle_by_did_found():
	"""Test handle_by_did with existing DID."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		test_did = "did:plc:test123"
		test_handle = "bob.test"
		db.create_account(
			did=test_did,
			handle=test_handle,
			password="password",
			privkey=crypto.keygen_p256(),
		)

		result = db.handle_by_did(test_did)
		assert result == test_handle


def test_handle_by_did_not_found():
	"""Test handle_by_did with non-existent DID."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		result = db.handle_by_did("did:plc:nonexistent")
		assert result is None


def test_signing_key_pem_by_did_found():
	"""Test signing_key_pem_by_did with existing DID."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		test_did = "did:plc:test123"
		privkey = crypto.keygen_p256()
		db.create_account(
			did=test_did,
			handle="charlie.test",
			password="password",
			privkey=privkey,
		)

		result = db.signing_key_pem_by_did(test_did)
		assert result is not None
		assert "BEGIN PRIVATE KEY" in result


def test_signing_key_pem_by_did_not_found():
	"""Test signing_key_pem_by_did with non-existent DID."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		result = db.signing_key_pem_by_did("did:plc:nonexistent")
		assert result is None


def test_list_repos():
	"""Test list_repos function."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		# Create multiple accounts
		dids = []
		for i in range(3):
			did = f"did:plc:test{i}"
			dids.append(did)
			db.create_account(
				did=did,
				handle=f"user{i}.test",
				password="password",
				privkey=crypto.keygen_p256(),
			)

		repos = db.list_repos()
		assert len(repos) == 3
		repo_dids = [did for did, head, rev in repos]
		for did in dids:
			assert did in repo_dids


def test_config_is_initialised():
	"""Test config_is_initialised with complete and incomplete config."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")

		# Initially config is not complete
		assert not db.config_is_initialised()

		# Complete the config
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		# Now it should be complete
		assert db.config_is_initialised()


def test_verify_account_login_success():
	"""Test successful account login verification."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		test_did = "did:plc:logintest"
		test_handle = "login.test"
		test_password = "correct_password"

		db.create_account(
			did=test_did,
			handle=test_handle,
			password=test_password,
			privkey=crypto.keygen_p256(),
		)

		# Test login with handle
		did, handle = db.verify_account_login(test_handle, test_password)
		assert did == test_did
		assert handle == test_handle

		# Test login with DID
		did, handle = db.verify_account_login(test_did, test_password)
		assert did == test_did
		assert handle == test_handle


def test_verify_account_login_wrong_password():
	"""Test login verification with wrong password."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		db.create_account(
			did="did:plc:badpass",
			handle="bad.test",
			password="correct_password",
			privkey=crypto.keygen_p256(),
		)

		with pytest.raises(ValueError, match="invalid password"):
			db.verify_account_login("bad.test", "wrong_password")


def test_verify_account_login_nonexistent_user():
	"""Test login verification with non-existent user."""
	with tempfile.TemporaryDirectory() as tempdir:
		db = database.Database(path=f"{tempdir}/test.db")
		db.update_config(
			pds_pfx="http://test.local",
			pds_did="did:web:test.local",
			bsky_appview_pfx="https://api.bsky.app",
			bsky_appview_did="did:web:api.bsky.app",
		)

		with pytest.raises(KeyError, match="no account found"):
			db.verify_account_login("nonexistent.test", "anypassword")
