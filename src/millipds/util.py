import os
import hashlib


def mkdirs_for_file(path: str) -> None:
	os.makedirs(os.path.dirname(path), exist_ok=True)


FILANEME_SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def did_to_safe_filename(did: str) -> str:
	"""
	The format is <sha256(did)>_<filtered_did>
	The former guarantees uniqueness, and the latter makes it human-recognizeable (ish)
	"""

	hexdigest = hashlib.sha256(did.encode()).hexdigest()
	filtered = "".join(char for char in did if char in FILANEME_SAFE_CHARS)

	# Truncate to make sure we're staying within PATH_MAX
	# (with room to spare, in case the caller appends a file extension)
	return f"{hexdigest}_{filtered}"[:200]
