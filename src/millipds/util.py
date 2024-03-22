import os
import time
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
	filtered = "".join(
		char for char in did.replace(":", "-") if char in FILANEME_SAFE_CHARS
	)

	# Truncate to make sure we're staying within PATH_MAX
	# (with room to spare, in case the caller appends a file extension)
	return f"{hexdigest}_{filtered}"[:200]


B32_CHARSET = "234567abcdefghijklmnopqrstuvwxyz"


def tid_now():  # XXX: this is not strongly guaranteed to be monotonic
	micros, nanos = divmod(int(time.time() * 1_000_000_000), 1000)
	clkid = nanos  # put the current timestamp in nanoseconds in the clkid field for extra collision resistance
	tid_int = (micros << 10) | clkid
	return "".join(B32_CHARSET[(tid_int >> (60 - (i * 5))) & 31] for i in range(13))
