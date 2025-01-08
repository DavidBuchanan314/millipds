import os
import time
import json
import datetime
import itertools
import asyncio
from typing import (
	BinaryIO,
	Iterator,
	Tuple,
	Optional,
	Any,
	Dict,
	Hashable,
	Type,
)
from weakref import WeakValueDictionary

from aiohttp import web

import cbrrr
from atmst.blockstore.car_file import encode_varint

from . import static_config


def mkdirs_for_file(path: str) -> None:
	os.makedirs(os.path.dirname(path), exist_ok=True)


FILANEME_SAFE_CHARS = (
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


B32_CHARSET = "234567abcdefghijklmnopqrstuvwxyz"


def tid_now():  # XXX: this is not strongly guaranteed to be monotonic
	micros, nanos = divmod(int(time.time() * 1_000_000_000), 1000)
	clkid = nanos  # put the current timestamp in nanoseconds in the clkid field for extra collision resistance
	tid_int = (micros << 10) | clkid
	return "".join(
		B32_CHARSET[(tid_int >> (60 - (i * 5))) & 31] for i in range(13)
	)


def iso_string_now():
	"""
	JavaScript-like timestamp strings
	e.g. 2000-01-01T00:00:00.000Z
	"""
	return (
		datetime.datetime.now(tz=datetime.timezone.utc)
		.replace(tzinfo=None)
		.isoformat(timespec="milliseconds")
		+ "Z"
	)


def deep_iter(obj: cbrrr.DagCborTypes) -> Iterator[cbrrr.DagCborTypes]:
	sentinel = object()
	# "stack" will consist of recursively chained iterators
	stack = iter([obj, sentinel])
	while (item := next(stack)) is not sentinel:
		yield item
		match item:
			case dict():
				stack = itertools.chain(item.values(), stack)
			case list():
				stack = itertools.chain(item, stack)


# expects obj to be in "native" format, not "atjson"
def enumerate_blob_cids(obj: cbrrr.DagCborTypes) -> Iterator[cbrrr.CID]:
	for item in deep_iter(obj):
		if isinstance(item, dict) and item.get("$type") == "blob":
			ref = item.get("ref")
			if not isinstance(ref, cbrrr.CID):
				continue
			if ref.is_cidv1_raw_sha256_32():  # XXX: will need updating if more CID types are accepted in future
				yield ref


# this in theory allows slashes in rkey but we probably shouldn't...
def split_path(path: str) -> Tuple[str, str]:  # "nsid/rkey" to ("nsid", "rkey")
	nsid, sep, rkey = path.partition("/")
	if sep != "/":
		raise Exception("invalid path")
	return nsid, rkey


# TODO: it's a little silly that we implement CAR serialization twice. unify them?
def serialize_car_header(root_bytes: Optional[bytes] = None) -> bytes:
	header_bytes = cbrrr.encode_dag_cbor(
		{
			"version": static_config.CAR_VERSION_1,
			"roots": [cbrrr.CID(root_bytes)] if root_bytes else [],
		}
	)
	return encode_varint(len(header_bytes)) + header_bytes


def serialize_car_entry(cid_bytes: bytes, value: bytes):
	return encode_varint(len(cid_bytes) + len(value)) + cid_bytes + value


class CarWriter:
	def __init__(self, stream: BinaryIO, root: cbrrr.CID) -> None:
		self.stream = stream
		header_bytes = cbrrr.encode_dag_cbor(
			{"version": static_config.CAR_VERSION_1, "roots": [root]}
		)
		stream.write(encode_varint(len(header_bytes)))
		stream.write(header_bytes)

	def write_block(self, cid: cbrrr.CID, value: bytes):
		cid_bytes = bytes(cid)
		self.stream.write(encode_varint(len(cid_bytes) + len(value)))
		self.stream.write(cid_bytes)
		self.stream.write(value)


def compact_json(obj: Any) -> bytes:
	return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()


class PartitionedLock:
	"""
	Note: like asyncio.Lock itself, this class is not thread-safe.
	"""

	def __init__(self) -> None:
		self._locks: WeakValueDictionary[Hashable, asyncio.Lock] = (
			WeakValueDictionary()
		)

	def get_lock(self, key: Hashable) -> asyncio.Lock:
		lock = self._locks.get(key)
		if lock is None:
			lock = asyncio.Lock()
			self._locks[key] = lock
		return lock


def atproto_json_http_error(
	exp: Type[web.HTTPError], ename: str, emsg: str
) -> web.HTTPError:
	return exp(
		body=json.dumps(
			{
				"error": ename,
				"message": emsg,
			}
		),
		content_type="application/json",
	)
