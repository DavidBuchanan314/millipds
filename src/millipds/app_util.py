from typing import Set, Optional, Tuple
import asyncio

import aiohttp
from aiohttp import web

from . import database


# these helpers are useful for conciseness and type hinting
def get_db(req: web.Request) -> database.Database:
	return req.app["MILLIPDS_DB"]

def get_client(req: web.Request) -> aiohttp.ClientSession:
	return req.app["MILLIPDS_AIOHTTP_CLIENT"]

def get_firehose_queues(req: web.Request) -> Set[asyncio.Queue[Optional[Tuple[int, bytes]]]]:
	return req.app["MILLIPDS_FIREHOSE_QUEUES"]

def get_firehose_queues_lock(req: web.Request) -> asyncio.Lock:
	return req.app["MILLIPDS_FIREHOSE_QUEUES_LOCK"]
