from typing import Set, Optional, Tuple
import asyncio

import aiohttp
from aiohttp import web

from . import database

MILLIPDS_DB = web.AppKey("MILLIPDS_DB", database.Database)
MILLIPDS_AIOHTTP_CLIENT = web.AppKey(
	"MILLIPDS_AIOHTTP_CLIENT", aiohttp.ClientSession
)
MILLIPDS_FIREHOSE_QUEUES = web.AppKey(
	"MILLIPDS_FIREHOSE_QUEUES", Set[asyncio.Queue[Optional[Tuple[int, bytes]]]]
)
MILLIPDS_FIREHOSE_QUEUES_LOCK = web.AppKey(
	"MILLIPDS_FIREHOSE_QUEUES_LOCK", asyncio.Lock
)


# these helpers are useful for conciseness and type hinting
def get_db(req: web.Request):
	return req.app[MILLIPDS_DB]


def get_client(req: web.Request):
	return req.app[MILLIPDS_AIOHTTP_CLIENT]


def get_firehose_queues(req: web.Request):
	return req.app[MILLIPDS_FIREHOSE_QUEUES]


def get_firehose_queues_lock(req: web.Request):
	return req.app[MILLIPDS_FIREHOSE_QUEUES_LOCK]


__all__ = [
	"MILLIPDS_DB",
	"MILLIPDS_AIOHTTP_CLIENT",
	"MILLIPDS_FIREHOSE_QUEUES",
	"MILLIPDS_FIREHOSE_QUEUES_LOCK",
	"get_db",
	"get_client",
	"get_firehose_queues",
	"get_firehose_queues_lock",
]
