from typing import Optional
import importlib_metadata
import logging

from aiohttp import web

from . import config

logging.basicConfig(level=logging.DEBUG) # TODO: make this configurable?


async def hello(request: web.Request):
	version = importlib_metadata.version("millipds")
	return web.Response(text=f"Hello! This is an ATProto PDS instance, running https://github.com/DavidBuchanan314/millipds (v{version})")

app = web.Application()
app.add_routes([
	web.get("/", hello),
])

"""
This gets invoked via millipds.__main__.py
"""
def run(sock_path: Optional[str], host: str, port: int):
	if sock_path is None:
		web.run_app(app, host=host, port=port, access_log_format=config.LOG_FMT)
	else:
		web.run_app(app, path=sock_path, access_log_format=config.LOG_FMT)
