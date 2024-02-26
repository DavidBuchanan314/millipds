from typing import Optional
import importlib.metadata
import logging
import asyncio
import os

from aiohttp import web

from . import config

logging.basicConfig(level=logging.DEBUG) # TODO: make this configurable?


async def hello(request: web.Request):
	version = importlib.metadata.version("millipds")
	msg = f"""Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds"""
	return web.Response(text=msg)

app = web.Application()
app.add_routes([
	web.get("/", hello),
])

"""
This gets invoked via millipds.__main__.py
"""
async def run(sock_path: Optional[str], host: str, port: int):
	runner = web.AppRunner(app, access_log_format=config.LOG_FMT)
	await runner.setup()

	if sock_path is None:
		site = web.TCPSite(runner, host=host, port=port)
	else:
		site = web.UnixSite(runner, path=sock_path)
	
	await site.start()

	if sock_path:
		os.chmod(sock_path, 0o770) # give group access to the socket (so that nginx can access it via a shared group)
		# see https://github.com/aio-libs/aiohttp/issues/4155#issuecomment-693979753

	while True:
		await asyncio.sleep(3600)  # sleep forever
