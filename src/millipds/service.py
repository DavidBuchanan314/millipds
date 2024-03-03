from typing import Optional
import importlib.metadata
import logging
import asyncio
import aiohttp_cors
import os

from aiohttp import web

from . import static_config

logging.basicConfig(level=logging.DEBUG) # TODO: make this configurable?


async def hello(request: web.Request):
	version = importlib.metadata.version("millipds")
	msg = f"""Hello! This is an ATProto PDS instance, running millipds v{version}

https://github.com/DavidBuchanan314/millipds"""
	return web.Response(text=msg)

async def server_describe_server(request: web.Request):
	return web.json_response({
		"did": "did:web:placeholder.invalid", # TODO: should probably do something with this!
		"availableUserDomains": []
	})

app = web.Application()
app.add_routes([
	web.get("/", hello),
	web.get("/xrpc/com.atproto.server.describeServer", server_describe_server),
])

cors = aiohttp_cors.setup(app, defaults={
	"*": aiohttp_cors.ResourceOptions(
		allow_credentials=True,
		expose_headers="*",
		allow_headers="*"
	)
})

for route in app.router.routes():
	cors.add(route)

"""
This gets invoked via millipds.__main__.py
"""
async def run(sock_path: Optional[str], host: str, port: int):
	runner = web.AppRunner(app, access_log_format=static_config.LOG_FMT)
	await runner.setup()

	if sock_path is None:
		site = web.TCPSite(runner, host=host, port=port)
	else:
		site = web.UnixSite(runner, path=sock_path)
	
	await site.start()

	if sock_path:
		# give group access to the socket (so that nginx can access it via a shared group)
		# see https://github.com/aio-libs/aiohttp/issues/4155#issuecomment-693979753
		import grp
		try:
			sock_gid = grp.getgrnam(static_config.GROUPNAME).gr_gid
			os.chown(sock_path, os.geteuid(), sock_gid)
		except KeyError:
			logging.warn(f"Failed to set socket group - group {static_config.GROUPNAME!r} not found.")
		except PermissionError:
			logging.warn(f"Failed to set socket group - are you a member of the {static_config.GROUPNAME!r} group?")

		os.chmod(sock_path, 0o770)

	while True:
		await asyncio.sleep(3600)  # sleep forever
