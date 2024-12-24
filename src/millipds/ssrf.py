"""
This is a bit of a bodge, for now.

See https://github.com/aio-libs/aiohttp/discussions/10224 for the discussion
that led to this, and maybe a better solution in the future.
"""

import ipaddress
from aiohttp import TCPConnector, ClientSession
import aiohttp.connector
from aiohttp.resolver import DefaultResolver, AbstractResolver

# XXX: monkeypatch to force all hosts to go through the resolver
# (without this, bare IPs in the URL will bypass the resolver, where our SSRF check is)
aiohttp.connector.is_ip_address = lambda _: False


class SSRFException(ValueError):
	pass


class SSRFSafeResolverWrapper(AbstractResolver):
	def __init__(self, resolver: AbstractResolver):
		self.resolver = resolver

	async def resolve(self, host: str, port: int, family: int):
		result = await self.resolver.resolve(host, port, family)
		for host in result:
			if ipaddress.ip_address(host["host"]).is_private:
				raise SSRFException(
					"Can't connect to private IP: " + host["host"]
				)
		return result

	async def close(self) -> None:
		await self.resolver.close()


def get_ssrf_safe_client() -> ClientSession:
	resolver = SSRFSafeResolverWrapper(DefaultResolver())
	connector = TCPConnector(resolver=resolver)
	return ClientSession(connector=connector)
