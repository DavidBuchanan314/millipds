import aiohttp
import asyncio
from typing import Dict, Callable, Any, Awaitable
import re
import json

DIDDoc = Dict[str, Any]


class DIDResolver:
	def __init__(
		self,
		session: aiohttp.ClientSession,
		plc_directory_host: str = "https://plc.directory",
	) -> None:
		self.session: aiohttp.ClientSession = session
		self.plc_directory_host: str = plc_directory_host
		self.did_methods: Dict[str, Callable[[str], Awaitable[DIDDoc]]] = {
			"web": self.resolve_did_web,
			"plc": self.resolve_did_plc,
		}

	async def resolve_uncached(self, did: str) -> DIDDoc:
		if len(did) > 2048:
			raise ValueError("DID too long for atproto")
		scheme, method, *_ = did.split(":")
		if scheme != "did":
			raise ValueError("not a valid DID")
		resolver = self.did_methods.get(method)
		if resolver is None:
			raise ValueError(f"Unsupported DID method: {method}")
		return await resolver(did)

	# 64k ought to be enough for anyone!
	async def _get_json_with_limit(
		self, url: str, limit: int = 0x10000
	) -> DIDDoc:
		async with self.session.get(url) as r:
			r.raise_for_status()
			try:
				await r.content.readexactly(limit)
				raise ValueError("DID document too large")
			except asyncio.IncompleteReadError as e:
				# this is actually the happy path
				return json.loads(e.partial)

	async def resolve_did_web(self, did: str) -> DIDDoc:
		# TODO: support port numbers on localhost?
		if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):
			raise ValueError("Invalid did:web")
		host = did.rpartition(":")[2]
		# XXX: there's technically a risk of SSRF here, but it's mitigated by
		# the fact that ports aren't supported, and that the path is fixed.
		# XXX: wait no, it's not mitigated at all since we follow redirects!!!
		return await self._get_json_with_limit(
			f"https://{host}/.well-known/did.json"
		)

	async def resolve_did_plc(self, did: str) -> DIDDoc:
		if not re.match(r"^did:plc:[a-z2-7]+$", did):  # base32-sortable
			raise ValueError("Invalid did:plc")
		return await self._get_json_with_limit(
			f"{self.plc_directory_host}/{did}"
		)


async def main() -> None:
	async with aiohttp.ClientSession() as session:
		resolver = DIDResolver(session)
		print(await resolver.resolve_uncached("did:web:retr0.id"))
		print(
			await resolver.resolve_uncached("did:plc:vwzwgnygau7ed7b7wt5ux7y2")
		)


if __name__ == "__main__":
	asyncio.run(main())
