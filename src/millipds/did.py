import aiohttp
import asyncio
from typing import Dict, Callable, Any, Awaitable
import re

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
		scheme, method, *_ = did.split(":")
		if scheme != "did":
			raise ValueError("not a valid DID")
		resolver = self.did_methods.get(method)
		if resolver is None:
			raise ValueError(f"Unsupported DID method: {method}")
		return await resolver(did)

	async def resolve_did_web(self, did: str) -> DIDDoc:
		# TODO: support port numbers on localhost?
		if not re.match(r"^did:web:[a-z0-9\.\-]+$", did):
			raise ValueError("Invalid did:web")
		host = did.rpartition(":")[2]
		# XXX: there's technically a risk of SSRF here, but it's mitigated by
		# the fact that ports aren't supported, and that the path is fixed.
		async with self.session.get(
			f"https://{host}/.well-known/did.json"
		) as r:
			r.raise_for_status()
			return await r.json()

	async def resolve_did_plc(self, did: str) -> DIDDoc:
		if not re.match(r"^did:plc:[a-z2-7]+$", did):  # base32-sortable
			raise ValueError("Invalid did:plc")
		async with self.session.get(f"{self.plc_directory_host}/{did}") as r:
			r.raise_for_status()
			return await r.json()


async def main() -> None:
	async with aiohttp.ClientSession() as session:
		resolver = DIDResolver(session)
		print(await resolver.resolve_uncached("did:web:retr0.id"))
		print(
			await resolver.resolve_uncached("did:plc:vwzwgnygau7ed7b7wt5ux7y2")
		)


if __name__ == "__main__":
	asyncio.run(main())
