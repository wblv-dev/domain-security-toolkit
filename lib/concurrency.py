"""
concurrency.py — Shared concurrency controls for large-account safety.

Provides semaphores that limit how many concurrent operations run in
each category, preventing rate-limit hits and resolver flooding when
auditing 100+ zones.

Usage:
    from lib.concurrency import sem

    async with sem.cf_api:
        result = await cf_get(session, path)

    async with sem.dns:
        records = await resolver_call(...)

All limits are configurable via set_limits().
"""

import asyncio


class _Semaphores:
    """Lazy-initialised semaphore container.

    Semaphores must be created inside a running event loop, so we
    initialise them on first access rather than at import time.
    """

    def __init__(self):
        self._cf_api = None
        self._dns = None
        self._rdap = None
        self._http = None
        self._domain = None

        # Configurable limits
        self.limit_cf_api = 10   # Concurrent Cloudflare API requests
        self.limit_dns = 30      # Concurrent DNS queries
        self.limit_rdap = 5      # Concurrent RDAP lookups
        self.limit_http = 10     # Concurrent external HTTP requests (MTA-STS)
        self.limit_domain = 20   # Concurrent domains being processed

    def set_limits(
        self, *,
        cf_api: int = None,
        dns: int = None,
        rdap: int = None,
        http: int = None,
        domain: int = None,
    ) -> None:
        """Override default concurrency limits. Call before audit starts."""
        if cf_api is not None:
            self.limit_cf_api = cf_api
        if dns is not None:
            self.limit_dns = dns
        if rdap is not None:
            self.limit_rdap = rdap
        if http is not None:
            self.limit_http = http
        if domain is not None:
            self.limit_domain = domain
        # Reset so they get re-created with new limits
        self._cf_api = self._dns = self._rdap = self._http = self._domain = None

    @property
    def cf_api(self) -> asyncio.Semaphore:
        if self._cf_api is None:
            self._cf_api = asyncio.Semaphore(self.limit_cf_api)
        return self._cf_api

    @property
    def dns(self) -> asyncio.Semaphore:
        if self._dns is None:
            self._dns = asyncio.Semaphore(self.limit_dns)
        return self._dns

    @property
    def rdap(self) -> asyncio.Semaphore:
        if self._rdap is None:
            self._rdap = asyncio.Semaphore(self.limit_rdap)
        return self._rdap

    @property
    def http(self) -> asyncio.Semaphore:
        if self._http is None:
            self._http = asyncio.Semaphore(self.limit_http)
        return self._http

    @property
    def domain(self) -> asyncio.Semaphore:
        if self._domain is None:
            self._domain = asyncio.Semaphore(self.limit_domain)
        return self._domain


sem = _Semaphores()


async def throttled_gather(coro_dict: dict, label: str = "check") -> dict:
    """Run a dict of {key: coroutine} through the domain semaphore.

    Returns {key: result} with per-domain error handling — one domain
    failing doesn't kill the others.
    """
    results = {}

    async def _run(key, coro):
        async with sem.domain:
            try:
                results[key] = await coro
            except Exception as e:
                print(f"  [ERROR] {label} failed for {key}: {e}")

    await asyncio.gather(*[_run(k, c) for k, c in coro_dict.items()])
    return results


async def run_in_executor_throttled(func, *args, semaphore=None):
    """Run a sync function in the thread pool, throttled by a semaphore.

    Used for DNS queries and other blocking I/O that runs via
    loop.run_in_executor but needs concurrency limits.
    """
    s = semaphore or sem.dns
    loop = asyncio.get_event_loop()
    async with s:
        return await loop.run_in_executor(None, func, *args)
