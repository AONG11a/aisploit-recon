"""Rate limiting.

A token-bucket limiter that keeps our request rate under the ceiling the
engagement scope declares. Being a well-behaved scanner isn't just courtesy:
hammering a target risks knocking over someone's service (a reportable harm)
and gets you rate-limited or banned, which corrupts results anyway.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, max_per_minute: int) -> None:
        if max_per_minute < 1:
            raise ValueError("max_per_minute must be >= 1")
        self._rate = max_per_minute / 60.0  # tokens/second
        self._capacity = float(max_per_minute)
        self._tokens = float(max_per_minute)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._last) * self._rate
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self._rate)
