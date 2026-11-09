"""
honeypot/core/geo_lookup.py
Lightweight GeoIP resolver using the free ip-api.com JSON endpoint.
No API key required for non-commercial use (<45 req/min).
Results are cached in-process to avoid hammering the API.
"""

from __future__ import annotations

import asyncio
import logging
from functools import lru_cache

import aiohttp

logger = logging.getLogger(__name__)

_cache: dict[str, dict] = {}
_PRIVATE_RANGES = ("10.", "192.168.", "172.", "127.", "::1", "0.0.0.0")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_RANGES)


async def lookup(ip: str) -> dict:
    """
    Returns a dict with keys: country, countryCode, city, lat, lon, isp.
    Returns an empty dict on failure or for private IPs.
    """
    if _is_private(ip):
        return {}
    if ip in _cache:
        return _cache[ip]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,lat,lon,isp,status",
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                data = await resp.json()
                if data.get("status") == "success":
                    _cache[ip] = data
                    return data
    except Exception as exc:  # noqa: BLE001
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
    return {}
