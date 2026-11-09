"""
honeypot/core/command_tracker.py
Tracks command frequency across all sessions for dashboard analytics.
Thread-safe; backed by an in-memory Counter.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class CommandTracker:
    """Records the frequency of attacker commands / paths across all sessions."""

    _counts: Counter = field(default_factory=Counter)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def record(self, protocol: str, raw_input: str) -> None:
        """Extract the base command/path and increment its counter."""
        key = self._normalize(protocol, raw_input)
        async with self._lock:
            self._counts[key] += 1

    async def top(self, n: int = 20) -> list[tuple[str, int]]:
        async with self._lock:
            return self._counts.most_common(n)

    @staticmethod
    def _normalize(protocol: str, raw: str) -> str:
        raw = raw.strip()
        if protocol == "ssh":
            # Keep only the first token (the command name)
            return raw.split()[0] if raw else "(empty)"
        elif protocol == "http":
            # Extract method + first path segment
            m = re.search(r"Path\s*:\s*(\S+)", raw)
            return m.group(1) if m else raw[:40]
        return raw[:40]
