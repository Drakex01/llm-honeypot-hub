"""
honeypot/core/fingerprinter.py
Persistent attacker fingerprinting — detects returning attackers across
sessions based on IP, user-agent, and behavioural patterns.

Stores a JSON fingerprint DB at logs/fingerprints.json.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class Fingerprinter:
    """
    Builds and updates a simple fingerprint DB for each attacker IP.
    """

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._db: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._db = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                self._db = {}

    async def record_session(
        self,
        ip: str,
        protocol: str,
        commands: list[str],
        geo: dict,
    ) -> dict:
        """
        Update the fingerprint for this IP and return the updated record.
        """
        async with self._lock:
            if ip not in self._db:
                self._db[ip] = {
                    "ip": ip,
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat(),
                    "session_count": 0,
                    "protocols": [],
                    "top_commands": [],
                    "geo": geo,
                }
            fp = self._db[ip]
            fp["last_seen"] = datetime.utcnow().isoformat()
            fp["session_count"] += 1
            if protocol not in fp["protocols"]:
                fp["protocols"].append(protocol)
            # Merge commands (keep unique, cap at 50)
            seen = set(fp["top_commands"])
            for cmd in commands:
                if cmd not in seen:
                    fp["top_commands"].append(cmd)
                    seen.add(cmd)
            fp["top_commands"] = fp["top_commands"][:50]
            # Persist
            self._save()
            returning = fp["session_count"] > 1
            if returning:
                logger.info(
                    "Returning attacker %s — %d previous sessions",
                    ip,
                    fp["session_count"] - 1,
                )
            return dict(fp)

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._db, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not save fingerprint DB: %s", exc)

    async def all_fingerprints(self) -> list[dict]:
        async with self._lock:
            return list(self._db.values())
