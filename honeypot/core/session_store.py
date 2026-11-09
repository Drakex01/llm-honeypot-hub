"""
honeypot/core/session_store.py
Thread-safe in-memory store for attacker sessions + JSONL event log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .llm_engine import Protocol, Session

logger = logging.getLogger(__name__)


class SessionStore:
    """
    Manages active sessions and persists events to a JSONL log file.

    All public methods are coroutine-safe (uses asyncio.Lock internally).
    """

    def __init__(self, log_path: Path) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()
        self._log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def create_session(
        self, protocol: Protocol, attacker_ip: str, attacker_port: int
    ) -> Session:
        session_id = str(uuid.uuid4())
        session = Session(
            session_id=session_id,
            protocol=protocol,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
        )
        async with self._lock:
            self._sessions[session_id] = session
        await self._log_event("session_start", session)
        logger.info(
            "New %s session %s from %s:%s",
            protocol,
            session_id,
            attacker_ip,
            attacker_port,
        )
        return session

    async def close_session(self, session_id: str) -> None:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            await self._log_event("session_end", session)
            logger.info("Closed session %s", session_id)

    async def log_interaction(
        self, session: Session, attacker_input: str, honeypot_reply: str
    ) -> None:
        await self._log_event(
            "interaction",
            session,
            extra={
                "attacker_input": attacker_input,
                "honeypot_reply": honeypot_reply,
            },
        )

    # ------------------------------------------------------------------
    # Read access (for dashboard)
    # ------------------------------------------------------------------

    async def active_sessions(self) -> list[dict]:
        async with self._lock:
            return [s.to_log_dict() for s in self._sessions.values()]

    def iter_log(self) -> Iterator[dict]:
        """Iterate all logged events from the JSONL file."""
        if not self._log_path.exists():
            return
        with self._log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    async def _log_event(
        self, event_type: str, session: Session, extra: dict | None = None
    ) -> None:
        record = {
            "event": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            **session.to_log_dict(),
        }
        if extra:
            record.update(extra)
        line = json.dumps(record, ensure_ascii=False)
        # Append to JSONL — run in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._append_line, line)

    def _append_line(self, line: str) -> None:
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
