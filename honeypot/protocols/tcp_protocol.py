"""
honeypot/protocols/tcp_protocol.py
Generic TCP honeypot using asyncio streams.

Identifies the service being probed from the first few bytes and
delegates all interaction to the LLM engine.
"""

from __future__ import annotations

import asyncio
import logging

from honeypot.core.llm_engine import LLMEngine
from honeypot.core.session_store import SessionStore

logger = logging.getLogger(__name__)

READ_TIMEOUT = 30.0  # seconds to wait for the next attacker message
MAX_LINE_LEN = 4096


class TCPHoneypotProtocol(asyncio.Protocol):
    """Single-connection TCP handler."""

    def __init__(self, engine: LLMEngine, store: SessionStore) -> None:
        self._engine = engine
        self._store = store
        self._transport: asyncio.Transport | None = None
        self._session = None
        self._buffer = b""
        self._loop = asyncio.get_event_loop()

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self._transport = transport
        peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._attacker_ip, self._attacker_port = peer[0], peer[1]
        logger.info("TCP connection from %s:%s", self._attacker_ip, self._attacker_port)
        asyncio.ensure_future(self._init_session())

    async def _init_session(self) -> None:
        self._session = await self._store.create_session(
            "tcp", self._attacker_ip, self._attacker_port
        )

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        # Process complete lines
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            decoded = line.rstrip(b"\r").decode("utf-8", errors="replace")
            if decoded.strip():
                asyncio.ensure_future(self._handle_input(decoded))

    async def _handle_input(self, user_input: str) -> None:
        if not self._session or not self._transport:
            return
        reply = await self._engine.respond(self._session, user_input)
        await self._store.log_interaction(self._session, user_input, reply)
        if reply:
            self._transport.write((reply + "\r\n").encode("utf-8", errors="replace"))

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info(
            "TCP connection lost from %s:%s",
            self._attacker_ip,
            self._attacker_port,
        )
        if self._session:
            asyncio.ensure_future(self._store.close_session(self._session.session_id))


async def start_tcp_server(
    engine: LLMEngine,
    store: SessionStore,
    host: str = "0.0.0.0",
    port: int = 9999,
) -> asyncio.AbstractServer:
    """Start the TCP honeypot server."""
    loop = asyncio.get_event_loop()
    server = await loop.create_server(
        lambda: TCPHoneypotProtocol(engine, store),
        host=host,
        port=port,
    )
    logger.info("TCP honeypot listening on %s:%s", host, port)
    return server
