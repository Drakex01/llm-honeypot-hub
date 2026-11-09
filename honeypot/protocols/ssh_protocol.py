"""
honeypot/protocols/ssh_protocol.py
Asyncio-based SSH honeypot using asyncssh.

The honeypot pretends to be a standard Ubuntu SSH server.
Every command the attacker types is forwarded to the LLM engine,
and the realistic (fake) output is sent back over the SSH channel.
"""

from __future__ import annotations

import asyncio
import logging

import asyncssh

from honeypot.core.llm_engine import LLMEngine
from honeypot.core.session_store import SessionStore

logger = logging.getLogger(__name__)

# Fake credentials — attacker must use one of these to "log in"
ACCEPTED_CREDENTIALS: set[tuple[str, str]] = {
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
    ("user", "user"),
    ("pi", "raspberry"),
}


class HoneypotSSHServerSession(asyncssh.SSHServerSession):
    """Handles a single attacker SSH shell session."""

    def __init__(
        self,
        engine: LLMEngine,
        store: SessionStore,
        attacker_ip: str,
        attacker_port: int,
    ) -> None:
        self._engine = engine
        self._store = store
        self._attacker_ip = attacker_ip
        self._attacker_port = attacker_port
        self._session = None
        self._chan = None
        self._buffer = ""

    def connection_made(self, chan: asyncssh.SSHChannel) -> None:
        self._chan = chan

    def session_started(self) -> None:
        # Create honeypot session asynchronously
        asyncio.ensure_future(self._init_session())

    async def _init_session(self) -> None:
        self._session = await self._store.create_session(
            "ssh", self._attacker_ip, self._attacker_port
        )
        # Send a realistic login banner
        self._chan.write(
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            "\r\n * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        )
        self._chan.write("root@prod-srv-01:~# ")

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        self._buffer += data
        # Process line-by-line
        while "\n" in self._buffer or "\r" in self._buffer:
            for sep in ("\r\n", "\r", "\n"):
                if sep in self._buffer:
                    line, self._buffer = self._buffer.split(sep, 1)
                    break
            line = line.strip()
            if line:
                asyncio.ensure_future(self._handle_command(line))
            else:
                self._chan.write("root@prod-srv-01:~# ")

    async def _handle_command(self, command: str) -> None:
        if not self._session:
            return

        self._chan.write(f"\r\n")  # newline after attacker's input

        # Special-case 'exit' / 'logout'
        if command.lower() in ("exit", "logout", "quit"):
            self._chan.write("logout\r\n")
            self._chan.close()
            return

        reply = await self._engine.respond(self._session, command)
        await self._store.log_interaction(self._session, command, reply)

        # Normalize newlines for SSH
        reply_ssh = reply.replace("\n", "\r\n")
        self._chan.write(reply_ssh)
        if not reply_ssh.endswith("\r\n"):
            self._chan.write("\r\n")
        self._chan.write("root@prod-srv-01:~# ")

    def eof_received(self) -> None:
        self._chan.close()

    def connection_lost(self, exc: Exception | None) -> None:
        if self._session:
            asyncio.ensure_future(self._store.close_session(self._session.session_id))


class HoneypotSSHServer(asyncssh.SSHServer):
    """Factory: validates credentials and spawns sessions."""

    def __init__(self, engine: LLMEngine, store: SessionStore) -> None:
        self._engine = engine
        self._store = store
        self._attacker_ip = "0.0.0.0"
        self._attacker_port = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        if peer:
            self._attacker_ip, self._attacker_port = peer[0], peer[1]
        logger.info("SSH connection from %s:%s", self._attacker_ip, self._attacker_port)

    def begin_auth(self, username: str) -> bool:
        # Always require a password — don't accept key auth
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """Accept a curated set of weak credentials to seem realistic."""
        accepted = (username, password) in ACCEPTED_CREDENTIALS
        if accepted:
            logger.info("SSH login accepted: %s / %s", username, password)
        else:
            logger.debug("SSH login rejected: %s / %s", username, password)
        return accepted

    def session_requested(self) -> HoneypotSSHServerSession:
        return HoneypotSSHServerSession(
            self._engine, self._store, self._attacker_ip, self._attacker_port
        )


async def start_ssh_server(
    engine: LLMEngine,
    store: SessionStore,
    host: str = "0.0.0.0",
    port: int = 2222,
    host_key_path: str = "configs/ssh_host_key",
) -> asyncssh.SSHAcceptor:
    """Start the SSH honeypot server."""
    # Generate a host key if one doesn't exist
    import os
    if not os.path.exists(host_key_path):
        logger.info("Generating SSH host key at %s", host_key_path)
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(host_key_path)

    server = await asyncssh.create_server(
        lambda: HoneypotSSHServer(engine, store),
        host=host,
        port=port,
        server_host_keys=[host_key_path],
        process_factory=None,
    )
    logger.info("SSH honeypot listening on %s:%s", host, port)
    return server
