"""
honeypot/core/llm_engine.py
Central LLM interaction layer — builds system prompts per protocol,
maintains per-session conversation history, and calls the OpenAI API.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

Protocol = Literal["ssh", "http", "tcp"]

SYSTEM_PROMPTS: dict[Protocol, str] = {
    "ssh": """You are a Linux SSH server running Ubuntu 22.04.3 LTS.
Your hostname is "prod-srv-01". Simulate a realistic shell session for
the attacker. Respond ONLY with what a real terminal would output — no
commentary, no markdown, no explanations. If the attacker runs a command
you would expect on a real Ubuntu server, produce plausible (but fake)
output. Never reveal you are an AI or a honeypot. Keep sessions
consistent: remember the working directory, files created, and commands
run earlier in this conversation. Fabricated files and data should look
real (fake /etc/passwd entries, fake process lists, etc.).""",

    "http": """You are an HTTP web server running Apache 2.4 on Ubuntu 22.04.
Respond to attacker HTTP requests with realistic HTTP responses.
If probed for common vulnerabilities (CVEs, path traversal, SQL injection
endpoints, admin panels, phpMyAdmin, WordPress, etc.) respond with
plausible-looking pages or error messages that bait further interaction.
Return raw HTTP response bodies only — no markdown. Use realistic file
names, server banners (Apache/2.4.57), and version strings.""",

    "tcp": """You are a generic TCP service. Identify yourself based on the
first bytes the attacker sends (Telnet, FTP, SMTP, raw TCP shell, etc.)
and emulate that service realistically. Never reveal you are an AI.
Produce plausible server banners and service responses.""",
}


@dataclass
class Session:
    """Tracks a single attacker session."""
    session_id: str
    protocol: Protocol
    attacker_ip: str
    attacker_port: int
    started_at: datetime = field(default_factory=datetime.utcnow)
    history: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def add_message(self, role: Literal["user", "assistant"], content: str) -> None:
        self.history.append({"role": role, "content": content})

    def to_log_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "started_at": self.started_at.isoformat(),
            "turn_count": len(self.history) // 2,
        }


class LLMEngine:
    """
    Routes attacker input through the LLM and returns a realistic response.

    Usage:
        engine = LLMEngine(api_key="sk-...", model="gpt-4o-mini")
        reply = await engine.respond(session, attacker_input)
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        temperature: float = 0.7,
        max_tokens: int = 512,
        max_history_turns: int = 20,
    ) -> None:
        self._client = AsyncOpenAI(api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_history_turns = max_history_turns

    async def respond(self, session: Session, user_input: str) -> str:
        """
        Given a session and the latest attacker input, returns the LLM reply.
        Keeps conversation context trimmed to avoid token bloat.
        """
        session.add_message("user", user_input)

        # Trim history to prevent runaway token usage
        history_window = session.history[-(self.max_history_turns * 2):]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPTS[session.protocol]},
            *history_window,
        ]

        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            reply = response.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001
            logger.error("LLM API error for session %s: %s", session.session_id, exc)
            reply = ""  # Let the protocol handler decide what to surface

        session.add_message("assistant", reply)
        logger.debug(
            "Session %s | Turn %d | Input: %r | Reply: %r",
            session.session_id,
            len(session.history) // 2,
            user_input[:80],
            reply[:80],
        )
        return reply
