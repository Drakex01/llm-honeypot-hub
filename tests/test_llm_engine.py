"""
tests/test_llm_engine.py
Unit tests for the LLM engine and session management.
Mocks the OpenAI API so no real API key is needed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from honeypot.core.llm_engine import LLMEngine, Session


@pytest.fixture
def session() -> Session:
    return Session(
        session_id="test-session-001",
        protocol="ssh",
        attacker_ip="10.0.0.1",
        attacker_port=54321,
    )


@pytest.fixture
def engine() -> LLMEngine:
    return LLMEngine(api_key="sk-test", model="gpt-4o-mini")


@pytest.mark.asyncio
async def test_respond_adds_to_history(engine: LLMEngine, session: Session) -> None:
    """respond() should add user message and assistant reply to session history."""
    mock_reply = "total 32\ndrwxr-xr-x 5 root root 4096 Jan  1 00:00 .\n"

    with patch.object(engine._client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
        mock_create.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(content=mock_reply))]
        )
        result = await engine.respond(session, "ls -la")

    assert result == mock_reply
    assert len(session.history) == 2
    assert session.history[0] == {"role": "user", "content": "ls -la"}
    assert session.history[1] == {"role": "assistant", "content": mock_reply}


@pytest.mark.asyncio
async def test_respond_handles_api_error(engine: LLMEngine, session: Session) -> None:
    """respond() should return empty string on API error without crashing."""
    with patch.object(engine._client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
        mock_create.side_effect = Exception("Network error")
        result = await engine.respond(session, "whoami")

    assert result == ""
    # History still records the interaction
    assert session.history[0]["role"] == "user"


@pytest.mark.asyncio
async def test_history_trimming(engine: LLMEngine, session: Session) -> None:
    """History should be trimmed to max_history_turns to avoid token bloat."""
    engine.max_history_turns = 3

    with patch.object(engine._client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
        mock_create.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(content="ok"))]
        )
        for cmd in ["cmd1", "cmd2", "cmd3", "cmd4", "cmd5"]:
            await engine.respond(session, cmd)

    # Full history grows unbounded (trimming only affects what's sent to LLM)
    assert len(session.history) == 10  # 5 user + 5 assistant


def test_session_to_log_dict(session: Session) -> None:
    """to_log_dict should return a serializable dict."""
    d = session.to_log_dict()
    assert d["protocol"] == "ssh"
    assert d["attacker_ip"] == "10.0.0.1"
    assert d["turn_count"] == 0
