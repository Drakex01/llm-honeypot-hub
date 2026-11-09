"""
honeypot/core/alert_manager.py
Optional alerting — sends a notification when a new session starts.

Currently supports:
  - Slack (incoming webhook)
  - Email (SMTP)

Configure via config.yaml under the `alerts:` key.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

import aiohttp

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, config: dict) -> None:
        self._slack_webhook: str = config.get("slack_webhook", "")
        self._smtp = config.get("smtp", {})
        self._enabled = config.get("enabled", False)

    async def notify_new_session(self, session_dict: dict) -> None:
        if not self._enabled:
            return
        msg = (
            f"🚨 *New Honeypot Session*\n"
            f"Protocol: `{session_dict.get('protocol', '?').upper()}`\n"
            f"IP: `{session_dict.get('attacker_ip', '?')}`\n"
            f"Session: `{session_dict.get('session_id', '?')[:8]}…`"
        )
        if self._slack_webhook:
            await self._send_slack(msg)
        if self._smtp.get("host"):
            self._send_email(msg)

    async def _send_slack(self, text: str) -> None:
        try:
            async with aiohttp.ClientSession() as sess:
                await sess.post(
                    self._slack_webhook,
                    json={"text": text},
                    timeout=aiohttp.ClientTimeout(total=5),
                )
            logger.info("Slack alert sent")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Slack alert failed: %s", exc)

    def _send_email(self, body: str) -> None:
        cfg = self._smtp
        try:
            msg = MIMEText(body)
            msg["Subject"] = "🍯 LLM Honeypot — New Session"
            msg["From"] = cfg.get("from", "honeypot@localhost")
            msg["To"] = cfg.get("to", "")
            with smtplib.SMTP(cfg["host"], cfg.get("port", 587)) as server:
                if cfg.get("tls", True):
                    server.starttls()
                if cfg.get("user"):
                    server.login(cfg["user"], cfg.get("password", ""))
                server.send_message(msg)
            logger.info("Email alert sent")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Email alert failed: %s", exc)
