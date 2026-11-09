"""
honeypot/main.py
Entry point — loads config, starts all protocol servers and the dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import yaml

from honeypot.core.alert_manager import AlertManager
from honeypot.core.command_tracker import CommandTracker
from honeypot.core.fingerprinter import Fingerprinter
from honeypot.core.llm_engine import LLMEngine
from honeypot.core.session_store import SessionStore
from honeypot.dashboard.app import start_dashboard
from honeypot.protocols.http_protocol import start_http_server
from honeypot.protocols.ssh_protocol import start_ssh_server
from honeypot.protocols.tcp_protocol import start_tcp_server


def _load_config(path: str = "configs/config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _setup_logging(level: str = "INFO", json_output: bool = False) -> None:
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format=fmt)


async def _main(config: dict) -> None:
    llm_cfg = config.get("llm", {})
    api_key = llm_cfg.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("ERROR: No OpenAI API key found. Set OPENAI_API_KEY or add api_key to config.yaml.")
        sys.exit(1)

    engine = LLMEngine(
        api_key=api_key,
        model=llm_cfg.get("model", "gpt-4o-mini"),
        temperature=llm_cfg.get("temperature", 0.7),
        max_tokens=llm_cfg.get("max_tokens", 512),
    )

    log_cfg = config.get("logging", {})
    log_path = Path(log_cfg.get("file", "logs/honeypot.jsonl"))
    store = SessionStore(log_path)
    tracker = CommandTracker()
    fingerprinter = Fingerprinter(log_path.parent / "fingerprints.json")
    alert_mgr = AlertManager(config.get("alerts", {}))

    proto_cfg = config.get("protocols", {})
    tasks = []

    # SSH
    ssh_cfg = proto_cfg.get("ssh", {})
    if ssh_cfg.get("enabled", True):
        await start_ssh_server(
            engine, store,
            host=ssh_cfg.get("host", "0.0.0.0"),
            port=ssh_cfg.get("port", 2222),
            host_key_path=ssh_cfg.get("host_key", "configs/ssh_host_key"),
        )

    # HTTP
    http_cfg = proto_cfg.get("http", {})
    if http_cfg.get("enabled", True):
        await start_http_server(
            engine, store,
            host=http_cfg.get("host", "0.0.0.0"),
            port=http_cfg.get("port", 8080),
        )

    # TCP
    tcp_cfg = proto_cfg.get("tcp", {})
    if tcp_cfg.get("enabled", True):
        await start_tcp_server(
            engine, store,
            host=tcp_cfg.get("host", "0.0.0.0"),
            port=tcp_cfg.get("port", 9999),
        )

    # Dashboard
    dash_cfg = config.get("dashboard", {})
    if dash_cfg.get("enabled", True):
        loop = asyncio.get_event_loop()
        start_dashboard(
            store, loop,
            host=dash_cfg.get("host", "127.0.0.1"),
            port=dash_cfg.get("port", 5000),
        )

    print("\n🍯  LLM Honeypot Hub is running!")
    print("    SSH  → port", ssh_cfg.get("port", 2222))
    print("    HTTP → port", http_cfg.get("port", 8080))
    print("    TCP  → port", tcp_cfg.get("port", 9999))
    print("    Dashboard → http://{}:{}\n".format(
        dash_cfg.get("host", "127.0.0.1"), dash_cfg.get("port", 5000)
    ))
    print("Press Ctrl+C to stop.\n")

    # Keep running until interrupted
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _handle_signal() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler for all signals
            pass

    await stop_event.wait()
    print("\n🛑 Shutting down honeypot…")


def main() -> None:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "configs/config.yaml"
    config = _load_config(cfg_path)
    log_cfg = config.get("logging", {})
    _setup_logging(log_cfg.get("level", "INFO"), log_cfg.get("json_output", False))
    asyncio.run(_main(config))


if __name__ == "__main__":
    main()
