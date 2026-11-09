"""
honeypot/protocols/http_protocol.py
Async HTTP honeypot using aiohttp.

Every request (path + method + headers + body) is serialized into a
prompt for the LLM, which returns a plausible HTTP response body.
"""

from __future__ import annotations

import logging

from aiohttp import web

from honeypot.core.llm_engine import LLMEngine
from honeypot.core.session_store import SessionStore

logger = logging.getLogger(__name__)


def _build_http_prompt(request: web.Request, body: bytes) -> str:
    """Convert an aiohttp Request into a plain-text prompt for the LLM."""
    headers_text = "\n".join(f"  {k}: {v}" for k, v in request.headers.items())
    body_text = body.decode("utf-8", errors="replace")[:512] if body else "(empty)"
    return (
        f"Incoming HTTP request:\n"
        f"  Method : {request.method}\n"
        f"  Path   : {request.path}\n"
        f"  Query  : {request.query_string or '(none)'}\n"
        f"Headers:\n{headers_text}\n"
        f"Body:\n{body_text}\n\n"
        "Respond with a realistic HTTP response body only "
        "(no HTTP status line, no headers). "
        "Make it convincing for the path requested."
    )


async def _handle_request(
    request: web.Request,
    engine: LLMEngine,
    store: SessionStore,
) -> web.Response:
    attacker_ip = request.remote or "0.0.0.0"
    attacker_port = 0  # aiohttp doesn't expose peer port easily

    session = await store.create_session("http", attacker_ip, attacker_port)

    try:
        body = await request.read()
        prompt = _build_http_prompt(request, body)
        reply = await engine.respond(session, prompt)
        await store.log_interaction(session, prompt, reply)

        # Choose a plausible content-type based on the path
        path = request.path.lower()
        if path.endswith(".json") or "api" in path:
            content_type = "application/json"
        elif path.endswith(".xml"):
            content_type = "application/xml"
        else:
            content_type = "text/html; charset=utf-8"

        return web.Response(
            text=reply,
            content_type=content_type,
            headers={
                "Server": "Apache/2.4.57 (Ubuntu)",
                "X-Powered-By": "PHP/8.1.12",
            },
        )
    finally:
        await store.close_session(session.session_id)


def create_http_app(engine: LLMEngine, store: SessionStore) -> web.Application:
    """Create the aiohttp Application for the HTTP honeypot."""
    app = web.Application()

    async def handler(request: web.Request) -> web.Response:
        return await _handle_request(request, engine, store)

    # Catch-all route
    app.router.add_route("*", "/{path_info:.*}", handler)
    return app


async def start_http_server(
    engine: LLMEngine,
    store: SessionStore,
    host: str = "0.0.0.0",
    port: int = 8080,
) -> web.AppRunner:
    """Start the HTTP honeypot server."""
    app = create_http_app(engine, store)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("HTTP honeypot listening on %s:%s", host, port)
    return runner
