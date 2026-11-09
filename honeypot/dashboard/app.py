"""
honeypot/dashboard/app.py
Real-time web dashboard built with Flask + Server-Sent Events.

Endpoints:
  GET /            → Dashboard HTML page
  GET /api/sessions → JSON: active sessions
  GET /api/events   → JSON: last N log events
  GET /stream       → SSE stream of live events
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections import Counter, deque
from pathlib import Path
from typing import Generator

from flask import Flask, Response, jsonify, render_template_string, stream_with_context

from honeypot.core.session_store import SessionStore

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>🍯 LLM Honeypot Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --accent:#58a6ff; --green:#3fb950; --red:#f85149; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:#c9d1d9; font-family:'Segoe UI',system-ui,sans-serif; }
  header { padding:1rem 2rem; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:1rem; }
  header h1 { font-size:1.4rem; color:var(--accent); }
  .badge { background:var(--green); color:#000; border-radius:4px; padding:2px 8px; font-size:.75rem; font-weight:700; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; padding:1.5rem 2rem; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:1rem; }
  .panel h2 { font-size:.85rem; color:#8b949e; text-transform:uppercase; letter-spacing:.08em; margin-bottom:.75rem; }
  table { width:100%; border-collapse:collapse; font-size:.85rem; }
  th, td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--border); }
  th { color:#8b949e; font-weight:600; }
  .proto-ssh  { color:#f7a327; }
  .proto-http { color:#58a6ff; }
  .proto-tcp  { color:#3fb950; }
  #log { height:300px; overflow-y:auto; font-family:monospace; font-size:.78rem; }
  .log-entry { padding:.2rem .4rem; border-bottom:1px solid var(--border); }
  .log-entry.interaction { color:#c9d1d9; }
  .log-entry.session_start { color:var(--green); }
  .log-entry.session_end { color:var(--red); }
  #stat-total, #stat-active { font-size:2rem; font-weight:700; color:var(--accent); }
  .stats-row { display:flex; gap:2rem; margin-bottom:.5rem; }
  .stat-box { text-align:center; }
  .stat-label { font-size:.75rem; color:#8b949e; }
</style>
</head>
<body>
<header>
  <span style="font-size:1.8rem">🍯</span>
  <h1>LLM Honeypot Hub — Live Dashboard</h1>
  <span class="badge" id="status">LIVE</span>
</header>

<div class="grid">
  <!-- Stats -->
  <div class="panel" style="grid-column:1/-1">
    <div class="stats-row">
      <div class="stat-box"><div id="stat-active">0</div><div class="stat-label">Active Sessions</div></div>
      <div class="stat-box"><div id="stat-total">0</div><div class="stat-label">Total Sessions</div></div>
      <div class="stat-box"><div id="stat-ssh">0</div><div class="stat-label">SSH</div></div>
      <div class="stat-box"><div id="stat-http">0</div><div class="stat-label">HTTP</div></div>
      <div class="stat-box"><div id="stat-tcp">0</div><div class="stat-label">TCP</div></div>
    </div>
  </div>

  <!-- Active Sessions -->
  <div class="panel">
    <h2>Active Sessions</h2>
    <table>
      <thead><tr><th>IP</th><th>Protocol</th><th>Session ID</th><th>Turns</th></tr></thead>
      <tbody id="sessions-tbody"><tr><td colspan="4" style="color:#8b949e">No active sessions</td></tr></tbody>
    </table>
  </div>

  <!-- Live Event Log -->
  <div class="panel">
    <h2>Live Event Log</h2>
    <div id="log"></div>
  </div>
</div>

<script>
  const MAX_LOG = 200;
  let totalSessions = 0, ssh = 0, http = 0, tcp = 0;

  function protoClass(p) { return 'proto-' + p; }

  const evtSource = new EventSource('/stream');
  evtSource.onmessage = function(e) {
    const ev = JSON.parse(e.data);
    appendLog(ev);
    if (ev.event === 'session_start') {
      totalSessions++;
      if (ev.protocol === 'ssh') ssh++;
      else if (ev.protocol === 'http') http++;
      else tcp++;
      document.getElementById('stat-total').textContent = totalSessions;
      document.getElementById('stat-ssh').textContent = ssh;
      document.getElementById('stat-http').textContent = http;
      document.getElementById('stat-tcp').textContent = tcp;
    }
  };

  function appendLog(ev) {
    const div = document.getElementById('log');
    const entry = document.createElement('div');
    entry.className = 'log-entry ' + ev.event;
    let text = '[' + ev.timestamp.slice(11,19) + '] ' + ev.event.toUpperCase() + ' | ';
    text += ev.attacker_ip + ' | ' + (ev.protocol || '').toUpperCase();
    if (ev.attacker_input) text += ' | > ' + ev.attacker_input.slice(0, 80);
    entry.textContent = text;
    div.prepend(entry);
    // Trim old entries
    while (div.children.length > MAX_LOG) div.removeChild(div.lastChild);
  }

  // Poll active sessions every 3s
  async function refreshSessions() {
    const r = await fetch('/api/sessions');
    const sessions = await r.json();
    document.getElementById('stat-active').textContent = sessions.length;
    const tbody = document.getElementById('sessions-tbody');
    if (sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:#8b949e">No active sessions</td></tr>';
    } else {
      tbody.innerHTML = sessions.map(s =>
        `<tr>
          <td>${s.attacker_ip}</td>
          <td class="${protoClass(s.protocol)}">${s.protocol.toUpperCase()}</td>
          <td style="font-family:monospace;font-size:.75rem">${s.session_id.slice(0,8)}…</td>
          <td>${s.turn_count}</td>
        </tr>`
      ).join('');
    }
  }
  setInterval(refreshSessions, 3000);
  refreshSessions();
</script>
</body>
</html>
"""


def create_dashboard_app(store: SessionStore, loop: asyncio.AbstractEventLoop) -> Flask:
    """Create and return the Flask dashboard app."""
    flask_app = Flask(__name__)
    # Ring buffer for SSE subscribers
    _sse_queue: deque[str] = deque(maxlen=500)
    _sse_lock = threading.Lock()

    # Monkey-patch SessionStore to also push events to SSE queue
    _original_append = store._append_line

    def _patched_append(line: str) -> None:
        _original_append(line)
        with _sse_lock:
            _sse_queue.append(line)

    store._append_line = _patched_append  # type: ignore[method-assign]

    @flask_app.route("/")
    def index():  # type: ignore[return]
        return render_template_string(DASHBOARD_HTML)

    @flask_app.route("/api/sessions")
    def api_sessions():  # type: ignore[return]
        future = asyncio.run_coroutine_threadsafe(store.active_sessions(), loop)
        sessions = future.result(timeout=5)
        return jsonify(sessions)

    @flask_app.route("/api/events")
    def api_events():  # type: ignore[return]
        events = list(store.iter_log())
        return jsonify(events[-200:])  # last 200

    @flask_app.route("/stream")
    def stream():  # type: ignore[return]
        """Server-Sent Events endpoint."""
        last_seen: int = 0

        @stream_with_context
        def generate() -> Generator[str, None, None]:
            nonlocal last_seen
            # Replay recent events on connect
            with _sse_lock:
                snapshot = list(_sse_queue)
            for item in snapshot[last_seen:]:
                yield f"data: {item}\n\n"
            last_seen = len(snapshot)

            import time

            while True:
                time.sleep(0.5)
                with _sse_lock:
                    new_items = list(_sse_queue)[last_seen:]
                for item in new_items:
                    yield f"data: {item}\n\n"
                last_seen += len(new_items)

        return Response(generate(), mimetype="text/event-stream")

    return flask_app


def start_dashboard(
    store: SessionStore,
    loop: asyncio.AbstractEventLoop,
    host: str = "127.0.0.1",
    port: int = 5000,
) -> None:
    """Run the Flask dashboard in a background thread."""
    flask_app = create_dashboard_app(store, loop)

    def run() -> None:
        flask_app.run(host=host, port=port, threaded=True, use_reloader=False)

    t = threading.Thread(target=run, daemon=True, name="dashboard")
    t.start()
    logger.info("Dashboard running at http://%s:%s", host, port)
