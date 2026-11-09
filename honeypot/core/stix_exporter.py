"""
honeypot/core/stix_exporter.py
Export captured attacker TTPs to STIX 2.1 JSON bundles.

Requires: stix2 (pip install stix2)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def export_to_stix(events: list[dict], output_path: Path) -> None:
    """
    Convert JSONL log events into a minimal STIX 2.1 bundle.
    Each unique attacker IP → ThreatActor.
    Each interaction → ObservedData.
    """
    try:
        import stix2  # noqa: F401 (optional dependency)
    except ImportError:
        logger.error("stix2 not installed — run: pip install stix2")
        return

    from stix2 import Bundle, ObservedData, ThreatActor, Indicator

    seen_ips: dict[str, ThreatActor] = {}
    objects = []

    for ev in events:
        if ev.get("event") != "interaction":
            continue
        ip = ev.get("attacker_ip", "unknown")
        protocol = ev.get("protocol", "?")
        cmd = ev.get("attacker_input", "")
        ts = ev.get("timestamp", datetime.utcnow().isoformat())

        if ip not in seen_ips:
            actor = ThreatActor(
                name=f"Attacker-{ip}",
                description=f"Attacker from {ip} observed via LLM honeypot",
                labels=["unknown"],
            )
            seen_ips[ip] = actor
            objects.append(actor)

        obs = ObservedData(
            first_observed=ts,
            last_observed=ts,
            number_observed=1,
            object_refs=[],
            created_by_ref=seen_ips[ip].id,
            custom_properties={
                "x_honeypot_protocol": protocol,
                "x_honeypot_command": cmd[:256],
            },
        )
        objects.append(obs)

    if not objects:
        logger.warning("No interaction events to export")
        return

    bundle = Bundle(*objects)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    logger.info("STIX bundle written to %s (%d objects)", output_path, len(objects))
