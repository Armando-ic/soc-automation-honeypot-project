# splunk-investigator/scripts/run_investigation.py
"""DI CLI: build client+splunk service -> investigate -> render_report.

Mirrors malware-triage/scripts/run_triage.py's DI shape: `run_investigation`
is a testable core that takes an already-built client + splunk_service, so
the whole investigation loop is exercisable offline and free. The LIVE
Anthropic client + a real splunklib Service connection are constructed only
inside main()'s live branch, which is never exercised in tests.
"""
from __future__ import annotations

import argparse

from splunk_investigator import agent
from splunk_investigator.config import load_config
from splunk_investigator.report import render_report

# A small built-in demo alert -- enough to drive the agent loop end to end
# without needing a live Splunk instance or a fixture file on disk.
DEMO_ALERT = {
    "src_ip": "45.61.53.10",
    "host": "vm-honeypot-win",
    "user": "Administrator",
    "event_time": "2026-07-11T14:03:00",
    "alert_text": "repeated failed logons from a single source",
}


def run_investigation(alert: dict, *, client, splunk_service, cfg) -> str:
    """Pure DI core: run the bounded agent loop over an already-built client
    + splunk_service and render the markdown report. No client/service
    construction happens here -- that's main()'s job -- so this function is
    free and offline whenever the caller passes in stubs."""
    result = agent.investigate(alert, client=client, splunk_service=splunk_service, cfg=cfg)
    return render_report(result)


def main(argv=None, *, client_factory=None, service_factory=None) -> int:
    """Injected path (client_factory + service_factory both given): fully
    offline, no network, no paid call -- everything is built from the
    factories. Live path (both None): builds a real anthropic.Anthropic
    client and a real splunklib Service connection from env vars; never
    exercised by tests."""
    ap = argparse.ArgumentParser(description="Run the Phase 4 Splunk investigation agent")
    ap.parse_args(argv)

    cfg = load_config()

    assert (client_factory is None) == (service_factory is None), "pass both factories or neither"
    if client_factory is not None and service_factory is not None:
        client = client_factory()
        splunk_service = service_factory()
    else:  # pragma: no cover - live wiring
        import os

        import anthropic
        import splunklib.client as splunklib_client

        client = anthropic.Anthropic(timeout=60.0)  # reads ANTHROPIC_API_KEY
        splunk_service = splunklib_client.connect(
            host=os.environ["SPLUNK_HOST"],
            port=int(os.environ.get("SPLUNK_PORT", "8089")),
            username=os.environ["SPLUNK_USERNAME"],
            password=os.environ["SPLUNK_PASSWORD"],
            scheme=os.environ.get("SPLUNK_SCHEME", "https"),
        )

    md = run_investigation(DEMO_ALERT, client=client, splunk_service=splunk_service, cfg=cfg)
    print(md)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
