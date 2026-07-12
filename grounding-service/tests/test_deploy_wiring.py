"""Deploy-layer regression guards.

The grounding-service app LAZY-imports two sibling engines at request time:
  - /deobfuscate + /triage-verdict import `malware_triage` (app.py ~146-149, 207-208)
  - /investigate imports `splunk_investigator` (app.py ~229-231)
Both imports sit inside a catch-all `except` that degrades to an empty result. So if
the Docker image does not install a package, the endpoint returns 200 with an empty
body and every unit test still passes -- the failure is invisible. That exact gap
shipped twice: the Jul-1 Dockerfile predated both Phase 3 (malware_triage) and Phase 4
(splunk_investigator), so both endpoints were silently inert in the deployed container.

Likewise, /investigate needs SPLUNK_* + INVESTIGATE_* env to reach Splunk; compose
injected none of it. These text-level guards catch both classes of deploy gap.
"""
from pathlib import Path

_GS = Path(__file__).resolve().parent.parent  # grounding-service/
_DOCKERFILE = _GS / "Dockerfile"
_COMPOSE = _GS / "docker-compose.yml"


def test_dockerfile_installs_every_lazy_imported_engine():
    text = _DOCKERFILE.read_text(encoding="utf-8")
    # Both engines are lazy-imported by the app and MUST be pip-installed into the image,
    # or the endpoint's import raises and the whole feature is silently inert (fail-safe).
    assert "pip install --no-cache-dir ./splunk-investigator" in text, \
        "/investigate lazy-imports splunk_investigator; the image must pip-install it"
    assert "pip install --no-cache-dir ./malware-triage" in text, \
        "/deobfuscate lazy-imports malware_triage; the image must pip-install it"


def test_compose_injects_investigate_env():
    text = _COMPOSE.read_text(encoding="utf-8")
    for key in ("SPLUNK_HOST", "SPLUNK_PORT", "SPLUNK_SCHEME", "SPLUNK_USERNAME",
                "SPLUNK_PASSWORD", "INVESTIGATE_ENABLED", "INVESTIGATE_LIVE_INDEXES"):
        assert key in text, f"{key} missing from the grounding-service compose environment block"
