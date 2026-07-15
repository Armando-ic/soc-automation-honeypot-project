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


def test_dockerfile_copies_verifier_prompt_json():
    # config.prompt_path defaults to <repo>/JSON/honeypot-triage.json and is passed EAGERLY into
    # TriageVerifier.from_paths (verify_adapter.py). In the container that resolves to
    # /app/JSON/honeypot-triage.json, but the Dockerfile copies only the four package dirs, not JSON/.
    # Result: EVERY /verify raises "No such file or directory: '/app/JSON/honeypot-triage.json'" and
    # fail-closes to verifier_error -- which shipped on the Task-17 first live run (runs 395/396/400).
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY JSON/" in text, (
        "the verifier's prompt_path needs JSON/honeypot-triage.json baked into the image; "
        "add a COPY for it or /verify fail-closes with verifier_error in the container"
    )


def test_verifier_prompt_json_present_in_source_tree():
    # The COPY only helps if the file exists in the build context. Guard the source side too:
    # config.prompt_path must resolve to a real file (locally _REPO_ROOT is the repo root).
    from grounding_service.config import load_settings
    p = Path(load_settings().prompt_path)
    assert p.is_file(), f"verifier prompt_path source missing: {p}"


def test_main_wires_brake_factory():
    # The auto-brake (Task A5) is only reachable in production if main.py builds and
    # passes the session factory -- otherwise /brake/nsg-deny and /brake/nsg-status are
    # silently inert in every deploy, the exact class of gap this file guards against.
    src = (_GS / "grounding_service" / "main.py").read_text(encoding="utf-8")
    assert "azure_brake_session_factory" in src
    assert "BRAKE_ENABLED" in src


def test_compose_persists_the_feed_watermark_on_the_data_volume():
    # THE DEPLOY TRAP, fourth instance. This project has shipped green tests over a dead deployed
    # path three times (the Phase-3 engine missing from the image; the Phase-4 factories unwired
    # in main.py; the Dockerfile missing honeypot-triage.json -> /verify fail-closed on EVERY
    # live run). The watermark is the same shape of hazard: config.py defaults
    # BRAKE_FEED_STATE_PATH to Path.cwd(), which is /app/grounding-service in the image -- NOT
    # on the grounding_runs:/data volume. The deploy step is `up -d --build --force-recreate`,
    # so the watermark would reset to total_posts:0 on every deploy and read STALE forever,
    # exactly like a dead feeder. It must sit on /data, the way FALCON_STATE_PATH already does.
    text = _COMPOSE.read_text(encoding="utf-8")
    assert "BRAKE_FEED_STATE_PATH: /data/brake-feed-state.json" in text
    assert "grounding_runs:/data" in text, "the /data volume is what makes the path persist"


def test_compose_injects_brake_env():
    # Without these keys in compose's environment block, main.py's gating always reads
    # them as unset and the brake factory is never built, no matter the .env contents.
    compose = (_GS / "docker-compose.yml").read_text(encoding="utf-8")
    for key in ("BRAKE_ENABLED", "AZURE_CLIENT_SECRET", "HONEYPOT_NSG_NAME", "SPLUNK_HOST_IP"):
        assert key in compose, f"{key} not injected in compose"
