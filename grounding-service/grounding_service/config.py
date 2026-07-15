"""Service settings, read from env with safe defaults (no pydantic-settings dep)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_VERIFIER = _REPO_ROOT / "triage-verifier"


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    qdrant_url: str = os.getenv("QDRANT_URL", "http://127.0.0.1:6333")
    collection: str = os.getenv("ATTACK_COLLECTION", "attack_techniques")
    embed_model: str = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    top_k_default: int = int(os.getenv("RETRIEVE_TOP_K", "6"))
    model: str = os.getenv("TRIAGE_MODEL", "claude-opus-4-8")
    runs_path: str = os.getenv("RUNS_PATH", str(Path.cwd() / "runs.jsonl"))
    schema_path: str = os.getenv(
        "VERIFIER_SCHEMA", str(_VERIFIER / "schema" / "submit_triage_result.json")
    )
    attack_ref_path: str = os.getenv(
        "ATTACK_REF", str(_VERIFIER / "data" / "attack_reference.json")
    )
    prompt_path: str = os.getenv(
        "VERIFIER_PROMPT_JSON", str(_REPO_ROOT / "JSON" / "honeypot-triage.json")
    )
    state_path: str = os.getenv(
        "FALCON_STATE_PATH", str(Path.cwd() / "falcon-poller-state.json")
    )
    falcon_pinned_aid: str = os.getenv("FALCON_PINNED_AID", "")
    falcon_poll_cap: int = int(os.getenv("FALCON_POLL_CAP", "8"))

    # --- honeypot-opening auto-brake (Part A) ---
    brake_enabled: bool = _env_bool("BRAKE_ENABLED")
    splunk_host_ip: str = os.getenv("SPLUNK_HOST_IP", "")
    brake_distinct_dst_max: int = int(os.getenv("BRAKE_DISTINCT_DST_MAX", "25"))
    brake_conn_rate_max: int = int(os.getenv("BRAKE_CONN_RATE_MAX", "200"))
    azure_tenant_id: str = os.getenv("AZURE_TENANT_ID", "")
    azure_client_id: str = os.getenv("AZURE_CLIENT_ID", "")
    azure_client_secret: str = os.getenv("AZURE_CLIENT_SECRET", "")
    honeypot_subscription_id: str = os.getenv("HONEYPOT_SUBSCRIPTION_ID", "")
    honeypot_nsg_rg: str = os.getenv("HONEYPOT_NSG_RG", "")
    honeypot_nsg_name: str = os.getenv("HONEYPOT_NSG_NAME", "")
    honeypot_nsg_deny_rule: str = os.getenv("HONEYPOT_NSG_DENY_RULE", "honeypot-brake-egress-deny")
    honeypot_nsg_deny_priority: int = int(os.getenv("HONEYPOT_NSG_DENY_PRIORITY", "100"))

    # --- feeder liveness watermark (session 40) ---
    # The brake cannot tell a quiet box from a dead feeder; both are trip:false/distinct_dst:0.
    # This records that a feeder POSTED at all, which is the only thing that separates them.
    brake_feed_state_path: str = os.getenv(
        "BRAKE_FEED_STATE_PATH", str(Path.cwd() / "brake-feed-state.json")
    )
    # The host feeder posts every 60s. Five missed ticks is not a blip, it is a dead feeder.
    # NOTE: this also goes stale forever after a legitimate trip, because the trip severs the
    # honeypot's 9997 forwarding (deny @100 beats allow-splunk-telemetry @1000). Stale means
    # "not reporting", NOT "faulty" -- check whether the brake fired before treating it as a bug.
    brake_feed_stale_s: int = int(os.getenv("BRAKE_FEED_STALE_S", "300"))


def load_settings() -> Settings:
    return Settings()
