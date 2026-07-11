"""Settings, read from env with safe defaults (mirrors malware-triage)."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    model: str = os.getenv("INVESTIGATE_MODEL", "claude-opus-4-8")
    max_tokens: int = int(os.getenv("INVESTIGATE_MAX_TOKENS", "1024"))
    max_turns: int = int(os.getenv("INVESTIGATE_MAX_TURNS", "8"))
    max_queries: int = int(os.getenv("INVESTIGATE_MAX_QUERIES", "4"))
    per_source_window_s: int = int(os.getenv("INVESTIGATE_DEDUP_WINDOW_S", "3600"))
    daily_budget: int = int(os.getenv("INVESTIGATE_DAILY_BUDGET", "200"))
    enabled: bool = os.getenv("INVESTIGATE_ENABLED", "1") == "1"
    live_indexes: tuple = tuple(os.getenv("INVESTIGATE_LIVE_INDEXES", "honeypot").split(","))
    lookahead_s: int = int(os.getenv("INVESTIGATE_LOOKAHEAD_S", "3600"))


def load_config() -> Config:
    return Config()
