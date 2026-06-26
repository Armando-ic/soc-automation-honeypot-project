"""Rebuild data/attack_reference.json from MITRE's enterprise-attack STIX bundle.

Usage:  python scripts/regen_attack_reference.py
Downloads the official enterprise-attack.json and writes the slim
{technique_id: {name, tactics[]}} table the verifier uses.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).resolve().parent.parent / "data" / "attack_reference.json"


def build() -> dict[str, dict]:
    with urllib.request.urlopen(STIX_URL) as resp:  # noqa: S310 (official MITRE source)
        bundle = json.load(resp)
    table: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext["external_id"]
        tactics = [ph["phase_name"] for ph in obj.get("kill_chain_phases", [])
                   if ph.get("kill_chain_name") == "mitre-attack"]
        table[tid] = {"name": obj["name"], "tactics": tactics}
    return dict(sorted(table.items()))


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
