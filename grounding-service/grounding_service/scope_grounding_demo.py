"""Offline, $0 demonstration of the scope-grounding verifier flip (Phase 4,
Task 17 deliverable #2 -- the reliable component that does NOT depend on a live
model populating scope_findings).

It runs the SAME adapter the live /verify endpoint calls (build_report) on two
labeled-SYNTHETIC fixtures, once WITH the scope_evidence bundle and once
WITHOUT, and shows each grounding channel flip pass->fail. This is exactly the
ablation the Task-17 runbook performs live -- proven offline before a dollar is
spent, and regression-locked by tests/test_scope_grounding_demo.py.

Everything here is SYNTHETIC: the source IP is 203.0.113.77 (TEST-NET-3, the
RFC 5737 documentation range -- never a real host), and the "successful auth"
in scenario B is a fixture, because index=honeypot is brute-force-only and can
never produce a real successful logon. Nothing here is a real attacker incident.

Run it:  python -m grounding_service.scope_grounding_demo
(Prints a markdown evidence page to stdout; redirect to a gitignored reports/
file, then scrub-gate before publishing any of it to the vault.)
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from grounding_service.config import Settings
from grounding_service.verify_adapter import build_report

# RFC 5737 TEST-NET-3 -- reserved for documentation, guaranteed non-routable.
SYNTHETIC_IP = "203.0.113.77"
SYNTHETIC_HOST = "vm-honeypot-win"


def build_scenarios() -> list[dict]:
    """Two scenarios, each isolating ONE grounding channel so the flip is
    unambiguous. Every other check passes identically WITH and WITHOUT scope,
    so the only thing that moves is the channel under test."""

    # --- Scenario A: scope_findings_grounded (the honeypot-relevant channel) --
    # A correct brute-force triage whose scope_findings verbatim-copy a grounded
    # claim. WITH scope_evidence it grounds; WITHOUT, a non-empty scope_findings
    # with nothing to check it against fails CLOSED -- the defense against a
    # model inventing scope claims.
    auth_claim = {"type": "auth_outcome", "ip": SYNTHETIC_IP, "user": None,
                  "success_count": 0, "fail_count": 214}
    scenario_a = {
        "name": "scope_findings_grounded_flip",
        "check": "scope_findings_grounded",
        "headline_claim": "A model's scope_findings are trusted only when they field-for-field "
                          "match the harness's out-of-model scope_evidence; with no evidence to "
                          "check them against, they fail CLOSED.",
        "retrieved": ["T1110"],
        "enrichment_results": {SYNTHETIC_IP: "suspicious"},
        "result": {
            "schema_version": "v1",
            "alert_summary": f"High-volume failed RDP logons from {SYNTHETIC_IP} against the honeypot",
            "severity": "medium",
            "severity_rationale": "Sustained brute force; no successful authentication observed",
            "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "credential-access"}],
            "iocs": {"ips": [SYNTHETIC_IP], "domains": [], "file_hashes": [], "users": [], "hosts": []},
            "iocs_enriched": [{"value": SYNTHETIC_IP, "ioc_type": "ip", "verdict": "suspicious",
                               "source": "abuseipdb", "summary": "known brute-force source"}],
            "recommended_actions": [{"description": "Block the source IP at the firewall",
                                     "priority": "medium"}],
            "investigation_notes": "No successful logon observed; brute force only.",
            "src_ip": SYNTHETIC_IP,
            "scope_findings": [dict(auth_claim)],
        },
        "scope_evidence": {
            "claims": [
                dict(auth_claim),
                {"type": "distinct_targets", "ip": SYNTHETIC_IP, "distinct_user_count": 8},
                {"type": "repeat_offender", "ip": SYNTHETIC_IP,
                 "first_seen": "2026-07-09T02:00:00Z", "last_seen": "2026-07-12T06:00:00Z",
                 "days_active": 3, "floored": False},
            ],
            "queries_run": [
                {"query": "logon_outcomes_for_ip",
                 "params": {"ip": SYNTHETIC_IP, "window": "-24h"}, "outcome": "ok", "row_count": 1},
            ],
        },
    }

    # --- Scenario B: severity_supported (the post-exploit escalation channel) -
    # SYNTHETIC by necessity: a high severity with NO malicious IOC and a NON-hot
    # tactic (T1059.001 = execution) is unjustifiable on its own. Only a grounded
    # successful-auth claim backs it. index=honeypot can never produce this
    # (brute-force-only, no successful logon, no Sysmon), so this is the channel
    # that WOULD fire on real post-exploit telemetry the honeypot doesn't have.
    scenario_b = {
        "name": "severity_supported_backing",
        "check": "severity_supported",
        "headline_claim": "A high severity with no malicious IOC and a non-hot tactic holds ONLY "
                          "because grounded scope_evidence confirms a successful authentication; "
                          "remove the evidence and the severity is no longer supported.",
        "retrieved": ["T1059.001"],
        "enrichment_results": {SYNTHETIC_IP: "clean"},
        "result": {
            "schema_version": "v1",
            "alert_summary": f"PowerShell execution on {SYNTHETIC_HOST} attributed to {SYNTHETIC_IP}",
            "severity": "high",
            "severity_rationale": "Post-authentication code execution backed by grounded scope evidence",
            "mitre_techniques": [{"id": "T1059.001", "name": "PowerShell", "tactic": "execution"}],
            "iocs": {"ips": [SYNTHETIC_IP], "domains": [], "file_hashes": [], "users": [],
                     "hosts": [SYNTHETIC_HOST]},
            "iocs_enriched": [{"value": SYNTHETIC_IP, "ioc_type": "ip", "verdict": "clean",
                               "source": "abuseipdb", "summary": "no adverse reports"}],
            "recommended_actions": [{"description": "Isolate the host and reset the account",
                                     "priority": "high"}],
            # Deliberately makes NO scope assertion (no "successful logon" phrasing),
            # so scope_notes_honesty passes identically both ways and only
            # severity_supported moves.
            "investigation_notes": "Code execution on the host, scoped to the source under investigation.",
            "src_ip": SYNTHETIC_IP,
            "scope_findings": [],
        },
        "scope_evidence": {
            "claims": [
                {"type": "auth_outcome", "ip": SYNTHETIC_IP, "user": None,
                 "success_count": 3, "fail_count": 210},
            ],
            "queries_run": [],
        },
    }

    return [scenario_a, scenario_b]


def _status(record: dict, name: str) -> str | None:
    for c in record["check_results"]:
        if c["name"] == name:
            return c["status"]
    return None


def run_scenario(scenario: dict, settings: Settings) -> dict:
    """Run build_report twice on the SAME result -- once with the scope bundle,
    once with scope_evidence=None -- and report the flip on the channel under
    test plus the overall verdict."""
    common = dict(
        retrieved=scenario["retrieved"],
        enrichment_results=scenario["enrichment_results"],
        run_meta={"run_id": scenario["name"] + "-with"},
        settings=settings,
    )
    with_report = build_report(scenario["result"], scope_evidence=scenario["scope_evidence"], **common)
    common_without = dict(common, run_meta={"run_id": scenario["name"] + "-without"})
    without_report = build_report(scenario["result"], scope_evidence=None, **common_without)
    check = scenario["check"]
    return {
        "name": scenario["name"],
        "check": check,
        "headline_claim": scenario["headline_claim"],
        "with_scope": _status(with_report, check),
        "without_scope": _status(without_report, check),
        "with_verification_passed": with_report["verification_passed"],
        "without_verification_passed": without_report["verification_passed"],
        "with_report": with_report,
        "without_report": without_report,
        "result": scenario["result"],
        "scope_evidence": scenario["scope_evidence"],
    }


def run_demo(settings: Settings | None = None) -> list[dict]:
    """Run every scenario. If no settings given, log build_report's runs.jsonl
    to a throwaway temp file (the demo never touches a real run log)."""
    if settings is None:
        tmp = Path(tempfile.mkdtemp(prefix="scope-grounding-demo-")) / "runs.jsonl"
        settings = Settings(runs_path=str(tmp))
    return [run_scenario(s, settings) for s in build_scenarios()]


def _fmt_status(status: str | None) -> str:
    return {"passed": "PASSED", "failed": "FAILED", "needs_human": "NEEDS-HUMAN"}.get(status, str(status))


def render_markdown(results: list[dict]) -> str:
    lines: list[str] = []
    lines.append("# Scope-grounding ablation -- SYNTHETIC fixture demonstration")
    lines.append("")
    lines.append("> **SYNTHETIC / FIXTURE DATA.** Source IP `203.0.113.77` is RFC 5737 TEST-NET-3 "
                 "(documentation range, never a real host). Scenario B's successful authentication "
                 "is a fixture: `index=honeypot` is brute-force-only and cannot produce a real "
                 "successful logon or post-exploit telemetry. This is NOT a real attacker incident.")
    lines.append("")
    lines.append("This is the exact ablation the live Task-17 run performs -- two `/verify` calls on "
                 "the same triage result, differing only in whether the out-of-model `scope_evidence` "
                 "bundle is supplied -- proven offline through `build_report`, the same adapter the "
                 "`/verify` endpoint calls. Each scenario isolates one grounding channel so the flip "
                 "is unambiguous.")
    lines.append("")
    for r in results:
        lines.append(f"## `{r['check']}` -- {r['name']}")
        lines.append("")
        lines.append(r["headline_claim"])
        lines.append("")
        lines.append("| Run | `scope_evidence` | "
                     f"`{r['check']}` | overall `verification_passed` |")
        lines.append("|-----|------------------|----------------|------------------------------|")
        lines.append(f"| WITH scope  | supplied | **{_fmt_status(r['with_scope'])}** | "
                     f"{r['with_verification_passed']} |")
        lines.append(f"| WITHOUT scope | `null` | **{_fmt_status(r['without_scope'])}** | "
                     f"{r['without_verification_passed']} |")
        lines.append("")
        delta = ("removing the grounding evidence flips this check "
                 f"`{_fmt_status(r['with_scope'])}` -> `{_fmt_status(r['without_scope'])}` "
                 "and drops the whole report to Needs-Human")
        lines.append(f"**Attribution:** {delta}.")
        lines.append("")
    lines.append("---")
    lines.append("Regenerate: `python -m grounding_service.scope_grounding_demo`. "
                 "Regression-locked by `grounding-service/tests/test_scope_grounding_demo.py`.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_markdown(run_demo()))
