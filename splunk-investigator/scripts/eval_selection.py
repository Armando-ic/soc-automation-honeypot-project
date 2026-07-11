# splunk-investigator/scripts/eval_selection.py
"""Phase 4 Task 15: opt-in, PAID, USER-run real-model selection-quality eval.

This is a SCAFFOLD, not a run. Importing this module -- including under
pytest -- NEVER makes a real Anthropic call and NEVER needs
ANTHROPIC_API_KEY. See EVAL.md before ever running this for real; it costs
real money and talks to a real Splunk instance.

Why this exists (spec §8): the offline fixture suite (Task 14,
tests/test_scenarios.py) validates loop MECHANICS and grounding -- that a
GIVEN scripted decision sequence executes and grounds correctly. It says
nothing about whether the real model actually CHOOSES the right catalog
queries for a given alert. Query-selection judgment is measured only here
(an opt-in, paid, N-repetition eval against a stated pass threshold) and in
the single live run -- never inferred from the offline suite.

Mirrors run_investigation.py's DI shape exactly:
    - `run_eval` is a testable, offline-capable core: given an
      ALREADY-BUILT client + splunk_service, it drives the real
      `agent.investigate` loop and scores the result. No client/service
      construction happens here.
    - `main(argv=None, *, client_factory=None, service_factory=None)`:
      when both factories are injected, the whole run is offline (tests
      use this path exclusively). When both are None, the live branch
      builds a real `anthropic.Anthropic()` (reads ANTHROPIC_API_KEY) and
      a real splunklib Service from env -- lazily imported, and reachable
      ONLY from that branch, marked `# pragma: no cover - live wiring`.

Do NOT add a new catalog query for this eval (controller notes SS3): v1
scope is single-entity and safe precisely because no catalog query emits a
new "ip" row field for `agent._admit_discovered` to (unsafely) admit. Every
SCENARIOS case below reuses the existing 5-query v1 catalog unchanged.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

from splunk_investigator import agent
from splunk_investigator.config import Config, load_config

# Sane defaults, overridable via CLI flags -- see main()'s argparse setup.
DEFAULT_REPETITIONS = 3
DEFAULT_THRESHOLD = 0.7


@dataclass(frozen=True)
class Scenario:
    """One labeled eval case: an alert plus what a competent Tier-1 SOC
    analyst should do with it, using ONLY the existing v1 catalog.

    `expected_queries` names the catalog queries the agent SHOULD run for
    this alert (scored as a subset check against what it actually ran --
    see `_run_passes`). `expected_conclusion` records that the agent
    should reach `conclude_investigation` for this alert rather than
    spamming the fixed lookup menu to MAX_TURNS.
    """
    name: str
    alert: dict
    expected_queries: frozenset[str]
    expected_conclusion: bool = True


# Labeled SYNTHETIC alerts (not captured real incidents), one per v1
# catalog query family. Every alert seeds src_ip + host + user so all five
# catalog queries are entity-bound-valid for it; `expected_queries` records
# what a sound investigation of THAT specific alert text should run, not
# merely what's technically callable.
SCENARIOS: list[Scenario] = [
    Scenario(
        name="brute_force_repeated_failed_logons",
        alert={
            "src_ip": "45.61.53.10",
            "host": "vm-honeypot-win",
            "user": "Administrator",
            "event_time": "2026-07-11T14:03:00",
            "alert_text": (
                "Repeated failed logon attempts from a single external "
                "source IP against local accounts."
            ),
        },
        expected_queries=frozenset({"logon_outcomes_for_ip"}),
    ),
    Scenario(
        name="password_spray_multiple_targets",
        alert={
            "src_ip": "45.61.53.20",
            "host": "vm-honeypot-win",
            "user": "Administrator",
            "event_time": "2026-07-11T09:15:00",
            "alert_text": (
                "One source IP attempted logons against several different "
                "local accounts in a short window (password-spray pattern)."
            ),
        },
        expected_queries=frozenset({"logon_outcomes_for_ip", "user_targets_for_ip"}),
    ),
    Scenario(
        name="successful_logon_followed_by_suspicious_powershell",
        alert={
            "src_ip": "45.61.53.30",
            "host": "vm-honeypot-win",
            "user": "Administrator",
            "event_time": "2026-07-11T18:47:00",
            "alert_text": (
                "A successful interactive logon was observed from an "
                "external IP, followed shortly by encoded PowerShell "
                "execution on the host."
            ),
        },
        expected_queries=frozenset({"logon_outcomes_for_ip", "encoded_powershell_on_host"}),
    ),
    Scenario(
        name="repeat_offender_source_ip",
        alert={
            "src_ip": "45.61.53.40",
            "host": "vm-honeypot-win",
            "user": "Administrator",
            "event_time": "2026-07-11T22:10:00",
            "alert_text": (
                "This source IP has triggered logon-failure alerts on this "
                "host multiple times over the past several days."
            ),
        },
        expected_queries=frozenset({"logon_outcomes_for_ip", "repeat_offender"}),
    ),
]


@dataclass(frozen=True)
class ScenarioScore:
    name: str
    passes: int
    total: int

    @property
    def pass_rate(self) -> float:
        return self.passes / self.total if self.total else 0.0


@dataclass(frozen=True)
class EvalReport:
    scenario_scores: tuple[ScenarioScore, ...]
    threshold: float

    @property
    def total_passes(self) -> int:
        return sum(s.passes for s in self.scenario_scores)

    @property
    def total_runs(self) -> int:
        return sum(s.total for s in self.scenario_scores)

    @property
    def overall_pass_rate(self) -> float:
        return self.total_passes / self.total_runs if self.total_runs else 0.0

    @property
    def passed(self) -> bool:
        return self.overall_pass_rate >= self.threshold


def _run_passes(scenario: Scenario, result) -> bool:
    """Score one `agent.investigate(...)` result against a scenario.

    Query selection is scored off `scope_evidence.queries_run` -- only
    outcome=="ok" catalog calls land there (see agent.py) -- not the raw
    transcript, so a param-rejected or errored attempt never counts as
    "ran the right query". Conclusion is scored as: the model actually
    called conclude_investigation (non-empty advisory_reasoning) AND the
    loop was not cut off by the MAX_TURNS hard stop.
    """
    ran = {q["query"] for q in result.scope_evidence.queries_run}
    queries_ok = scenario.expected_queries.issubset(ran)

    concluded = bool(result.advisory_reasoning) and "max_turns_reached" not in result.flags
    conclusion_ok = concluded if scenario.expected_conclusion else not concluded

    return queries_ok and conclusion_ok


def run_eval(client, splunk_service, cfg: Config, *, scenarios: list[Scenario] | None = None,
             repetitions: int = DEFAULT_REPETITIONS, threshold: float = DEFAULT_THRESHOLD) -> EvalReport:
    """Testable core: given an ALREADY-BUILT client + splunk_service, run
    every scenario `repetitions` times through the real `agent.investigate`
    loop and score each run. Pure DI -- like run_investigation.py's
    run_investigation -- this function never constructs a client or
    service; that is main()'s job. Whether this makes real paid calls
    depends entirely on what `client` and `splunk_service` the caller
    passed in.
    """
    scenarios = SCENARIOS if scenarios is None else scenarios
    scores: list[ScenarioScore] = []
    for scenario in scenarios:
        passes = 0
        for _ in range(repetitions):
            result = agent.investigate(scenario.alert, client=client, splunk_service=splunk_service, cfg=cfg)
            if _run_passes(scenario, result):
                passes += 1
        scores.append(ScenarioScore(name=scenario.name, passes=passes, total=repetitions))
    return EvalReport(scenario_scores=tuple(scores), threshold=threshold)


def format_report(report: EvalReport) -> str:
    lines = ["Query-selection eval results (opt-in, paid, real model -- see EVAL.md):", ""]
    for s in report.scenario_scores:
        lines.append(f"  {s.name}: {s.passes}/{s.total} ({s.pass_rate:.0%})")
    lines.append("")
    verdict = "PASS" if report.passed else "FAIL"
    lines.append(
        f"Overall: {report.total_passes}/{report.total_runs} ({report.overall_pass_rate:.0%}) "
        f"vs threshold {report.threshold:.0%} -- {verdict}"
    )
    return "\n".join(lines)


def main(argv=None, *, client_factory=None, service_factory=None) -> int:
    """Injected path (client_factory + service_factory both given): fully
    offline, no network, no paid call -- the ONLY path pytest ever
    exercises. Live path (both None): builds a real anthropic.Anthropic
    client (reads ANTHROPIC_API_KEY) and a real splunklib Service
    connection from env, and DOES make paid calls against a real model and
    a real Splunk instance. Never exercised by tests. Read EVAL.md before
    running this for real."""
    ap = argparse.ArgumentParser(
        description="Opt-in, PAID real-model query-selection eval for the Phase 4 investigation agent"
    )
    ap.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS,
                     help="investigate() runs per scenario (default: %(default)s)")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                     help="required overall pass rate, 0..1 (default: %(default)s)")
    args = ap.parse_args(argv)

    cfg = load_config()

    if client_factory is not None and service_factory is not None:
        client = client_factory()
        splunk_service = service_factory()
    else:  # pragma: no cover - live wiring (paid, never exercised by pytest)
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

    report = run_eval(client, splunk_service, cfg, repetitions=args.repetitions, threshold=args.threshold)
    print(format_report(report))
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
