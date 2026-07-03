"""Red-team baseline campaign runner (Task 15, offline-buildable half).

Thin CLI glue: load the seed attack corpus, resolve a per-case trial count K
(uniform baseline K, with optional per-class "headline" overrides), replay
every case through the SAME frozen harness `test_runner.py` already covers
(`run_case`), and render the aggregate markdown report via
`build_baseline_report`.

This module deliberately contains no scoring/harness logic of its own --
`run_case`, `ModelClient`, `build_local_retriever`, `TriageVerifier`, and
`build_baseline_report` are frozen, reviewed modules. `run_campaign` takes
every live dependency as a parameter so it is fully testable with a mocked
Anthropic client and the in-memory `seeded_retriever` fixture -- no network,
no API key, and no Qdrant are required to exercise this module's logic.

`main()` is the only place that constructs anything live (the real Anthropic
client, the local Qdrant-backed retriever, the verifier) -- and it does so
only on the non-`--dry-run` path.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from red_team.cases import AttackCase, load_cases
from red_team.harness.model_client import ModelClient
from red_team.harness.retriever import build_local_retriever
from red_team.harness.system_prompt import load_system_prompt, load_tool_def
from red_team.report import build_baseline_report
from red_team.runner import CaseResult, run_case
from triage_verifier.verifier import TriageVerifier

_ROOT = Path(__file__).resolve().parent.parent  # red-team/
DEFAULT_ATTACKS_DIR = _ROOT / "attacks"
DEFAULT_REPORTS_DIR = _ROOT / "reports"


def _class_code(case: AttackCase) -> str:
    """Mirror report._class_code: the A1..E1 taxonomy prefix of case.id."""
    return case.id.split("-")[0]


def resolve_k(case: AttackCase, k_default: int, headline: dict[str, int]) -> int:
    """The K for one case: the headline override for its class code if
    present, else the campaign default."""
    return headline.get(_class_code(case), k_default)


def parse_headline(spec: str | None) -> dict[str, int]:
    """Parse a `"A2:50,B1:30"`-shaped spec into `{"A2": 50, "B1": 30}`.

    Empty string or None -> `{}`. A malformed token (missing ':', non-int K,
    empty class code) raises ValueError -- a clean, early CLI error rather
    than a silent misconfiguration or a crash deep in the campaign."""
    if not spec:
        return {}
    headline: dict[str, int] = {}
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" not in token:
            raise ValueError(f"malformed --headline token (expected CLASS:K): {token!r}")
        class_code, _, k_str = token.partition(":")
        class_code = class_code.strip()
        if not class_code:
            raise ValueError(f"malformed --headline token (empty class code): {token!r}")
        try:
            k = int(k_str.strip())
        except ValueError:
            raise ValueError(f"malformed --headline token (K must be an int): {token!r}") from None
        headline[class_code] = k
    return headline


def _print_case_progress(progress: Callable[[str], None], result: CaseResult) -> None:
    """The one progress line for a finished case's `CaseResult`. Shared by the
    sequential and concurrent paths so both print an identical format."""
    valid = [t for t in result.trials if not t.score.invalid]
    deviated = sum(1 for t in valid if t.score.deviated)
    bypassed = sum(1 for t in valid if t.score.bypassed)
    invalid = len(result.trials) - len(valid)
    progress(
        f"{result.case.id}: k={result.k} deviated={deviated}/{len(valid)} "
        f"bypassed={bypassed}/{len(valid)} invalid={invalid}"
    )


def _run_campaign_sequential(
    cases: list[AttackCase],
    model_client: ModelClient,
    retriever,
    verifier,
    *,
    k_default: int,
    headline: dict[str, int],
    progress: Callable[[str], None],
) -> list[CaseResult]:
    """Today's exact behavior: one case at a time, in order."""
    results: list[CaseResult] = []
    for case in cases:
        k = resolve_k(case, k_default, headline)
        result = run_case(case, model_client, retriever, verifier, k=k)
        _print_case_progress(progress, result)
        results.append(result)
    return results


def _run_campaign_concurrent(
    cases: list[AttackCase],
    model_client: ModelClient,
    retriever,
    verifier,
    *,
    k_default: int,
    headline: dict[str, int],
    concurrency: int,
    progress: Callable[[str], None],
) -> list[CaseResult]:
    """Trial-level thread pool: submit every (case, trial) unit as an
    independent `run_case(..., k=1)` call and merge single-trial results back
    into one `CaseResult` per case, in the original `cases` order.

    Thread-safety: `model_client` wraps the thread-safe `anthropic` client,
    `retriever.search` is a stateless per-call Qdrant query, and
    `verifier.verify` is pure -- all three are read-only shared state across
    threads, and `run_case` builds all of its per-trial state internally. The
    only mutation of shared accumulators (`trials_by_id`) happens here, in the
    main thread, while draining `as_completed` -- worker threads never touch
    them -- so no lock is required.

    Live progress: without this, a long headline run (~455 trials, ~45min)
    would print nothing until the whole pool drained. Two kinds of feedback
    stream out during the drain instead of only at the end: (1) each case's
    per-case summary line, printed the moment that case's k trials have all
    landed, and (2) a throttled overall "[done/total] trials complete" tick
    (~20 ticks across the run, plus a guaranteed final one at done == total).
    """
    plan = [(case, resolve_k(case, k_default, headline)) for case in cases]
    trials_by_id: dict[int, list] = {id(case): [] for case, _ in plan}
    k_by_id: dict[int, int] = {id(case): k for case, k in plan}
    total = sum(k for _, k in plan)
    tick_every = max(1, total // 20)
    done = 0
    printed: set[int] = set()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_case_id = {}
        for case, k in plan:
            for _ in range(k):
                future = executor.submit(run_case, case, model_client, retriever, verifier, 1)
                future_to_case_id[future] = id(case)

        for future in as_completed(future_to_case_id):
            case_id = future_to_case_id[future]
            single = future.result()  # let exceptions propagate: matches sequential behavior
            trials_by_id[case_id].extend(single.trials)
            done += 1

            if len(trials_by_id[case_id]) == k_by_id[case_id]:
                case = next(c for c, _ in plan if id(c) == case_id)
                result = CaseResult(case=case, trials=trials_by_id[case_id], k=k_by_id[case_id])
                _print_case_progress(progress, result)
                printed.add(case_id)

            if done == total or done % tick_every == 0:
                progress(f"[{done}/{total}] trials complete")

    results: list[CaseResult] = []
    for case, k in plan:
        result = CaseResult(case=case, trials=trials_by_id[id(case)], k=k)
        if id(case) not in printed:
            _print_case_progress(progress, result)
        results.append(result)
    return results


def run_campaign(
    cases: list[AttackCase],
    model_client: ModelClient,
    retriever,
    verifier,
    *,
    k_default: int,
    headline: dict[str, int],
    concurrency: int = 1,
    progress: Callable[[str], None] = print,
) -> list[CaseResult]:
    """Run every case at its resolved K, printing one progress line per case.

    All live dependencies (`model_client`, `retriever`, `verifier`) are
    parameters -- this function constructs nothing live, which is what makes
    it testable offline with a mocked client and the in-memory
    `seeded_retriever` fixture.

    `concurrency <= 1` (the default) preserves the original sequential
    behavior exactly: one case at a time, `run_case(..., k=k)` called once per
    case, same result and progress-line order. `concurrency > 1` switches to a
    trial-level thread pool (see `_run_campaign_concurrent`) -- per-case trial
    COUNT and resolved K are unaffected; only intra-case trial order and
    wall-clock time change."""
    if concurrency <= 1:
        return _run_campaign_sequential(
            cases, model_client, retriever, verifier,
            k_default=k_default, headline=headline, progress=progress,
        )
    return _run_campaign_concurrent(
        cases, model_client, retriever, verifier,
        k_default=k_default, headline=headline, concurrency=concurrency, progress=progress,
    )


def _harness_git_commit() -> str:
    """Best-effort short git commit for the default --out filename. Mirrors
    report._harness_git_commit -- never raises, falls back to 'unknown'."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        commit = out.stdout.strip()
        return commit if commit else "unknown"
    except Exception:
        return "unknown"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the red-team baseline campaign against the deployed honeypot-triage node."
    )
    parser.add_argument("--k", type=int, default=5, help="Default trials per case (baseline K).")
    parser.add_argument(
        "--headline",
        type=str,
        default=None,
        help='Comma-separated per-class K overrides, e.g. "A2:50,B1:50".',
    )
    parser.add_argument(
        "--attacks",
        type=Path,
        default=DEFAULT_ATTACKS_DIR,
        help="Seed attack corpus directory (non-recursive; held_out/ is never swept).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Report output path (default: red-team/reports/baseline-<short-commit>.md).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the campaign plan and total live-call count, then exit. No client, no calls.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Trials to run in parallel via a thread pool (default 1 = today's sequential behavior).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    headline = parse_headline(args.headline)
    cases = load_cases(args.attacks)

    if args.dry_run:
        total_calls = 0
        for case in cases:
            k = resolve_k(case, args.k, headline)
            total_calls += k
            print(f"{case.id}: k={k}")
        print(f"Total live calls: {total_calls}")
        return

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set -- export it before running a live campaign.", file=sys.stderr)
        sys.exit(1)

    import anthropic

    client = anthropic.Anthropic(max_retries=8)
    model_client = ModelClient(client, system=load_system_prompt(), tool=load_tool_def())
    retriever = build_local_retriever()
    verifier = TriageVerifier.from_paths(
        _ROOT.parent / "triage-verifier/schema/submit_triage_result.json",
        _ROOT.parent / "triage-verifier/data/attack_reference.json",
    )

    results = run_campaign(cases, model_client, retriever, verifier, k_default=args.k, headline=headline,
                            concurrency=args.concurrency)
    report_md = build_baseline_report(results)

    out_path = args.out or (DEFAULT_REPORTS_DIR / f"baseline-{_harness_git_commit()}.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report_md, encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
