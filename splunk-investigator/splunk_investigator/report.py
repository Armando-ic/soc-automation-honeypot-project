# splunk_investigator/report.py
"""Evidence artifact renderer (Phase 4 Task 8).

Renders an `InvestigationResult` into a markdown report with two
unambiguously separated sections:

    1. Grounded scope claims -- derived by claims.py straight from Splunk
       query results (verifier-checked). Trustworthy.
    2. Model narrative -- the model's own free-text summary
       (`advisory_reasoning`) plus the tool-call transcript. This is NOT
       gated by the verifier and may overstate what actually happened --
       it is context for a human reader, never evidence.

Load-bearing honesty rule (breadth-not-targeting -- this whole phase exists
to not let the artifact overstate scope): a `distinct_targets` or
`repeat_offender` claim only ever proves BREADTH of a brute-force attempt
(N accounts tried, activity spread over N days) -- it says nothing about
whether any of it worked. Only an `auth_outcome` claim with
`success_count > 0` ANYWHERE in the same bundle unlocks "targeting"/success
wording for the others. Absent that, this module always renders
"brute-force breadth", never "targeting" -- a failed brute-force must never
read as a successful campaign.

Second-order safety: `advisory_reasoning` and the transcript are
model/attacker-influenced free text (transcript rows are echoed straight
from Splunk via agent.py's `_summarize`, unsanitized -- claims.py's
sanitization only covers CLAIM fields, not this narrative surface). Both
are rendered inside dynamically-sized fenced code blocks, sized strictly
longer than any backtick run already present in the text, so embedded
markdown (a fake "## Grounded scope claims" header, or an attempt to close
the fence early and inject fake structure after it) can never escape into
real document structure -- it stays literal text under the advisory header.
"""
from __future__ import annotations

from .models import InvestigationResult, ScopeClaim

GROUNDED_HEADER = "## Grounded scope claims (verifier-checked, trustworthy)"
ADVISORY_HEADER = "## Model narrative - not gated, may overstate (advisory only)"


def _fmt(value) -> str:
    return "unknown" if value is None else str(value)


def _has_confirmed_success(claims: tuple[ScopeClaim, ...]) -> bool:
    return any(
        c.type == "auth_outcome" and c.fields.get("success_count", 0) > 0
        for c in claims
    )


def _render_auth_outcome(f: dict, has_success: bool) -> str:
    success = f.get("success_count", 0)
    outcome = "successful login(s) observed" if success > 0 else "no successful logins (brute-force only)"
    return (
        f"- **auth_outcome** ip={_fmt(f.get('ip'))} user={_fmt(f.get('user'))} "
        f"success_count={_fmt(success)} fail_count={_fmt(f.get('fail_count'))} -- {outcome}"
    )


def _render_process_exec(f: dict, has_success: bool) -> str:
    return (
        f"- **process_exec_by_user_in_window** host={_fmt(f.get('host'))} user={_fmt(f.get('user'))} "
        f"image={_fmt(f.get('image'))} count={_fmt(f.get('count'))}"
    )


def _render_distinct_targets(f: dict, has_success: bool) -> str:
    n = f.get("distinct_user_count", 0)
    if has_success:
        label = f"targeting: {n} distinct account(s) attempted (confirmed successful login in this bundle)"
    else:
        label = f"brute-force breadth: {n} distinct account(s) attempted"
    return f"- **distinct_targets** ip={_fmt(f.get('ip'))} distinct_user_count={_fmt(n)} -- {label}"


def _render_repeat_offender(f: dict, has_success: bool) -> str:
    days = f.get("days_active", 0)
    floor_note = " (lookback-floored, true start may be earlier)" if f.get("floored") else ""
    if has_success:
        label = f"sustained targeting: activity spread over {days} day(s) (confirmed successful login in this bundle)"
    else:
        label = f"brute-force breadth: activity spread over {days} day(s), no confirmed success"
    return (
        f"- **repeat_offender** ip={_fmt(f.get('ip'))} first_seen={_fmt(f.get('first_seen'))} "
        f"last_seen={_fmt(f.get('last_seen'))} days_active={_fmt(days)} -- {label}{floor_note}"
    )


def _render_encoded_powershell(f: dict, has_success: bool) -> str:
    return f"- **encoded_powershell** host={_fmt(f.get('host'))} count={_fmt(f.get('count'))}"


def _render_generic_claim(f: dict, has_success: bool) -> str:
    # Defensive fallback only -- not expected for the v1 claim set (claims.py
    # only ever emits the five types dispatched below).
    return f"- **unrecognized claim** fields={f}"


_CLAIM_RENDERERS = {
    "auth_outcome": _render_auth_outcome,
    "process_exec_by_user_in_window": _render_process_exec,
    "distinct_targets": _render_distinct_targets,
    "repeat_offender": _render_repeat_offender,
    "encoded_powershell": _render_encoded_powershell,
}


def _render_grounded_section(r: InvestigationResult) -> list[str]:
    claims = r.scope_evidence.claims
    lines: list[str] = [
        "_Derived directly from Splunk query results by the claims verifier. Trustworthy._",
        "",
    ]
    if not claims:
        lines.append("_No grounded scope claims were returned by this investigation._")
    else:
        has_success = _has_confirmed_success(claims)
        for claim in claims:
            renderer = _CLAIM_RENDERERS.get(claim.type, _render_generic_claim)
            lines.append(renderer(claim.fields, has_success))
    if r.flags:
        lines.append("")
        lines.append(f"**Flags:** {', '.join(r.flags)}")
    return lines


def _fence(text: str) -> str:
    """A fenced code block sized strictly longer than the longest run of
    backticks already inside `text` -- an attacker-influenced string can
    never smuggle its own closing fence (and whatever comes after it)
    out into real document structure."""
    max_run = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    fence = "`" * max(3, max_run + 1)
    return f"{fence}\n{text}\n{fence}"


def _render_transcript(transcript: tuple[dict, ...]) -> str:
    if not transcript:
        return "(no tool-call transcript recorded)"
    lines = []
    for entry in transcript:
        lines.append(
            f"turn={entry.get('turn')} tool={entry.get('tool')} "
            f"params={entry.get('params')} result={entry.get('result')}"
        )
    return "\n".join(lines)


def _render_advisory_section(r: InvestigationResult) -> list[str]:
    return [
        "_Free text produced by the model. NOT verified against Splunk -- may "
        "overstate scope, or simply repeat something an attacker's own logged "
        "input said. Treat as a hypothesis, never as evidence._",
        "",
        "**Advisory summary:**",
        "",
        _fence(r.advisory_reasoning or "(no summary provided)"),
        "",
        "**Tool-call transcript:**",
        "",
        _fence(_render_transcript(r.transcript)),
    ]


def render_report(r: InvestigationResult) -> str:
    """InvestigationResult -> a markdown artifact with two unambiguously
    separated sections: grounded scope claims (trustworthy) and model
    narrative (advisory only, not gated, may overstate). See module
    docstring for the breadth-not-targeting and anti-injection fencing
    rules this enforces."""
    lines: list[str] = ["# Honeypot investigation report", ""]
    lines.append(GROUNDED_HEADER)
    lines.append("")
    lines.extend(_render_grounded_section(r))
    lines.append("")
    lines.append(ADVISORY_HEADER)
    lines.append("")
    lines.extend(_render_advisory_section(r))
    return "\n".join(lines) + "\n"
