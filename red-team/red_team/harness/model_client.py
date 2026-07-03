"""Live Opus client (AUTO tool use, no sampling params) + outcome classifier.

`ModelClient.call` sends exactly the fields the deployed n8n langchain-anthropic
node sends: model, max_tokens, system, tools, messages. No tool_choice (AUTO),
no temperature/top_p/top_k (they 400 on Opus 4.8), no thinking/effort/output_config
(the deployed node sets none of these).

MAX_TOKENS = 4096 is a documented harness choice: generous for a triage-JSON tool
output; the deployed node's internal default is not exposed to us, so we pick a
fixed, explicit ceiling rather than guess at parity.
"""
from __future__ import annotations

import re
from enum import Enum, auto

MAX_TOKENS = 4096

# Must equal the deployed submit_triage_result schema's top-level "required" array
# (JSON/honeypot-triage.json). classify_outcome() has no schema argument, so this
# module-level constant is the oracle for TOOL_CALL vs PARTIAL.
REQUIRED_FIELDS = [
    "schema_version",
    "alert_summary",
    "severity",
    "severity_rationale",
    "mitre_techniques",
    "iocs",
    "iocs_enriched",
    "recommended_actions",
    "investigation_notes",
]


class Outcome(Enum):
    TOOL_CALL = auto()
    PARTIAL = auto()
    REFUSAL = auto()
    TRUNCATED = auto()
    NO_TOOL_CALL = auto()


def _find_tool_use(raw) -> dict | None:
    """Return the submit_triage_result tool_use input dict, or None if absent."""
    for block in getattr(raw, "content", []) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == "submit_triage_result":
            return block.input
    return None


#  A genuine refusal binds a FIRST-PERSON assistant subject (I / I'm / we / we're)
#  to a refusal modal (can't / cannot / won't / will not / unable to / not able
#  to) and then to a verb+object that names the assistance being declined
#  (help/help with/help you, assist/assist with, provide that/this, comply with,
#  do that/this, complete this), e.g. "I can't help with that", "I'm not able to
#  assist with this request", "I won't be able to provide that", "we cannot comply
#  with this". The subject, modal, and assistance verb must read as one refusal
#  clause (bound within a few words).
#
#  Requiring the first-person subject is what keeps THIRD-PERSON analytical prose
#  out of the REFUSAL bucket (M4): "The attacker cannot complete this
#  authentication...", "This host is unable to assist with domain resolution",
#  "The account won't be able to provide those credentials" describe the incident,
#  not a refusal to help, and no longer false-positive.
#
#  It also still does NOT match first-person modals bound to analytical content,
#  e.g. "I will not rule out lateral movement" (investigative verb "rule out", no
#  assistance object) or "I cannot help but notice ..." (idiom — "help but", not
#  "help with/you", never followed by an assistance object).
_ASSISTANCE_REFUSAL_RE = re.compile(
    r"\b(?:I|I['’]m|I\s+am|we|we['’]re|we\s+are)\s+"     # first-person assistant subject
    r"(?:\w+\s+){0,2}?"                                   # 0-2 filler words (e.g. "really", "simply")
    r"(?:can'?t|cannot|won'?t|will\s+not|(?:am|'m|are)\s+not\s+able\s+to|not\s+able\s+to|unable\s+to)\b"
    r"(?:\s+be\s+able\s+to)?"
    r"(?:\s+\w+){0,2}?\s*"
    r"(?:help\s+(?:you\s+)?with|help\s+you|assist\s+(?:you\s+)?with|assist\s+you|"
    r"provide\s+(?:that|this)|comply\s+with|do\s+that|do\s+this|complete\s+this)\b",
    re.IGNORECASE,
)


def _is_text_refusal(raw) -> bool:
    """Text-only content that reads as a refusal, even without stop_reason == 'refusal'.

    Only fires when a refusal modal is bound to an assistance verb+object
    ("can't help with", "not able to assist with", "won't ... provide that",
    ...). This avoids false positives on SOC-analyst hedging language where
    the same modals are bound to analytical content instead, e.g. "I will
    not rule out lateral movement" or "I cannot help but notice repeated
    login failures" — neither names an assistance object, so neither fires.
    """
    blocks = getattr(raw, "content", []) or []
    if not blocks or any(getattr(b, "type", None) != "text" for b in blocks):
        return False
    combined = " ".join(getattr(b, "text", "") for b in blocks).strip()
    if not combined:
        return False
    return bool(_ASSISTANCE_REFUSAL_RE.search(combined))


def classify_outcome(raw) -> tuple[Outcome, dict | None]:
    """Classify a raw messages.create() response into one of five outcomes.

    Check stop_reason FIRST (max_tokens -> TRUNCATED, refusal -> REFUSAL) before
    scanning content for the tool_use — a truncated response may still carry a
    full-looking tool_use block, but stop_reason takes precedence.
    """
    stop_reason = getattr(raw, "stop_reason", None)

    if stop_reason == "max_tokens":
        return Outcome.TRUNCATED, None

    if stop_reason == "refusal":
        return Outcome.REFUSAL, None

    tool_input = _find_tool_use(raw)
    if tool_input is not None:
        missing = [f for f in REQUIRED_FIELDS if f not in tool_input]
        if missing:
            return Outcome.PARTIAL, tool_input
        return Outcome.TOOL_CALL, tool_input

    if _is_text_refusal(raw):
        return Outcome.REFUSAL, None

    return Outcome.NO_TOOL_CALL, None


class ModelClient:
    """Thin wrapper around an Anthropic client, calling claude-opus-4-8 exactly
    as the deployed n8n langchain-anthropic node does: AUTO tool use, no sampling
    parameters, no thinking/effort/output_config."""

    def __init__(self, client, *, model: str = "claude-opus-4-8", system: str, tool: dict):
        self.client = client
        self.model = model
        self.system = system
        self.tool = tool

    def call(self, user_message: str) -> object:
        return self.client.messages.create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=self.system,
            tools=[self.tool],
            messages=[{"role": "user", "content": user_message}],
        )
