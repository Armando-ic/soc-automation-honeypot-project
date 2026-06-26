"""Advisory same-model judge. Always NEEDS_HUMAN — never auto-approves."""
from __future__ import annotations

from typing import Protocol

from triage_verifier.attack_reference import AttackReference
from triage_verifier.constants import MODEL
from triage_verifier.models import CheckResult, CheckStatus


class Judge(Protocol):
    def assess(self, result: dict, attack_ref: AttackReference) -> CheckResult: ...


class StubJudge:
    """Deterministic judge for eval/tests: flags for human review, no model call."""

    def assess(self, result: dict, attack_ref: AttackReference) -> CheckResult:
        return CheckResult("judge", CheckStatus.NEEDS_HUMAN, "advisory: human review required")


class ClaudeJudge:
    """Same-model advisory judge. Correlated-failure risk; never blocks or approves."""

    def __init__(self, client, model: str = MODEL) -> None:
        self._client = client
        self._model = model

    def assess(self, result: dict, attack_ref: AttackReference) -> CheckResult:
        techniques = ", ".join(t.get("id", "") for t in result.get("mitre_techniques", []))
        prompt = (
            "You are an advisory reviewer of a SOC triage result. Comment on whether the "
            f"severity and cited techniques ({techniques}) are consistent with the evidence. "
            "Do NOT approve; a human always reviews.\n\n" + str(result)
        )
        msg = self._client.messages.create(
            model=self._model, max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        notes = msg.content[0].text if msg.content else ""
        return CheckResult("judge", CheckStatus.NEEDS_HUMAN, notes)
