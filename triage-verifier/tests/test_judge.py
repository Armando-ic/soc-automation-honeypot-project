from unittest.mock import MagicMock

from triage_verifier.attack_reference import AttackReference
from triage_verifier.judge import ClaudeJudge, StubJudge
from triage_verifier.models import CheckStatus
from tests.conftest import DATA, load_fixture


def test_stub_judge_needs_human():
    res = StubJudge().assess(load_fixture("positive", "rdp_bruteforce")["result"],
                             AttackReference.load(DATA))
    assert res.status == CheckStatus.NEEDS_HUMAN
    assert res.name == "judge"


def test_claude_judge_mocked_never_approves():
    client = MagicMock()
    client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="Looks consistent with the cited techniques.")])
    res = ClaudeJudge(client).assess(load_fixture("positive", "rdp_bruteforce")["result"],
                                     AttackReference.load(DATA))
    assert res.status == CheckStatus.NEEDS_HUMAN
    assert "consistent" in res.detail
    client.messages.create.assert_called_once()
