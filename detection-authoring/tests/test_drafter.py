from detection_authoring.context import GroundingPack
from detection_authoring.drafter import build_system_prompt, draft_rule

PACK = GroundingPack("T1059.001", "PowerShell", ["execution"], "encoded PS", ["Image", "CommandLine"], [])


class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [_Block(text)]
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, resp):
        self._resp = resp

    def create(self, **kwargs):
        return self._resp


class _FakeClient:
    def __init__(self, resp):
        self.messages = _FakeMessages(resp)


def test_system_prompt_lists_allowed_fields_and_subset():
    sp = build_system_prompt(PACK)
    assert "process_creation" in sp
    assert "CommandLine" in sp
    assert "contains" in sp


def test_draft_extracts_fenced_yaml():
    fenced = "Here is the rule:\n```yaml\ntitle: x\ndetection: {sel: {Image: a}, condition: sel}\n```\nDone."
    r = draft_rule(PACK, _FakeClient(_Resp(fenced)))
    assert r.outcome == "ok"
    assert r.yaml_text.strip().startswith("title: x")


def test_draft_no_yaml_is_no_rule():
    r = draft_rule(PACK, _FakeClient(_Resp("I cannot help with that.")))
    assert r.outcome == "no_rule"
    assert r.yaml_text is None


def test_draft_refusal_stop_reason():
    r = draft_rule(PACK, _FakeClient(_Resp("", stop_reason="refusal")))
    assert r.outcome == "refusal"
