from pathlib import Path

from scripts.run_authoring import run

GROUNDING = Path(__file__).resolve().parent.parent / "corpus" / "grounding"

GOOD_YAML = (
    "```yaml\n"
    "title: PowerShell EncodedCommand\n"
    "logsource: {product: windows, category: process_creation}\n"
    "detection:\n"
    "  selection:\n"
    "    Image|endswith: '\\powershell.exe'\n"
    "    CommandLine|re: '(?i)\\s-e(nc(odedcommand)?)?\\s'\n"
    "  condition: selection\n"
    "```\n"
)


class _Block:
    def __init__(self, text):
        self.type = "text"; self.text = text


class _Resp:
    def __init__(self, text):
        self.content = [_Block(text)]; self.stop_reason = "end_turn"


class _Msgs:
    def create(self, **kw):
        return _Resp(GOOD_YAML)


class _Client:
    messages = _Msgs()


def test_run_produces_passing_run(seeded_retriever, monkeypatch, tmp_path):
    # write_artifact in run() uses scripts.run_authoring.load_config().rules_dir;
    # redirect it to tmp_path so a passing run does not litter the repo's rules/ dir
    monkeypatch.setattr(
        "scripts.run_authoring.load_config",
        lambda: type("C", (), {"rules_dir": tmp_path})(),
    )
    runs = run("T1059.001", 2, seeded_retriever, _Client(), grounding_dir=GROUNDING)
    assert len(runs) == 2
    assert all(r.passed for r in runs)
    assert (tmp_path / "T1059.001.yml").exists()  # passing artifact written to tmp, not the repo
