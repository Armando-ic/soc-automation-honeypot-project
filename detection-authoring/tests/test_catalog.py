from detection_authoring.catalog import write_artifact
from detection_authoring.gate import GateResult


def test_write_artifact_creates_three_files(tmp_path):
    gr = GateResult(t1_parse_ok=True, subset_ok=True, t2_compile_ok=True,
                    spl='Image="*\\\\powershell.exe"', t3_tp_ok=True, t4_tn_ok=True, passed=True)
    write_artifact("T1059.001", "title: x\ncondition: sel\n", gr, tmp_path)
    assert (tmp_path / "T1059.001.yml").exists()
    assert (tmp_path / "T1059.001.spl").read_text(encoding="utf-8").startswith("Image=")
    md = (tmp_path / "T1059.001.gate.md").read_text(encoding="utf-8")
    assert "PASS" in md
