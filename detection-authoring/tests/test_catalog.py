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


def test_write_artifact_is_honest_about_failures(tmp_path):
    # a failing rule is still written (the catalog stays honest), the spl file
    # is empty when T2 did not compile, and the gate report surfaces FAIL plus
    # the unsupported + benign-false-positive detail
    gr = GateResult(
        t1_parse_ok=True,
        subset_ok=False,
        unsupported=["modifier 'base64' outside the subset"],
        t2_compile_ok=False,
        spl=None,
        benign_false_positives=[{"CommandLine": "cmd /c ping 8.8.8.8"}],
        passed=False,
    )
    write_artifact("T1059.003", "title: bad\n", gr, tmp_path)
    assert (tmp_path / "T1059.003.yml").exists()
    assert (tmp_path / "T1059.003.spl").read_text(encoding="utf-8") == ""
    md = (tmp_path / "T1059.003.gate.md").read_text(encoding="utf-8")
    assert "FAIL" in md
    assert "base64" in md
    assert "False positives on benign baseline: 1" in md
