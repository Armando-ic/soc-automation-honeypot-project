"""Persist a gate-judged rule: the Sigma YAML, the compiled SPL, and a per-rule
gate report. Written for any rule (pass or fail) so the catalog is honest."""
from __future__ import annotations

from pathlib import Path

from detection_authoring.gate import GateResult


def _gate_md(technique_id: str, gr: GateResult) -> str:
    verdict = "PASS" if gr.passed else "FAIL"
    rows = [
        ("T1 valid Sigma", gr.t1_parse_ok),
        ("subset guard", gr.subset_ok),
        ("T2 compiles to SPL", gr.t2_compile_ok),
        ("T3 fires on positive", gr.t3_tp_ok),
        ("T4 quiet on benign", gr.t4_tn_ok),
    ]
    lines = [f"# Gate report {technique_id}: {verdict}", ""]
    for name, ok in rows:
        lines.append(f"- {'PASS' if ok else 'FAIL'} - {name}")
    if gr.unsupported:
        lines += ["", "Unsupported features:"] + [f"- {u}" for u in gr.unsupported]
    if gr.benign_false_positives:
        lines += ["", f"False positives on benign baseline: {len(gr.benign_false_positives)}"]
    return "\n".join(lines) + "\n"


def write_artifact(technique_id: str, yaml_text: str, gate_result: GateResult, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{technique_id}.yml").write_text(yaml_text, encoding="utf-8")
    (out_dir / f"{technique_id}.spl").write_text(gate_result.spl or "", encoding="utf-8")
    (out_dir / f"{technique_id}.gate.md").write_text(_gate_md(technique_id, gate_result), encoding="utf-8")
    return out_dir
