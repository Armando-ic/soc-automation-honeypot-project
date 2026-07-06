"""DI CLI: RAG-ground -> draft with Claude -> 4-tier gate -> report.

The live wiring (real BgeEmbedder + Qdrant + Anthropic) is built only in main();
run()/author_once() take injected collaborators so the whole loop is testable
offline.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from detection_authoring.catalog import write_artifact
from detection_authoring.config import load_config
from detection_authoring.context import build_grounding_pack
from detection_authoring.drafter import draft_rule
from detection_authoring.gate import GateResult, run_gate
from detection_authoring.report import AuthoringRun, build_authoring_report


def _first_fail_tier(gr: GateResult) -> str | None:
    if not gr.t1_parse_ok:
        return "t1_parse"
    if not gr.subset_ok:
        return "subset"
    if not gr.t2_compile_ok:
        return "t2_compile"
    if not gr.t3_tp_ok:
        return "t3_tp"
    if not gr.t4_tn_ok:
        return "t4_tn"
    return None


def author_once(pack, client, technique_id: str):
    draft = draft_rule(pack, client)
    if draft.outcome != "ok":
        return AuthoringRun(technique_id, False, None, draft.outcome), None, None
    gr = run_gate(draft.yaml_text, technique_id)
    return AuthoringRun(technique_id, gr.passed, _first_fail_tier(gr), "ok"), draft.yaml_text, gr


def run(technique_id: str, k: int, retriever, client, grounding_dir: Path | None = None) -> list[AuthoringRun]:
    pack = build_grounding_pack(technique_id, retriever, grounding_dir=grounding_dir)
    runs: list[AuthoringRun] = []
    for i in range(k):
        rec, yaml_text, gr = author_once(pack, client, technique_id)
        runs.append(rec)
        print(f"[{technique_id}] trial {i + 1}/{k}: passed={rec.passed} outcome={rec.outcome}")
        if gr is not None and gr.passed:
            write_artifact(technique_id, yaml_text, gr, load_config().rules_dir)
    return runs


def main() -> None:  # pragma: no cover - live wiring
    import anthropic
    from grounding_service.embedder import BgeEmbedder
    from grounding_service.retriever import AttackRetriever
    from qdrant_client import QdrantClient

    ap = argparse.ArgumentParser()
    ap.add_argument("--technique", action="append", required=True)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--out", type=Path, default=load_config().reports_dir / "authoring-report.md")
    args = ap.parse_args()

    cfg = load_config()
    client_qd = QdrantClient(url=cfg.qdrant_url)
    if not client_qd.collection_exists(cfg.collection):
        raise SystemExit(f"Qdrant collection '{cfg.collection}' not found at {cfg.qdrant_url}. Seed it first.")
    retriever = AttackRetriever(client_qd, BgeEmbedder(cfg.embed_model), cfg.collection)
    anthropic_client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    all_runs: list[AuthoringRun] = []
    for tid in args.technique:
        all_runs.extend(run(tid, args.k, retriever, anthropic_client))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_authoring_report(all_runs), encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":  # pragma: no cover
    main()
