from pathlib import Path

from detection_authoring.context import build_grounding_pack

GROUNDING = Path(__file__).resolve().parent.parent / "corpus" / "grounding"


def test_grounding_pack_from_committed_pack(seeded_retriever):
    pack = build_grounding_pack("T1059.001", seeded_retriever, grounding_dir=GROUNDING)
    assert pack.technique_id == "T1059.001"
    assert "PowerShell" in pack.name
    assert pack.tactics == ["execution"]
    assert "EncodedCommand" in pack.description
    assert "Image" in pack.allowed_fields


def test_grounding_pack_has_neighbors(seeded_retriever):
    pack = build_grounding_pack("T1059.001", seeded_retriever, grounding_dir=GROUNDING)
    assert isinstance(pack.neighbors, list)
