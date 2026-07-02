import inspect

import pytest

from red_team.harness.retriever import retrieve, assert_pinned_subset


def test_retrieve_default_top_k_is_8():
    assert inspect.signature(retrieve).parameters["top_k"].default == 8


def test_retrieve_returns_techniques_and_ids(seeded_retriever):
    techniques, ids = retrieve(seeded_retriever, "powershell", top_k=3)  # query == a technique name in the fixture
    assert isinstance(ids, list) and all(isinstance(i, str) for i in ids)
    assert [t["id"] for t in techniques] == ids


def test_pinned_subset_guard_rejects_drift():
    with pytest.raises(AssertionError):
        assert_pinned_subset(["T9999"], ["T1110", "T1059"])
