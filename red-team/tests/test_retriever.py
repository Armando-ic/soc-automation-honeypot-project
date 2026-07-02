import inspect

import pytest

from red_team.harness.retriever import retrieve, assert_pinned_subset


def test_retrieve_default_top_k_is_8():
    assert inspect.signature(retrieve).parameters["top_k"].default == 8


def test_retrieve_returns_techniques_and_ids(seeded_retriever):
    # The fixture is engineered for a deterministic result: each doc's text is
    # its lowercased name, so FakeEmbedder gives an exact cosine match for the
    # query 'powershell' -> the PowerShell technique (T1059.001) ranks first.
    # (Asserting the observable behavior, not the parallel-list tautology.)
    techniques, ids = retrieve(seeded_retriever, "powershell", top_k=3)
    assert ids[0] == "T1059.001"                 # exact-match technique ranks first
    assert techniques[0]["name"] == "PowerShell"  # the top dict carries the name
    assert len(ids) == 3                          # top_k honored (fixture has 3 live techniques)
    # Secondary sanity checks: ids is a parallel str list of the technique dicts.
    assert isinstance(ids, list) and all(isinstance(i, str) for i in ids)
    assert [t["id"] for t in techniques] == ids


def test_pinned_subset_guard_rejects_drift():
    with pytest.raises(AssertionError):
        assert_pinned_subset(["T9999"], ["T1110", "T1059"])
