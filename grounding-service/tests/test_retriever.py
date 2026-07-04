def test_search_returns_ranked_payloads(seeded_retriever):
    hits = seeded_retriever.search("brute force", top_k=3)
    assert hits[0]["id"] == "T1110"
    assert hits[0]["name"] == "Brute Force"
    assert hits[0]["tactics"] == ["credential-access"]
    assert hits[0]["score"] >= hits[-1]["score"]


def test_retrieved_ids_is_id_list(seeded_retriever):
    ids = seeded_retriever.retrieved_ids("powershell", top_k=3)
    assert ids[0] == "T1059.001"
    assert all(isinstance(i, str) for i in ids)


def test_search_still_returns_top_k_length(seeded_retriever):
    hits = seeded_retriever.search("brute force", top_k=3)
    assert len(hits) == 3
    assert hits[0]["id"] == "T1110"              # top hit preserved through rerank
    assert hits[0]["score"] >= hits[-1]["score"]


def test_search_overfetches_more_than_top_k(monkeypatch, seeded_retriever):
    # Assert the Qdrant query is issued with an over-fetch limit > top_k so the
    # rerank has a pool to promote a starved tactic from.
    seen = {}
    real = seeded_retriever._client.query_points

    def spy(*args, **kwargs):
        seen["limit"] = kwargs.get("limit")
        return real(*args, **kwargs)

    monkeypatch.setattr(seeded_retriever._client, "query_points", spy)
    seeded_retriever.search("brute force", top_k=3)
    assert seen["limit"] is not None and seen["limit"] > 3
