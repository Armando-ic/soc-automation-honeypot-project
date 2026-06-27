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
