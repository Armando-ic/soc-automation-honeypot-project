# grounding-service/tests/test_rerank.py
from grounding_service.rerank import select_with_tactic_diversity


def _c(id, tactic, score):
    return {"id": id, "name": id, "tactics": [tactic], "score": score}


def test_starved_tactic_is_promoted_into_top_k():
    # Top-8 by score are all "execution"; the only "credential-access"
    # techniques sit at ranks 9-10 (starved). Rerank must surface one.
    candidates = [_c(f"E{i}", "execution", 100 - i) for i in range(8)]
    candidates += [_c("T1110", "credential-access", 20), _c("T1003", "credential-access", 10)]
    out = select_with_tactic_diversity(candidates, top_k=8)
    ids = [h["id"] for h in out]
    assert len(out) == 8
    assert any(h["tactics"] == ["credential-access"] for h in out)
    assert "T1110" in ids           # the higher-scoring representative wins
    assert "E0" in ids              # the top hit (score 100) is never demoted


def test_promotes_parent_over_higher_scoring_subtechnique():
    # GATE-2 CRITICAL: a sub-technique (T1110.001) outscores its parent (T1110)
    # in the pool, but the A3 predicate needs the PARENT id. The rerank must
    # promote the parent, not the higher-scoring sub.
    candidates = [_c(f"E{i}", "execution", 100 - i) for i in range(8)]
    candidates += [_c("T1110.001", "credential-access", 25), _c("T1110", "credential-access", 20)]
    out = select_with_tactic_diversity(candidates, top_k=8)
    ids = [h["id"] for h in out]
    assert "T1110" in ids            # the dot-less parent is what the predicate checks
    assert "T1110.001" not in ids    # the higher-scoring sub must NOT win the slot


def test_no_change_when_all_tactics_already_covered():
    # Base top_k already spans every tactic in the pool -> return plain top_k.
    candidates = [
        _c("A", "execution", 50), _c("B", "credential-access", 40),
        _c("C", "impact", 30), _c("D", "execution", 20), _c("E", "impact", 10),
    ]
    out = select_with_tactic_diversity(candidates, top_k=3)
    assert [h["id"] for h in out] == ["A", "B", "C"]


def test_returns_top_k_sorted_by_score_and_preserves_top_hit():
    candidates = [_c(f"X{i}", "execution", 100 - i) for i in range(6)]
    candidates += [_c("CRED", "credential-access", 5)]
    out = select_with_tactic_diversity(candidates, top_k=4)
    assert len(out) == 4
    assert out[0]["id"] == "X0"                       # top hit retained
    assert [h["score"] for h in out] == sorted((h["score"] for h in out), reverse=True)
    assert "CRED" in [h["id"] for h in out]           # starved tactic promoted


def test_never_evicts_the_top_hit_even_when_it_is_the_only_redundant():
    # GATE-2: the rank-2 item is a multi-tactic superset of the rank-1 top hit,
    # so the top hit is the only "redundant" base item. It must NOT be evicted.
    base = [{"id": "A", "name": "A", "tactics": ["x"], "score": 100},
            {"id": "C", "name": "C", "tactics": ["x", "y"], "score": 90}]
    rest = [{"id": "D", "name": "D", "tactics": ["z"], "score": 10}]
    out = select_with_tactic_diversity(base + rest, top_k=2)
    ids = [h["id"] for h in out]
    assert "A" in ids                # index-0 top hit survives
    assert len(out) == 2


def test_small_pool_returned_unchanged():
    candidates = [_c("A", "execution", 50), _c("B", "impact", 40)]
    out = select_with_tactic_diversity(candidates, top_k=8)
    assert [h["id"] for h in out] == ["A", "B"]


def test_never_evicts_a_uniquely_covered_tactic():
    # Base = one execution + one impact; pool has a credential-access at rank 3.
    # There is no redundant base item to evict, so nothing is promoted.
    candidates = [_c("A", "execution", 50), _c("B", "impact", 40), _c("C", "credential-access", 5)]
    out = select_with_tactic_diversity(candidates, top_k=2)
    assert [h["id"] for h in out] == ["A", "B"]
