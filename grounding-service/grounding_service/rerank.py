"""Tactic-diversity rerank: guarantee tactic breadth in the top_k without
demoting the top hit or dropping a uniquely-covered tactic, preferring the
parent technique id when promoting a starved tactic (Plan 2, A3)."""
from __future__ import annotations


def _tactics(hit: dict) -> set[str]:
    return set(hit.get("tactics") or [])


def _is_parent(hit: dict) -> bool:
    """A parent technique id has no dot (T1110); a sub-technique does (T1110.001).
    The A3 predicate checks exact PARENT ids, so promotion must prefer parents."""
    return "." not in (hit.get("id") or "")


def _lowest_redundant_index(base: list[dict]) -> int | None:
    """Index of the lowest-score base item (NEVER index 0, the top hit) whose
    every tactic also appears in another base item, so evicting it loses no
    tactic coverage. None if nothing is safe to evict."""
    for i in range(len(base) - 1, 0, -1):  # last..1; index 0 (top hit) is protected
        mine = _tactics(base[i])
        others: set[str] = set()
        for j, h in enumerate(base):
            if j != i:
                others |= _tactics(h)
        if mine <= others:  # fully covered by the rest
            return i
    return None


def select_with_tactic_diversity(candidates: list[dict], top_k: int, max_promotions: int = 3) -> list[dict]:
    """Keep the plain cosine top_k, then promote up to `max_promotions` starved
    tactics. For each tactic present in the over-fetch pool but absent from the
    base top_k, promote its best PARENT-preferring representative (dot-less id
    first, then score) in place of the lowest-score redundant base item. Never
    evicts the top hit (index 0) and never drops a uniquely-covered tactic.
    `candidates` must be score-descending; returns min(top_k, len)."""
    if len(candidates) <= top_k:
        return list(candidates)
    base = list(candidates[:top_k])
    rest = list(candidates[top_k:])
    covered: set[str] = set()
    for h in base:
        covered |= _tactics(h)
    # Starved tactics, ordered by their best representative's rank (rest is score-desc).
    missing: list[str] = []
    for cand in rest:
        for t in _tactics(cand):
            if t not in covered and t not in missing:
                missing.append(t)
    promoted_ids: set[str] = set()
    promotions = 0
    for t in missing:
        if promotions >= max_promotions:
            break
        if t in covered:
            continue  # already covered by an earlier promotion
        reps = [c for c in rest if t in _tactics(c) and c["id"] not in promoted_ids]
        if not reps:
            continue
        # Prefer a parent id (dot-less), then higher score.
        reps.sort(key=lambda c: (_is_parent(c), c["score"]), reverse=True)
        rep = reps[0]
        evict = _lowest_redundant_index(base)
        if evict is None:
            break  # nothing safe to evict; keep the top hit rather than force diversity
        base.pop(evict)
        base.append(rep)
        covered |= _tactics(rep)
        promoted_ids.add(rep["id"])
        promotions += 1
    base.sort(key=lambda h: h["score"], reverse=True)
    return base[:top_k]


def _parent_id(tid: str) -> str:
    """The dot-less parent id of a technique id (T1110.001 -> T1110)."""
    return tid.split(".")[0]


def collapse_to_parents(candidates: list[dict], by_id: dict[str, dict]) -> list[dict]:
    """Roll each retrieved sub-technique up to its PARENT technique (Plan 2, A3).

    A sub-technique (id contains a dot) is replaced by its parent id carrying the
    parent's real name/tactics from `by_id`, keeping the sub's score. A sub whose
    parent is absent from `by_id` is kept as-is (never fabricate a parent). Parent
    techniques pass through unchanged. Deduped by resulting id keeping the highest
    score. Returns the list sorted score-descending."""
    best: dict[str, dict] = {}
    for c in candidates:
        cid = c.get("id", "")
        if "." in cid:
            pid = _parent_id(cid)
            if pid in by_id:
                info = by_id[pid]
                item = {"id": pid, "name": info.get("name", ""),
                        "tactics": info.get("tactics", []), "score": c["score"]}
            else:
                item = dict(c)  # parent unknown -> keep the sub, do not fabricate
        else:
            item = dict(c)
        rid = item["id"]
        if rid not in best or item["score"] > best[rid]["score"]:
            best[rid] = item
    return sorted(best.values(), key=lambda h: h["score"], reverse=True)
