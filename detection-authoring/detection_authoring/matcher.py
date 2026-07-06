"""Owned Sigma matcher for the supported subset (spec section 6).

Two layers: this file's field/selection matching, and the condition evaluator
(Task 4). Faithfulness is guarded by sigma_subset.check_supported (reject the
unmodeled) and the one-time Zircolite cross-check. Plain, contains, startswith,
endswith, and equals matching are case-insensitive; the re modifier is
case-sensitive by default and honors inline flags like (?i), matching Sigma
semantics.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

_WILDCARD_CACHE: dict[str, re.Pattern] = {}


def _wildcard_regex(pattern: str) -> re.Pattern:
    if pattern not in _WILDCARD_CACHE:
        out = []
        for ch in pattern:
            if ch == "*":
                out.append(".*")
            elif ch == "?":
                out.append(".")
            else:
                out.append(re.escape(ch))
        _WILDCARD_CACHE[pattern] = re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)
    return _WILDCARD_CACHE[pattern]


def _match_scalar(mods: list[str], expected: Any, event_val: Any) -> bool:
    if event_val is None:
        return False
    ev = event_val if isinstance(event_val, str) else str(event_val)
    exp = expected if isinstance(expected, str) else str(expected)
    if "re" in mods:
        return re.search(exp, ev) is not None
    if "contains" in mods:
        return exp.lower() in ev.lower()
    if "startswith" in mods:
        return ev.lower().startswith(exp.lower())
    if "endswith" in mods:
        return ev.lower().endswith(exp.lower())
    if "*" in exp or "?" in exp:
        return _wildcard_regex(exp).match(ev) is not None
    return ev.lower() == exp.lower()


def _field_matches(field_expr: str, expected: Any, event: dict) -> bool:
    parts = field_expr.split("|")
    field, mods = parts[0], parts[1:]
    all_mode = "all" in mods
    value_mods = [m for m in mods if m != "all"]
    event_val = event.get(field)
    if isinstance(expected, list):
        results = [_match_scalar(value_mods, e, event_val) for e in expected]
        return all(results) if all_mode else any(results)
    return _match_scalar(value_mods, expected, event_val)


def selection_matches(selection: dict, event: dict) -> bool:
    """Every field entry in a selection is AND-ed together."""
    return all(_field_matches(fe, val, event) for fe, val in selection.items())


def _selection_names(detection: dict) -> list[str]:
    return [n for n in detection if n != "condition"]


def _resolve_pattern(pattern: str, detection: dict, event: dict) -> list[bool]:
    if pattern == "them":
        names = _selection_names(detection)
    else:
        names = [n for n in _selection_names(detection) if fnmatch.fnmatchcase(n, pattern)]
    return [selection_matches(detection[n], event) for n in names]


def _tokenize(condition: str) -> list[str]:
    return condition.replace("(", " ( ").replace(")", " ) ").split()


class _Parser:
    """Recursive-descent over the supported condition grammar. Evaluates as it
    parses against the given detection + event (no separate AST needed)."""

    def __init__(self, tokens: list[str], detection: dict, event: dict) -> None:
        self.toks = tokens
        self.i = 0
        self.detection = detection
        self.event = event

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> str:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        val = self._or()
        if self.i != len(self.toks):
            raise ValueError(f"unparsed condition tokens: {self.toks[self.i:]}")
        return val

    def _or(self) -> bool:
        val = self._and()
        while self._peek() == "or":
            self._next()
            val = self._and() or val
        return val

    def _and(self) -> bool:
        val = self._not()
        while self._peek() == "and":
            self._next()
            val = self._not() and val
        return val

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._primary()

    def _primary(self) -> bool:
        tok = self._next()
        if tok == "(":
            val = self._or()
            if self._next() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return val
        if tok in ("1", "all"):
            if self._next() != "of":
                raise ValueError("expected 'of' after quantifier")
            pattern = self._next()
            results = _resolve_pattern(pattern, self.detection, self.event)
            return all(results) if tok == "all" else any(results)
        # bare selection identifier
        return selection_matches(self.detection[tok], self.event)


def matches(detection: dict, event: dict) -> bool:
    condition = detection["condition"]
    return _Parser(_tokenize(condition), detection, event).parse()
