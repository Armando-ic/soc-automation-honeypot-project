"""T1 (valid Sigma) and T2 (compiles to SPL) via pySigma.

parse_errors uses SigmaRule.from_yaml(collect_errors=True) so a malformed rule
yields a list instead of raising. compile_spl converts via the Splunk backend
and returns None if the backend raises (rule parses but will not compile).
"""
from __future__ import annotations

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def parse_errors(yaml_text: str) -> list[str]:
    try:
        rule = SigmaRule.from_yaml(yaml_text, collect_errors=True)
    except Exception as exc:  # yaml-level or structural failure before rule build
        return [f"parse raised: {exc}"]
    return [str(e) for e in rule.errors]


def compile_spl(yaml_text: str) -> str | None:
    try:
        collection = SigmaCollection.from_yaml(yaml_text)
        queries = SplunkBackend().convert(collection)
    except Exception:
        return None
    if not queries:
        return None
    return queries[0]
