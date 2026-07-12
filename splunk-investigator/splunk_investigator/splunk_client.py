# splunk_investigator/splunk_client.py
"""Read-only splunklib wrapper + pure JSON-envelope outcome mapping.

This is the ONLY module that imports `splunklib`. `parse_envelope` is a pure
function (bytes in, QueryResult out) with zero splunklib dependency -- that's
what the test suite exercises. `run_catalog_query` does the actual I/O and is
injected into the agent; it is never unit-tested against a live Splunk.

Outcome precedence (get this order exactly right):
    1. Any message type in {"FATAL", "ERROR"}      -> "error"   (rows empty)
    2. A truncation/incomplete message OR
       len(results) > result_cap                    -> "capped_incomplete"
    3. Otherwise                                    -> "ok"     (0 rows is a
                                                        real negative finding,
                                                        not a failure)

Field values stay verbatim strings -- Splunk's output_mode=json returns every
field as a string (e.g. "success_count": "0"). Coercing to int/bool is Task
5's job, not this module's.
"""
from __future__ import annotations

import json

from .models import QueryResult

_ERROR_MESSAGE_TYPES = {"FATAL", "ERROR"}
_TRUNCATION_KEYWORDS = ("truncat", "incomplete")


def _is_error_message(message: dict) -> bool:
    return message.get("type") in _ERROR_MESSAGE_TYPES


def _is_truncation_message(message: dict) -> bool:
    # Gate the keyword match on type == "WARN" only. Splunk emits benign
    # INFO/DEBUG messages during normal search runs (e.g. a lookup-table
    # refresh notice) that can contain words like "incomplete" without
    # indicating a truncated result set -- matching those would wrongly
    # downgrade a genuinely complete "ok" result to "capped_incomplete".
    # FATAL/ERROR are already routed to outcome="error" by the earlier
    # precedence step, so WARN is the only remaining severity that should
    # signal a truncation/incomplete warning here.
    #
    # UNCONFIRMED: the exact Splunk truncation message `type` and wording
    # have not yet been validated against a live Splunk instance -- that
    # happens in Task 16's read-only `| head` capture. If the live message
    # turns out to use a different type, adjust this gate then. Until it
    # is confirmed, the len(results) > result_cap check below is the
    # type-independent guarantee that still catches an over-cap result
    # regardless of what the message type turns out to be.
    if message.get("type") != "WARN":
        return False
    text = str(message.get("text", "")).lower()
    return any(keyword in text for keyword in _TRUNCATION_KEYWORDS)


def parse_envelope(raw_bytes: bytes, query_name: str, params: dict, result_cap: int) -> QueryResult:
    """Pure: decode a Splunk `output_mode=json` results envelope into a QueryResult.

    No splunklib, no I/O -- exercised directly by tests with byte-stream input.
    """
    envelope = json.loads(raw_bytes.decode("utf-8"))
    results: list = envelope.get("results", [])
    messages: list = envelope.get("messages", [])

    # 1. error wins, even over a non-empty (or empty) results list.
    if any(_is_error_message(m) for m in messages):
        return QueryResult(query_name=query_name, params=params, outcome="error", rows=(), row_count=0)

    # 2. explicit truncation message, or results overflowing the cap.
    if any(_is_truncation_message(m) for m in messages) or len(results) > result_cap:
        capped_rows = tuple(results[:result_cap])
        # row_count is intentionally len(capped_rows), i.e. the actual tuple
        # length (which can be under result_cap when a WARN-truncation
        # message fires on a small result set) -- NOT result_cap itself.
        # This keeps the invariant row_count == len(rows) true for every
        # outcome, which downstream consumers rely on.
        return QueryResult(
            query_name=query_name, params=params, outcome="capped_incomplete",
            rows=capped_rows, row_count=len(capped_rows),
        )

    # 3. clean -- including a legitimate zero-row result.
    rows = tuple(results)
    return QueryResult(query_name=query_name, params=params, outcome="ok", rows=rows, row_count=len(rows))


def run_catalog_query(service, spl: str, query_name: str, params: dict, result_cap: int, timeout_s: float) -> QueryResult:
    """Execute a read-only catalog query via splunklib and map the result.

    Any splunklib exception (connection, timeout, HTTP, auth) degrades to
    outcome="error" -- this function never raises.
    """
    try:
        import splunklib.client  # noqa: F401  (lazy import -- keeps splunklib isolated to this function)

        # maxTime is a real Splunk search-job control param: finalize the
        # search after N seconds instead of blocking forever.
        job = service.jobs.create(spl, exec_mode="blocking", maxTime=int(timeout_s))
        # LB-4: fetch ONE more than the cap so parse_envelope's
        # `len(results) > result_cap` overflow guard can actually fire. With
        # count=result_cap the server returns at most result_cap rows, so a
        # genuine overflow is invisible and a capped result silently reads as a
        # complete "ok". parse_envelope already slices back down to result_cap.
        raw = job.results(output_mode="json", count=result_cap + 1).read()
        return parse_envelope(raw, query_name, params, result_cap)
    except Exception:
        return QueryResult(query_name=query_name, params=params, outcome="error", rows=(), row_count=0)
