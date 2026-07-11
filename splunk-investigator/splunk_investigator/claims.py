# splunk_investigator/claims.py
"""Pure, outcome-aware QueryResult -> ScopeClaim derivation.

No I/O, no splunklib, no Anthropic -- this module only reads the already-
parsed `QueryResult` (see splunk_client.parse_envelope) and derives typed,
machine-checkable `ScopeClaim`s from it. Two load-bearing rules drive every
branch below (spec §2.3, red-team findings F-scope-0row / F-test-envelope):

1. Outcome-aware: an "error" query never manufactures a claim (the caller
   sets the query_error flag instead); a "capped_incomplete" query is
   UNKNOWN, never a negative -- a capped result must not become "0 found".
   Only "ok" derives a claim.
2. Strict parse: every string value Splunk hands back (output_mode=json
   serializes everything as a string) is parsed to its typed form with
   strict failure. A non-numeric where a count is expected RAISES -- it
   must never silently become 0, which would manufacture a false negative
   and is exactly the failure mode this phase exists to prevent.

Entity-identity fields (`ip`, `host`) are not always echoed on the row --
several of the catalog's SPL templates aggregate across the whole search
without a `by ip`/`by host` clause (see catalog.py: logon_outcomes_for_ip,
repeat_offender, user_targets_for_ip, encoded_powershell_on_host all lack
such a grouping). Since every catalog query is entity-scoped via its own
params in the first place (that's what params.py's entity-binding gate
enforces), the identity field is sourced from `qr.params` whenever the row
itself doesn't carry it -- see `_entity_field`.

KNOWN GAP (surfaced, not guessed at): spec §2.3 lists `auth_outcome` fields
as `{ip, user, success_count, fail_count}`, but `logon_outcomes_for_ip`
(catalog.py) declares only an `ip` + `window` param -- there is no `user`
param and the SPL never groups by user (it counts 4624/4625 across the
whole src_ip, not a specific account). There is therefore no live source
for a per-user breakdown on this query in v1. This module keeps the `user`
key present (for shape-consistency with the other claim types / a future
verifier) but its value is None unless a row or params dict happens to
carry one -- it is never fabricated.
"""
from __future__ import annotations

import re

from .models import QueryResult, ScopeClaim

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_FREETEXT_MAX_LEN = 256


def _sanitize_freetext(value: str) -> str:
    """Strip control chars and cap length on attacker-authored row values
    (Sysmon `image` paths, Windows `user` names -- query rows are
    attacker-influenced honeypot data, a second-order injection vector).

    This is NOT the params.py charset gate: legitimate image paths carry
    `\\ : space`, which must survive untouched. Only control/injection
    chars (\\r, \\n, \\t, and other non-printable bytes) are stripped, plus
    a sane length cap so a single row can't blow up a downstream artifact.
    """
    return _CONTROL_CHARS_RE.sub("", value)[:_FREETEXT_MAX_LEN]


def _required(row: dict, key: str) -> str:
    """Fetch a required row field, raising loudly on schema drift instead
    of silently defaulting -- a missing key on a non-empty row means the
    live schema no longer matches what this module was written against."""
    if key not in row:
        raise ValueError(f"missing expected field {key!r} in query row: {row!r}")
    return row[key]


def _strict_int(value: str, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"expected an integer for {field!r}, got {value!r}") from exc


def _strict_days_active(value: str) -> int:
    # repeat_offender's SPL computes days_active via round((...)/86400, 1),
    # so the row carries a decimal string ("8.0", "8.3") -- plain int()
    # would raise on that. The claim field is INT per spec, so parse as
    # float first, then round to the nearest whole day. Still strict:
    # non-numeric garbage raises, it never defaults to 0.
    try:
        return int(round(float(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"expected a numeric days_active, got {value!r}") from exc


def _strict_bool(value: str, field: str) -> bool:
    # repeat_offender's SPL already emits the literal string "true"/"false"
    # via `eval floored=if(...,"true","false")` -- this is a strict parse
    # of that exact sentinel, not a re-derivation of the floor logic.
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"expected 'true' or 'false' for {field!r}, got {value!r}")


def _entity_field(row: dict, params: dict, key: str) -> str | None:
    """Prefer the row's own value (when the SPL groups by it); otherwise
    fall back to the param the query was scoped on. See module docstring."""
    if key in row:
        return row[key]
    if key in params:
        return params[key]
    return None


def _sanitized_or_none(value) -> str | None:
    return _sanitize_freetext(value) if value is not None else None


def _derive_auth_outcome(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    if qr.rows:
        row = qr.rows[0]
        success_count = _strict_int(_required(row, "success_count"), "success_count")
        fail_count = _strict_int(_required(row, "fail_count"), "fail_count")
    else:
        # ok + 0 rows is a real negative finding, not an absence of data.
        row = {}
        success_count = 0
        fail_count = 0
    ip = _entity_field(row, qr.params, "ip")
    user = _sanitized_or_none(row.get("user", qr.params.get("user")))
    return (ScopeClaim(type="auth_outcome", fields={
        "ip": ip, "user": user, "success_count": success_count, "fail_count": fail_count,
    }),)


def _derive_process_exec(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    # processes_by_user's SPL is `stats count by host, User, Image` -- each
    # row is a distinct image identity, so one claim per row. A 0-row ok
    # result derives nothing: there is no image identity to hang a claim
    # on, unlike the scalar-aggregate queries below.
    claims = []
    for row in qr.rows:
        host = _entity_field(row, qr.params, "host")
        user = _sanitized_or_none(row.get("user", qr.params.get("user")))
        image = _sanitize_freetext(_required(row, "image"))
        count = _strict_int(_required(row, "count"), "count")
        claims.append(ScopeClaim(type="process_exec_by_user_in_window", fields={
            "host": host, "user": user, "image": image, "count": count,
        }))
    return tuple(claims)


def _derive_repeat_offender(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    if not qr.rows:
        # No first/last-seen to report -- unlike a scalar count, a temporal
        # claim has no meaningful "zero" value, so nothing is derived.
        return ()
    row = qr.rows[0]
    ip = _entity_field(row, qr.params, "ip")
    first_seen = _required(row, "first_seen")   # stays string/temporal form
    last_seen = _required(row, "last_seen")     # stays string/temporal form
    days_active = _strict_days_active(_required(row, "days_active"))
    floored = _strict_bool(_required(row, "floored"), "floored")
    return (ScopeClaim(type="repeat_offender", fields={
        "ip": ip, "first_seen": first_seen, "last_seen": last_seen,
        "days_active": days_active, "floored": floored,
    }),)


def _derive_distinct_targets(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    if qr.rows:
        row = qr.rows[0]
        distinct_user_count = _strict_int(_required(row, "distinct_user_count"), "distinct_user_count")
    else:
        row = {}
        distinct_user_count = 0
    ip = _entity_field(row, qr.params, "ip")
    return (ScopeClaim(type="distinct_targets", fields={
        "ip": ip, "distinct_user_count": distinct_user_count,
    }),)


def _derive_encoded_powershell(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    if qr.rows:
        row = qr.rows[0]
        count = _strict_int(_required(row, "count"), "count")
    else:
        row = {}
        count = 0
    host = _entity_field(row, qr.params, "host")
    return (ScopeClaim(type="encoded_powershell", fields={"host": host, "count": count}),)


_DERIVERS = {
    "logon_outcomes_for_ip": _derive_auth_outcome,
    "processes_by_user": _derive_process_exec,
    "repeat_offender": _derive_repeat_offender,
    "user_targets_for_ip": _derive_distinct_targets,
    "encoded_powershell_on_host": _derive_encoded_powershell,
}


def derive_claims(qr: QueryResult) -> tuple[ScopeClaim, ...]:
    """Pure: QueryResult -> the claim(s) for its query, outcome-aware.

    - "error"             -> () -- no claim; the caller raises query_error.
    - "capped_incomplete" -> () -- unknown, never a negative.
    - "ok"                -> the query's claim(s), strictly typed.
    """
    if qr.outcome != "ok":
        return ()
    deriver = _DERIVERS.get(qr.query_name)
    if deriver is None:
        raise ValueError(f"no claim derivation known for query {qr.query_name!r}")
    return deriver(qr)
