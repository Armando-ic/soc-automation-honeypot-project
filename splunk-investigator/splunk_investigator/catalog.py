# splunk_investigator/catalog.py
"""The v1 query catalog + event_time-anchored SPL rendering.

Load-bearing rule (red-team F-scope-time): every time-bounded query is
anchored on the ALERT's event_time, never on wall-clock "now". A
now-anchored window silently returns 0 rows for past events and manufactures
a false "no activity" scope -- exactly the failure this module exists to
prevent. Nothing in this file reads the real clock via any wall-clock API.
The only place a "current time" concept shows up is the literal Splunk
keyword `now` inside the repeat_offender SPL template, which Splunk itself
resolves at dispatch time -- this module never computes that value in
Python.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .config import Config
from .models import ParamSpec, QuerySpec
from .params import EntityScope, ParamError, validate_param

# window enum -> fixed timedelta, keyed off the same 4 literals as
# params.WINDOW_ENUM (duplicated here as an explicit table rather than
# derived, so a change to one is visible as a diff in both places).
_WINDOW_DELTAS: dict[str, timedelta] = {
    "-1h": timedelta(hours=1),
    "-4h": timedelta(hours=4),
    "-24h": timedelta(hours=24),
    "-7d": timedelta(days=7),
}

_SPLUNK_TS_FMT = "%m/%d/%Y:%H:%M:%S"


CATALOG: dict[str, QuerySpec] = {
    "logon_outcomes_for_ip": QuerySpec(
        name="logon_outcomes_for_ip",
        description="Windows logon success/fail counts for a source IP in a time window.",
        params=(ParamSpec("ip", "ip"), ParamSpec("window", "window")),
        spl_template=(
            'search index={index} (EventCode=4624 OR EventCode=4625) src_ip="{ip}" '
            "earliest={earliest} latest={latest}\n"
            "| stats count(eval(EventCode=4624)) as success_count, "
            "count(eval(EventCode=4625)) as fail_count"
        ),
        result_cap=1,
        time_bounded=True,
        derives=("auth_outcome",),
    ),
    "processes_by_user": QuerySpec(
        name="processes_by_user",
        description="Sysmon process-creation events for a user on a host in a time window.",
        params=(ParamSpec("host", "host"), ParamSpec("user", "user"), ParamSpec("window", "window")),
        spl_template=(
            'search index={index} EventID=1 host="{host}" User="{user}" '
            "earliest={earliest} latest={latest}\n"
            "| stats count by host, User, Image\n"
            "| rename User as user, Image as image"
        ),
        result_cap=50,
        time_bounded=True,
        derives=("process_exec_by_user_in_window",),
    ),
    "repeat_offender": QuerySpec(
        name="repeat_offender",
        description="First/last-seen history for a source IP over a fixed 90-day lookback.",
        params=(ParamSpec("ip", "ip"),),
        spl_template=(
            'search index={index} EventCode=4625 src_ip="{ip}" '
            "earliest={earliest} latest={latest}\n"
            "| addinfo\n"
            "| stats earliest(_time) as first_seen, latest(_time) as last_seen, "
            "values(info_min_time) as info_min_time\n"
            "| eval days_active=round((last_seen-first_seen)/86400,1)\n"
            '| eval floored=if(first_seen<=info_min_time+300,"true","false")'
        ),
        result_cap=1,
        time_bounded=False,
        derives=("repeat_offender",),
    ),
    "user_targets_for_ip": QuerySpec(
        name="user_targets_for_ip",
        description="Distinct target accounts a source IP attempted in a time window.",
        params=(ParamSpec("ip", "ip"), ParamSpec("window", "window")),
        spl_template=(
            'search index={index} EventCode=4625 src_ip="{ip}" '
            "earliest={earliest} latest={latest}\n"
            "| stats dc(user) as distinct_user_count"
        ),
        result_cap=1,
        time_bounded=True,
        derives=("distinct_targets",),
    ),
    "encoded_powershell_on_host": QuerySpec(
        name="encoded_powershell_on_host",
        description="PowerShell -EncodedCommand usage on a host in a time window.",
        params=(ParamSpec("host", "host"), ParamSpec("window", "window")),
        spl_template=(
            'search index={index} EventCode=4104 host="{host}" ScriptBlockText="*-EncodedCommand*" '
            "earliest={earliest} latest={latest}\n"
            "| stats count"
        ),
        result_cap=1,
        time_bounded=True,
        derives=("encoded_powershell",),
    ),
}


def render_spl(spec: QuerySpec, params: dict, event_time: str, scope: EntityScope, cfg: Config) -> str:
    """Validate every declared param, compute the event_time-anchored bounds
    (fixed -90d floor for repeat_offender), and render the owned template.

    Raises ParamError for any missing/invalid/off-scope param -- never
    swallowed, never silently rendered with a default.
    """
    canon: dict[str, str] = {}
    for p in spec.params:
        if p.name not in params:
            raise ParamError(f"missing required param {p.name!r} for query {spec.name!r}")
        canon[p.name] = validate_param(p.name, p.type, params[p.name], scope)

    if spec.name == "repeat_offender":
        # The one exception to event-anchoring: a fixed relative-lookback
        # literal, resolved by Splunk at dispatch time -- not by Python.
        earliest, latest = "-90d", "now"
    elif spec.time_bounded:
        window = canon["window"]
        event_dt = datetime.fromisoformat(event_time)
        earliest_dt = event_dt - _WINDOW_DELTAS[window]
        latest_dt = event_dt + timedelta(seconds=cfg.lookahead_s)
        earliest = earliest_dt.strftime(_SPLUNK_TS_FMT)
        latest = latest_dt.strftime(_SPLUNK_TS_FMT)
    else:
        earliest = latest = None

    index = cfg.live_indexes[0]
    return spec.spl_template.format(index=index, earliest=earliest, latest=latest, **canon)
