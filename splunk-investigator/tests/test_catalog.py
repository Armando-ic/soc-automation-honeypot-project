# splunk-investigator/tests/test_catalog.py
from splunk_investigator.catalog import CATALOG, render_spl
from splunk_investigator.params import EntityScope
from splunk_investigator.config import load_config

CFG = load_config()
SCOPE = EntityScope(ips=frozenset({"45.61.53.10"}), hosts=frozenset({"vm-honeypot-win"}),
                    users=frozenset({"Administrator"}))
EVENT_TIME = "2026-07-11T14:03:00"

def test_catalog_has_five_v1_queries():
    assert set(CATALOG) == {"logon_outcomes_for_ip", "processes_by_user",
                            "repeat_offender", "user_targets_for_ip", "encoded_powershell_on_host"}

def test_logon_outcomes_renders_bounded_and_index_scoped():
    spl = render_spl(CATALOG["logon_outcomes_for_ip"],
                     {"ip": "45.61.53.10", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)
    assert spl.startswith("search index=honeypot")
    assert "45.61.53.10" in spl
    assert "earliest=" in spl and "latest=" in spl        # anchored on event_time, not now
    assert "8.8.8.8" not in spl

def test_render_rejects_off_scope_param():
    import pytest
    from splunk_investigator.params import ParamError
    with pytest.raises(ParamError):
        render_spl(CATALOG["logon_outcomes_for_ip"],
                   {"ip": "8.8.8.8", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)

def test_repeat_offender_has_fixed_floor_not_event_relative_lower_bound():
    spl = render_spl(CATALOG["repeat_offender"], {"ip": "45.61.53.10"}, EVENT_TIME, SCOPE, CFG)
    assert "-90d" in spl

# --- Step 5: required cases ---

import re
import pytest
from datetime import datetime
from splunk_investigator.params import ParamError

_ALL_PARAMS = {
    "logon_outcomes_for_ip": {"ip": "45.61.53.10", "window": "-24h"},
    "processes_by_user": {"host": "vm-honeypot-win", "user": "Administrator", "window": "-24h"},
    "repeat_offender": {"ip": "45.61.53.10"},
    "user_targets_for_ip": {"ip": "45.61.53.10", "window": "-24h"},
    "encoded_powershell_on_host": {"host": "vm-honeypot-win", "window": "-24h"},
}

@pytest.mark.parametrize("query_name", list(_ALL_PARAMS))
def test_each_catalog_query_renders_index_scoped_with_its_params(query_name):
    spec = CATALOG[query_name]
    params = _ALL_PARAMS[query_name]
    spl = render_spl(spec, params, EVENT_TIME, SCOPE, CFG)
    assert spl.startswith("search index=honeypot")
    for key, value in params.items():
        if key == "window":
            continue          # window is consumed into earliest/latest, never rendered literally
        assert value in spl

def test_processes_by_user_rejects_missing_required_param():
    # missing "window" entirely -- must NOT silently render
    with pytest.raises((ParamError, KeyError)):
        render_spl(CATALOG["processes_by_user"],
                   {"host": "vm-honeypot-win", "user": "Administrator"}, EVENT_TIME, SCOPE, CFG)
    # missing "user" entirely
    with pytest.raises((ParamError, KeyError)):
        render_spl(CATALOG["processes_by_user"],
                   {"host": "vm-honeypot-win", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)
    # missing "host" entirely
    with pytest.raises((ParamError, KeyError)):
        render_spl(CATALOG["processes_by_user"],
                   {"user": "Administrator", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)

def test_window_outside_enum_raises():
    with pytest.raises(ParamError):
        render_spl(CATALOG["logon_outcomes_for_ip"],
                   {"ip": "45.61.53.10", "window": "-3h"}, EVENT_TIME, SCOPE, CFG)

def test_latest_is_strictly_after_earliest():
    spl = render_spl(CATALOG["logon_outcomes_for_ip"],
                     {"ip": "45.61.53.10", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)
    earliest_str = re.search(r"earliest=(\S+)", spl).group(1)
    latest_str = re.search(r"latest=(\S+)", spl).group(1)
    earliest_dt = datetime.strptime(earliest_str, "%m/%d/%Y:%H:%M:%S")
    latest_dt = datetime.strptime(latest_str, "%m/%d/%Y:%H:%M:%S")
    assert latest_dt > earliest_dt


# --- LB-1 TZ hardening: a timezone-AWARE anchor (the epoch-normalized live
# shape, or falcon's Z-suffixed created_timestamp) must render earliest/latest
# as ABSOLUTE epoch seconds. A bare strftime timestamp is read by Splunk in the
# search head's LOCAL tz; on a non-UTC search head that shifts the window off a
# UTC anchor and manufactures a false 'no activity' scope. Epoch is tz-independent.
# A NAIVE anchor (genuinely-unknown tz) keeps the strftime bounds (above). ---

def test_aware_event_time_renders_absolute_epoch_bounds():
    from datetime import timezone
    aware = "2026-07-11T14:03:00+00:00"
    spl = render_spl(CATALOG["logon_outcomes_for_ip"],
                     {"ip": "45.61.53.10", "window": "-24h"}, aware, SCOPE, CFG)
    earliest_val = re.search(r"earliest=(\S+)", spl).group(1)
    latest_val = re.search(r"latest=(\S+)", spl).group(1)
    # absolute epoch seconds (all digits), NOT a strftime m/d/Y:H:M:S date
    assert earliest_val.isdigit() and latest_val.isdigit()
    event_epoch = int(datetime(2026, 7, 11, 14, 3, 0, tzinfo=timezone.utc).timestamp())
    assert int(earliest_val) == event_epoch - 24 * 3600
    assert int(latest_val) == event_epoch + CFG.lookahead_s


def test_naive_event_time_keeps_local_strftime_bounds():
    # Regression guard: a naive anchor (tz unknown) must still render the
    # Splunk-local strftime format, unchanged by the aware-branch addition.
    spl = render_spl(CATALOG["logon_outcomes_for_ip"],
                     {"ip": "45.61.53.10", "window": "-24h"}, EVENT_TIME, SCOPE, CFG)
    earliest_val = re.search(r"earliest=(\S+)", spl).group(1)
    assert not earliest_val.isdigit()                      # strftime, not epoch
    datetime.strptime(earliest_val, "%m/%d/%Y:%H:%M:%S")   # parses in the local format
