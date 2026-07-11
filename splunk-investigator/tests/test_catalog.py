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
