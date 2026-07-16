from grounding_service.config import Settings, _env_bool


def test_brake_defaults_are_safe():
    # In a clean test env these fields fall back to their safe defaults.
    s = Settings()
    assert s.brake_enabled is False                # inert until deliberately enabled
    assert s.splunk_host_ip == ""
    assert s.brake_distinct_dst_max == 150         # fan-out gate, decided 2026-07-16 (see config.py)
    assert s.brake_conn_rate_max == 400            # NOT a rate limit: keeps egress_rate dead
    assert s.honeypot_nsg_deny_priority == 100     # low number = high precedence


def test_rate_stays_dead_at_the_configured_thresholds():
    # egress_rate is dead ONLY while 2 * distinct_dst_max <= conn_rate_max. Both feeders
    # pre-aggregate to <= 2 * distinct_dst connections (one row per (ip, port) across two watched
    # ports), so the rate limb can never fire before fan-out while the invariant holds. Raising
    # the fan-out gate WITHOUT raising conn_rate_max resurrects the un-baselined rate rule BELOW
    # the gate -- the coupling found when the gate went 25 -> 150 on 2026-07-16. This fails loudly
    # the moment a future edit breaks the relationship, in either file.
    s = Settings()
    assert 2 * s.brake_distinct_dst_max <= s.brake_conn_rate_max


def test_env_bool_parses_truthy_at_call_time(monkeypatch):
    monkeypatch.setenv("X_FLAG", "true");  assert _env_bool("X_FLAG") is True
    monkeypatch.setenv("X_FLAG", "1");     assert _env_bool("X_FLAG") is True
    monkeypatch.setenv("X_FLAG", "ON");    assert _env_bool("X_FLAG") is True
    monkeypatch.setenv("X_FLAG", "false"); assert _env_bool("X_FLAG") is False
    monkeypatch.delenv("X_FLAG", raising=False); assert _env_bool("X_FLAG") is False


def test_settings_accepts_explicit_overrides():
    # frozen dataclass still takes constructor kwargs (used across the brake tests)
    s = Settings(brake_enabled=True, splunk_host_ip="20.1.2.3")
    assert s.brake_enabled is True and s.splunk_host_ip == "20.1.2.3"
