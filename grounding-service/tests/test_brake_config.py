from grounding_service.config import Settings, _env_bool


def test_brake_defaults_are_safe():
    # In a clean test env these fields fall back to their safe defaults.
    s = Settings()
    assert s.brake_enabled is False                # inert until deliberately enabled
    assert s.splunk_host_ip == ""
    assert s.brake_distinct_dst_max == 25          # tuned in Part B against a baseline
    assert s.brake_conn_rate_max == 200
    assert s.honeypot_nsg_deny_priority == 100     # low number = high precedence


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
