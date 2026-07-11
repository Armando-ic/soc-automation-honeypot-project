# splunk-investigator/tests/test_params.py
import pytest
from splunk_investigator.params import validate_param, EntityScope, ParamError, WINDOW_ENUM

SCOPE = EntityScope(ips=frozenset({"45.61.53.10"}), hosts=frozenset({"vm-honeypot-win"}),
                    users=frozenset({"Administrator"}))

def test_valid_ip_is_canonicalized_and_bound():
    assert validate_param("ip", "ip", "45.61.53.10", SCOPE) == "45.61.53.10"

def test_ip_not_in_scope_is_rejected_even_if_valid():
    with pytest.raises(ParamError):
        validate_param("ip", "ip", "8.8.8.8", SCOPE)          # well-typed but off-request

def test_host_with_trailing_metacharacter_is_rejected_not_truncated():
    with pytest.raises(ParamError):
        validate_param("host", "host", 'vm-honeypot-win"| delete', SCOPE)

def test_empty_token_rejected():
    with pytest.raises(ParamError):
        validate_param("user", "user", "", SCOPE)

def test_window_enum_only():
    assert validate_param("window", "window", "-24h", SCOPE) == "-24h"
    with pytest.raises(ParamError):
        validate_param("window", "window", "-3h", SCOPE)

def test_discovered_entity_admitted():
    scope2 = SCOPE.with_discovered("user", "victim01")
    assert validate_param("user", "user", "victim01", scope2) == "victim01"

# --- adversarial cases (Step 5) ---

def test_ipv6_is_canonicalized_when_in_scope():
    scope_v6 = EntityScope(ips=frozenset({"2001:0DB8:0:0:0:0:0:1"}), hosts=frozenset(), users=frozenset())
    assert validate_param("ip", "ip", "2001:db8::1", scope_v6) == "2001:db8::1"

def test_host_with_interior_space_is_rejected():
    with pytest.raises(ParamError):
        validate_param("host", "host", "vm honeypot-win", SCOPE)

def test_user_of_exactly_65_chars_is_rejected():
    with pytest.raises(ParamError):
        validate_param("user", "user", "a" * 65, SCOPE)

def test_user_with_semicolon_injection_is_rejected():
    with pytest.raises(ParamError):
        validate_param("user", "user", "admin;drop", SCOPE)

def test_ip_given_non_string_int_is_rejected():
    with pytest.raises(ParamError):
        validate_param("ip", "ip", 12345, SCOPE)
