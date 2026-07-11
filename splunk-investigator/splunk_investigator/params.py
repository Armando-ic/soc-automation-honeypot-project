# splunk_investigator/params.py
from __future__ import annotations
import ipaddress, re
from dataclasses import dataclass, replace

WINDOW_ENUM = ("-1h", "-4h", "-24h", "-7d")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")   # anchored full-match; N=64


class ParamError(ValueError):
    pass


@dataclass(frozen=True)
class EntityScope:
    ips: frozenset
    hosts: frozenset
    users: frozenset

    def with_discovered(self, kind: str, value: str) -> "EntityScope":
        f = {"ip": "ips", "host": "hosts", "user": "users"}[kind]
        cur = getattr(self, f)
        return replace(self, **{f: cur | {value}})


def _canon_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ParamError(f"not a valid ip: {value!r}") from exc


def validate_param(name: str, type_: str, value, scope: EntityScope) -> str:
    if type_ == "window":
        if value not in WINDOW_ENUM:
            raise ParamError(f"window not in enum: {value!r}")
        return value
    if not isinstance(value, str):
        raise ParamError(f"{name} must be a string, got {type(value).__name__}")
    if type_ == "ip":
        canon = _canon_ip(value)
        if canon not in {_canon_ip(i) for i in scope.ips}:
            raise ParamError(f"ip not bound to alert entities: {canon}")
        return canon
    if type_ in ("host", "user"):
        if not _TOKEN_RE.fullmatch(value):     # rejects empty + any out-of-set char, no truncation
            raise ParamError(f"{type_} failed charset/length: {value!r}")
        pool = scope.hosts if type_ == "host" else scope.users
        if value not in pool:
            raise ParamError(f"{type_} not bound to alert entities: {value!r}")
        return value
    raise ParamError(f"unknown param type: {type_}")
