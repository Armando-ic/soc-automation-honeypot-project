# grounding-service/tests/test_brake_endpoints.py
from fastapi.testclient import TestClient

from grounding_service.app import create_app
from grounding_service.config import Settings


class _StubRetriever:
    def search(self, text, top_k):
        return []


def _client(**env):
    settings = Settings(**env) if env else Settings()
    return TestClient(create_app(_StubRetriever(), settings))


# --- /brake/host-feed: the pull-based Splunk host feeder ----------------------------------
# Splunk's built-in webhook alert action cannot deliver the {events, source} contract (its
# envelope is fixed and carries only the FIRST result row), so the fast feeder pulls instead:
# n8n Schedule Trigger -> GET /brake/host-feed -> POST the contract to the brake webhook.

class _FakeService:
    """Stands in for a splunklib Service. run_catalog_query is faked, so it is never touched."""


def _feed_client(splunk_factory, **env):
    settings = Settings(**env) if env else Settings()
    return TestClient(create_app(_StubRetriever(), settings, splunk_service_factory=splunk_factory))


def _fake_query(monkeypatch, *, outcome, rows=()):
    """Fake run_catalog_query. Returns a `calls` list so a test can prove the patch INTERCEPTED.

    Without that proof the 503 tests are worthless: if the monkeypatch silently missed, the real
    run_catalog_query would hit _FakeService, raise, and degrade to outcome="error" -> 503 -- the
    exact status those tests assert. They would pass for the wrong reason, forever.
    """
    from splunk_investigator import splunk_client as sc
    from splunk_investigator.models import QueryResult

    calls = []

    def _fake(*a, **k):
        calls.append(1)
        return QueryResult(query_name="brake_host_feed", params={}, outcome=outcome,
                           rows=tuple(rows), row_count=len(rows))

    monkeypatch.setattr(sc, "run_catalog_query", _fake)
    return calls


def test_host_feed_spl_targets_the_live_sourcetype():
    # Regression lock with a live receipt. `sourcetype=*Sysmon*` -- the A8 trigger doc's filter
    # since d39a1c4, and this endpoint's own first draft -- matches ZERO events forever:
    # splunk-inputs.conf sets renderXml=1, so Sysmon lands under sourcetype `XmlWinEventLog`,
    # which does not contain the substring "Sysmon". Measured on the live box 2026-07-15 over
    # 24h: `sourcetype=XmlWinEventLog EventCode=3` -> 15,935 events; `sourcetype=*Sysmon*` -> 0.
    # It went uncaught for two sessions because B3 proved telemetry with `index=honeypot |
    # stats count by EventCode`, which has no sourcetype filter -- the filter itself was never
    # once executed. A dead filter here is a permanently inert feeder that reports 200/all-quiet.
    from grounding_service.app import host_feed_spl
    spl = host_feed_spl("20.1.2.3")
    assert "sourcetype=XmlWinEventLog" in spl
    assert "*Sysmon*" not in spl


def test_host_feed_spl_starts_with_the_search_command():
    # splunklib's jobs.create rejects a bare `index=...`; every catalog.py template carries the
    # prefix for exactly this reason. Drop it and the search errors -> run_catalog_query swallows
    # it into outcome="error" -> 503 -> the feeder is red on run #1 and every run after.
    from grounding_service.app import host_feed_spl
    assert host_feed_spl("20.1.2.3").startswith("search ")


def test_host_feed_spl_ships_only_rows_the_brake_can_act_on():
    # The 5000-row cap must be reachable ONLY by a genuine watched-port fan-out.
    # Unfiltered, this SPL ships every (dst_ip, dst_port) pair the box touches -- including
    # NSG-DENIED connect ATTEMPTS, which Sysmon logs anyway (it hooks the guest network stack,
    # while the NSG drops the packet out in the Azure fabric). So an attacker port-scanning
    # generates thousands of distinct (ip,port) rows that never leave the box, parse_envelope
    # takes results[:5000] ordered by DestinationIp, and the REAL 443 fan-out rows can be
    # truncated straight out of the feed -> no trip during the exact event the brake exists for.
    # Scoping to the watched ports makes 5000 rows imply >2500 watched destinations, which trips
    # fan-out on its own -- which is what makes riding through capped_incomplete sound rather
    # than merely assumed.
    from grounding_service.app import host_feed_spl
    spl = host_feed_spl("20.1.2.3")
    assert "DestinationPort IN (80,443)" in spl
    # splunk_nonuf needs Splunk rows on ANY port (it trips on port != 9997), so the Splunk host
    # is an explicit OR rather than something the port filter could ever admit.
    assert 'OR DestinationIp="20.1.2.3"' in spl


def test_host_feed_spl_without_a_splunk_host_still_scopes_to_watched_ports():
    # splunk_host_ip unset must not produce `DestinationIp=""` (matches nothing, harmless) NOR
    # widen the filter. Degrade to ports only: splunk_nonuf is already inert without a host to
    # compare against, so nothing is lost.
    from grounding_service.app import host_feed_spl
    spl = host_feed_spl("")
    assert "DestinationPort IN (80,443)" in spl
    assert "DestinationIp=" not in spl


def test_host_feed_maps_rows_to_the_brake_contract(monkeypatch):
    _fake_query(monkeypatch, outcome="ok", rows=[
        {"dst_ip": "93.184.0.1", "dst_port": "443"},
        {"dst_ip": "93.184.0.2", "dst_port": "80"},
    ])
    c = _feed_client(lambda: _FakeService())
    r = c.get("/brake/host-feed")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "splunk"
    assert body["events"] == [
        {"dst_ip": "93.184.0.1", "dst_port": "443"},
        {"dst_ip": "93.184.0.2", "dst_port": "80"},
    ]


def test_host_feed_error_does_not_launder_into_an_empty_feed(monkeypatch):
    # THE load-bearing test. run_catalog_query NEVER raises: a dead Splunk, an expired
    # phase4_investigator password, a role regression, or bad SPL all degrade to
    # outcome="error" with rows=(). Mapping rows straight to events would answer
    # 200 {"events": []}, the brake would read that as "all quiet", and the fast feeder would
    # be silently inert while every n8n execution stayed green -- the exact failure the whole
    # pull rebuild exists to avoid. An error must be LOUD: no POST, red execution.
    calls = _fake_query(monkeypatch, outcome="error", rows=[])
    c = _feed_client(lambda: _FakeService())
    r = c.get("/brake/host-feed")
    assert r.status_code == 503
    assert calls, "the monkeypatch never intercepted: this 503 came from _FakeService blowing up"


def test_host_feed_capped_with_zero_rows_is_loud_not_empty(monkeypatch):
    # capped_incomplete does NOT imply rows >= cap. parse_envelope's truncation limb is
    # `if any(_is_truncation_message(m) ...) or len(results) > result_cap` -- the MESSAGE limb
    # fires independently of row count, on any WARN containing "truncat"/"incomplete". So a
    # degraded Splunk can answer capped_incomplete with ZERO rows, which rode through as
    # 200 {"events": []} = green and dead. Zero rows plus an admission of incompleteness is not
    # "the box is quiet", it is "we do not know", and unknown must be loud.
    calls = _fake_query(monkeypatch, outcome="capped_incomplete", rows=[])
    c = _feed_client(lambda: _FakeService())
    assert c.get("/brake/host-feed").status_code == 503
    assert calls, "the monkeypatch never intercepted"


def test_host_feed_capped_with_rows_still_feeds_the_brake(monkeypatch):
    # The counterpart, and precisely why NOT to 503 on capped_incomplete outright: a genuine
    # overflow of the 5000 cap means >2500 watched destinations, which IS the massive fan-out the
    # brake exists to catch. 503-ing it would POST nothing and the brake would never fire during
    # the exact event. Ride through and let evaluate_egress trip on the rows we do have.
    rows = [{"dst_ip": f"93.184.{i}.1", "dst_port": "443"} for i in range(30)]
    _fake_query(monkeypatch, outcome="capped_incomplete", rows=rows)
    c = _feed_client(lambda: _FakeService())
    r = c.get("/brake/host-feed")
    assert r.status_code == 200
    assert len(r.json()["events"]) == 30


def test_host_feed_quiet_box_is_a_legitimate_empty_feed(monkeypatch):
    # The counterpart to the test above, and the distinction the brake itself cannot make:
    # outcome="ok" with zero rows means the box genuinely had no watched connections. That is
    # a real answer, not a failure, and it must NOT be conflated with outcome="error".
    _fake_query(monkeypatch, outcome="ok", rows=[])
    c = _feed_client(lambda: _FakeService())
    r = c.get("/brake/host-feed")
    assert r.status_code == 200
    assert r.json()["events"] == []


def test_host_feed_unconfigured_splunk_is_loud_not_empty():
    # A deploy that never wired the Splunk factory (main.py gates on SPLUNK_HOST AND
    # SPLUNK_PASSWORD) must not present as a healthy quiet box.
    c = _feed_client(None)
    r = c.get("/brake/host-feed")
    assert r.status_code == 503


def test_host_feed_factory_outage_is_loud_not_empty():
    def _boom():
        raise RuntimeError("splunk connect failed")

    c = _feed_client(_boom)
    r = c.get("/brake/host-feed")
    assert r.status_code == 503


def test_evaluate_quiet_no_trip():
    c = _client(splunk_host_ip="20.1.2.3")
    r = c.post("/brake/evaluate", json={
        "events": [{"dst_ip": "93.184.0.1", "dst_port": 443}], "source": "splunk"})
    assert r.status_code == 200
    body = r.json()
    assert body["trip"] is False and body["source"] == "splunk"


def test_evaluate_fanout_trips():
    c = _client(splunk_host_ip="20.1.2.3", brake_distinct_dst_max=5)
    events = [{"dst_ip": f"93.184.{i}.{i}", "dst_port": 443} for i in range(10)]
    r = c.post("/brake/evaluate", json={"events": events, "source": "nsg"})
    assert r.json()["trip"] is True and r.json()["reason"] == "egress_fanout"


def test_missing_events_key_fails_closed():
    # Splunk's built-in webhook alert action POSTs a FIXED envelope with no `events` key at
    # all (result/sid/results_link/search_name/owner/app, `result` being the first row only).
    # An `events` default of [] laundered that into an empty list, and an empty list does not
    # trip -- so the feeder answers 200/trip:false forever while looking perfectly healthy.
    # A body this endpoint cannot understand must fail closed, not read as "all quiet".
    c = _client(splunk_host_ip="20.1.2.3")
    r = c.post("/brake/evaluate", json={
        "sid": "scheduler__admin__search__RMD5x_at_1_ABC",
        "search_name": "honeypot-egress-fanout",
        "app": "search",
        "owner": "admin",
        "results_link": "http://splunk:8000/app/search/@go?sid=x",
        "result": {"dst_ip": "93.184.0.1", "dst_port": "443", "count": "7"},
    })
    assert r.status_code == 422


def test_one_junk_row_does_not_strangle_the_box():
    # evaluate_egress is deliberately written to skip a non-dict row and evaluate the rest
    # (`if not isinstance(e, dict): continue`). Strict per-element validation overrode that:
    # one junk row 422s the whole call, and a 422 routes out the evaluate node's error output
    # into nsg_deny, so a single malformed row from a feeder denies ALL egress and contains
    # the box. Strict on the container, lenient on the elements -- brake.py governs row junk.
    c = _client(splunk_host_ip="20.1.2.3")
    r = c.post("/brake/evaluate", json={
        "events": [{"dst_ip": "93.184.0.1", "dst_port": 443}, "garbage"], "source": "splunk"})
    assert r.status_code == 200
    body = r.json()
    assert body["trip"] is False
    assert body["distinct_dst"] == 1


def test_non_list_events_still_fails_closed():
    # Regression lock (already green): the container type stays strict, so a non-list `events`
    # cannot reach evaluate_egress as a scalar. Fails closed via 422 -> error output -> nsg_deny.
    c = _client(splunk_host_ip="20.1.2.3")
    r = c.post("/brake/evaluate", json={"events": "garbage", "source": "splunk"})
    assert r.status_code == 422


class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._p = payload or {}

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("boom")


class _FakeSession:
    def post(self, url, data=None, timeout=None):
        return _FakeResp(payload={"access_token": "tok"})

    def put(self, url, json=None, headers=None, timeout=None):
        return _FakeResp(payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})

    def get(self, url, headers=None, timeout=None):
        return _FakeResp(payload={"properties": {"provisioningState": "Succeeded", "access": "Deny"}})


_CREDS = dict(brake_enabled=True, azure_tenant_id="t", azure_client_id="c",
              azure_client_secret="x", honeypot_subscription_id="sub",
              honeypot_nsg_rg="rg", honeypot_nsg_name="nsg")


def _client_with_factory(factory, **env):
    from grounding_service.app import create_app
    from grounding_service.config import Settings
    return TestClient(create_app(_StubRetriever(), Settings(**env),
                                 azure_brake_session_factory=factory))


def test_nsg_deny_inert_when_disabled():
    c = _client_with_factory(lambda: _FakeSession())  # brake_enabled defaults False
    r = c.post("/brake/nsg-deny", json={})
    assert r.json() == {"fired": False, "reason": "brake_not_configured",
                        "access": "", "provisioning_state": ""}


def test_nsg_deny_inert_when_creds_missing():
    c = _client_with_factory(lambda: _FakeSession(), brake_enabled=True)  # no creds
    assert c.post("/brake/nsg-deny", json={}).json()["reason"] == "brake_not_configured"


def test_nsg_deny_fires_when_enabled_and_configured():
    c = _client_with_factory(lambda: _FakeSession(), **_CREDS)
    body = c.post("/brake/nsg-deny", json={}).json()
    assert body["fired"] is True and body["access"] == "Deny"


def test_nsg_deny_never_raises_on_azure_error():
    class _BoomSession(_FakeSession):
        def put(self, url, json=None, headers=None, timeout=None):
            return _FakeResp(status_code=500)
    c = _client_with_factory(lambda: _BoomSession(), **_CREDS)
    body = c.post("/brake/nsg-deny", json={}).json()
    assert body["fired"] is False and body["reason"] == "brake_error"


def test_nsg_status_configured_false_when_disabled():
    c = _client_with_factory(lambda: _FakeSession())  # brake_enabled defaults False
    r = c.get("/brake/nsg-status")
    assert r.json() == {"configured": False, "access": "", "provisioning_state": ""}


def test_nsg_status_configured_false_when_creds_missing():
    c = _client_with_factory(lambda: _FakeSession(), brake_enabled=True)  # no creds
    r = c.get("/brake/nsg-status")
    assert r.json() == {"configured": False, "access": "", "provisioning_state": ""}


def test_nsg_status_reports_when_enabled_and_configured():
    c = _client_with_factory(lambda: _FakeSession(), **_CREDS)
    body = c.get("/brake/nsg-status").json()
    assert body == {"configured": True, "access": "Deny", "provisioning_state": "Succeeded"}


def test_nsg_status_never_raises_on_azure_error():
    class _BoomSession(_FakeSession):
        def get(self, url, headers=None, timeout=None):
            return _FakeResp(status_code=500)
    c = _client_with_factory(lambda: _BoomSession(), **_CREDS)
    body = c.get("/brake/nsg-status").json()
    assert body == {"configured": True, "access": "unknown", "provisioning_state": "error"}
