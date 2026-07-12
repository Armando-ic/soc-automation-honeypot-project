import grounding_service.main as main


def test_build_default_app_is_constructible(monkeypatch):
    # Avoid real Qdrant/fastembed/network: stub the retriever builder.
    monkeypatch.setattr(main, "_build_retriever", lambda settings: object())
    app = main.build_default_app()
    routes = {r.path for r in app.routes}
    assert {"/health", "/retrieve", "/verify", "/normalize"} <= routes


def _capture_create_app_kwargs(monkeypatch):
    monkeypatch.setattr(main, "_build_retriever", lambda settings: object())
    captured = {}

    def _fake_create_app(retriever, settings, **kw):
        captured.update(kw)
        return object()

    monkeypatch.setattr(main, "create_app", _fake_create_app)
    return captured


def test_build_default_app_wires_deobf_client_factory(monkeypatch):
    # Task 15: the DEPLOYED /deobfuscate must be able to solicit the paid Claude proposal.
    # main.py used to pass only judge_client_factory, so the deployed endpoint always ran
    # decode_and_verify(client=None) and the model-in-the-loop decode was silently dead
    # (novel-transform samples floored to unknown through the n8n path). Both the judge and
    # the deobf proposal use the same Anthropic client builder, gated on the key.
    captured = _capture_create_app_kwargs(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    main.build_default_app()
    assert callable(captured.get("judge_client_factory"))
    assert callable(captured.get("deobf_client_factory"))     # the fix
    assert captured["deobf_client_factory"] is captured["judge_client_factory"]


def test_build_default_app_no_key_disables_both_factories(monkeypatch):
    # Without a key, BOTH factories are None so triage degrades to builtins and never blocks.
    captured = _capture_create_app_kwargs(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main.build_default_app()
    assert captured.get("judge_client_factory") is None
    assert captured.get("deobf_client_factory") is None


def test_build_default_app_wires_investigation_factories(monkeypatch):
    # Phase 4 Task 17: the DEPLOYED /investigate must be able to call Claude AND reach
    # Splunk. main.py used to pass only judge+deobf factories, so create_app defaulted
    # investigation_client_factory/splunk_service_factory to None and /investigate returned
    # claude_not_configured/splunk_not_configured for EVERY alert -- the whole investigation
    # silently inert. This is the Phase-3 deobf-factory trap repeated for Phase 4.
    captured = _capture_create_app_kwargs(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    monkeypatch.setenv("SPLUNK_HOST", "10.0.0.5")
    monkeypatch.setenv("SPLUNK_PASSWORD", "pw-not-a-real-secret")
    main.build_default_app()
    # The investigation loop reuses the SAME key-gated Anthropic client builder as the judge.
    assert callable(captured.get("investigation_client_factory"))
    assert captured["investigation_client_factory"] is captured["judge_client_factory"]
    # And a Splunk service factory must be wired so run_investigation can query.
    assert callable(captured.get("splunk_service_factory"))


def test_build_default_app_no_splunk_host_disables_splunk_factory(monkeypatch):
    # A deploy without Splunk config must fail SAFE: splunk_service_factory=None so
    # /investigate returns splunk_not_configured (fail-closed), never a KeyError crash.
    # The investigation CLIENT factory stays wired (it's the same key-gated Anthropic builder).
    captured = _capture_create_app_kwargs(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    monkeypatch.setenv("SPLUNK_PASSWORD", "pw-not-a-real-secret")
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    main.build_default_app()
    assert captured.get("splunk_service_factory") is None
    assert callable(captured.get("investigation_client_factory"))


def test_build_default_app_no_splunk_password_disables_splunk_factory(monkeypatch):
    # SPLUNK_HOST is a literal in compose (always truthy), so gating on host alone would
    # make the deployed service ALWAYS attempt a live connect -- on a deallocated/down host
    # that blocks on the TCP connect. Gating ALSO on SPLUNK_PASSWORD keeps /investigate
    # cheaply inert (splunk_not_configured) until the run is deliberately configured (the
    # password is supplied via the gitignored .env only for a Task-17 live run).
    captured = _capture_create_app_kwargs(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    monkeypatch.setenv("SPLUNK_HOST", "10.0.0.5")
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    main.build_default_app()
    assert captured.get("splunk_service_factory") is None
    assert callable(captured.get("investigation_client_factory"))


def test_judge_client_factory_bounds_the_request_timeout(monkeypatch):
    # The shared Anthropic factory feeds the up-to-MAX_TURNS /investigate loop, where an
    # unbounded per-call timeout can tie up a worker on a hung response. Mirror the CLI live
    # branch's timeout=60.0 so every judge/deobf/investigation call is wall-clock bounded.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    client = main._judge_client_factory()
    assert client.timeout == 60.0
