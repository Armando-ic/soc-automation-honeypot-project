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
