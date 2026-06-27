import grounding_service.main as main


def test_build_default_app_is_constructible(monkeypatch):
    # Avoid real Qdrant/fastembed/network: stub the retriever builder.
    monkeypatch.setattr(main, "_build_retriever", lambda settings: object())
    app = main.build_default_app()
    routes = {r.path for r in app.routes}
    assert {"/health", "/retrieve", "/verify", "/normalize"} <= routes
