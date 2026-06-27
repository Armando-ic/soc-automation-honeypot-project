from grounding_service.embedder import FakeEmbedder


def test_fake_embedder_dim_and_shape():
    emb = FakeEmbedder(dim=8)
    vecs = emb.embed(["alpha", "beta"])
    assert emb.dim == 8
    assert len(vecs) == 2
    assert all(len(v) == 8 for v in vecs)


def test_fake_embedder_is_deterministic():
    emb = FakeEmbedder(dim=8)
    assert emb.embed(["same text"]) == emb.embed(["same text"])


def test_fake_embedder_distinguishes_text():
    emb = FakeEmbedder(dim=8)
    assert emb.embed(["a"])[0] != emb.embed(["b"])[0]
