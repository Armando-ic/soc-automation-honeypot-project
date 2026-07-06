from detection_authoring.config import load_config


def test_config_defaults():
    cfg = load_config()
    assert cfg.collection == "attack_techniques"
    assert cfg.embed_model == "BAAI/bge-small-en-v1.5"
    assert cfg.model == "claude-opus-4-8"
    assert cfg.max_tokens == 4096
    assert cfg.corpus_dir.name == "corpus"
