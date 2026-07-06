import pytest

from detection_authoring.corpus import load_benign, load_positives


def test_load_positives_t1059_001():
    events = load_positives("T1059.001")
    assert len(events) == 3
    assert all(e["EventID"] == 1 for e in events)


def test_load_positives_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_positives("T9999")


def test_load_benign_has_near_miss_ip():
    benign = load_benign()
    assert any("8.8.8.8" in e["CommandLine"] for e in benign)
