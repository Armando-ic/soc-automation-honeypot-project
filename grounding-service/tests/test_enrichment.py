from grounding_service.enrichment import (
    build_enrichment_results,
    normalize_abuseipdb,
    normalize_greynoise,
    normalize_urlscan,
    normalize_virustotal,
)


def test_greynoise_classifications():
    assert normalize_greynoise({"classification": "malicious"}) == "malicious"
    assert normalize_greynoise({"classification": "benign"}) == "clean"
    assert normalize_greynoise({}) == "unknown"


def test_abuseipdb_thresholds():
    assert normalize_abuseipdb({"data": {"abuseConfidenceScore": 100}}) == "malicious"
    assert normalize_abuseipdb({"data": {"abuseConfidenceScore": 40}}) == "suspicious"
    assert normalize_abuseipdb({"data": {"abuseConfidenceScore": 0}}) == "clean"
    assert normalize_abuseipdb({}) == "unknown"


def test_virustotal_thresholds():
    assert normalize_virustotal(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60}}}}
    ) == "malicious"
    assert normalize_virustotal(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 60}}}}
    ) == "suspicious"
    assert normalize_virustotal(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}
    ) == "clean"
    assert normalize_virustotal({}) == "unknown"


def test_urlscan_verdict():
    assert normalize_urlscan({"verdicts": {"overall": {"malicious": True, "score": 80}}}) == "malicious"
    assert normalize_urlscan({"verdicts": {"overall": {"malicious": False, "score": 50}}}) == "suspicious"
    assert normalize_urlscan({"verdicts": {"overall": {"malicious": False, "score": 0}}}) == "clean"
    assert normalize_urlscan({}) == "unknown"


def test_build_enrichment_results_takes_worst_per_ioc():
    items = [
        {"ioc": "1.2.3.4", "provider": "greynoise", "response": {"classification": "benign"}},
        {"ioc": "1.2.3.4", "provider": "abuseipdb", "response": {"data": {"abuseConfidenceScore": 100}}},
        {"ioc": "evil.com", "provider": "urlscan", "response": {"verdicts": {"overall": {"malicious": False, "score": 50}}}},
    ]
    out = build_enrichment_results(items)
    assert out == {"1.2.3.4": "malicious", "evil.com": "suspicious"}
