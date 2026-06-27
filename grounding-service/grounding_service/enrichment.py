"""Map provider enrichment responses to a single verdict per IOC.

Returns one of: malicious | suspicious | clean | unknown (the verifier's vocab).
Thresholds are pinned starting values (design spec §10); tune against real data.
"""
from __future__ import annotations

_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


def normalize_greynoise(resp: dict) -> str:
    cls = (resp or {}).get("classification")
    if cls == "malicious":
        return "malicious"
    if cls == "suspicious":
        return "suspicious"
    if cls == "benign":
        return "clean"
    return "unknown"


def normalize_abuseipdb(resp: dict) -> str:
    data = (resp or {}).get("data")
    if not isinstance(data, dict) or "abuseConfidenceScore" not in data:
        return "unknown"
    score = data["abuseConfidenceScore"]
    if score >= 85:
        return "malicious"
    if score >= 25:
        return "suspicious"
    if score == 0:
        return "clean"
    return "unknown"


def normalize_virustotal(resp: dict) -> str:
    stats = (
        (resp or {}).get("data", {}).get("attributes", {}).get("last_analysis_stats")
    )
    if not isinstance(stats, dict) or "malicious" not in stats:
        return "unknown"
    mal = stats["malicious"]
    if mal >= 3:
        return "malicious"
    if mal >= 1:
        return "suspicious"
    if mal == 0 and stats.get("harmless", 0) > 0:
        return "clean"
    return "unknown"


def normalize_urlscan(resp: dict) -> str:
    overall = (resp or {}).get("verdicts", {}).get("overall")
    if not isinstance(overall, dict) or "malicious" not in overall:
        return "unknown"
    if overall["malicious"]:
        return "malicious"
    if overall.get("score", 0) >= 40:
        return "suspicious"
    return "clean"


_NORMALIZERS = {
    "greynoise": normalize_greynoise,
    "abuseipdb": normalize_abuseipdb,
    "virustotal": normalize_virustotal,
    "urlscan": normalize_urlscan,
}


def build_enrichment_results(items: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        ioc = item.get("ioc", "")
        provider = item.get("provider", "")
        normalizer = _NORMALIZERS.get(provider)
        verdict = normalizer(item.get("response", {})) if normalizer else "unknown"
        if ioc not in out or _RANK[verdict] > _RANK[out[ioc]]:
            out[ioc] = verdict
    return out
