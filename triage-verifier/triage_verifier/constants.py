"""Pinned model + enum/threshold constants for the triage verifier."""

MODEL = "claude-opus-4-8"

SEVERITIES = ("low", "medium", "high", "critical")
VERDICTS = ("malicious", "suspicious", "clean", "unknown")
IOC_TYPES = ("ip", "domain", "file_hash")
PRIORITIES = ("low", "medium", "high", "critical")

BAD_VERDICTS = frozenset({"malicious", "suspicious"})

# Tactics that justify a high/critical severity (honesty check 7).
HIGH_SEVERITY_TACTICS = frozenset(
    {"credential-access", "lateral-movement", "exfiltration", "impact", "command-and-control"}
)
