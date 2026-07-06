"""The process_creation field vocabulary the honeypot's Sysmon telemetry exposes.

Drawn from vault/architecture/components/sysmon.md and the captured events in
vault/detections/. These are the ONLY fields a drafted rule may reference; the
subset guard rejects anything else so the matcher never sees an unknown field.
"""
from __future__ import annotations

ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "Image",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "OriginalFileName",
        "User",
        "IntegrityLevel",
        "CurrentDirectory",
        "Hashes",
    }
)
