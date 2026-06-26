"""Loader + queries over a bundled slim MITRE ATT&CK technique table."""
from __future__ import annotations

import json
from pathlib import Path


class AttackReference:
    def __init__(self, table: dict[str, dict]) -> None:
        self._table = table

    @classmethod
    def load(cls, path: str | Path) -> "AttackReference":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def id_exists(self, technique_id: str) -> bool:
        return technique_id in self._table

    def name_for(self, technique_id: str) -> str | None:
        entry = self._table.get(technique_id)
        return entry["name"] if entry else None

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        entry = self._table.get(technique_id)
        return tuple(entry["tactics"]) if entry else ()
