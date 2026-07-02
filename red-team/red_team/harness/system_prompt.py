"""Load the deployed system prompt and tool definition (fidelity: what production runs)."""
from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW_JSON = _ROOT / "JSON" / "honeypot-triage.json"
_OPUS_NODE_TYPE = "@n8n/n8n-nodes-langchain.anthropic"


def _load_workflow(path: Path | None) -> dict:
    return json.loads(Path(path or _WORKFLOW_JSON).read_text(encoding="utf-8"))


def load_system_prompt(workflow_json_path: Path | None = None) -> str:
    wf = _load_workflow(workflow_json_path)
    for node in wf["nodes"]:
        if node.get("type") == _OPUS_NODE_TYPE:
            return node["parameters"]["options"]["system"]
    raise LookupError("Opus triage node not found in workflow JSON")


def load_tool_def(workflow_json_path: Path | None = None) -> dict:
    wf = _load_workflow(workflow_json_path)
    for node in wf["nodes"]:
        params = node.get("parameters", {})
        # The tool's identity is the node's TOP-LEVEL name, not parameters.name.
        # Verified against JSON/honeypot-triage.json: the toolCode node has
        # node["name"] == "submit_triage_result" and NO parameters.name key.
        if node.get("name") == "submit_triage_result" and "inputSchema" in params:
            return {
                "name": "submit_triage_result",
                "description": params.get("description", ""),
                "input_schema": json.loads(params["inputSchema"]),
            }
    raise LookupError("submit_triage_result tool node not found in workflow JSON")
