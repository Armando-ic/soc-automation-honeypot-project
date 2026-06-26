import json
from pathlib import Path

import jsonschema
import triage_verifier

SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "submit_triage_result.json"


def test_package_imports():
    assert triage_verifier.__doc__


def test_schema_is_valid_draft7():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(schema)
    assert schema["required"][0] == "schema_version"
