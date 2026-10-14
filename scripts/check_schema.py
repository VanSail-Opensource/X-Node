"""Validate API documents, examples, and the distinction between null and empty users."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / "docs/schemas/config.schema.json").read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
for example in sorted((root / "examples").glob("remote-*.json")):
    validator.validate(json.loads(example.read_text()))
validator.validate({"xray": {"inbounds": []}, "users": []})
for bad in ({"xray": {"inbounds": []}}, {"xray": {"inbounds": []}, "users": None}):
    assert not validator.is_valid(bad), "missing/null user snapshots must be rejected"
Draft202012Validator.check_schema(json.loads((root / "docs/schemas/master-message.schema.json").read_text()))
validate(json.loads((root / "docs/openapi.json").read_text()))
asyncapi = json.loads((root / "docs/asyncapi.json").read_text())
assert asyncapi["asyncapi"] == "3.1.0"
assert asyncapi["servers"]["master"]["protocol"] == "wss"
print("API documents and example schemas validated")
