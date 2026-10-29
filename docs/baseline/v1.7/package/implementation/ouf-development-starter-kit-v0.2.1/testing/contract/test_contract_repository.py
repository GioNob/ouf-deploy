from pathlib import Path
import json, yaml
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2]
C=ROOT/"contracts"/"ouf-contracts-v1.0.0-rc3-coherence"

def test_catalog_paths_exist():
    catalog=yaml.safe_load((C/"contract-catalog.yaml").read_text())
    for item in catalog["contracts"]:
        assert (C/item["path"]).exists(), item["path"]

def test_all_json_schemas_are_valid():
    for p in C.rglob("*.json"):
        obj=json.loads(p.read_text())
        if isinstance(obj,dict) and obj.get("$schema")=="https://json-schema.org/draft/2020-12/schema":
            Draft202012Validator.check_schema(obj)
