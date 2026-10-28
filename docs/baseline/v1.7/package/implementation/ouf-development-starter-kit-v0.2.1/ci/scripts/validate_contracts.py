#!/usr/bin/env python3
from pathlib import Path
import json, yaml, sys
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "ouf-contracts-v1.0.0-rc3-coherence"
errors = []

for p in CONTRACTS.rglob("*.json"):
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"JSON parse {p}: {e}")
        continue
    if isinstance(obj, dict) and obj.get("$schema") == "https://json-schema.org/draft/2020-12/schema":
        try:
            Draft202012Validator.check_schema(obj)
        except Exception as e:
            errors.append(f"JSON Schema {p}: {e}")

for p in list(CONTRACTS.rglob("*.yaml")) + list(CONTRACTS.rglob("*.yml")):
    try:
        yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"YAML parse {p}: {e}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("OUF shared contracts: OK")
