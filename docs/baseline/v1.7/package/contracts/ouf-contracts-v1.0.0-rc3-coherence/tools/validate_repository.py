#!/usr/bin/env python3
from pathlib import Path
import json, sys

ROOT = Path(__file__).resolve().parents[1]
errors = []
schemas = list(ROOT.rglob("*.json"))

for p in schemas:
    try:
        json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"{p.relative_to(ROOT)}: invalid JSON: {e}")

catalog = ROOT / "contract-catalog.yaml"
if not catalog.exists():
    errors.append("contract-catalog.yaml missing")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(f"OUF contract repository basic validation OK: {len(schemas)} JSON files.")
