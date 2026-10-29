#!/usr/bin/env python3
from pathlib import Path
import json, sys
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
C = ROOT / "contracts" / "ouf-contracts-v1.0.0-rc3-coherence"
schema = json.loads((C/"identity/m2m-identity-integration-profile-v1.json").read_text())
v = Draft202012Validator(schema)
examples = [
    C/"examples/identity/m2m-identity-profile.alpha.valid.json",
    C/"examples/identity/m2m-identity-profile.beta.valid.json",
]
errors=[]
for p in examples:
    obj=json.loads(p.read_text())
    errors.extend([f"{p.name}: {e.message}" for e in v.iter_errors(obj)])
    selected=obj.get("scenarioDecision",{}).get("selectedScenario")
    if selected is not None:
        errors.append(f"{p.name}: selectedScenario must remain null")

# Scan starter/application templates for forbidden direct scenario branches.
for p in ROOT.rglob("*"):
    if not p.is_file() or "contracts" in p.parts:
        continue
    if p.suffix.lower() not in {".java",".kt",".yaml",".yml",".json",".properties",".md",".template",".py"}:
        continue
    txt=p.read_text(encoding="utf-8",errors="ignore")
    if any(x in txt for x in ["scenario == \"A\"", "scenario == \"B\"", "scenario == \"C\""]):
        errors.append(f"{p}: direct IAM scenario branch found")

if errors:
    print("\n".join(errors)); sys.exit(1)
print("OUF scenario-neutral identity checks: OK")
