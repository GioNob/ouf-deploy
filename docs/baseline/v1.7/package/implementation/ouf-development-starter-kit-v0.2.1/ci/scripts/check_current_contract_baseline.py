#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
BAD="ouf-contracts-v1.0.0-rc2"
errors=[]
for p in ROOT.rglob("*"):
    if not p.is_file(): continue
    rel=p.relative_to(ROOT)
    if rel.parts[0]=="contracts": continue
    if "history" in rel.parts: continue
    if p.suffix.lower() not in {".md",".yaml",".yml",".json",".py",".txt",".template"}: continue
    text=p.read_text(encoding="utf-8",errors="ignore")
    if BAD in text and p.name!="check_current_contract_baseline.py":
        errors.append(str(rel))
if errors:
    print("Stale rc2 baseline references in current starter docs:")
    print("\n".join(errors))
    sys.exit(1)
print("Starter current contract baseline: OK")
