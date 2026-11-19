#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
required=[
    "contracts/ouf-contracts-v1.0.0-rc3-coherence/contract-catalog.yaml",
    "ci/pipeline-contract.yaml",
    "platform/platform-version-bindings.yaml",
    "platform/environment-bindings.schema.json",
    "helm/ouf-service/Chart.yaml",
    "observability/observability-baseline.yaml",
    "docs/adoption-checklist.md",
]
missing=[p for p in required if not (ROOT/p).exists()]
if missing:
    print("Missing starter-kit artifacts:")
    print("\n".join(missing))
    sys.exit(1)
print("OUF starter-kit layout: OK")
