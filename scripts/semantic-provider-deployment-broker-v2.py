#!/usr/bin/env python3
"""Thin entrypoint; v1 and mandate bytes are verified by the broker loader."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools/semantic_provider_operation"))
from tools.semantic_provider_admission_v2.broker_v2 import main

if __name__ == "__main__":
    raise SystemExit(main())
