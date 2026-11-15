#!/usr/bin/env python3
"""Thin, isolated Python entrypoint; configuration supplies no import path."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/semantic_provider_operation"))
from lease_supervisor import main

if __name__ == "__main__":
    raise SystemExit(main())
