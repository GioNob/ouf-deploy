#!/usr/bin/env python3
"""Upgrade a stopped R3 provider using an already issued N+1 authorization."""
import sys

sys.dont_write_bytecode = True
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3.upgrade import main

if __name__ == "__main__":
    raise SystemExit(main())
