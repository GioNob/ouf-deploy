#!/usr/bin/env python3
"""Human-invoked R3 lifecycle entrypoint."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3.operate import main

if __name__ == "__main__":
    raise SystemExit(main())
