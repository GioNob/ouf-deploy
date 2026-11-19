#!/usr/bin/env python3
"""Human-only recovery entrypoint for R3 v18."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3.reconcile_prepared_epoch import main

if __name__ == "__main__":
    raise SystemExit(main())
