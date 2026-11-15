#!/usr/bin/env python3
"""Hash-pinned trust windows entrypoint."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.operational_signals.trust_windows import main

if __name__ == "__main__":
    raise SystemExit(main())
