#!/usr/bin/env python3
"""D-049: human-invoked, read-only JWT/TLS probe."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_c.probe import main

if __name__ == "__main__":
    raise SystemExit(main())
