#!/usr/bin/env python3
"""Install composed R3 documents, supervisor and v5.2 wrapper; never start containers."""
import sys

# Even an invalid invocation must not create import caches before main denies it.
sys.dont_write_bytecode = True
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3.install_common import main

if __name__ == "__main__":
    raise SystemExit(main())
