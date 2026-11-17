#!/usr/bin/env python3
"""D-050: plan/apply/restore/finalize of a quiescent lease kernel generation."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_lease_kernel_migration.cli import main

if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
