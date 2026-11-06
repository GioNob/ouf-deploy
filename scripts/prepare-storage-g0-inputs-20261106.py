#!/usr/bin/env python3
"""Local private input preparation; never invokes the G0 collector."""
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from tools.storage_planning.g0_input_draft import main
raise SystemExit(main(root))
