"""Offline activation preflight. Run with python -I -B."""
import sys
from pathlib import Path

tools = Path(__file__).resolve().parents[1] / "tools"
sys.path[:0] = [str(tools), str(tools / "privileged_executor")]

from activation_preflight.cli import main

if __name__ == "__main__":
    sys.exit(main())
