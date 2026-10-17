#!/usr/bin/env python3
"""Reuse the qualified image packager with a separate immutable release lock."""
import importlib.util
import json
from pathlib import Path

def main():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('candidate', here / 'package-resolution-comparison-candidate.py')
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    candidate.LOCK_PATH = here.parent / 'releases/linked-property-compatibility-candidate-20261017.json'
    candidate.LOCK = json.loads(candidate.LOCK_PATH.read_text())
    candidate.SOURCES = {row['module']: (row['repository'], row['commit']) for row in candidate.LOCK['modules']}
    candidate.KINDS = {row['module']: row['kind'] for row in candidate.LOCK['modules']}
    candidate.main()

if __name__ == '__main__':
    main()
