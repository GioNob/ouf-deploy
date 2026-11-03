#!/usr/bin/env python3
"""Verify the proposed vendor source supplement; never rewrites raw evidence."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.storage_security import vendor_yaml_source as guard


def read(path):
    guard.require(path.is_file() and not path.is_symlink(), "REGULAR_EVIDENCE_FILE_REQUIRED")
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "previous-manifest", "root", "binary", "packages", "build-info", "execution", "module-origins", "patch", "materializer", "scan", "spdx", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    inputs = [getattr(args, name) for name in ("profile", "previous_manifest", "binary", "packages", "build_info", "execution", "module_origins", "patch", "materializer", "scan", "spdx")]
    guard.require(args.output.resolve() not in {p.resolve() for p in inputs}
                  and not args.output.resolve().is_relative_to(args.root.resolve()),
                  "SEPARATE_PROVENANCE_OUTPUT_REQUIRED")
    scan, spdx = read(args.scan), read(args.spdx)
    result = guard.assess(json.loads(read(args.profile)), args.root,
                         read(args.patch), read(args.materializer), read(args.binary),
                         json.loads(read(args.packages))["packages"], read(args.build_info).decode(),
                         json.loads(read(args.execution)), scan, spdx, read(args.previous_manifest), read(args.module_origins))
    args.output.write_bytes(guard.canonical(result))
    guard.require(read(args.scan) == scan and read(args.spdx) == spdx, "RAW_EVIDENCE_CHANGED")


if __name__ == "__main__":
    main()
