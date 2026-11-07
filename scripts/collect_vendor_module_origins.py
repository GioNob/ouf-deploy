#!/usr/bin/env python3
"""Hash original inputs from existing Go download records without downloading."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.storage_security import vendor_module_origins as origins


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("build-info", "root-go-sum", "module-download-records", "module-cache", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    inputs = [args.build_info, args.root_go_sum, args.module_download_records]
    origins.require(args.output.resolve() not in {p.resolve() for p in inputs}, "SEPARATE_ORIGIN_OUTPUT_REQUIRED")
    origins.require(not args.output.resolve().is_relative_to(args.module_cache.resolve())
                    and not args.output.resolve().is_relative_to(args.root_go_sum.resolve().parent),
                    "CACHE_AND_SOURCE_OUTPUT_DENIED")
    records = origins.parse_records(args.module_download_records.read_bytes())
    cache_files = {Path(r[key]).resolve() for r in records for key in ("Zip", "GoMod", "Info") if r.get(key)}
    origins.require(args.output.resolve() not in cache_files, "MODULE_CACHE_OUTPUT_DENIED")
    origins.require(all(path.is_relative_to(args.module_cache.resolve()) for path in cache_files),
                    "EXACT_MODULE_CACHE_INPUTS_REQUIRED")
    result = origins.collect(args.build_info.read_text(), args.root_go_sum.read_text(), records)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
