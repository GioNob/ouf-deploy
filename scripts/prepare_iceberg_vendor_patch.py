#!/usr/bin/env python3
"""Prototype fail-closed materializer; requires externally pinned tree digests.

This changes an owned generated vendor tree, never GOMODCACHE. It does not
qualify a release, authenticate a producer or declare downstream maintenance.
"""
import argparse
import hashlib
import json
from pathlib import Path

MODULE = "github.com/apache/iceberg-go"
CONFIG = MODULE + "/config/config.go"
BASE_CONFIG_SHA256 = "30ec8eebf86cd2f5df0c8d6bbf8661c0bf72d10fc8c025d6943c9565ae13a604"
ZIP_SHA256 = "a042ec87708c376362859041b1741213dc4e05400cad7ad0220ea4361a250d55"
LICENSES = {
    "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "NOTICE": "f519dc027959fc106b1b53706b70eb3bd5da2c0bac79336888c58a79d03c8f52",
}
NOTICE = ("// OUF downstream modification (2026-11-03): use the YAML organization\n"
          "// maintained go.yaml.in/yaml/v3 implementation. Base: Apache Iceberg Go\n"
          "// v0.7.0, commit 89a9104ec3639d38ab07e4461721cb5270e95571.\n\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    rows = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise ValueError("VENDOR_SYMLINK_DENIED")
        if p.is_file():
            name = p.relative_to(root).as_posix()
            if "\n" in name or "\r" in name:
                raise ValueError("AMBIGUOUS_VENDOR_PATH")
            rows[name] = digest(p.read_bytes())
    return rows


def tree_digest(rows):
    return digest("".join(rows[name] + "  " + name + "\n" for name in sorted(rows)).encode())


def patched_bytes(original):
    if digest(original) != BASE_CONFIG_SHA256:
        raise ValueError("BASE_CONFIG_CHANGED")
    value = original.replace(b'"gopkg.in/yaml.v3"', b'"go.yaml.in/yaml/v3"')
    return value.replace(b"package config\n", NOTICE.encode() + b"package config\n", 1)


def prepare(vendor, module_zip, expected_base, expected_patched):
    vendor = Path(vendor)
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError("OWNED_VENDOR_DIRECTORY_REQUIRED")
    if digest(Path(module_zip).read_bytes()) != ZIP_SHA256:
        raise ValueError("UPSTREAM_MODULE_ZIP_CHANGED")
    before = inventory(vendor)
    if tree_digest(before) != expected_base:
        raise ValueError("BASE_VENDOR_TREE_CHANGED")
    for name, wanted in LICENSES.items():
        if before.get(MODULE + "/" + name) != wanted:
            raise ValueError("UPSTREAM_LICENSE_OR_NOTICE_CHANGED")
    metadata = (vendor / "modules.txt").read_text().splitlines()
    for header in ("# github.com/apache/iceberg-go v0.7.0", "# go.yaml.in/yaml/v3 v3.0.5"):
        if metadata.count(header) != 1:
            raise ValueError("EXACT_MODULE_METADATA_REQUIRED")
    if "go.yaml.in/yaml/v3/yaml.go" not in before:
        raise ValueError("MAINTAINED_YAML_SOURCE_REQUIRED")
    new_bytes = patched_bytes((vendor / CONFIG).read_bytes())
    after = dict(before)
    after[CONFIG] = digest(new_bytes)
    if tree_digest(after) != expected_patched:
        raise ValueError("EXPECTED_PATCHED_TREE_MISMATCH")
    # No writes occur before all source, license, metadata and result checks.
    (vendor / CONFIG).write_bytes(new_bytes)
    if inventory(vendor) != after:
        raise ValueError("PATCHED_VENDOR_TREE_CHANGED")
    return {
        "status": "VENDOR_PATCH_MATERIALIZED_NOT_RELEASE_QUALIFIED",
        "upstreamModule": MODULE,
        "upstreamVersion": "v0.7.0",
        "upstreamModuleZipSha256": ZIP_SHA256,
        "upstreamH1InputOnly": "h1:bTD6Pb4uM4sWcMfIx0/cV1haHMc84r+CvPieUqYzD4I=",
        "baseVendorTreeSha256": expected_base,
        "patchedVendorTreeSha256": expected_patched,
        "changedFiles": [CONFIG],
        "patchedFileSha256": after[CONFIG],
        "upstreamChecksumDoesNotDescribePatchedBytes": True,
        "downstreamOwnershipRequired": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vendor", required=True, type=Path)
    p.add_argument("--upstream-zip", required=True, type=Path)
    p.add_argument("--expected-base-tree", required=True)
    p.add_argument("--expected-patched-tree", required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.vendor, args.upstream_zip, args.expected_base_tree,
                             args.expected_patched_tree), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
