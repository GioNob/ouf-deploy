#!/usr/bin/env python3
"""Run old-v2/local DB compatibility outside the candidate module graph.

Development only: an isolated temporary module retains the archived reader
solely as a comparison oracle. It is never added to the candidate source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def run(argv, cwd, *, output=None):
    environment = dict(os.environ, GOWORK="off", GOFLAGS="", GOTOOLCHAIN="local")
    result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=180, check=False, env=environment)
    if output is not None:
        output.write_bytes(result.stdout)
        output.with_suffix(output.suffix + ".stderr").write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError("bounded compatibility command failed: " + argv[1])
    return result.stdout


def requirements(go, directory):
    return {row["Path"]: row["Version"] for row in json.loads(
        run([go, "mod", "edit", "-json"], directory))["Require"]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--go", default="go")
    args = p.parse_args()
    source = args.source.resolve(strict=True)
    work = args.work.absolute()
    if work.exists():
        raise ValueError("work directory must be new")
    if work == source or source in work.parents:
        raise ValueError("comparison module must stay outside candidate source")
    work.mkdir(parents=True)
    before = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in ("go.mod", "go.sum")}
    for name in before:
        shutil.copyfile(source / name, work / name)
    fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/seaweedfs-raftstore-compat/compat_test.go"
    shutil.copyfile(fixture, work / "compat_test.go")
    original_requirements = requirements(args.go, source)
    run([args.go, "mod", "edit", "-module=ouf.storage.raftstore.compat",
         "-require=github.com/hashicorp/raft-boltdb/v2@v2.4.2",
         "-require=github.com/seaweedfs/seaweedfs@v0.0.0",
         "-replace=github.com/seaweedfs/seaweedfs=" + str(source)], work)
    # Resolution is confined to this throwaway comparator module. Post-check
    # retained candidate pins: a successful comparison cannot hide upgrades.
    run([args.go, "test", "-mod=mod", "-count=1", "-timeout=60s", "-json", "./..."], work,
        output=work / "compat-tests.jsonl")
    after_requirements = requirements(args.go, work)
    if any(after_requirements.get(name) != version for name, version in original_requirements.items()):
        raise RuntimeError("candidate dependency pins changed in comparison module")
    after = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in before}
    if after != before:
        raise RuntimeError("comparison modified candidate module files")
    sums = (work / "go.sum").read_text().splitlines()
    for exact in (
        "github.com/hashicorp/raft-boltdb/v2 v2.4.2 h1:r2RRgZ6ajT+VH8/9yC5mfoKAlt3KrYiUDhfbUSmaoTs=",
        "github.com/boltdb/bolt v1.3.1 h1:JQmyP4ZBrce+ZQu0dY660FMfatumYDLun9hBCUVIkF4=",
    ):
        if exact not in sums:
            raise RuntimeError("comparison oracle sum mismatch")
    events = [json.loads(line) for line in (work / "compat-tests.jsonl").read_bytes().split(b"\n") if line]
    tests = sorted(event["Test"] for event in events if event.get("Action") == "pass" and "Test" in event)
    expected_tests = ["TestLocalFileReadByOldV2AndReadOnlyLocalDoesNotChangeBytes",
                      "TestLogStoreMonotonicInterfaceRemainsUnclaimed",
                      "TestOldV2FileReadAndWriteWithLocalThenReopenOldV2"]
    if tests != expected_tests or any(event.get("Action") == "fail" for event in events):
        raise RuntimeError("complete compatibility test set required")
    receipt = {"schema": "ouf.raftstore-local-compatibility.v1",
        "status": "LOCAL_DB_FILE_COMPATIBILITY_VERIFIED_NOT_RUNTIME_ACCEPTANCE",
        "testsPassed": tests, "candidateModuleFilesUnchanged": before,
        "candidateRequirementPinsUnchanged": True,
        "oracle": "github.com/hashicorp/raft-boltdb/v2@v2.4.2",
        "oracleContainsArchivedBoltOutsideCandidateOnly": True,
        "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "dbFormatMigrationPerformed": False, "crashOrPowerLossQualified": False,
        "runtimeAuthorityIssued": False, "targetOperations": 0}
    (work / "compat-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
