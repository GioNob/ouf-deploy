#!/usr/bin/env python3
"""Reconcile a restored fixture catalog against real GETs from restored OCI32."""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from tools.storage_recovery import coordinated, manifest
from tools.storage_recovery.profile import canonical_json
import run_storage_postgres_logical_restore as postgres

LOCK_SHA = "91a7c874deb5b11f1a18dc483e99f6031644b62abb769a9e11ff1ad29250fb7d"
COHORT_SHA = "cf3a01b6426bdb64725b155d252089026a3cf08bc94859da7619ac17a88af19c"
COHORT_ARCHIVE_SHA = "b235c9e9b53d20d7c4eb58250602a051f9e6d66b5faf4cf55417afa905234772"
COHORT = ROOT / "evidence/artifacts/seaweedfs-generation32-cohort-41778371999.zip"
GENERATION = postgres.native.GENERATION
GENERATION_HEADER = "x-amz-meta-ouf-recovery-generation"
HASH_HEADER = "x-amz-meta-ouf-content-hash"
S3_NS = {"s": "http://s3.amazonaws.com/doc/2006-03-01/"}
SYNTHETIC_ONLY = {
    "targetOperations": 0, "gatesClosed": 0, "acceptanceTestsPassed": 0,
    "releaseAdmitted": False, "runtimeAuthorityIssued": False,
    "writerFenceEnforced": False, "simultaneousRecoveryCutQualified": False,
    "pitrQualified": False, "livePostgresRecoveryQualified": False,
    "rpoMeasured": False, "rtoMeasured": False, "completeProductionBackupClaimed": False,
}


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def write(path, value):
    path.write_bytes(canonical_json(value))


def load_generation32():
    import importlib.util
    spec = importlib.util.spec_from_file_location("coordinated_generation32",
        ROOT / "scripts/run-seaweedfs-452-generation32-labs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_listing(request):
    payload, _ = request("GET", "", query={"list-type": "2", "max-keys": "4"},
                         bucket=coordinated.BUCKET)
    require(len(payload) <= 16 * 1024, "FIXTURE_LIST_RESPONSE_BUDGET")
    root = ElementTree.fromstring(payload)
    require(root.tag == "{" + S3_NS["s"] + "}ListBucketResult"
            and root.findtext("s:IsTruncated", namespaces=S3_NS) == "false"
            and root.find("s:NextContinuationToken", S3_NS) is None,
            "COMPLETE_SINGLE_PAGE_FIXTURE_LIST_REQUIRED")
    return [(coordinated.BUCKET, row.text) for row in root.findall("s:Contents/s:Key", S3_NS)]


def s3_readback(request, bucket, key):
    require(bucket == coordinated.BUCKET, "FIXTURE_BUCKET_REQUIRED")
    body, headers = request("GET", key, timeout=10, bucket=bucket)
    length = headers.get("content-length", "")
    return coordinated.ObjectReadback(
        io.BytesIO(body), headers.get(GENERATION_HEADER), headers.get(HASH_HEADER),
        int(length) if length.isascii() and length.isdecimal() and len(length) <= 8 else None,
    )


def seed(request, digest, encoded):
    require(isinstance(encoded, dict) and len(encoded) == 3, "EXACT_THREE_POSTGRES_FIXTURE_BODIES_REQUIRED")
    bodies = {}
    for key, value in sorted(encoded.items()):
        require(isinstance(key, str) and key and len(key.encode()) <= 1024 and
                isinstance(value, str) and len(value) <= 1368, "FIXTURE_SEED_INPUT_BUDGET")
        body = base64.b64decode(value, validate=True)
        require(len(body) <= 1024, "FIXTURE_BODY_BUDGET")
        bodies[key] = body
    request("PUT", "", bucket=coordinated.BUCKET)
    for key, body in bodies.items():
        request("PUT", key, body, bucket=coordinated.BUCKET, extra={
            GENERATION_HEADER: GENERATION, HASH_HEADER: digest(body),
            "content-type": "application/octet-stream",
        })
    return {"seededObjects": len(encoded), "mutatingRequestRetries": 0}


def reconcile_restored(request, proof):
    pg = proof / "postgres/destination"
    profile = json.loads((ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
    return coordinated.reconcile(
        profile, json.loads((proof / "joint-manifest.json").read_bytes()),
        fence_evidence=(pg / "snapshot-00-fenceEvidence.json").read_bytes(),
        catalog_snapshot=(pg / "snapshot-00-catalogSnapshot.json").read_bytes(),
        listed_objects=fixture_listing(request), listing_complete=True,
        read_object=lambda bucket, key: s3_readback(request, bucket, key),
    )


def postgres_stage(pg_bin, proof):
    work = proof / "postgres"
    work.mkdir()
    source = postgres.native.NativeLab(pg_bin, work / "source")
    destination = postgres.native.NativeLab(pg_bin, work / "destination")
    result = {}
    errors = []
    try:
        postgres.exercise(source, destination, work, result)
    finally:
        for lab in (destination, source):
            try:
                lab.stop()
            except Exception as error:
                errors.append(str(error))
        require(not errors, "POSTGRES_CLEANUP_FAILED:" + ";".join(errors))
    write(work / "logical-restore-joined.json", {
        **result, "bothClustersStopped": True, "sourceDumpRestoreVerified": True,
    })
    return source.bodies, result


def bind_joint_manifest(proof, inventory):
    roles = {"config": "config_snapshot", "filer": "filer_metadata",
             "master": "master_metadata", "volume": "volume_data"}
    artifacts = [manifest.record_artifact(proof, "postgres/catalog.dump",
        logical_id="postgres-dump", kind="postgres_dump", generation=GENERATION)]
    for role, kind in roles.items():
        entries = {path: item for path, item in inventory.items() if path.startswith(role + "/")}
        require(entries, "COLD_BACKUP_ROLE_INDEX_REQUIRED:" + role)
        path = role + "-cold-copy-index.json"
        write(proof / path, entries)
        artifacts.append(manifest.record_artifact(proof, path, logical_id=role + "-cold-copy-index",
            kind=kind, generation=GENERATION))
    profile = json.loads((ROOT / "profiles/seaweedfs-452-lab/profile.json").read_bytes())
    fence = proof / "postgres/destination/snapshot-00-fenceEvidence.json"
    result = manifest.build_manifest(
        profile, artifacts, backup_id="lab-coordinated-generation32",
        created_at="2026-11-04T00:00:00Z",
        writer_fence={"status": "CONFIRMED", "generation": GENERATION,
                      "evidenceSha256": postgres.native.digest(fence)},
    )
    write(proof / "joint-manifest.json", result)


def namespace_client(cold, lab, action, path, proof):
    argv = ["sudo", "-n", "nsenter", "-t", lab.pid, "-n", sys.executable,
            "-I", "-B", "-S", str(Path(__file__).resolve()), "client", action, str(path)]
    try:
        result = json.loads(cold.command(argv, timeout=60))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (proof / (action + "-stderr.log")).write_text(
            cold.bounded_diagnostic(error.stderr, "COORDINATED_CHILD_FAILURE"))
        raise
    write(proof / (action + ".json"), result)
    return result


def exercise(archive, pg_bin, work, proof):
    generation32 = load_generation32()
    bound = generation32.binding_api.load(ROOT, LOCK_SHA)
    receipt = generation32.bind_cohort_artifact(
        COHORT, work / "cohort", bound, COHORT_ARCHIVE_SHA, COHORT_SHA)
    binding = generation32.preflight(LOCK_SHA, COHORT_SHA, cohort_path=receipt)
    cold = generation32.configured_harness("cold", binding)
    image = work / "image-binding"
    image.mkdir()
    write(proof / "exact-image.json", cold.prepare_image(archive, image))
    bodies, pg_result = postgres_stage(pg_bin, proof)
    seed_input = work / "seed-input.json"
    write(seed_input, {key: base64.b64encode(body).decode("ascii") for key, body in bodies.items()})
    original = work / "original"
    for role in ("master", "filer", "volume", "s3", "config"):
        (original / role).mkdir(parents=True)
    write(original / "config/s3.json", {"identities": [{
        "name": cold.ACCESS, "credentials": [{"accessKey": cold.ACCESS, "secretKey": cold.SECRET}],
        "actions": ["Admin", "Read", "Write", "List"],
    }]})
    cold.command(["sudo", "-n", "chown", "-R", "65532:65532", str(original)])
    prefix = "ouf-coord32-" + str(os.getpid())
    source = cold.Lab(prefix + "-source", original, proof)
    restored = None
    try:
        source.start()
        namespace_client(cold, source, "seed", seed_input, proof)
        source.stop()
        cold.command(["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(original)])
        backup, restored_root = work / "backup", work / "restored"
        inventory = cold.cold_copy(original, backup)
        original.rename(work / "withheld-original")
        require(cold.cold_copy(backup, restored_root) == inventory, "COLD_RESTORE_BYTES_CHANGED")
        write(proof / "cold-backup-inventory.json", inventory)
        bind_joint_manifest(proof, inventory)
        cold.command(["sudo", "-n", "chown", "-R", "65532:65532", str(restored_root)])
        restored = cold.Lab(prefix + "-restored", restored_root, proof)
        restored.start()
        result = namespace_client(cold, restored, "reconcile", proof, proof)
        require(result["fixtureReconciled"] and result["allExpectedReadbacksCompleted"]
                and result["expectedObjects"] == result["listedObjects"] == len(bodies) == 3
                and result["bodyBytesRead"] == pg_result["objectBytesRead"],
                "REAL_S3_RESTORE_RECONCILIATION_FAILED")
        restored.stop()
    finally:
        for lab in (restored, source):
            if lab and lab.names:
                lab.stop(strict=False)
    return {
        **SYNTHETIC_ONLY, "schema": "ouf.storage-coordinated-fixture32.v1",
        "status": "SYNTHETIC_POSTGRES_AND_COLD_S3_RESTORE_PASS",
        "lockSha256": LOCK_SHA, "cohortReceiptSha256": COHORT_SHA,
        "ociManifestDigest": binding["lock"]["image"]["manifestDigest"],
        "postgresDumpSha256": pg_result["dumpSha256"], "postgresVersion": postgres.native.VERSION,
        "coldBackupFiles": len(inventory), "coldBackupBytes": sum(x["bytes"] for x in inventory.values()),
        "s3ObjectsReconciled": result["expectedObjects"], "s3ObjectBytesRead": result["bodyBytesRead"],
        "twoIndependentColdRoots": True, "eightCleanContainerStops": True,
        "fixtureWriterReturnedBeforeColdCopy": True,
        "restoredClientIssuedOnlyListAndGet": True,
        "manifestStorageRecordsRepresentVerifiedColdCopyIndices": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--image", required=True, type=Path)
    run.add_argument("--pg-bin", required=True, type=Path)
    run.add_argument("--work", required=True, type=Path)
    client = sub.add_parser("client")
    client.add_argument("action", choices=("seed", "reconcile"))
    client.add_argument("input", type=Path)
    args = parser.parse_args()
    if args.command == "client":
        generation32 = load_generation32()
        cold = generation32.load_module("coordinated_s3_client", ROOT / "scripts/run-seaweedfs-452-cold-recovery.py")
        routes = json.loads(cold.command(["ip", "-j", "route", "show", "table", "all"], timeout=5))
        require(all(route.get("dev") == "lo" for route in routes), "LOOPBACK_NAMESPACE_REQUIRED")
        result = (seed(cold.request, cold.digest, json.loads(args.input.read_bytes()))
                  if args.action == "seed" else reconcile_restored(cold.request, args.input))
        print(json.dumps(result))
        return 0
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.geteuid() != 0, "ISOLATED_CI_REQUIRED")
    work = args.work.absolute()
    require(not work.exists() and not work.is_symlink(), "NEW_WORK_DIRECTORY_REQUIRED")
    proof = work / "evidence"
    proof.mkdir(parents=True, mode=0o700)
    try:
        write(proof / "receipt.json", exercise(args.image.resolve(), args.pg_bin.resolve(), work, proof))
    except Exception as error:
        write(proof / "receipt.json", {
            **SYNTHETIC_ONLY, "status": "SYNTHETIC_COORDINATED_FIXTURE_BLOCKED",
            "failureClass": type(error).__name__, "failure": str(error)[:512],
        })
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
