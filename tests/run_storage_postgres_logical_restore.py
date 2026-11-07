"""Restore the fixture catalog into a separate, initially empty cluster."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_storage_postgres_fixture_native as native
from tools.storage_recovery import manifest
from tools.storage_recovery.profile import canonical_json

DUMP_LIMIT = 1 << 20


def checked_command(output, label, argv):
    result = native.run(argv, timeout=30)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    if result.returncode or result.stderr:
        raise RuntimeError("LOGICAL_RESTORE_COMMAND_FAILED:" + label)
    return result.stdout


def connection(lab):
    return ["--host=" + str(lab.socket), "--port=" + str(native.PORT),
            "--username=fixture_admin", "--no-password", "--dbname=" + native.ROLE]


def system_identifier(lab):
    identifier = lab.sql("SELECT system_identifier FROM pg_control_system()").stdout.strip()
    if not identifier.isdigit() or lab.sql("SHOW listen_addresses").stdout.strip():
        raise RuntimeError("PRIVATE_POSTGRES_CLUSTER_REQUIRED")
    return identifier.decode("ascii")


def archive_digest(archive):
    if archive.is_symlink() or not archive.is_file() or not 0 < archive.stat().st_size <= DUMP_LIMIT:
        raise RuntimeError("BOUNDED_REGULAR_POSTGRES_DUMP_REQUIRED")
    with archive.open("rb") as stream:
        if stream.read(5) != b"PGDMP":
            raise RuntimeError("POSTGRES_CUSTOM_DUMP_REQUIRED")
    return native.digest(archive)


def restore_archive(destination, archive, expected_digest, output):
    if archive_digest(archive) != expected_digest:
        raise RuntimeError("POSTGRES_DUMP_SHA256_MISMATCH")
    checked_command(output, "pg-restore", [str(destination.binary("pg_restore")),
        *connection(destination), "--exit-on-error", "--single-transaction",
        "--no-owner", "--no-acl", str(archive)])
    if archive_digest(archive) != expected_digest:
        raise RuntimeError("POSTGRES_DUMP_CHANGED_DURING_RESTORE")


def exercise(source, destination, output, report):
    identities = {}
    for name in ("pg_dump", "pg_restore"):
        executable = source.binary(name)
        version = checked_command(output, name + "-version", [str(executable), "--version"])
        version = version.decode().strip()
        if not version.endswith(" " + native.VERSION):
            raise RuntimeError("EXACT_POSTGRES_VERSION_REQUIRED:" + name)
        identities[name] = {"version": version, "sha256": native.digest(executable)}
    (output / "dump-restore-binary-identities.json").write_bytes(canonical_json(identities))

    source.start()
    source.reset()
    destination.start(initialize_catalog=False)
    source_id = system_identifier(source)
    destination_id = system_identifier(destination)
    if source_id == destination_id or source.socket == destination.socket:
        raise RuntimeError("INDEPENDENT_POSTGRES_CLUSTER_REQUIRED")
    empty = destination.sql(
        "SELECT CASE WHEN to_regnamespace('ouf_recovery_fixture') IS NULL THEN 'empty' ELSE 'present' END"
    ).stdout.strip()
    if empty != b"empty":
        raise RuntimeError("RESTORE_DESTINATION_NOT_EMPTY")
    report.update(sourceSystemIdentifier=source_id, destinationSystemIdentifier=destination_id,
                  destinationFixtureSchemaAbsentBeforeRestore=True)

    archive = output / "catalog.dump"
    checked_command(output, "pg-dump", [str(source.binary("pg_dump")), *connection(source),
        "--format=custom", "--compress=0", "--no-acl",
        "--schema=ouf_recovery_fixture", "--file=" + str(archive)])
    checksum = archive_digest(archive)
    source.dump_reference = checksum
    before = source.snapshot()
    # Use a private destination copy for both pg_restore and the reconciliation manifest.
    restore_input = destination.artifact_root / "postgres_dump"
    restore_input.write_bytes(archive.read_bytes())
    restore_archive(destination, restore_input, checksum, output)
    if archive_digest(archive) != checksum:
        raise RuntimeError("RETAINED_POSTGRES_DUMP_CHANGED")
    destination.grant_fixture_readback()
    destination.dump_reference = checksum
    destination.artifacts = [
        manifest.record_artifact(destination.artifact_root, "postgres_dump",
            logical_id="postgres-dump", kind="postgres_dump", generation=native.GENERATION)
        if item["kind"] == "postgres_dump" else item
        for item in destination.artifacts
    ]
    after = destination.snapshot()
    for field in ("catalogSnapshot", "fenceEvidence"):
        if before[field] != after[field]:
            raise RuntimeError("RESTORED_FIXTURE_SNAPSHOT_MISMATCH:" + field)
    reconciliation = destination.reconcile(after)
    (output / "reconciliation.json").write_bytes(canonical_json(reconciliation))
    if not reconciliation["fixtureReconciled"] or not reconciliation["allExpectedReadbacksCompleted"]:
        raise RuntimeError("RESTORED_FIXTURE_RECONCILIATION_FAILED")
    report.update(dumpSha256=checksum, dumpBytes=archive.stat().st_size,
                  snapshotEqualityVerified=True, objectCount=reconciliation["expectedObjects"],
                  objectBytesRead=reconciliation["bodyBytesRead"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = native.NativeLab(args.pg_bin, output / "source")
    destination = native.NativeLab(args.pg_bin, output / "destination")
    report = dict(native.CLAIMS, schema="ouf.postgres-logical-restore-lab.v1",
                  postgresVersion=native.VERSION, expectedSourceTarballSha256=native.SOURCE_SHA256,
                  sourceArchiveVerifiedByHarness=False, otherBackupArtifactsSynthetic=True,
                  status="BLOCKED", failures=[])
    try:
        exercise(source, destination, output, report)
    except Exception as error:
        report["failures"].append(type(error).__name__ + ": " + str(error))
    finally:
        cleanup = {}
        for name, lab in (("destination", destination), ("source", source)):
            try:
                lab.stop()
                cleanup[name] = True
            except Exception as error:
                cleanup[name] = False
                report["failures"].append(name + " cleanup: " + str(error))
        report["cleanupSucceeded"] = cleanup
        if not report["failures"]:
            report["status"] = "SYNTHETIC_LOGICAL_POSTGRES_RESTORE_PASS"
            report["dumpRestoreOriginVerified"] = True
        (output / "receipt.json").write_bytes(canonical_json(report))
        print(json.dumps(report, indent=2))
    return 1 if report["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
