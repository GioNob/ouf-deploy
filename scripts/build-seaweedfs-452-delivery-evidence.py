#!/usr/bin/env python3
"""Build a deterministic, review-open SeaweedFS 4.52 delivery dossier.

This tool packages technical evidence.  It deliberately does not infer a
licence expression, decide applicability, accept redistribution, admit a
release, or authorize runtime/target operations.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


DATE = (1980, 1, 1, 0, 0, 0)
BASELINE_SHA256 = "851d65dc1ac3788178978b9effc04c257475492ad6d3e5dcc04346d033288c67"
DELTA_SHA256 = "7cf2b9dc596ded071c9c75f1bfeb87245f443e25984b9cddf8bf4f411791eda2"
LOCK_SHA256 = "81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea"
BINARY_SHA256 = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
OCI_DIGEST = "sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4"
BUNDLE_PART_BYTES = 610711
BUNDLE_PART_PREFIX = "seaweedfs-452-attribution-source-review-bundle.zip.part-"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    require(str(path) == name and not path.is_absolute() and ".." not in path.parts,
            "UNSAFE_ARCHIVE_PATH:" + name)
    return path


def checked_archive(path: Path, expected_sha: str) -> zipfile.ZipFile:
    require(path.is_file() and sha256_file(path) == expected_sha,
            "EXACT_INPUT_ARCHIVE_REQUIRED:" + path.name)
    archive = zipfile.ZipFile(path)
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    require(len(names) == len(set(names)) and len(names) <= 10000,
            "UNIQUE_BOUNDED_ARCHIVE_MEMBERS_REQUIRED")
    require(sum(entry.file_size for entry in entries) <= 1024 ** 3,
            "EXPANDED_ARCHIVE_BUDGET_EXCEEDED")
    for entry in entries:
        safe_name(entry.filename)
        require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                "REGULAR_ARCHIVE_MEMBER_REQUIRED:" + entry.filename)
    require("SHA256SUMS" in names, "SHA256SUMS_REQUIRED")
    for line in archive.read("SHA256SUMS").decode().splitlines():
        digest, name = line.split("  ", 1)
        require(name in names and sha256_bytes(archive.read(name)) == digest,
                "ARCHIVE_MEMBER_HASH_MISMATCH:" + name)
    return archive


def detector_map(classifier: dict) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for group in classifier["Results"]:
        for row in group.get("Licenses", []):
            result.setdefault(row["FilePath"], []).append({
                "name": row["Name"],
                "severity": row["Severity"],
                "category": row["Category"],
                "confidence": row["Confidence"],
            })
    for rows in result.values():
        rows.sort(key=lambda row: (row["name"], row["severity"], row["confidence"]))
    return result


def view_path(module: str, version: str, path: str) -> str:
    identity = sha256_bytes(f"{module}@{version}:{path}".encode())
    return f"{identity}/LICENSE"


def zip_write(archive: zipfile.ZipFile, name: str, raw: bytes) -> None:
    safe_name(name)
    info = zipfile.ZipInfo(name, DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, raw)


def current_components(baseline: zipfile.ZipFile, delta: zipfile.ZipFile) -> tuple[list[dict], dict]:
    inventory = json.loads(baseline.read("inventory.json"))
    preflight = json.loads(delta.read("licence-preflight-receipt.json"))
    current_detector = detector_map(json.loads(delta.read("classifier-results.json")))
    retired = {tuple(row) for row in preflight["retiredModuleVersions"]}
    components = []
    for source in inventory["components"]:
        identity = (source["name"], source["version"])
        if source["name"] in ("github.com/seaweedfs/seaweedfs", "stdlib") or identity in retired:
            continue
        texts = []
        for text in source["legalTexts"]:
            archive_path = "texts/" + text["evidencePath"]
            raw = baseline.read(archive_path)
            require(len(raw) == text["bytes"] and sha256_bytes(raw) == text["sha256"],
                    "HISTORICAL_TEXT_BINDING_REQUIRED:" + archive_path)
            classifications = current_detector.get(
                view_path(source["name"], source["version"], text["sourcePath"]), [])
            texts.append({
                "path": text["sourcePath"], "sha256": text["sha256"],
                "bytes": text["bytes"], "detectorObservations": classifications,
                "bundlePath": f"texts/{source['id']}/{text['sourcePath']}",
                "_raw": raw,
            })
        components.append({
            "componentId": source["id"], "module": source["name"],
            "version": source["version"], "evidenceOrigin": "HISTORICAL_EXACT_REUSE",
            "sourceProvenance": source["provenance"], "legalTexts": texts,
        })
    for source in preflight["newModuleVersionEvidence"]:
        component_id = sha256_bytes(f"{source['module']}@{source['version']}".encode())
        texts = []
        for text in source["legalTexts"]:
            archive_path = f"new-module-texts/{source['module']}@{source['version']}/{text['path']}"
            raw = delta.read(archive_path)
            require(len(raw) == text["bytes"] and sha256_bytes(raw) == text["sha256"],
                    "DELTA_TEXT_BINDING_REQUIRED:" + archive_path)
            texts.append({
                "path": text["path"], "sha256": text["sha256"], "bytes": text["bytes"],
                "detectorObservations": current_detector.get(
                    view_path(source["module"], source["version"], text["path"]), []),
                "bundlePath": f"texts/{component_id}/{text['path']}", "_raw": raw,
            })
        components.append({
            "componentId": component_id, "module": source["module"],
            "version": source["version"], "evidenceOrigin": "PATCH15_NEW_VERSION",
            "sourceProvenance": source["provenance"], "legalTexts": texts,
        })
    components.sort(key=lambda row: (row["module"], row["version"]))
    require(len(components) == preflight["thirdPartyModulesVerified"] == 262,
            "EXACT_THIRD_PARTY_COMPONENT_COUNT_REQUIRED")
    require(sum(len(row["legalTexts"]) for row in components) ==
            preflight["thirdPartyLegalTextsFound"] == 353,
            "EXACT_THIRD_PARTY_TEXT_COUNT_REQUIRED")
    require(sum(row["evidenceOrigin"] == "HISTORICAL_EXACT_REUSE" for row in components) == 224,
            "EXACT_REUSED_COMPONENT_COUNT_REQUIRED")
    require(sum(row["evidenceOrigin"] == "PATCH15_NEW_VERSION" for row in components) == 38,
            "EXACT_CHANGED_COMPONENT_COUNT_REQUIRED")
    require(sum(len(text["detectorObservations"]) for row in components
                for text in row["legalTexts"]) == preflight["classifierFindingCount"] == 311,
            "EXACT_CLASSIFIER_FINDING_COUNT_REQUIRED")
    return components, preflight


def public_component(row: dict) -> dict:
    result = {key: value for key, value in row.items() if key != "legalTexts"}
    result["candidateBinarySha256"] = BINARY_SHA256
    result["licenceExpression"] = "NOASSERTION"
    result["applicabilityStatus"] = "OPEN_HUMAN"
    result["obligationsAccepted"] = False
    result["reviewQuestions"] = [
        "Which detected text(s) govern the delivered component?",
        "Which attribution, notice, modification, or source-delivery duties apply?",
        "Is the prepared co-delivery material sufficient for the intended distribution?",
    ]
    result["legalTexts"] = [{key: value for key, value in text.items() if key != "_raw"}
                            for text in row["legalTexts"]]
    return result


def csv_bytes(components: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    fields = ["componentId", "module", "version", "evidenceOrigin", "originalPath",
              "textSha256", "bytes", "bundlePath", "rawDetections",
              "applicabilityStatus", "obligationsAccepted"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for component in components:
        for text in component["legalTexts"]:
            writer.writerow({
                "componentId": component["componentId"], "module": component["module"],
                "version": component["version"], "evidenceOrigin": component["evidenceOrigin"],
                "originalPath": text["path"], "textSha256": text["sha256"],
                "bytes": text["bytes"], "bundlePath": text["bundlePath"],
                "rawDetections": ";".join(row["name"] for row in text["detectorObservations"]),
                "applicabilityStatus": "OPEN_HUMAN", "obligationsAccepted": "false",
            })
    return output.getvalue().encode()


def build(lock_path: Path, baseline_path: Path, delta_path: Path, output_dir: Path) -> dict:
    require(not output_dir.exists(), "NEW_OUTPUT_DIRECTORY_REQUIRED")
    require(sha256_file(lock_path) == LOCK_SHA256, "EXACT_ATTESTED_CANDIDATE_LOCK_REQUIRED")
    lock_raw = lock_path.read_bytes()
    lock = json.loads(lock_raw)
    require(lock["version"] == "4.52" and lock["orderedPatchCount"] == 15,
            "EXACT_452_PATCH15_CANDIDATE_REQUIRED")
    require(lock["buildProfile"]["binarySha256"] == BINARY_SHA256 and
            lock["image"]["manifestDigest"] == OCI_DIGEST, "CANDIDATE_IDENTITY_REQUIRED")
    require(not lock["releaseAdmitted"] and not lock["runtimeAuthorityIssued"] and
            lock["targetOperations"] == 0, "NO_AUTHORITY_OR_TARGET_OPERATIONS_REQUIRED")
    baseline = checked_archive(baseline_path, BASELINE_SHA256)
    delta = checked_archive(delta_path, DELTA_SHA256)
    components, preflight = current_components(baseline, delta)
    require(not preflight["redistributionAccepted"] and preflight["licenceReview"] == "OPEN" and
            not preflight["releaseAdmitted"] and preflight["targetOperations"] == 0,
            "LICENCE_REVIEW_MUST_REMAIN_OPEN")

    matrix = {
        "schema": "ouf.seaweedfs-452-component-obligation-matrix.v1",
        "status": "TECHNICAL_EVIDENCE_PREPARED_REVIEW_OPEN",
        "candidateLockSha256": LOCK_SHA256,
        "binarySha256": BINARY_SHA256,
        "ociManifestDigest": OCI_DIGEST,
        "componentCount": 262, "legalTextCount": 353,
        "licenceExpressionPolicy": "NOASSERTION_UNTIL_HUMAN_REVIEW",
        "components": [public_component(row) for row in components],
        "licenceReview": "OPEN_HUMAN", "redistributionAccepted": False,
        "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
    }
    matrix_raw = canonical(matrix)
    matrix_csv = csv_bytes(components)
    unknowns = preflight["unknownClassifications"]
    unclassified = preflight["unclassifiedViews"]
    require(len(unknowns) == 3 and len(unclassified) == 3,
            "EXACT_REVIEW_EXCEPTION_COUNTS_REQUIRED")
    review = {
        "schema": "ouf.seaweedfs-452-delivery-review-open.v1",
        "status": "OPEN_HUMAN",
        "rawUnknownClassifications": unknowns,
        "unclassifiedViews": unclassified,
        "decisionsRequired": [
            "Confirm applicable licence expressions and obligations per component.",
            "Approve final attribution/source-delivery form for intended distribution.",
            "Accept or reject redistribution of the exact candidate cohort.",
            "Execute and verify durable custody before any release admission.",
        ],
        "licenceReview": "OPEN_HUMAN", "redistributionAccepted": False,
        "releaseAdmitted": False, "targetOperations": 0,
    }
    source_manifest = json.loads(baseline.read("mpl-source-manifest.json"))
    require(source_manifest["sourceCount"] == 17 and
            not source_manifest["redistributionAccepted"], "EXACT_MPL_SOURCE_SET_REQUIRED")
    source_index = {
        "schema": "ouf.seaweedfs-452-source-index.v1",
        "status": "PREPARED_REVIEW_OPEN",
        "sources": source_manifest["components"],
        "sourceCount": 17, "moduleSourcesModified": False,
        "redistributionAccepted": False,
    }
    third_party_index = "".join(
        f"{row['module']}@{row['version']}\t{len(row['legalTexts'])}\t{row['evidenceOrigin']}\n"
        for row in components).encode()

    output_dir.mkdir(parents=True)
    bundle_path = output_dir / "seaweedfs-452-attribution-source-review-bundle.zip"
    members: dict[str, bytes] = {
        "COMPONENTS.json": matrix_raw, "COMPONENTS.csv": matrix_csv,
        "THIRD-PARTY-INDEX.txt": third_party_index,
        "SOURCE-INDEX.json": canonical(source_index), "REVIEW-OPEN.json": canonical(review),
        "candidate-lock.json": lock_raw,
        "classifier/raw-results.json": delta.read("classifier-results.json"),
    }
    for component in components:
        for text in component["legalTexts"]:
            members[text["bundlePath"]] = text["_raw"]
    for name in sorted(delta.namelist()):
        if name.startswith("candidate-source-legal-texts/"):
            members["candidate/" + name.removeprefix("candidate-source-legal-texts/")] = delta.read(name)
    for source in source_manifest["components"]:
        raw = baseline.read(source["path"])
        require(sha256_bytes(raw) == source["sha256"], "MPL_SOURCE_HASH_REQUIRED")
        members[source["path"]] = raw
    sums = "".join(f"{sha256_bytes(members[name])}  {name}\n" for name in sorted(members)).encode()
    members["SHA256SUMS"] = sums
    with zipfile.ZipFile(bundle_path, "x") as archive:
        for name in sorted(members):
            zip_write(archive, name, members[name])

    (output_dir / "seaweedfs-452-component-obligation-matrix-20261103.json").write_bytes(matrix_raw)
    (output_dir / "seaweedfs-452-component-obligation-matrix-20261103.csv").write_bytes(matrix_csv)
    bundle_sha = sha256_file(bundle_path)
    bundle_raw = bundle_path.read_bytes()
    bundle_parts = []
    for index, offset in enumerate(range(0, len(bundle_raw), BUNDLE_PART_BYTES)):
        raw = bundle_raw[offset:offset + BUNDLE_PART_BYTES]
        name = f"{BUNDLE_PART_PREFIX}{index:03d}"
        (output_dir / name).write_bytes(raw)
        bundle_parts.append({
            "bytes": len(raw),
            "path": f"evidence/artifacts/{name}",
            "sha256": sha256_bytes(raw),
        })
    require(len(bundle_parts) == 3 and all(row["bytes"] == BUNDLE_PART_BYTES
                                           for row in bundle_parts),
            "EXACT_THREE_EQUAL_BUNDLE_PARTS_REQUIRED")
    delivery_lock = {
        "schema": "ouf.seaweedfs-452-delivery-evidence-lock.v1",
        "status": "TECHNICAL_DELIVERY_DOSSIER_PREPARED_REVIEW_OPEN",
        "candidateLock": "releases/seaweedfs-452-candidate-lock-20261103.json",
        "candidateLockSha256": LOCK_SHA256,
        "historicalCorpusSha256": BASELINE_SHA256,
        "licenceDeltaSha256": DELTA_SHA256,
        "matrixSha256": sha256_bytes(matrix_raw), "matrixCsvSha256": sha256_bytes(matrix_csv),
        "bundleSha256": bundle_sha, "bundleBytes": bundle_path.stat().st_size,
        "bundleParts": bundle_parts,
        "thirdPartyComponents": 262, "thirdPartyLegalTexts": 353,
        "mplSourceArchives": 17, "rawUnknownClassifications": 3,
        "unclassifiedViews": 3, "licenceReview": "OPEN_HUMAN",
        "redistributionAccepted": False, "durableImageCustody": "OPEN",
        "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
    }
    custody = {
        "schema": "ouf.seaweedfs-452-durable-custody-plan.v1",
        "status": "PLAN_ONLY_NOT_EXECUTED",
        "candidateArtifact": {"sha256": lock["producerArtifact"]["digest"].removeprefix("sha256:"),
                              "bytes": lock["producerArtifact"]["bytes"],
                              "currentRetention": lock["producerArtifact"]["retention"],
                              "expiresAt": lock["producerArtifact"]["expiresAt"]},
        "requiredObjects": ["candidate OCI archive", "independent readback", "candidate lock",
                            "SBOM and raw vulnerability scan", "historical licence corpus",
                            "patch15 licence delta", "delivery review bundle"],
        "executionRequirements": ["approved immutable versioned destination",
                                  "independent replica and retention owner",
                                  "complete post-copy hash readback", "offline recovery drill",
                                  "separate signed custody receipt"],
        "destination": "OPEN_HUMAN", "retentionApproval": "OPEN_HUMAN",
        "copyExecuted": False, "readbackExecuted": False, "recoveryDrillExecuted": False,
        "durableImageCustody": "OPEN", "releaseAdmitted": False, "targetOperations": 0,
    }
    lock_output = output_dir / "seaweedfs-452-delivery-evidence-lock-20261103.json"
    custody_output = output_dir / "seaweedfs-452-durable-custody-plan-20261103.json"
    lock_output.write_bytes(canonical(delivery_lock))
    custody_output.write_bytes(canonical(custody))
    baseline.close()
    delta.close()
    return delivery_lock


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-lock", type=Path, required=True)
    parser.add_argument("--historical-licences", type=Path, required=True)
    parser.add_argument("--licence-delta", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.candidate_lock, args.historical_licences,
                           args.licence_delta, args.output_dir), indent=2, sort_keys=True))
