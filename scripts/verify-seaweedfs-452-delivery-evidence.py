#!/usr/bin/env python3
"""Fail closed when a SeaweedFS 4.52 review bundle overclaims or is incomplete."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


LOCK_SHA256 = "81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea"
BINARY_SHA256 = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
OCI_DIGEST = "sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4"
BUNDLE_PARTS = [
    {
        "bytes": 610711,
        "path": "evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip.part-000",
        "sha256": "1838d239086f60fddcf858712bc0f5c0e5d4df68741cf8ee372c75d014983af3",
    },
    {
        "bytes": 610711,
        "path": "evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip.part-001",
        "sha256": "985cdd3bdd500ef72352999167e086d7e51558943f50cc8ac5d341cc0ea96095",
    },
    {
        "bytes": 610711,
        "path": "evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip.part-002",
        "sha256": "4e9614091d92160a26ae19c5c0997e58d893012d0af8996f4c3290bd75f2cc6d",
    },
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_archive(archive: zipfile.ZipFile) -> list[str]:
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    require(len(names) == len(set(names)) <= 10000, "UNIQUE_BOUNDED_MEMBERS_REQUIRED")
    require(sum(entry.file_size for entry in entries) <= 1024 ** 3, "EXPANDED_BUDGET")
    for entry in entries:
        path = PurePosixPath(entry.filename)
        require(str(path) == entry.filename and not path.is_absolute() and ".." not in path.parts,
                "SAFE_PATH_REQUIRED")
        require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                "REGULAR_MEMBER_REQUIRED")
    return names


def verify(delivery_lock_path: Path, matrix_path: Path, matrix_csv_path: Path,
           bundle_path: Path, custody_path: Path) -> dict:
    delivery = json.loads(delivery_lock_path.read_bytes())
    matrix_raw = matrix_path.read_bytes()
    matrix = json.loads(matrix_raw)
    csv_raw = matrix_csv_path.read_bytes()
    custody = json.loads(custody_path.read_bytes())
    require(delivery["status"] == "TECHNICAL_DELIVERY_DOSSIER_PREPARED_REVIEW_OPEN",
            "REVIEW_OPEN_STATUS_REQUIRED")
    require(delivery["candidateLockSha256"] == LOCK_SHA256, "LOCK_BINDING_REQUIRED")
    require(delivery["matrixSha256"] == sha(matrix_raw) and
            delivery["matrixCsvSha256"] == sha(csv_raw), "MATRIX_HASH_BINDING_REQUIRED")
    require(delivery["bundleSha256"] == file_sha(bundle_path) and
            delivery["bundleBytes"] == bundle_path.stat().st_size, "BUNDLE_BINDING_REQUIRED")
    require(delivery.get("bundleParts") == BUNDLE_PARTS,
            "EXACT_BUNDLE_PARTS_REQUIRED")
    require(matrix["candidateLockSha256"] == LOCK_SHA256 and
            matrix["binarySha256"] == BINARY_SHA256 and
            matrix["ociManifestDigest"] == OCI_DIGEST, "CANDIDATE_BINDING_REQUIRED")
    require(matrix["componentCount"] == len(matrix["components"]) == 262,
            "EXACT_COMPONENT_COUNT_REQUIRED")
    require(sum(len(row["legalTexts"]) for row in matrix["components"]) ==
            matrix["legalTextCount"] == 353, "EXACT_TEXT_COUNT_REQUIRED")
    require(len(list(csv.DictReader(io.StringIO(csv_raw.decode())))) == 353,
            "CSV_TEXT_COUNT_REQUIRED")
    for row in matrix["components"]:
        require(row["licenceExpression"] == "NOASSERTION" and
                row["applicabilityStatus"] == "OPEN_HUMAN" and
                not row["obligationsAccepted"], "NO_AUTOMATED_LEGAL_DECISION_REQUIRED")
    require(matrix["licenceReview"] == "OPEN_HUMAN" and
            not matrix["redistributionAccepted"] and not matrix["releaseAdmitted"] and
            not matrix["runtimeAuthorityIssued"] and matrix["targetOperations"] == 0,
            "MATRIX_AUTHORITY_BOUNDARY_REQUIRED")
    require(custody["status"] == "PLAN_ONLY_NOT_EXECUTED" and
            custody["destination"] == "OPEN_HUMAN" and
            not custody["copyExecuted"] and not custody["readbackExecuted"] and
            not custody["recoveryDrillExecuted"] and custody["durableImageCustody"] == "OPEN" and
            not custody["releaseAdmitted"] and custody["targetOperations"] == 0,
            "CUSTODY_MUST_REMAIN_OPEN_REQUIRED")
    require(delivery["licenceReview"] == "OPEN_HUMAN" and
            not delivery["redistributionAccepted"] and delivery["durableImageCustody"] == "OPEN" and
            not delivery["releaseAdmitted"] and not delivery["runtimeAuthorityIssued"] and
            delivery["targetOperations"] == 0, "DELIVERY_AUTHORITY_BOUNDARY_REQUIRED")

    with zipfile.ZipFile(bundle_path) as bundle:
        names = safe_archive(bundle)
        required = {"COMPONENTS.json", "COMPONENTS.csv", "SOURCE-INDEX.json", "REVIEW-OPEN.json",
                    "THIRD-PARTY-INDEX.txt", "candidate-lock.json",
                    "classifier/raw-results.json", "SHA256SUMS"}
        require(required <= set(names), "REQUIRED_BUNDLE_MEMBERS_MISSING")
        require(bundle.read("COMPONENTS.json") == matrix_raw and
                bundle.read("COMPONENTS.csv") == csv_raw, "BUNDLED_MATRIX_MISMATCH")
        require(sha(bundle.read("candidate-lock.json")) == LOCK_SHA256,
                "BUNDLED_CANDIDATE_LOCK_MISMATCH")
        sums = bundle.read("SHA256SUMS").decode().splitlines()
        require(len(sums) == len(names) - 1, "CLOSED_BUNDLE_MANIFEST_REQUIRED")
        listed = set()
        for line in sums:
            digest, name = line.split("  ", 1)
            require(name in names and name != "SHA256SUMS" and name not in listed,
                    "UNIQUE_MANIFEST_MEMBER_REQUIRED")
            require(sha(bundle.read(name)) == digest, "BUNDLE_MEMBER_HASH_MISMATCH:" + name)
            listed.add(name)
        require(listed == set(names) - {"SHA256SUMS"}, "ALL_MEMBERS_MANIFESTED_REQUIRED")
        for component in matrix["components"]:
            for text in component["legalTexts"]:
                require(text["bundlePath"] in names and
                        sha(bundle.read(text["bundlePath"])) == text["sha256"] and
                        len(bundle.read(text["bundlePath"])) == text["bytes"],
                        "TEXT_BINDING_REQUIRED:" + text["bundlePath"])
        source_index = json.loads(bundle.read("SOURCE-INDEX.json"))
        require(source_index["sourceCount"] == len(source_index["sources"]) == 17 and
                not source_index["moduleSourcesModified"] and
                not source_index["redistributionAccepted"], "SOURCE_SET_BOUNDARY_REQUIRED")
        for source in source_index["sources"]:
            require(source["path"] in names and sha(bundle.read(source["path"])) == source["sha256"],
                    "SOURCE_ARCHIVE_BINDING_REQUIRED")
        review = json.loads(bundle.read("REVIEW-OPEN.json"))
        require(review["status"] == "OPEN_HUMAN" and
                len(review["rawUnknownClassifications"]) == 3 and
                len(review["unclassifiedViews"]) == 3 and
                not review["redistributionAccepted"] and not review["releaseAdmitted"] and
                review["targetOperations"] == 0, "REVIEW_EXCEPTION_SET_REQUIRED")
    return {
        "status": "TECHNICAL_DELIVERY_DOSSIER_VERIFIED_REVIEW_OPEN",
        "thirdPartyComponents": 262, "thirdPartyLegalTexts": 353,
        "mplSourceArchives": 17, "rawUnknownClassifications": 3,
        "unclassifiedViews": 3, "licenceReview": "OPEN_HUMAN",
        "redistributionAccepted": False, "durableImageCustody": "OPEN",
        "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delivery-lock", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--matrix-csv", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--custody-plan", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.delivery_lock, args.matrix, args.matrix_csv,
                           args.bundle, args.custody_plan), indent=2, sort_keys=True))
