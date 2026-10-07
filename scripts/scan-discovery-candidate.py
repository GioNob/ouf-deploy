#!/usr/bin/env python3
"""Hosted CI only: verify exact candidate archives and scan offline; no deployment authority."""
import gzip, hashlib, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path("verification-source").resolve()))
from tools import verify_semantic_image_archive as archive
from tools import prepare_semantic_image_sbom as sbom
os.umask(0o077)
assert os.geteuid() == 0
lock = json.loads(Path("evidence/discovery-package-20261007.json").read_bytes())["report"]
assert lock["runId"] == "37658048241"
for name, expected in lock["archiveDigests"].items():
    assert hashlib.sha256((Path("package") / name).read_bytes()).hexdigest() == expected
root = Path("/root/ouf-discovery-scan")
root.mkdir(mode=0o700)
output = Path("scan-evidence").resolve()
output.mkdir()
rows = []
for role in ("semantic", "mcp"):
    with gzip.open(Path("package") / (role + ".image.tar.gz"), "rb") as stream:
        verified = archive.archive_verify(stream, lock["images"][role]["imageId"], archive.Budget(180, 2147483648, 100000))
    tar = root / (role + ".tar")
    with gzip.open(Path("package") / (role + ".image.tar.gz"), "rb") as source, tar.open("wb") as target:
        while chunk := source.read(65536):
            target.write(chunk)
    home = root / role
    home.mkdir(mode=0o700)
    env = {"PATH":"/usr/bin:/bin", "HOME":str(home), "XDG_CONFIG_HOME":str(home),
           "SYFT_CHECK_FOR_APP_UPDATE":"false", "SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP":"false"}
    syft = output / (role + ".syft.json")
    subprocess.run(["/usr/bin/unshare", "--net", "--", "/root/ouf-ci-vulnerability/syft",
                    "scan", "docker-archive:" + str(tar), "--quiet", "-o", "syft-json=" + str(syft)],
                   env=env, check=True, timeout=180)
    document = json.loads(syft.read_bytes())
    assert document["descriptor"]["version"] == "1.54.0"
    assert document["source"]["metadata"]["imageID"] == lock["images"][role]["imageId"]
    scanned = subprocess.run(["/usr/bin/python3", "-B", "verification-source/tests/scan_semantic_extended_inventory.py",
                              "--sbom", str(syft)], check=True, capture_output=True, timeout=400)
    report = json.loads(scanned.stdout)
    (output / (role + ".grype.json")).write_bytes(scanned.stdout)
    counts = {k:0 for k in ("Critical","High","Medium","Low","Negligible","Unknown")}
    for match in report["matches"]:
        counts[match["vulnerability"]["severity"]] += 1
    rows.append({"role":role, "imageId":lock["images"][role]["imageId"],
                 "archiveBytesVerified":True, "severityCounts":counts,
                 "packageCount":len(document["artifacts"]),
                 "packagesWithoutVersion":sum(not p.get("version") for p in document["artifacts"]),
                 "thresholdMet":not any(counts[k] for k in ("Critical","High","Unknown")) and not report.get("alertsByPackage")})
result = {"schema":"ouf.discovery.candidate-scan.v1", "producerRun":lock["runId"],
          "scannerSource":"84e91e199892bfda1d116a49f53a9990f61724c7",
          "networkIsolatedScanners":True, "images":rows,
          "allSeverityThresholdsMet":all(r["thresholdMet"] for r in rows),
          "acceptanceGranted":False, "publisherTrustAccepted":False, "releaseApplied":False}
(output / "inventory.json").write_text(json.dumps(result, indent=2) + "\n")
print("OUF_DISCOVERY_CANDIDATE_SCAN=" + json.dumps(result, sort_keys=True))
if not result["allSeverityThresholdsMet"]:
    raise SystemExit("CANDIDATE_SCAN_BLOCKED")
