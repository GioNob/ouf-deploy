#!/usr/bin/env python3
"""Hosted CI only: verify exact candidate archives and scan offline; no deployment authority."""
import base64, gzip, hashlib, json, os, subprocess, sys, tarfile
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
def verify_general_image(path, expected_id):
    # Read archive members only; no rootfs files are extracted or executed.
    blobs, names = {}, set()
    with tarfile.open(path, "r:") as bundle:
        members = bundle.getmembers()
        assert len(members) <= 512
        for entry in members:
            name = archive.path_name(entry.name)
            assert name not in names
            names.add(name)
            if entry.isdir():
                continue
            assert entry.isfile() and 0 <= entry.size <= 2147483648
            source = bundle.extractfile(entry)
            prefix = source.read(min(entry.size, 512))
            h = hashlib.sha256(prefix)
            metadata = prefix.lstrip().startswith((b"{", b"["))
            chunks = [prefix] if metadata else []
            if metadata:
                assert entry.size <= 2097152
            while chunk := source.read(65536):
                h.update(chunk)
                if metadata:
                    chunks.append(chunk)
            row = {"sha256":h.hexdigest(), "size":entry.size}
            if name.startswith("blobs/sha256/"):
                assert name == "blobs/sha256/" + row["sha256"]
            if metadata:
                row["json"] = archive.json_bytes(b"".join(chunks))
            else:
                stream = bundle.extractfile(entry)
                if prefix.startswith(bytes.fromhex("1f8b")):
                    stream = gzip.GzipFile(fileobj=stream)
                diff = hashlib.sha256()
                size = 0
                while chunk := stream.read(65536):
                    size += len(chunk)
                    assert size <= 2147483648
                    diff.update(chunk)
                row["diffId"] = "sha256:" + diff.hexdigest()
            blobs[name] = row
        manifests = blobs["manifest.json"]["json"]
        assert len(manifests) == 1
        item = manifests[0]
        config = blobs[archive.path_name(item["Config"])]
        doc = config["json"]
        layers = item["Layers"]
        diffs = doc["rootfs"]["diff_ids"]
        assert doc["rootfs"]["type"] == "layers"
        assert len(layers) == len(diffs) and 1 <= len(layers) <= 256
        assert len(set(layers)) == len(layers)
        assert (doc["os"], doc["architecture"]) == ("linux", "amd64")
        for name, expected in zip(layers, diffs):
            assert blobs[archive.path_name(name)]["diffId"] == expected
        kind = archive.image_identity_binding(blobs, expected_id, config, layers, ("linux", "amd64"))
        return {"configByteSha256":config["sha256"], "imageIdentityBindingKind":kind}

root = Path("/root/ouf-discovery-scan")
root.mkdir(mode=0o700)
output = Path("scan-evidence").resolve()
output.mkdir()
rows = []
for role in ("semantic", "mcp"):
    tar = root / (role + ".tar")
    with gzip.open(Path("package") / (role + ".image.tar.gz"), "rb") as source, tar.open("wb") as target:
        while chunk := source.read(65536):
            target.write(chunk)
    verified = verify_general_image(tar, lock["images"][role]["imageId"])
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
    assert document["source"]["type"] == "image"
    assert document["source"]["metadata"]["imageID"] == "sha256:" + verified["configByteSha256"]
    assert hashlib.sha256(base64.b64decode(document["source"]["metadata"]["config"], validate=True)).hexdigest() == verified["configByteSha256"]
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
