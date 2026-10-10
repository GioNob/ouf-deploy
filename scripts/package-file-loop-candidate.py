#!/usr/bin/env python3
"""Prepare an unsigned, hashed offline image package; never applies to a host."""
import argparse, hashlib, json, pathlib, re, subprocess

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("phase", choices=["build", "export"])
    p.add_argument("--source", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--module", required=True, choices=["semantic", "ingestion", "udp"])
    p.add_argument("--output", required=True)
    a = p.parse_args()
    source = pathlib.Path(a.source).resolve()
    output = pathlib.Path(a.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not re.fullmatch(r"[0-9a-f]{40}", a.commit):
        raise SystemExit("EXACT_SOURCE_COMMIT_REQUIRED")
    if run("git", "-C", str(source), "rev-parse", "HEAD") != a.commit:
        raise SystemExit("SOURCE_COMMIT_MISMATCH")
    if run("git", "-C", str(source), "status", "--porcelain"):
        raise SystemExit("DIRTY_SOURCE_DENIED")
    tag = "ouf-cohort-" + a.module + ":" + a.commit
    record_path = output / "package-record.json"
    if a.phase == "build":
        original = (source / "Dockerfile").read_text()
        stages, bases, lines = set(), [], []
        for line in original.splitlines():
            if line.upper().startswith("FROM "):
                fields = line.split()
                if len(fields) not in (2, 4) or (len(fields) == 4 and fields[2].upper() != "AS"):
                    raise SystemExit("UNSUPPORTED_FROM_REQUIRES_REVIEW")
                ref = fields[1]
                if ref not in stages and ref != "scratch":
                    subprocess.run(["docker", "pull", ref], check=True)
                    data = json.loads(run("docker", "image", "inspect", ref))[0]
                    digests = data.get("RepoDigests", [])
                    if len(digests) != 1 or not re.search(r"@sha256:[0-9a-f]{64}$", digests[0]):
                        raise SystemExit("UNAMBIGUOUS_BASE_DIGEST_REQUIRED")
                    bases.append({"requested": ref, "resolved": digests[0], "imageId": data["Id"]})
                    fields[1] = digests[0]
                if len(fields) == 4:
                    stages.add(fields[3])
                line = " ".join(fields)
            lines.append(line)
        frozen = output / "Dockerfile.resolved"
        frozen.write_text("\n".join(lines) + "\n")
        subprocess.run(["docker", "build", "--label", "org.opencontainers.image.revision=" + a.commit,
                        "-f", str(frozen), "-t", tag, str(source)], check=True)
        image = json.loads(run("docker", "image", "inspect", tag))[0]
        if image["Config"].get("User") in ("", "0", "0:0", "root"):
            raise SystemExit("NON_ROOT_IMAGE_REQUIRED")
        write_json(record_path, {"schema": "ouf.unsigned-offline-candidate-package.v1",
                   "module": a.module, "sourceCommit": a.commit, "imageId": image["Id"],
                   "runtimeUser": image["Config"]["User"], "imageTag": tag,
                   "baseImages": bases, "notReleaseAcceptance": True,
                   "signatureIssued": False, "targetApplyAuthorized": False,
                   "vpsOperations": 0, "futureBuildByteReproducibilityProven": False})
    else:
        record = json.loads(record_path.read_text())
        if record["sourceCommit"] != a.commit or record["module"] != a.module:
            raise SystemExit("PACKAGE_RECORD_BINDING_MISMATCH")
        if run("docker", "image", "inspect", "--format", "{{.Id}}", tag) != record["imageId"]:
            raise SystemExit("IMAGE_CHANGED_AFTER_SCAN")
        scan = json.loads((output / "trivy-image.json").read_text())
        if scan.get("Metadata", {}).get("ImageID") != record["imageId"]:
            raise SystemExit("SCAN_IMAGE_BINDING_MISMATCH")
        rejected = [v for r in scan.get("Results", []) for v in r.get("Vulnerabilities", [])
                    if v.get("Severity") in ("HIGH", "CRITICAL", "UNKNOWN")]
        if rejected:
            raise SystemExit("IMAGE_VULNERABILITY_GATE_BLOCKED")
        subprocess.run(["docker", "save", "-o", str(output / "image.docker.tar"), tag], check=True)
        subprocess.run(["git", "-C", str(source), "archive", "--format=tar",
                        "-o", str(output / "source.tar"), a.commit], check=True)
        cid = run("docker", "create", tag)
        try:
            jar = "/app/application.jar" if a.module == "semantic" else "/app/app.jar"
            subprocess.run(["docker", "cp", cid + ":" + jar, str(output / "application.jar")], check=True)
        finally:
            subprocess.run(["docker", "rm", cid], check=True)
        inventory = []
        raw = subprocess.check_output(["git", "-C", str(source), "ls-tree", "-rz", a.commit])
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            metadata, path = entry.split(b"\t", 1)
            mode, kind, blob = metadata.decode().split()
            inventory.append({"path": path.decode(), "mode": mode, "type": kind, "sha": blob})
        write_json(output / "source-inventory.json", {"truncated": False, "tree": inventory})
        record["imageScanGate"] = "PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED"
        record["artifactFormat"] = "DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION"
        write_json(record_path, record)
        files = sorted(x for x in output.rglob("*") if x.is_file() and x.name != "SHA256SUMS")
        hashes = []
        for path in files:
            h = hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            hashes.append(h.hexdigest() + "  " + str(path.relative_to(output)))
        (output / "SHA256SUMS").write_text("\n".join(hashes) + "\n")

if __name__ == "__main__":
    main()
