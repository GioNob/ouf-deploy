#!/usr/bin/env python3
"""Bounded, synthetic Docker-only cold recovery of the exact 4.52 OCI cohort.

This is a storage-only experiment, not a PostgreSQL recovery or target authority.
"""
import argparse
import datetime
import errno
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
LOCK_SHA = "81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea"
IMAGE_ID = "sha256:add1988121001fe6339a31635d5f61bc560b3c9a540da8027e376a4ebdf0df35"
MANIFEST = "sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4"
BINARY_SHA = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
ACCESS = "ouf-recovery-synthetic"
SECRET = "public-fixture-only-not-a-production-secret"
BUCKET = "ouf-recovery-fixture"
COMPAT_BUCKET = "ouf-recovery-mime-fixture"
RECOVERY_MIME = "application/x-ouf-recovery-fixture"
HOST = "127.0.0.1:18333"
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def command(args, timeout=60):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout).stdout.strip()


def signed_headers(method, path, query="", body=b"", extra=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = timestamp[:8]
    headers = {"host": HOST, "x-amz-date": timestamp,
               "x-amz-content-sha256": digest(body), **(extra or {})}
    names = ";".join(sorted(headers))
    canonical = "\n".join([method, path, query,
                            "".join(k + ":" + headers[k].strip() + "\n" for k in sorted(headers)),
                            names, digest(body)])
    scope = day + "/us-east-1/s3/aws4_request"
    string = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + digest(canonical.encode())
    key = ("AWS4" + SECRET).encode()
    for value in (day, "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = ("AWS4-HMAC-SHA256 Credential=" + ACCESS + "/" + scope
                                + ", SignedHeaders=" + names + ", Signature=" + signature)
    return headers


def request(method, key=None, body=b"", query=None, extra=None, expected=(200,), timeout=30,
            bucket=BUCKET):
    require(bucket in {BUCKET, COMPAT_BUCKET}, "FIXTURE_BUCKET_REQUIRED")
    path = "/" if key is None else "/" + bucket + ("/" + quote(key, safe="/~") if key else "")
    query = urlencode(sorted((query or {}).items()), quote_via=quote, safe="~")
    headers = signed_headers(method, path, query, body, extra)
    connection = http.client.HTTPConnection("127.0.0.1", 18333, timeout=timeout)
    try:
        connection.request(method, path + ("?" + query if query else ""), body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(16 * 1024 * 1024 + 1)
        require(len(payload) <= 16 * 1024 * 1024, "RESPONSE_BUDGET")
        require(response.status in expected, "HTTP_" + str(response.status) + "_" + method)
        return payload, {k.lower(): v for k, v in response.getheaders()}
    finally:
        connection.close()


def fixtures():
    return {"empty": b"", "unicode/città + %.txt": "Trieste è una città\n".encode(),
            "overwritten.bin": b"final-confirmed-version\x00\xff",
            "large.bin": bytes(range(256)) * 32768}


def check_content_type(key, method, headers, expected):
    observed = headers.get("content-type")
    require(observed == expected, "CONTENT_TYPE_MISMATCH:" + json.dumps({
        "key": key, "method": method, "expected": expected, "observed": observed,
    }, sort_keys=True))


def probe_octet_stream(action):
    """Distinct, finite compatibility result; mismatch never becomes a PASS."""
    key, body = "octet-stream.txt", b"public octet-stream MIME compatibility fixture\n"
    expected = "application/octet-stream"
    if action == "seed":
        request("PUT", "", bucket=COMPAT_BUCKET)
        request("PUT", key, body, bucket=COMPAT_BUCKET, extra={
            "content-type": expected, "x-amz-meta-ouf-content-hash": digest(body),
        })
    actual, get_headers = request("GET", key, bucket=COMPAT_BUCKET)
    _, head_headers = request("HEAD", key, bucket=COMPAT_BUCKET)
    require(actual == body, "COMPAT_PROBE_BODY_MISMATCH")
    for method, headers in (("GET", get_headers), ("HEAD", head_headers)):
        require(headers.get("x-amz-meta-ouf-content-hash") == digest(body),
                "COMPAT_PROBE_METADATA_MISMATCH:" + method)
        require(int(headers["content-length"]) == len(body),
                "COMPAT_PROBE_LENGTH_MISMATCH:" + method)
    findings = [{"key": key, "method": method, "expected": expected,
                 "observed": headers.get("content-type")}
                for method, headers in (("GET", get_headers), ("HEAD", head_headers))
                if headers.get("content-type") != expected]
    return {"status": "FAIL" if findings else "PASS", "bucket": COMPAT_BUCKET,
            "key": key, "requestedContentType": expected,
            "getContentType": get_headers.get("content-type"),
            "headContentType": head_headers.get("content-type"),
            "findings": findings, "bytes": len(body), "sha256": digest(body),
            "g2Closed": False, "mutatingRequestRetries": 0}


def client(action):
    if action == "ready":
        # Only this read-only readiness probe retries; mutations below never do.
        deadline = time.monotonic() + 90
        attempts = 0
        while attempts < 60 and time.monotonic() < deadline:
            attempts += 1
            try:
                request("GET", timeout=remaining_timeout(
                    deadline, failure_code="HTTP_READINESS_BUDGET"))
            except RuntimeError as error:
                require(str(error) in {"HTTP_500_GET", "HTTP_502_GET", "HTTP_503_GET", "HTTP_504_GET"},
                        "PERMANENT_READINESS_FAILURE:" + str(error))
            except OSError as error:
                require(isinstance(error, TimeoutError) or error.errno in
                        {errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT},
                        "UNCLASSIFIED_READINESS_FAILURE")
            else:
                remaining_timeout(deadline, failure_code="HTTP_READINESS_BUDGET")
                return {"readinessAttempts": attempts}
            time.sleep(remaining_timeout(deadline, maximum=1,
                                         failure_code="HTTP_READINESS_BUDGET"))
        raise RuntimeError("BOUNDED_READINESS_EXHAUSTED")
    values = fixtures()
    if action == "seed":
        request("PUT", "", expected=(200,))
        request("PUT", "overwritten.bin", b"superseded")
        request("PUT", "deleted.bin", b"to-be-deleted")
        for key, body in values.items():
            request("PUT", key, body, extra={"content-type": RECOVERY_MIME,
                                             "x-amz-meta-ouf-content-hash": digest(body)})
        request("DELETE", "deleted.bin", expected=(204,))
    seen, token, pages = [], None, 0
    while True:
        query = {"list-type": "2", "max-keys": "2"}
        if token:
            query["continuation-token"] = token
        body, _ = request("GET", "", query=query)
        root = ET.fromstring(body)
        namespace = {"s": "http://s3.amazonaws.com/doc/2006-03-01/"}
        seen.extend(item.text for item in root.findall("s:Contents/s:Key", namespace))
        pages += 1
        require(pages <= 4, "PAGINATION_BUDGET")
        if root.findtext("s:IsTruncated", namespaces=namespace) != "true":
            break
        next_token = root.findtext("s:NextContinuationToken", namespaces=namespace)
        require(next_token and next_token != token, "PAGINATION_PROGRESS_REQUIRED")
        token = next_token
    require(len(seen) == len(set(seen)) and set(seen) == set(values), "EXACT_OBJECT_SET_REQUIRED")
    records = []
    for key, expected in sorted(values.items()):
        actual, headers = request("GET", key)
        require(actual == expected, "BODY_MISMATCH")
        require(headers.get("x-amz-meta-ouf-content-hash") == digest(expected), "METADATA_MISMATCH")
        check_content_type(key, "GET", headers, RECOVERY_MIME)
        _, head = request("HEAD", key)
        require(int(head["content-length"]) == len(expected), "HEAD_LENGTH_MISMATCH")
        require(head.get("x-amz-meta-ouf-content-hash") == digest(expected), "HEAD_METADATA_MISMATCH")
        check_content_type(key, "HEAD", head, RECOVERY_MIME)
        records.append({"key": key, "bytes": len(expected), "sha256": digest(expected),
                        "getContentType": headers["content-type"], "headContentType": head["content-type"]})
    request("GET", "deleted.bin", expected=(404,))
    return {"action": action, "objects": records, "listPages": pages,
            "deletedObjectAbsent": True, "mutatingRequestRetries": 0,
            "octetStreamCompatibility": probe_octet_stream(action)}


def ready_lock_ring(log):
    """Pinned upstream's applied-ring event; LIST readiness alone precedes this."""
    rings = re.findall(r"LockRing: applying master ring update v[0-9]+: \[([^\]\r\n]*)\]", log)
    return bool(rings) and rings[-1] == "127.0.0.1:18888"


def bounded_diagnostic(stderr, fallback):
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    value = stderr or fallback
    return value.encode("utf-8")[-32768:].decode("utf-8", errors="ignore")


def remaining_timeout(deadline, maximum=5, failure_code="LOCK_RING_READINESS_BUDGET"):
    remaining = deadline - time.monotonic()
    require(remaining > 0, failure_code)
    return min(maximum, remaining)


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), "REGULAR_ROOT_REQUIRED")
    records, total = {}, 0
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), "SYMLINK_FORBIDDEN")
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), "REGULAR_FILES_ONLY")
        size = path.stat().st_size
        require(size <= MAX_FILE, "FILE_BUDGET")
        total += size
        require(total <= MAX_TOTAL and len(records) < 10000, "BACKUP_BUDGET")
        records[path.relative_to(root).as_posix()] = {"bytes": size, "sha256": file_digest(path)}
    require(records, "EMPTY_BACKUP_FORBIDDEN")
    return records


def cold_copy(source, destination):
    require(source.resolve() != destination.resolve()
            and source.resolve() not in destination.resolve().parents
            and destination.resolve() not in source.resolve().parents,
            "INDEPENDENT_ROOT_REQUIRED")
    require(not destination.exists(), "EMPTY_NEW_DESTINATION_REQUIRED")
    before = inventory(source)
    shutil.copytree(source, destination, symlinks=False)
    require(inventory(destination) == before == inventory(source), "COLD_COPY_MISMATCH")
    return before


def prepare_image(archive, work):
    lock_path = ROOT / "releases/seaweedfs-452-candidate-lock-20261103.json"
    require(file_digest(lock_path) == LOCK_SHA, "EXACT_LOCK_REQUIRED")
    lock = json.loads(lock_path.read_bytes())
    require(archive.stat().st_size == lock["producerArtifact"]["bytes"]
            and file_digest(archive) == lock["producerArtifact"]["digest"].removeprefix("sha256:"),
            "EXACT_PRODUCER_ARCHIVE_REQUIRED")
    spec = importlib.util.spec_from_file_location("recovery_readback", ROOT / "scripts/readback-seaweedfs-452-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image_root = work / "image"
    image_root.mkdir()
    module.unpack(archive, image_root)
    record = module.candidate.image.verify_layout(image_root, profile=module.candidate.PROFILE)
    require(record["manifestDigest"] == MANIFEST and record["configDigest"] == IMAGE_ID
            and record["binarySha256"] == BINARY_SHA, "EXACT_OCI_REQUIRED")
    require(file_digest(image_root / "runtime.docker.tar") == lock["image"]["dockerArchiveSha256"],
            "EXACT_DOCKER_ARCHIVE_REQUIRED")
    command(["docker", "load", "--input", str(image_root / "runtime.docker.tar")], timeout=120)
    require(command(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_ID]) == IMAGE_ID,
            "DAEMON_IMAGE_CHANGED")
    return record


class Lab:
    def __init__(self, prefix, data, evidence):
        self.prefix, self.data, self.evidence = prefix, data, evidence
        self.names = []

    def start(self):
        commands = {
            "master": ["master", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=19333",
                       "-port.grpc=29333", "-mdir=/data", "-peers=none", "-telemetry=false",
                       "-volumeSizeLimitMB=32", "-defaultReplication=000"],
            "volume": ["volume", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18080",
                       "-port.grpc=28080", "-master=127.0.0.1:19333", "-dir=/data", "-max=24",
                       "-preStopSeconds=1"],
            "filer": ["filer", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18888",
                      "-port.grpc=28888", "-master=127.0.0.1:19333", "-defaultStoreDir=/data"],
            "s3": ["s3", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18333",
                   "-port.iceberg=0", "-port.lance=0", "-filer=127.0.0.1:18888", "-config=/config/s3.json"],
        }
        for role, args in commands.items():
            name = self.prefix + "-" + role
            network = "none" if role == "master" else "container:" + self.prefix + "-master"
            command(["docker", "run", "--detach", "--name", name, "--network", network,
                     "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--pids-limit", "128",
                     "--memory", "512m", "--cpus", "1", "--log-opt", "max-size=8m",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,size=67108864,mode=1777",
                     "--mount", "type=bind,src=" + str(self.data / role) + ",dst=/data",
                     "--mount", "type=bind,src=" + str(self.data / "config") + ",dst=/config,readonly",
                     IMAGE_ID, "-logtostderr=true", *args])
            self.names.append(name)
        snapshots = json.loads(command(["docker", "inspect", *self.names]))
        for item in snapshots:
            require(item["Image"] == IMAGE_ID and item["Config"]["User"] == "65532:65532"
                    and item["HostConfig"]["ReadonlyRootfs"]
                    and item["HostConfig"]["CapDrop"] == ["ALL"]
                    and not item["HostConfig"]["PortBindings"], "CONTAINER_ISOLATION_REQUIRED")
            mounts = {m["Destination"]: m for m in item["Mounts"]}
            role = item["Name"].rsplit("-", 1)[1]
            expected_networks = {"none"} if role == "master" else {
                "container:" + snapshots[0]["Id"], "container:" + self.prefix + "-master"}
            require(item["HostConfig"]["NetworkMode"] in expected_networks,
                    "EXACT_NETWORK_NAMESPACE_REQUIRED")
            require(mounts["/data"]["Source"] == str(self.data / role)
                    and mounts["/config"]["Source"] == str(self.data / "config")
                    and mounts["/config"]["RW"] is False, "EXACT_GENERATION_MOUNTS_REQUIRED")
        write_json(self.evidence / (self.prefix + "-containers.json"), snapshots)
        self.pid = str(snapshots[0]["State"]["Pid"])
        routes = command(["sudo", "-n", "nsenter", "-t", self.pid, "-n", "ip", "-j", "route", "show", "table", "all"])
        route_records = json.loads(routes)
        require(all(r.get("dev") == "lo" for r in route_records), "LOOPBACK_ROUTES_ONLY")
        write_json(self.evidence / (self.prefix + "-routes.json"), route_records)
        self.client("ready")
        # Read-only startup precondition: the pinned filer must have applied its
        # own ring membership before the sole writer is admitted. No PUT probe.
        deadline = time.monotonic() + 90
        for attempt in range(1, 61):
            state = json.loads(command(["docker", "inspect", self.prefix + "-filer"],
                                       timeout=remaining_timeout(deadline)))[0]["State"]
            require(state["Running"] and not state["OOMKilled"], "FILER_EXITED_BEFORE_RING_READY")
            result = subprocess.run(["docker", "logs", "--tail", "200", self.prefix + "-filer"],
                                    check=True, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=remaining_timeout(deadline))
            remaining_timeout(deadline)
            if ready_lock_ring(result.stdout):
                write_json(self.evidence / (self.prefix + "-lock-ring-ready.json"), {
                    "readOnlyPolls": attempt, "member": "127.0.0.1:18888",
                    "evidence": "PINNED_FILER_APPLIED_RING_LOG_EVENT", "mutatingProbes": 0,
                })
                break
            time.sleep(remaining_timeout(deadline, maximum=1))
        else:
            raise RuntimeError("LOCK_RING_READINESS_BUDGET")

    def client(self, action):
        try:
            output = command(["sudo", "-n", "nsenter", "-t", self.pid, "-n",
                              sys.executable, "-I", "-B", "-S", str(Path(__file__).resolve()),
                              "client", action], timeout=90 if action == "ready" else 180)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            (self.evidence / (self.prefix + "-client-" + action + "-stderr.log")).write_text(
                bounded_diagnostic(error.stderr, "CHILD_TIMEOUT_NO_STDERR" if timed_out
                                   else "CHILD_FAILURE_NO_STDERR"))
            raise RuntimeError(("CLIENT_ACTION_TIMED_OUT:" if timed_out else "CLIENT_ACTION_FAILED:")
                               + action) from error
        result = json.loads(output)
        write_json(self.evidence / (self.prefix + "-" + action + ".json"), result)
        return result

    def stop(self, strict=True):
        errors = []
        for name in reversed(self.names):
            try:
                command(["docker", "stop", "--time", "30", name], timeout=40)
                item = json.loads(command(["docker", "inspect", name]))[0]
                log = subprocess.run(["docker", "logs", name], check=True, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                (self.evidence / (name + ".log")).write_text(log.stdout)
                write_json(self.evidence / (name + "-stopped.json"), item["State"])
                if strict:
                    require(not item["State"]["Running"] and item["State"]["ExitCode"] == 0,
                            "CLEAN_STOP_REQUIRED:" + name)
            except Exception as error:
                errors.append(str(error))
            finally:
                try:
                    command(["docker", "rm", "--force", name])
                except Exception as error:
                    errors.append(str(error))
        self.names = []
        require(not errors or not strict, "STOP_OR_CLEANUP_FAILED:" + ";".join(errors))


def run(archive, work):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "ISOLATED_CI_ONLY")
    require(not work.exists() and not work.is_symlink(), "NEW_WORK_DIRECTORY_REQUIRED")
    work.mkdir(parents=True)
    evidence = work / "evidence"
    evidence.mkdir()
    record = prepare_image(archive, work)
    write_json(evidence / "exact-image.json", record)
    original = work / "original"
    for role in ("master", "filer", "volume", "s3", "config"):
        (original / role).mkdir(parents=True)
    write_json(original / "config/s3.json", {"identities": [{"name": ACCESS,
               "credentials": [{"accessKey": ACCESS, "secretKey": SECRET}],
               "actions": ["Admin", "Read", "Write", "List", "Tagging"]}]})
    command(["sudo", "-n", "chown", "-R", "65532:65532", str(original)])
    prefix = "ouf-cold-" + str(os.getpid())
    first = Lab(prefix + "-original", original, evidence)
    second = None
    try:
        first.start()
        before = first.client("seed")
        # The sole finite writer has returned; cleanly stop every service before copying.
        first.stop()
        require(not first.names, "ALL_WRITERS_AND_SERVICES_STOPPED_REQUIRED")
        command(["sudo", "-n", "chown", "-R", str(os.getuid()) + ":" + str(os.getgid()), str(original)])
        backup = work / "cold-backup"
        manifest = cold_copy(original, backup)
        require(any(k.startswith("filer/") for k in manifest)
                and any(k.startswith("volume/") and k.endswith(".dat") for k in manifest),
                "PERSISTENT_FILER_AND_VOLUME_DATA_REQUIRED")
        write_json(evidence / "cold-backup-manifest.json", manifest)
        original.rename(work / "withheld-original")
        restored = work / "restored"
        require(cold_copy(backup, restored) == manifest, "RESTORED_BYTES_REQUIRED")
        command(["sudo", "-n", "chown", "-R", "65532:65532", str(restored)])
        second = Lab(prefix + "-restored", restored, evidence)
        start = time.monotonic()
        second.start()
        after = second.client("verify")
        require(before["objects"] == after["objects"], "INDEPENDENT_RESTORE_OBJECT_PARITY_REQUIRED")
        require(before["octetStreamCompatibility"] == after["octetStreamCompatibility"],
                "COMPATIBILITY_PROBE_RESTORE_PARITY_REQUIRED")
        duration = round(time.monotonic() - start, 3)
        second.stop()
        write_json(evidence / "recovery-result.json", {
            "schema": "ouf.seaweedfs-452-storage-cold-recovery.v1",
            "status": "SYNTHETIC_STORAGE_COLD_RESTORE_PASS_NOT_ACCEPTANCE",
            "candidateLockSha256": LOCK_SHA, "ociManifestDigest": MANIFEST,
            "binarySha256": BINARY_SHA, "syntheticObjects": len(after["objects"]) + 1,
            "dataRecoveryFixtures": len(after["objects"]), "mimeCompatibilityFixtures": 1,
            "syntheticBytes": sum(r["bytes"] for r in after["objects"])
                              + after["octetStreamCompatibility"]["bytes"],
            "explicitRecoveryMimePreserved": RECOVERY_MIME,
            "octetStreamCompatibility": after["octetStreamCompatibility"],
            "s3MetadataCompatibilityQualified": False, "g2Closed": False,
            "backupFiles": len(manifest), "allBodiesAndHashMetadataEqual": True,
            "overwritePreserved": True, "deletedObjectAbsent": True,
            "originalContainersRemoved": True, "restoreUsesOnlyIndependentRoots": True,
            "fourSeparateRoles": True, "nonrootReadOnlyContainers": True,
            "network": "DOCKER_NONE_SHARED_LOOPBACK_ONLY_NO_PUBLISHED_PORTS",
            "syntheticRecoveryObservationSeconds": duration,
            "postgresRecovery": "NOT_TESTED", "tlsAndRotation": "NOT_TESTED",
            "crashOrPowerLoss": "NOT_TESTED", "rpoAcceptance": False, "rtoAcceptance": False,
            "fullFoundationBackupContractSatisfied": False,
            "foundationProfileMaterializedVerbatim": False,
            "releaseAdmitted": False, "runtimeAuthorityIssued": False,
            "targetOperations": 0, "gatesClosed": 0, "acceptanceTestsPassed": 0,
        })
    except Exception as error:
        write_json(evidence / "recovery-failure.json", {
            "status": "SYNTHETIC_COLD_RECOVERY_FAILED_NO_ACCEPTANCE",
            "failureClass": type(error).__name__,
            "safeReason": str(error)[:512] if isinstance(error, RuntimeError) else "LOCAL_COMMAND_OR_IO_FAILED",
            "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
        })
        raise
    finally:
        for lab in (second, first):
            if lab and lab.names:
                try:
                    lab.stop(strict=False)
                except Exception:
                    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    remote = sub.add_parser("run")
    remote.add_argument("archive", type=Path)
    remote.add_argument("work", type=Path)
    inner = sub.add_parser("client")
    inner.add_argument("action", choices=("ready", "seed", "verify"))
    args = parser.parse_args()
    if args.command == "client":
        print(json.dumps(client(args.action)))
    else:
        try:
            run(args.archive.resolve(), args.work.absolute())
        except Exception as error:
            # Includes acquisition/identity failures that occur before any service starts.
            evidence = args.work.absolute() / "evidence"
            if evidence.is_dir() and not (evidence / "recovery-failure.json").exists():
                write_json(evidence / "recovery-failure.json", {
                    "status": "SYNTHETIC_COLD_RECOVERY_FAILED_NO_ACCEPTANCE",
                    "failureClass": type(error).__name__,
                    "safeReason": str(error)[:512] if isinstance(error, RuntimeError) else "LOCAL_COMMAND_OR_IO_FAILED",
                    "releaseAdmitted": False, "runtimeAuthorityIssued": False, "targetOperations": 0,
                })
            raise

