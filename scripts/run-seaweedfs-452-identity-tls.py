#!/usr/bin/env python3
"""Synthetic identity/TLS/egress experiment on locked OCI15; NOT_ACCEPTANCE."""
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
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cold", ROOT / "scripts/run-seaweedfs-452-cold-recovery.py")
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)
require, command, write_json = cold.require, cold.command, cold.write_json
BUCKET = "ouf-identity-fixture"
OTHER = "ouf-identity-other"
OWNER = ("ouf-fixture-bootstrap", "public-bootstrap-fixture-not-production")
APP = ("ouf-fixture-prefix", "public-prefix-fixture-not-production")
HOST = "localhost:18333"
BODY = b"synthetic identity fixture\x00\xff\n"


def fixture_config():
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": ["arn:aws:s3:::" + BUCKET + "/staging/*"]},
        {"Effect": "Allow", "Action": ["s3:ListBucket"],
         "Resource": ["arn:aws:s3:::" + BUCKET],
         "Condition": {"StringLike": {"s3:prefix": ["staging/*"]}}},
    ]}
    return {"identities": [
        {"name": OWNER[0], "credentials": [{"accessKey": OWNER[0], "secretKey": OWNER[1]}],
         "actions": ["Admin:" + BUCKET, "Admin:" + OTHER]},
        {"name": APP[0], "credentials": [{"accessKey": APP[0], "secretKey": APP[1]}],
         "policyNames": ["SyntheticPrefixOnly"]},
    ], "policies": [{"name": "SyntheticPrefixOnly", "content": json.dumps(policy)}]}


def certificates(config):
    """Fresh disposable CA and localhost certificate; private keys never in evidence."""
    tls = config / "tls"
    tls.mkdir()
    for name in ("ca", "wrong-ca"):
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                 "-days", "2", "-subj", "/CN=OUF synthetic " + name,
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-keyout", str(tls / (name + ".key")), "-out", str(tls / (name + ".pem"))])
    command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-subj", "/CN=localhost", "-keyout", str(tls / "server.key"),
             "-out", str(tls / "server.csr")])
    (tls / "server.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                                   "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                   "extendedKeyUsage=serverAuth\n")
    command(["openssl", "x509", "-req", "-in", str(tls / "server.csr"),
             "-CA", str(tls / "ca.pem"), "-CAkey", str(tls / "ca.key"),
             "-set_serial", "1", "-days", "2", "-sha256", "-extfile", str(tls / "server.ext"),
             "-out", str(tls / "server.pem")])
    for key in tls.glob("*.key"):
        key.chmod(0o600)
    return tls


def signed_headers(method, path, query="", body=b"", credentials=APP, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = timestamp[:8]
    headers = {"host": HOST, "x-amz-date": timestamp, "x-amz-content-sha256": cold.digest(body)}
    names = ";".join(sorted(headers))
    canonical = "\n".join([method, path, query,
                            "".join(k + ":" + headers[k] + "\n" for k in sorted(headers)),
                            names, cold.digest(body)])
    scope = day + "/us-east-1/s3/aws4_request"
    string = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + cold.digest(canonical.encode())
    key = ("AWS4" + credentials[1]).encode()
    for value in (day, "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = ("AWS4-HMAC-SHA256 Credential=" + credentials[0] + "/" + scope
                                + ", SignedHeaders=" + names + ", Signature=" + signature)
    return headers


def request(tls, method, path, query=None, body=b"", credentials=APP, timeout=30):
    query = urlencode(sorted((query or {}).items()), quote_via=quote, safe="~")
    headers = signed_headers(method, path, query, body, credentials) if credentials else {"host": HOST}
    context = ssl.create_default_context(cafile=str(tls / "ca.pem"))
    connection = http.client.HTTPSConnection("localhost", 18333, timeout=timeout, context=context)
    try:
        connection.request(method, path + ("?" + query if query else ""), body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024 + 1)
        require(len(payload) <= 1024 * 1024, "RESPONSE_BUDGET")
        return response.status, payload
    finally:
        connection.close()


def check_response(status, body, expected, code=None):
    require(status == expected, "EXPECTED_HTTP_" + str(expected) + "_GOT_" + str(status))
    if code:
        require(ET.fromstring(body).findtext("Code") == code, "EXACT_S3_ERROR_REQUIRED:" + code)


def egress_probe():
    records = []
    # Called only after namespace routes and interfaces are proven loopback-only.
    for kind, port, label in ((socket.SOCK_STREAM, 443, "TCP"), (socket.SOCK_DGRAM, 53, "UDP")):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(1)
            try:
                if kind == socket.SOCK_STREAM:
                    code = sock.connect_ex(("192.0.2.1", port))
                else:
                    sock.sendto(b"OUF synthetic egress fixture", ("192.0.2.1", port))
                    code = 0
            except OSError as error:
                code = error.errno
        require(code in {errno.ENETUNREACH, errno.EHOSTUNREACH}, "EGRESS_NOT_ROUTE_DENIED:" + label)
        records.append({"transport": label, "destination": "192.0.2.1", "port": port,
                        "errno": code, "errnoName": errno.errorcode[code], "attempts": 1})
    return records


def tls_negative(tls, host, ca):
    context = ssl.create_default_context(cafile=str(tls / ca))
    connection = http.client.HTTPSConnection(host, 18333, timeout=5, context=context)
    try:
        connection.connect()
    except ssl.SSLCertVerificationError as error:
        return {"host": host, "ca": ca, "verificationRejected": True,
                "verifyCode": error.verify_code, "verifyMessage": error.verify_message}
    finally:
        connection.close()
    raise RuntimeError("INVALID_CERTIFICATE_ACCEPTED")


def client(action, tls):
    if action == "ready":
        deadline = time.monotonic() + 80
        for attempt in range(1, 61):
            try:
                status, body = request(tls, "GET", "/", credentials=OWNER,
                                       timeout=cold.remaining_timeout(deadline, failure_code="TLS_READINESS_BUDGET"))
                require(status in {200, 500, 502, 503, 504}, "PERMANENT_READINESS_HTTP_" + str(status))
                if status == 200:
                    cold.remaining_timeout(deadline, failure_code="TLS_READINESS_BUDGET")
                    return {"readOnlyAttempts": attempt, "trustedTLS": True}
            except ssl.SSLError:
                raise  # Never retry certificate/configuration failures.
            except OSError as error:
                require(isinstance(error, TimeoutError) or error.errno in
                        {errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT}, "UNKNOWN_READINESS_ERROR")
            time.sleep(cold.remaining_timeout(deadline, maximum=1, failure_code="TLS_READINESS_BUDGET"))
        raise RuntimeError("TLS_READINESS_BUDGET")
    records = []

    def probe(name, method, path, expected=200, code=None, **kwargs):
        status, body = request(tls, method, path, **kwargs)
        check_response(status, body, expected, code)
        records.append({"case": name, "method": method, "path": path,
                        "status": status, "errorCode": code, "attempts": 1})
        return body

    for bucket in (BUCKET, OTHER):
        probe("bootstrap-create-" + bucket, "PUT", "/" + bucket, credentials=OWNER)
        probe("bootstrap-protected-" + bucket, "PUT", "/" + bucket + "/protected.txt",
              body=b"owner protected", credentials=OWNER)
    path = "/" + BUCKET + "/staging/fixture.bin"
    probe("prefix-put", "PUT", path, body=BODY)
    require(probe("prefix-get", "GET", path) == BODY, "OBJECT_BYTES_MISMATCH")
    listing = probe("prefix-list", "GET", "/" + BUCKET, query={"list-type": "2", "prefix": "staging/"})
    ns = {"s": "http://s3.amazonaws.com/doc/2006-03-01/"}
    require([e.text for e in ET.fromstring(listing).findall("s:Contents/s:Key", ns)] == ["staging/fixture.bin"],
            "EXACT_PREFIX_LIST_REQUIRED")
    for name, method, key, query in (
        ("outside-prefix-get", "GET", "/" + BUCKET + "/protected.txt", None),
        ("outside-prefix-put", "PUT", "/" + BUCKET + "/outside.bin", None),
        ("other-bucket-get", "GET", "/" + OTHER + "/protected.txt", None),
        ("other-bucket-put", "PUT", "/" + OTHER + "/staging/no.bin", None),
        ("prefix-delete-not-granted", "DELETE", path, None),
        ("unscoped-list", "GET", "/" + BUCKET, {"list-type": "2"}),
        ("outside-list", "GET", "/" + BUCKET, {"list-type": "2", "prefix": "protected"}),
        ("bucket-versioning-prefix-escalation", "PUT", "/" + BUCKET, {"versioning": "", "prefix": "staging/"}),
        ("bucket-policy-admin", "GET", "/" + BUCKET, {"policy": ""}),
    ):
        body = (b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                b'<Status>Enabled</Status></VersioningConfiguration>') if name.startswith("bucket-versioning") else BODY
        probe(name, method, key, expected=403, code="AccessDenied", query=query,
              body=body if method == "PUT" else b"")
    for name, credentials, code in (
        ("anonymous", None, "AccessDenied"),
        ("unknown-access-key", ("unknown-synthetic-key", APP[1]), "InvalidAccessKeyId"),
        ("wrong-signature", (APP[0], "wrong-synthetic-secret"), "SignatureDoesNotMatch"),
    ):
        probe(name, "GET", path, expected=403, code=code, credentials=credentials)
    require(probe("denied-delete-preserved-object", "GET", path) == BODY, "DENIED_DELETE_CHANGED_OBJECT")
    require(probe("protected-object-preserved", "GET", "/" + BUCKET + "/protected.txt", credentials=OWNER)
            == b"owner protected", "PROTECTED_OBJECT_CHANGED")
    probe("denied-outside-put-created-no-object", "GET", "/" + BUCKET + "/outside.bin",
          credentials=OWNER, expected=404, code="NoSuchKey")
    probe("denied-other-bucket-put-created-no-object", "GET", "/" + OTHER + "/staging/no.bin",
          credentials=OWNER, expected=404, code="NoSuchKey")
    return {"cases": records, "applicationIdentityPolicy": "GetObject/PutObject staging/* and prefix-conditioned ListBucket",
            "tlsNegatives": [tls_negative(tls, "127.0.0.1", "ca.pem"),
                             tls_negative(tls, "localhost", "wrong-ca.pem")],
            "egress": egress_probe(), "mutatingRequestRetries": 0,
            "syntheticBodySha256": cold.digest(BODY)}


class Lab(cold.Lab):
    def start(self):
        commands = {
            "master": ["master", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=19333",
                       "-port.grpc=29333", "-mdir=/data", "-peers=none", "-telemetry=false",
                       "-volumeSizeLimitMB=32", "-defaultReplication=000"],
            "volume": ["volume", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18080",
                       "-port.grpc=28080", "-master=127.0.0.1:19333", "-dir=/data", "-max=24", "-preStopSeconds=1"],
            "filer": ["filer", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18888",
                      "-port.grpc=28888", "-master=127.0.0.1:19333", "-defaultStoreDir=/data"],
            "s3": ["s3", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18333", "-port.https=0",
                   "-port.iceberg=0", "-port.lance=0", "-filer=127.0.0.1:18888", "-config=/config/s3.json",
                   "-key.file=/config/tls/server.key", "-cert.file=/config/tls/server.pem"],
        }
        for role, args in commands.items():
            name = self.prefix + "-" + role
            network = "none" if role == "master" else "container:" + self.prefix + "-master"
            command(["docker", "run", "--detach", "--name", name, "--network", network,
                     "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m",
                     "--cpus", "1", "--log-opt", "max-size=8m",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,size=67108864,mode=1777",
                     "--mount", "type=bind,src=" + str(self.data / role) + ",dst=/data",
                     "--mount", "type=bind,src=" + str(self.data / "config") + ",dst=/config,readonly",
                     cold.IMAGE_ID, "-logtostderr=true", *args])
            self.names.append(name)
        snapshots = json.loads(command(["docker", "inspect", *self.names]))
        require(len(snapshots) == 4, "FOUR_ROLES_ONLY")
        for item in snapshots:
            host = item["HostConfig"]
            require(item["Image"] == cold.IMAGE_ID and item["Config"]["User"] == "65532:65532"
                    and host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
                    and not host["PortBindings"], "CONTAINER_ISOLATION_REQUIRED")
            role = item["Name"].rsplit("-", 1)[1]
            networks = {"none"} if role == "master" else {
                "container:" + snapshots[0]["Id"], "container:" + self.prefix + "-master"}
            require(host["NetworkMode"] in networks, "EXACT_NETWORK_NAMESPACE_REQUIRED")
            mounts = {m["Destination"]: m for m in item["Mounts"]}
            require(mounts["/data"]["Source"] == str(self.data / role)
                    and mounts["/config"]["Source"] == str(self.data / "config")
                    and mounts["/config"]["RW"] is False, "EXACT_FIXTURE_MOUNTS_REQUIRED")
        write_json(self.evidence / "containers.json", snapshots)
        self.pid = str(snapshots[0]["State"]["Pid"])
        base = ["sudo", "-n", "nsenter", "-t", self.pid, "-n", "ip", "-j"]
        routes = json.loads(command(base + ["route", "show", "table", "all"]))
        links = json.loads(command(base + ["link", "show"]))
        require(all(r.get("dev") == "lo" for r in routes)
                and [link["ifname"] for link in links] == ["lo"], "LOOPBACK_ONLY_BEFORE_PROBES")
        write_json(self.evidence / "network.json", {"routes": routes, "links": links})
        self.client("ready")
        deadline = time.monotonic() + 90
        for attempt in range(1, 61):
            state = json.loads(command(["docker", "inspect", self.prefix + "-filer"],
                                       timeout=cold.remaining_timeout(deadline)))[0]["State"]
            require(state["Running"] and not state["OOMKilled"], "FILER_EXITED_BEFORE_RING_READY")
            log = subprocess.run(["docker", "logs", "--tail", "200", self.prefix + "-filer"], check=True,
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=cold.remaining_timeout(deadline))
            cold.remaining_timeout(deadline)
            if cold.ready_lock_ring(log.stdout):
                write_json(self.evidence / "lock-ring-ready.json", {"readOnlyPolls": attempt,
                           "member": "127.0.0.1:18888", "mutatingProbes": 0})
                break
            time.sleep(cold.remaining_timeout(deadline, maximum=1))
        else:
            raise RuntimeError("LOCK_RING_READINESS_BUDGET")

    def client(self, action):
        try:
            output = command(["sudo", "-n", "nsenter", "-t", self.pid, "-n", sys.executable,
                              "-I", "-B", "-S", str(Path(__file__).resolve()), "client", action,
                              str(self.data / "config/tls")], timeout=90 if action == "ready" else 240)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            (self.evidence / ("client-" + action + "-stderr.log")).write_text(
                cold.bounded_diagnostic(error.stderr, "CLIENT_FAILED_WITHOUT_STDERR"))
            raise RuntimeError("CLIENT_FAILED:" + action) from error
        result = json.loads(output)
        write_json(self.evidence / ("client-" + action + ".json"), result)
        return result


def run(archive, work):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "ISOLATED_CI_ONLY")
    require(not work.exists() and not work.is_symlink(), "NEW_WORK_DIRECTORY_REQUIRED")
    work.mkdir(parents=True)
    evidence = work / "evidence"
    evidence.mkdir()
    lab = None
    try:
        write_json(evidence / "exact-image.json", cold.prepare_image(archive, work))
        data = work / "fixture"
        for role in ("master", "volume", "filer", "s3", "config"):
            (data / role).mkdir(parents=True)
        write_json(data / "config/s3.json", fixture_config())
        tls = certificates(data / "config")
        for name in ("ca.pem", "wrong-ca.pem", "server.pem"):
            (evidence / name).write_bytes((tls / name).read_bytes())
        write_json(evidence / "fixture-policy.json", fixture_config())
        command(["sudo", "-n", "chown", "-R", "65532:65532", str(data)])
        lab = Lab("ouf-identity-" + str(os.getpid()), data, evidence)
        lab.start()
        result = lab.client("verify")
        lab.stop()
        write_json(evidence / "identity-result.json", {
            "schema": "ouf.seaweedfs-452-identity-tls.v1", "status": "SYNTHETIC_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE",
            "candidateLockSha256": cold.LOCK_SHA, "ociManifestDigest": cold.MANIFEST,
            "binarySha256": cold.BINARY_SHA, "s3CasesPassed": len(result["cases"]),
            "tlsNegativesPassed": len(result["tlsNegatives"]), "egressProbesPassed": len(result["egress"]),
            "maximumContainers": 4, "network": "DOCKER_NONE_SHARED_LOOPBACK_ONLY_NO_PUBLISHED_PORTS",
            "fixtureCredentialsOnly": True, "mutatingRequestRetries": 0,
            "certificateRotation": "NOT_TESTED", "interRoleLateralIsolation": "NOT_TESTED",
            "mTLS": "NOT_TESTED", "publicInternetPolicy": "NOT_TESTED",
            "targetOperations": 0, "gatesClosed": 0, "acceptanceTestsPassed": 0,
            "releaseAdmitted": False, "runtimeAuthorityIssued": False,
        })
    except Exception as error:
        write_json(evidence / "identity-failure.json", {
            "status": "SYNTHETIC_IDENTITY_TLS_EGRESS_FAILED_NOT_ACCEPTANCE", "failureClass": type(error).__name__,
            "safeReason": str(error)[:512] if isinstance(error, RuntimeError) else "LOCAL_COMMAND_OR_IO_FAILED",
            "targetOperations": 0, "releaseAdmitted": False, "runtimeAuthorityIssued": False,
        })
        raise
    finally:
        if lab and lab.names:
            lab.stop(strict=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("archive", type=Path)
    run_parser.add_argument("work", type=Path)
    client_parser = sub.add_parser("client")
    client_parser.add_argument("action", choices=("ready", "verify"))
    client_parser.add_argument("tls", type=Path)
    args = parser.parse_args()
    if args.operation == "run":
        run(args.archive.resolve(), args.work.resolve())
    else:
        print(json.dumps(client(args.action, args.tls)))
