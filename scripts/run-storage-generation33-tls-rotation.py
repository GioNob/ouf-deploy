#!/usr/bin/env python3
"""Exact OCI33 fixture: staged TLS trust and bounded S3 gateway replacement.

One finite synthetic writer, then only reads. This is neither hot reload,
zero downtime, mTLS, S3 credential rotation nor target acceptance.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = Path(__file__).resolve()
LOCK_SHA = "c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8"
COHORT_SHA = "5b28de1dd43fca337064d41439d302d53dc7f470640fe3fc0d8d1292b1ec02dc"
COHORT_ARTIFACT_ID = 13305200887
COHORT_ARCHIVE_SHA = "5a8a59be0d0ee6230322e4828cc1edef5ca1e24689dc2ff7f19ede830203430e"
COHORT_ARCHIVE_BYTES = 127980
BODY = b"OUF synthetic TLS rotation, identical durable object before and after\x00\xff\n"
KEY = "staging/tls-rotation.bin"
MIME = "application/octet-stream"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


labs = load("generation33_labs_for_rotation", ROOT / "scripts/run-seaweedfs-452-generation33-labs.py")
require = labs.require


def sha(data): return hashlib.sha256(data).hexdigest()


def binding(receipt):
    return labs.preflight(LOCK_SHA, COHORT_SHA, cohort_path=receipt)


def configure(bound):
    # Both original harness files remain byte-for-byte frozen by binding.load.
    return labs.configured_harness("identity", bound)


def certificate_identity(path):
    raw = path.read_text()
    der = ssl.PEM_cert_to_DER_cert(raw)
    serial = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-serial"],
                            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    require(serial.startswith("serial=") and len(serial) <= 128, "CERTIFICATE_SERIAL_REQUIRED")
    return {"pemSha256": sha(raw.encode()), "derSha256": sha(der), "serialHex": serial[7:]}


def make_certificates(config, command):
    """Disposable public fixtures; all private keys stay under fixture roots."""
    records = {}
    for generation, directory, serial in (("a", "tls", "101"), ("b", "tls-next", "202")):
        dest = config / directory; dest.mkdir(mode=0o755)
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                 "-days", "2", "-subj", "/CN=OUF synthetic rotation " + generation,
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-keyout", str(dest / "ca.key"), "-out", str(dest / "ca.pem")])
        command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                 "-subj", "/CN=localhost", "-keyout", str(dest / "server.key"),
                 "-out", str(dest / "server.csr")])
        (dest / "server.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                                        "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                        "extendedKeyUsage=serverAuth\n")
        command(["openssl", "x509", "-req", "-in", str(dest / "server.csr"), "-CA", str(dest / "ca.pem"),
                 "-CAkey", str(dest / "ca.key"), "-set_serial", serial, "-days", "2", "-sha256",
                 "-extfile", str(dest / "server.ext"), "-out", str(dest / "server.pem")])
        for key in dest.glob("*.key"): key.chmod(0o600)
        records[generation] = {"ca": certificate_identity(dest / "ca.pem"),
                               "leaf": certificate_identity(dest / "server.pem")}
    require(records["a"]["ca"]["derSha256"] != records["b"]["ca"]["derSha256"]
            and records["a"]["leaf"]["derSha256"] != records["b"]["leaf"]["derSha256"],
            "INDEPENDENT_ROTATION_CERTIFICATES_REQUIRED")
    (config / "ca-overlap.pem").write_bytes((config / "tls/ca.pem").read_bytes()
                                          + (config / "tls-next/ca.pem").read_bytes())
    return records


def trust_file(config, trust):
    paths = {"a": "tls/ca.pem", "b": "tls-next/ca.pem", "overlap": "ca-overlap.pem"}
    require(trust in paths, "KNOWN_TRUST_GENERATION_REQUIRED")
    return config / paths[trust]


def request(module, config, trust, generation, method, path, body=b"", owner=False):
    require(method in {"GET", "HEAD", "PUT"}, "BOUNDED_FIXTURE_HTTP_METHOD_REQUIRED")
    context = ssl.create_default_context(cafile=str(trust_file(config, trust)))
    conn = http.client.HTTPSConnection("localhost", 18333, timeout=15, context=context)
    try:
        conn.connect()
        leaf = sha(conn.sock.getpeercert(binary_form=True))
        expected = certificate_identity(config / ("tls" if generation == "a" else "tls-next") / "server.pem")
        require(leaf == expected["derSha256"], "UNEXPECTED_PRESENTED_CERTIFICATE")
        bare, _, query = path.partition("?")
        headers = module.signed_headers(method, bare, query, body,
                                         module.OWNER if owner else module.APP)
        headers["content-type"] = MIME
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse(); payload = response.read(1024 * 1024 + 1)
        require(len(payload) <= 1024 * 1024 and response.status == 200, "FIXTURE_HTTP_RESPONSE_REJECTED")
        return {"status": response.status, "headers": {k.lower():v for k,v in response.getheaders()},
                "body": payload, "peerCertificateSha256": leaf}
    finally:
        conn.close()


def denied(config, trust, hostname="localhost"):
    context = ssl.create_default_context(cafile=str(trust_file(config, trust)))
    connection = http.client.HTTPSConnection(hostname, 18333, timeout=5, context=context)
    try:
        connection.connect()
    except ssl.SSLCertVerificationError as error:
        return {"trust": trust, "hostname": hostname, "verificationRejected": True,
                "verifyCode": error.verify_code, "attempts": 1}
    finally:
        connection.close()
    raise ValueError("WRONG_TRUST_OR_HOSTNAME_ACCEPTED")


def object_evidence(result, method):
    headers = result["headers"]
    require(int(headers["content-length"]) == len(BODY) and headers.get("content-type") == MIME,
            "ROTATION_OBJECT_METADATA_MISMATCH")
    if method == "GET": require(result["body"] == BODY, "ROTATION_OBJECT_BODY_MISMATCH")
    else: require(result["body"] == b"", "HEAD_MUST_NOT_RETURN_BODY")
    return {"method": method, "bytes": len(BODY), "bodySha256": sha(BODY),
            "contentType": MIME, "peerCertificateSha256": result["peerCertificateSha256"]}


def verify_stage(module, config, generation, requester=request, rejector=denied):
    require(generation in {"a", "b"}, "KNOWN_CERTIFICATE_GENERATION_REQUIRED")
    path = "/" + module.BUCKET + "/" + KEY
    positives = []
    for trust in (generation, "overlap"):
        reads = [object_evidence(requester(module, config, trust, generation, method, path), method)
                 for method in ("GET", "HEAD")]
        require(reads[0]["peerCertificateSha256"] == reads[1]["peerCertificateSha256"],
                "INCONSISTENT_PEER_CERTIFICATE")
        positives.append({"trust": trust, "hostname": "localhost", "reads": reads})
    listing = requester(module, config, generation, generation, "GET",
                        "/" + module.BUCKET + "?list-type=2&prefix=staging%2F")
    ns={"s":"http://s3.amazonaws.com/doc/2006-03-01/"}; root=ET.fromstring(listing["body"])
    require([x.text for x in root.findall("s:Contents/s:Key",ns)] == [KEY]
            and root.findtext("s:IsTruncated", namespaces=ns) == "false", "ROTATION_EXACT_LIST_REQUIRED")
    opposite = "b" if generation == "a" else "a"
    negatives=[rejector(config, opposite), rejector(config, generation, "127.0.0.1")]
    require(all(n["verificationRejected"] is True for n in negatives), "TLS_REJECTION_REQUIRED")
    return {"certificateGeneration": generation, "positiveTrustCases": positives, "negativeTrustCases": negatives,
            "object": {"key":KEY,"bytes":len(BODY),"sha256":sha(BODY),"contentType":MIME},
            "listKeys":[KEY],"mutatingRequests":0,"mutatingRequestRetries":0}


def client(module, config, action):
    if action in {"ready-a", "ready-b"}:
        return module.client("ready", config / ("tls" if action == "ready-a" else "tls-next"))
    require(action in {"seed", "verify-b"}, "KNOWN_ROTATION_ACTION_REQUIRED")
    if action == "seed":
        request(module, config, "a", "a", "PUT", "/" + module.BUCKET, owner=True)
        request(module, config, "a", "a", "PUT", "/" + module.BUCKET + "/" + KEY, BODY)
    result = verify_stage(module, config, "a" if action == "seed" else "b")
    result["mutatingRequests"] = 2 if action == "seed" else 0
    return result


def replacement_argv(lab, image_id):
    name = lab.prefix + "-s3-next"
    return ["docker", "run", "--detach", "--name", name, "--network", "container:" + lab.prefix + "-master",
            "--user", "65532:65532", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--log-opt", "max-size=8m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=67108864,mode=1777",
            "--mount", "type=bind,src=" + str(lab.data / "s3") + ",dst=/data",
            "--mount", "type=bind,src=" + str(lab.data / "config") + ",dst=/config,readonly",
            image_id, "-logtostderr=true", "s3", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-port=18333",
            "-port.https=0", "-port.iceberg=0", "-port.lance=0", "-filer=127.0.0.1:18888",
            "-config=/config/s3.json", "-key.file=/config/tls-next/server.key", "-cert.file=/config/tls-next/server.pem"]


def replace_gateway(module, lab):
    command, write = module.command, module.write_json
    old_name=lab.prefix+"-s3"; retained_names=[lab.prefix+"-"+r for r in ("master","volume","filer")]
    before=json.loads(command(["docker","inspect",*retained_names,old_name]))
    require(len(before)==4 and all(x["State"]["Running"] for x in before), "LIVE_ORIGINAL_ROLES_REQUIRED")
    old_id=before[-1]["Id"]
    command(["docker","stop","--time","30",old_name],timeout=40)
    old=json.loads(command(["docker","inspect",old_name]))[0]
    write(lab.evidence/"retired-gateway.json",old)
    require(old["Id"]==old_id and not old["State"]["Running"] and old["State"]["ExitCode"]==0
            and not old["State"]["OOMKilled"], "OLD_GATEWAY_CLEAN_STOP_REQUIRED")
    logs=subprocess.run(["docker","logs",old_name],check=True,text=True,stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,timeout=30)
    (lab.evidence/"retired-gateway.log").write_text(logs.stdout)
    command(["docker","rm",old_name]);lab.names.remove(old_name)
    args=replacement_argv(lab,module.cold.IMAGE_ID);new_name=lab.prefix+"-s3-next"
    command(args);lab.names.append(new_name)
    after=json.loads(command(["docker","inspect",*retained_names,new_name]))
    validate_replacement(before,after,lab,module.cold.IMAGE_ID)
    write(lab.evidence/"replacement-containers.json",after)
    lab.client("ready-b")
    return {"retiredGatewayId":old_id,"replacementGatewayId":after[-1]["Id"],
            "retainedRoleIds":[x["Id"] for x in after[:-1]],"oldGatewayExitCode":0,
            "simultaneousS3Gateways":1,"method":"STOP_REMOVE_RECREATE_S3_GATEWAY"}


def validate_replacement(before,after,lab,image_id):
    require(len(before)==len(after)==4 and [x["Id"] for x in before[:-1]]==[x["Id"] for x in after[:-1]],
            "MASTER_VOLUME_FILER_MUST_REMAIN_IDENTICAL")
    require(before[-1]["Id"]!=after[-1]["Id"] and len({x["Id"] for x in before+after})==5,
            "DISTINCT_GATEWAY_GENERATIONS_REQUIRED")
    require(all(old["State"]["StartedAt"]==new["State"]["StartedAt"]
                and old["RestartCount"]==new["RestartCount"]==0 for old,new in zip(before[:-1],after[:-1])),
            "STORAGE_ROLES_MUST_NOT_RESTART")
    for item in after:
        require(item["State"]["Running"] and not item["State"]["OOMKilled"]
                and item["Image"]==image_id,"LIVE_EXACT_IMAGE_REQUIRED")
    item=after[-1];host=item["HostConfig"];mounts={m["Destination"]:m for m in item["Mounts"]}
    require(item["Config"]["User"]=="65532:65532" and host["ReadonlyRootfs"] and host["CapDrop"]==["ALL"]
            and not host["PortBindings"] and host["NetworkMode"] in {"container:"+after[0]["Id"],"container:"+lab.prefix+"-master"},
            "REPLACEMENT_ISOLATION_REQUIRED")
    require(mounts["/data"]["Source"]==str(lab.data/"s3") and mounts["/config"]["Source"]==str(lab.data/"config")
            and mounts["/config"]["RW"] is False,"REPLACEMENT_ROOTS_MUST_MATCH")
    require("-key.file=/config/tls-next/server.key" in item["Config"]["Cmd"]
            and "-cert.file=/config/tls-next/server.pem" in item["Config"]["Cmd"],"NEW_CERTIFICATE_FILES_REQUIRED")


def run(archive,work,receipt):
    require(os.environ.get("GITHUB_ACTIONS")=="true","ISOLATED_CI_ONLY")
    bound=binding(receipt);module=configure(bound);cold=module.cold
    require(not work.exists() and not work.is_symlink(),"NEW_WORK_DIRECTORY_REQUIRED")
    work.mkdir(parents=True);evidence=work/"evidence";evidence.mkdir();lab=None
    class RotationLab(module.Lab):
        def client(self,action):
            action="ready-a" if action=="ready" else action
            require(action in {"ready-a","ready-b","seed","verify-b"},"KNOWN_ROTATION_ACTION_REQUIRED")
            argv=["sudo","-n","nsenter","-t",self.pid,"-n",sys.executable,"-I","-B","-S",str(ENTRYPOINT),
                  "client",action,str(self.data/"config"),str(receipt)]
            try:result=json.loads(module.command(argv,timeout=90 if action.startswith("ready") else 150))
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
                (evidence/(action+"-stderr.log")).write_text(cold.bounded_diagnostic(error.stderr,"TLS_ROTATION_CHILD_FAILED"))
                raise RuntimeError("TLS_ROTATION_CHILD_FAILED:"+action) from error
            module.write_json(evidence/(action+".json"),result);return result
    try:
        module.write_json(evidence/"exact-image.json",cold.prepare_image(archive,work))
        data=work/"fixture"
        for role in ("master","volume","filer","s3","config"):(data/role).mkdir(parents=True)
        module.write_json(data/"config/s3.json",module.fixture_config())
        certs=make_certificates(data/"config",module.command)
        module.write_json(evidence/"certificate-identities.json",certs)
        for generation,directory in (("a","tls"),("b","tls-next")):
            for kind in ("ca","server"):(evidence/(generation+"-"+kind+".pem")).write_bytes((data/"config"/directory/(kind+".pem")).read_bytes())
        (evidence/"ca-overlap.pem").write_bytes((data/"config/ca-overlap.pem").read_bytes())
        module.command(["sudo","-n","chown","-R","65532:65532",str(data)])
        lab=RotationLab("ouf-tls33-"+str(os.getpid()),data,evidence);lab.start()
        before=lab.client("seed");replacement=replace_gateway(module,lab);after=lab.client("verify-b")
        require(before["object"]==after["object"] and before["listKeys"]==after["listKeys"]
                and before["mutatingRequests"]==2 and after["mutatingRequests"]==0,"ROTATION_READ_ONLY_PARITY_REQUIRED")
        lab.stop()
        stopped=[json.loads(p.read_bytes()) for p in evidence.glob("*-stopped.json")]
        require(len(stopped)==4 and all(not x["Running"] and x["ExitCode"]==0 and not x["OOMKilled"] for x in stopped),
                "FOUR_FINAL_CLEAN_STOPS_REQUIRED")
        module.write_json(evidence/"receipt.json",{
            "schema":"ouf.storage-generation33-tls-rotation.v1","status":"SYNTHETIC_TLS_STAGED_TRUST_AND_GATEWAY_REPLACEMENT_PASS",
            "generation":33,"candidateLockSha256":LOCK_SHA,"cohortReceiptSha256":COHORT_SHA,
            "cohortArtifactId":COHORT_ARTIFACT_ID,"cohortArchiveSha256":COHORT_ARCHIVE_SHA,
            "binarySha256":labs.binding_api.BINARY_SHA,"ociManifestDigest":bound["lock"]["image"]["manifestDigest"],
            "positiveTrustCases":4,"negativeTrustCases":4,"publicCertificateIdentities":certs,
            "objectParity":after["object"],"gatewayReplacement":replacement,"cleanContainerStops":5,
            "maximumConcurrentContainers":4,"fixtureCredentialsOnly":True,"privateKeysUploaded":False,
            "postRotationMutatingRequests":0,"mutatingRequestRetries":0,"overlapTrustBeforeAndAfter":True,
            "finalNewTrustAccepted":True,"finalOldTrustRejected":True,"serverCertificateRotationByRestart":True,
            "hotReloadQualified":False,"zeroDowntimeQualified":False,"mTLSQualified":False,
            "s3CredentialRotationQualified":False,"interRoleLateralIsolationQualified":False,
            "productionSecretCustodyQualified":False,"targetOperations":0,"releaseAdmitted":False,
            "runtimeAuthorityIssued":False,"gatesClosed":0,"acceptanceTestsPassed":0})
    except Exception as error:
        module.write_json(evidence/"failure.json",{"status":"SYNTHETIC_TLS_ROTATION_FAILED","failureClass":type(error).__name__,
                          "safeReason":str(error)[:512] if isinstance(error,(ValueError,RuntimeError)) else "COMMAND_OR_IO_FAILED",
                          "targetOperations":0,"releaseAdmitted":False,"runtimeAuthorityIssued":False})
        raise
    finally:
        if lab and lab.names:lab.stop(strict=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest="operation",required=True)
    runner=sub.add_parser("run");runner.add_argument("archive",type=Path);runner.add_argument("work",type=Path);runner.add_argument("receipt",type=Path)
    child=sub.add_parser("client");child.add_argument("action",choices=("ready-a","ready-b","seed","verify-b"));child.add_argument("config",type=Path);child.add_argument("receipt",type=Path)
    args=parser.parse_args()
    if args.operation=="run":run(args.archive.resolve(),args.work.absolute(),args.receipt.resolve())
    else:print(json.dumps(client(configure(binding(args.receipt)),args.config,args.action)))


if __name__=="__main__":main()
