#!/usr/bin/env python3
"""Plan or perform D, the same-image Semantic cutover with bounded restoration."""

import argparse
from contextlib import closing
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import types


OLD = "ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a"
OLD_FRAME = "1ff2ed51293a5295016c0cfe713c87dba519322543b2d0c3ccbb802f3f63c3e7"
IMAGE = "sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048"
NETWORK = "ouf-backend"
NETWORK_ID = "113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3"
ADDRESS = "172.18.0.6"
MAC = "b2:96:a1:e2:c1:8d"
MCP = "41c1e01dfd86535d75d2db6d7bd0f9e3eae27c24684af0b149d6b51c54d90943"
SUCCESSORS = (
    "85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef",
    "34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52",
)
SUCCESSOR_TRANSACTION = "7ff12b95c3f70c5eaebb1d0a12ab931d"
MATERIAL = Path("/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1")
MATERIAL_SHA = "68daa9c9af2e3d5b41aceff988405e78a6fd3cb90a8c71f922816dd85964d392"
CREDENTIAL = MATERIAL / "schema-gov-client-secret"
PUBLIC_TRUST = Path("/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1/provider-trust.p12")
PUBLIC_TRUST_SHA = "33418234a5428623b3f82e4219b1c29e014a14de1a537452366d9e54878c9559"
WORK = Path("/var/lib/ouf-storage-migration/semantic-provider-cutover-20261111")
CREDENTIAL_TARGET = "/run/secrets/schema-gov-client-secret"
TRUST_TARGET = "/run/ouf-discovery-trust/merged-trust.p12"
ARGS_TARGET = "/run/ouf-discovery-trust/java.args"
LABEL = "ouf.semantic.provider-cutover.plan"
DOCKER_SOCKET = "/run/docker.sock"
RECONNECT_API = "1.54"
READINESS = "/actuator/health/readiness"
SEMANTIC_HEALTH = ("/actuator/health/liveness", READINESS, "/actuator/health")
CUTOVER_HEALTH = "/actuator/health/cutover"
START_SECONDS = 155
HEALTH_SECONDS = 100
RESTORE_SECONDS = 130
JOURNAL_FILES = ("manifest.json", "merged-trust.p12", "java.args", "created.json",
                 "creation-request.private.json", "complete.json", "restored.json")


class Held(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise Held(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def code(error):
    message = str(error)
    return message if type(error) in (Held, RuntimeError, ValueError) and re.fullmatch(
        r"[A-Z][A-Z_0-9]{0,110}", message
    ) else type(error).__name__


def load_helpers():
    directory = Path(__file__).parent
    package = types.ModuleType("cutover_trust")
    package.__path__ = []
    sys.modules[package.__name__] = package
    helpers = []
    for name, file, digest in (
        ("rollout", "upgrade-semantic-application-20261108.py", "2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1"),
        ("retained_mac", "retained_mac.py", "cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"),
        ("cutover_trust.audit", "audit.py", "e8b7813a8f6f009054593025dc2df9b79315bf2100a70f02a41973a0536658c3"),
        ("cutover_trust.public_truststore", "public_truststore.py", "ade7e834d8b011da28534f416bfbb958d9cab1b1eb32dd94360c4c29dd589579"),
    ):
        path = directory / file
        source = path.read_bytes()
        require(sha(source) == digest, "CUTOVER_HELPER_HASH_CHANGED")
        module = types.ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = name.rpartition(".")[0]
        sys.modules[name] = module
        exec(compile(source, str(path), "exec"), module.__dict__)
        helpers.append(module)
    return helpers[0], helpers[1], helpers[3]


def remaining(deadline, maximum):
    seconds = deadline - time.monotonic()
    require(seconds > 0, "CUTOVER_DEADLINE_EXPIRED")
    return min(seconds, maximum)


class UnixEngine(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DOCKER_SOCKET)


def engine(deadline, method, resource, body=None, *, allow_absent=False, api="1.44"):
    with closing(UnixEngine("localhost", timeout=remaining(deadline, 23))) as connection:
        connection.request(method, f"/v{api}" + resource, body=None if body is None else canonical(body),
                           headers={"Content-Type": "application/json"})
        with connection.getresponse() as response:
            raw = response.read(2_097_153)
            if allow_absent and response.status == 404:
                return None
            if method == "POST" and response.status == 304 and re.fullmatch(r"/containers/[0-9a-f]{64}/stop\?t=\d+", resource):
                return None
            require(response.status in (200, 201, 204) and len(raw) <= 2_097_152, "ENGINE_RESPONSE_UNPROVEN")
    return json.loads(raw) if raw else None


def inspect(deadline, name, *, allow_absent=False):
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,200}", name), "CONTAINER_SELECTOR_INVALID")
    return engine(deadline, "GET", f"/containers/{name}/json", allow_absent=allow_absent)


def action(deadline, cid, operation, body=None):
    require(re.fullmatch(r"[0-9a-f]{64}", cid), "CONTAINER_ID_INVALID")
    return engine(deadline, "POST", f"/containers/{cid}/{operation}", body)


def namespace_read(deadline, cid, namespace, *args, maximum=5):
    doc = inspect(deadline, cid)
    require(doc["Id"] == cid and doc["State"]["Running"] and doc["State"]["Pid"] > 1,
            "PROBE_PROCESS_UNPROVEN")
    target = str(doc["State"]["Pid"])
    options = ("--mount", "--root", "--wdns=/") if namespace == "mount" else ("--net",)
    result = subprocess.run(("/usr/bin/nsenter", "--target", target, *options, "--", *args),
                            capture_output=True, timeout=remaining(deadline, maximum),
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(result.returncode == 0 and len(result.stdout) <= 1_048_576, "CONTAINER_PROBE_FAILED")
    return result.stdout


def private_input(path, *, uid, gid, mode, limit):
    require(path.is_absolute(), "ABSOLUTE_MATERIAL_PATH_REQUIRED")
    for parent in path.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                "MATERIAL_PARENT_UNPROVEN")
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
                and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, mode),
                "MATERIAL_METADATA_CHANGED")
        raw = stream.read(limit + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                == identity(path.lstat()), "MATERIAL_CHANGED_DURING_READ")
    return raw


def env_map(config, *, check_secret_names=True):
    result = {}
    for row in config["Env"]:
        name, separator, value = row.partition("=")
        require(separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in result,
                "ENVIRONMENT_UNPROVEN")
        if check_secret_names:
            require((name.endswith("_FILE") or name == "GPG_KEY"
                     or not re.search(r"PASSWORD|PASSPHRASE|SECRET|(?:^|_)(?:KEY|TOKEN|BEARER)$", name, re.I))
                    and name != "SPRING_APPLICATION_JSON", "SECRET_ENVIRONMENT_REQUIRES_REVIEW")
        result[name] = value
    return result


def prepare_material(deadline, old, trust):
    receipt_path = MATERIAL / "prepared-inputs.private.json"
    receipt = json.loads(private_input(receipt_path, uid=0, gid=0, mode=0o600, limit=4194304))
    require(sha(canonical(receipt)) == MATERIAL_SHA, "MATERIAL_RECEIPT_CHANGED")
    item = receipt["preparedCopies"]["providerCredential"]
    require(item["path"] == str(CREDENTIAL), "CREDENTIAL_SOURCE_CHANGED")
    credential = private_input(CREDENTIAL, uid=0, gid=10001, mode=0o440, limit=4096)
    require(sha(credential) == item["sha256"], "CREDENTIAL_CUSTODY_CHANGED")
    public = private_input(PUBLIC_TRUST, uid=0, gid=10001, mode=0o440, limit=1048576)
    require(sha(public) == PUBLIC_TRUST_SHA, "PREPARED_TRUSTSTORE_CHANGED")

    env = env_map(old["Config"])
    retained_env = env_map(receipt["selectedInstallationObservations"]["semantic"]["Config"], check_secret_names=False)
    for key in ("OUF_SCHEMA_GOV_CLIENT_ID", "OUF_SCHEMA_GOV_WORKLOAD_SCOPE", "OUF_SCHEMA_GOV_TOKEN_ENDPOINT"):
        require(env.get(key) and env.get(key) == retained_env.get(key), "WORKLOAD_BINDING_CHANGED")
    require(env.get("OUF_SCHEMA_GOV_CLIENT_ID") == "ouf-semantic"
            and env.get("OUF_SCHEMA_GOV_GATEWAY_BASE_URL") == "https://ouf-semantic-southbound-v2:10443"
            and env.get("OUF_SCHEMA_GOV_ENABLED") == env.get("OUF_DISCOVERY_WORKER_ENABLED") == "false"
            and env.get("OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED") == "true"
            and env.get("OUF_SCHEMA_GOV_CLIENT_SECRET_FILE") == CREDENTIAL_TARGET
            and not any(env.get(key) for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")),
            "SEMANTIC_PROVIDER_SETTINGS_CHANGED")
    home = env["JAVA_HOME"]
    require(re.fullmatch(r"/[a-zA-Z0-9_/.-]{1,160}", home) and ".." not in Path(home).parts, "JAVA_HOME_INVALID")
    stock = namespace_read(deadline, OLD, "mount", "/bin/sh", "-c",
                           'test ! -e "$1/lib/security/jssecacerts" && '
                           'exec "$1/bin/keytool" -J-XX:-UsePerfData -list -rfc -cacerts -storepass changeit',
                           "ouf-read-trust", home, maximum=12)
    extra = subprocess.run(("/usr/bin/openssl", "pkcs12", "-nokeys", "-passin", "pass:changeit"),
                           input=public, capture_output=True, timeout=remaining(deadline, 10))
    require(extra.returncode == 0 and len(extra.stdout) <= 1048576, "PUBLIC_TRUSTSTORE_UNREADABLE")
    def certificates(pem):
        return {ssl.PEM_cert_to_DER_cert(match.decode("ascii")) for match in trust.PEM.findall(pem)}
    existing, additional = certificates(stock), certificates(extra.stdout)
    require(50 <= len(existing) <= 512 and 1 <= len(additional) <= 16, "CA_INVENTORY_UNPROVEN")
    merged = trust._pkcs12(sorted(existing | additional, key=sha))
    require(len(merged) <= trust.MAX_STORE, "MERGED_TRUSTSTORE_TOO_LARGE")
    args = (f"-Djavax.net.ssl.trustStore={TRUST_TARGET}\n-Djavax.net.ssl.trustStoreType=PKCS12\n"
            "-Djavax.net.ssl.trustStorePassword=changeit\n").encode()
    return merged, args, len(existing), len(existing | additional), sha(credential)


def http_health(deadline, cid, host="127.0.0.1", paths=SEMANTIC_HEALTH):
    for path in paths:
        raw = namespace_read(deadline, cid, "network", "/usr/bin/curl", "--silent", "--fail", "--max-time", "2",
                             f"http://{host}:8080{path}", maximum=4)
        require(len(raw) < 65536 and json.loads(raw).get("status") == "UP", "SEMANTIC_HEALTH_NOT_UP")


def service_probes(deadline, cid, gateway):
    paths = SEMANTIC_HEALTH if cid == OLD else (CUTOVER_HEALTH,)
    http_health(deadline, cid, paths=paths)
    http_health(deadline, gateway, ADDRESS, (READINESS,))
    status = namespace_read(deadline, MCP, "network", "/usr/bin/curl", "--silent", "--fail", "--max-time", "2",
                            "--output", "/dev/null", "--write-out", "%{http_code}",
                            "http://127.0.0.1:8080/health/ready", maximum=4)
    require(status == b"204", "MCP_READINESS_CHANGED")


def process(deadline, doc):
    pid = doc["State"]["Pid"]
    require(doc["State"]["Running"] is True and pid > 1, "SEMANTIC_PID_UNPROVEN")
    remaining(deadline, 1)
    return Path("/proc", str(pid), "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")


def plan(rollout, mac, trust):
    deadline = time.monotonic() + 65
    require(not os.path.lexists(WORK), "CUTOVER_ATTEMPT_EXISTS")
    info = engine(deadline, "GET", "/info")
    require((info["ServerVersion"], info["Driver"], info["CgroupDriver"], info["DockerRootDir"])
            == ("29.8.1", "overlayfs", "systemd", "/var/lib/docker"), "ENGINE_PROFILE_CHANGED")
    require(engine(deadline, "GET", "/version", api=RECONNECT_API)["Version"] == info["ServerVersion"],
            "MAC_PRESERVING_RECONNECT_API_UNPROVEN")
    old = inspect(deadline, OLD)
    fields = ("Id", "Image", "Config", "HostConfig", "Mounts", "Path", "Args", "NetworkSettings")
    frame = {key: old.get(key) for key in fields}
    frame["State"] = {key: old["State"].get(key) for key in
                      ("Running", "Restarting", "Paused", "Status", "Pid", "StartedAt", "FinishedAt")}
    require(sha(canonical(frame) + b"\n") == OLD_FRAME and old["Image"] == IMAGE
            and re.fullmatch(r"/ouf-semantic-cutover-c0a824e8[0-9a-f]*", old["Name"]),
            "CURRENT_SEMANTIC_FRAME_CHANGED")
    require(process(deadline, old) == rollout.JAVA, "CURRENT_JAVA_UNPROVEN")
    mac.policy(old)
    net = engine(deadline, "GET", "/networks/" + NETWORK_ID)
    endpoint = old["NetworkSettings"]["Networks"][NETWORK]
    require(net["Name"] == NETWORK and net["Id"] == NETWORK_ID and net["Driver"] == "bridge"
            and (endpoint["IPAddress"], endpoint["MacAddress"]) == (ADDRESS, MAC)
            and not endpoint.get("GlobalIPv6Address")
            and "ouf-semantic-registry" in endpoint["Aliases"]
            and [cid for cid, row in net["Containers"].items() if row["IPv4Address"].split("/")[0] == ADDRESS] == [OLD],
            "BACKEND_PEER_CHANGED")
    gateways = [cid for cid, row in net["Containers"].items() if re.fullmatch(r"ouf-apisix(?:-[a-zA-Z0-9]+)*", row["Name"])]
    require(len(gateways) == 1, "ONE_CURRENT_APISIX_REQUIRED")
    gateway = gateways[0]
    for cid in SUCCESSORS:
        doc = inspect(deadline, cid)
        state = doc["State"]
        require(doc["Config"]["Labels"].get("ouf.semantic.provider.successor.creation") == SUCCESSOR_TRANSACTION
                and state["Status"] == "created" and state["Running"] is False and state["Pid"] == 0
                and state["StartedAt"].startswith("0001-") and doc["HostConfig"]["RestartPolicy"]["Name"] == "no"
                and not any(e.get("EndpointID") or e.get("IPAddress") for e in doc["NetworkSettings"]["Networks"].values()),
                "SUCCESSOR_NOT_STOPPED")
    service_probes(deadline, OLD, gateway)
    merged, args, existing_count, merged_count, credential_digest = prepare_material(deadline, old, trust)
    request = rollout.request(old, IMAGE)
    request["Labels"] = dict(old["Config"].get("Labels") or {})
    require(LABEL not in request["Labels"], "CUTOVER_LABEL_COLLISION")
    env = env_map(request)
    env.update(OUF_SCHEMA_GOV_ENABLED="true", OUF_DISCOVERY_WORKER_ENABLED="false",
               SPRING_FLYWAY_ENABLED="false", JDK_JAVA_OPTIONS="@" + ARGS_TARGET,
               MANAGEMENT_ENDPOINT_HEALTH_GROUP_CUTOVER_INCLUDE="livenessState,readinessState,db")
    request["Env"] = [name + "=" + value for name, value in env.items()]
    mounts = ((CREDENTIAL, CREDENTIAL_TARGET), (WORK / "merged-trust.p12", TRUST_TARGET),
              (WORK / "java.args", ARGS_TARGET))
    existing = {m["Destination"] for m in old["Mounts"]}
    require(not existing.intersection(target for _, target in mounts), "CUTOVER_MOUNT_TARGET_COLLISION")
    request["HostConfig"]["Mounts"] = list(request["HostConfig"].get("Mounts") or []) + [
        {"Type": "bind", "Source": str(source), "Target": target, "ReadOnly": True} for source, target in mounts
    ]
    name = old["Name"].lstrip("/")
    retained, failed = name + "-before-provider-D-20261111", name + "-failed-provider-D-20261111"
    live_root = Path("/proc") / str(old["State"]["Pid"]) / "root"
    cacerts = live_root / env["JAVA_HOME"].lstrip("/") / "lib/security/cacerts"
    require(all(inspect(deadline, item, allow_absent=True) is None for item in (retained, failed)), "CUTOVER_NAME_IN_USE")
    require(inspect(deadline, OLD) == old, "SEMANTIC_CHANGED_DURING_PLAN")
    manifest = {
        "oldContainer": OLD, "newContainer": {"name": name, "image": IMAGE, "idAssignedByEngine": True},
        "retainedName": retained, "failureName": failed, "network": {"name": NETWORK, "id": NETWORK_ID,
             "ipv4": ADDRESS, "mac": MAC, "aliases": endpoint["Aliases"]},
        "observedGateway": gateway, "observedMcp": MCP, "stoppedSuccessors": list(SUCCESSORS),
        "inputFiles": [str(MATERIAL / "prepared-inputs.private.json"), str(CREDENTIAL), str(PUBLIC_TRUST),
                       f"/proc/{old['State']['Pid']}/cmdline", str(cacerts)],
        "privateDirectory": str(WORK), "filesCreatedUnderPrivateDirectory": list(JOURNAL_FILES),
        "readOnlyBinds": [{"host": str(source), "target": target, "uid": 0, "gid": 10001, "mode": "0440"}
                          for source, target in mounts],
        "environmentNamesChanged": ["JDK_JAVA_OPTIONS", "MANAGEMENT_ENDPOINT_HEALTH_GROUP_CUTOVER_INCLUDE",
                                    "OUF_SCHEMA_GOV_ENABLED", "SPRING_FLYWAY_ENABLED"],
        "existingCaCount": existing_count, "mergedCaCount": merged_count,
        "health": {"currentAndRestoredSemantic": list(SEMANTIC_HEALTH), "newSemantic": CUTOVER_HEALTH,
                   "gatewayBackend": READINESS, "mcp": "/health/ready"},
        "limitsSeconds": {"forward": START_SECONDS, "health": HEALTH_SECONDS, "automaticRestore": RESTORE_SECONDS},
        "rollbackNetworkConnectApi": RECONNECT_API,
        "mutations": ["stop and detach old CID", "rename old CID", "create new CID", "start gate and release Java",
                      "on failure stop, detach and rename new CID", "reattach, rename and restart old CID"],
    }
    binding = {"manifest": manifest, "oldFrameSha256": OLD_FRAME, "request": request,
               "credentialDigest": credential_digest, "mergedTrustDigest": sha(merged), "javaArgsDigest": sha(args)}
    return manifest, sha(canonical(binding)), old, request, merged, args, credential_digest


def save(name, raw, *, group=0, mode=0o600):
    with os.fdopen(os.open(WORK / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def await_health(deadline, cid, gateway, rollout):
    while time.monotonic() < deadline:
        doc = inspect(deadline, cid)
        require(doc["State"]["Running"], "SEMANTIC_EXITED_BEFORE_READY")
        try:
            require(process(deadline, doc) == rollout.JAVA, "JAVA_NOT_READY")
            service_probes(deadline, cid, gateway)
            return
        except (Held, OSError, ValueError, subprocess.SubprocessError):
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise Held("SEMANTIC_READINESS_TIMEOUT")


def verify_new(rollout, old, request, actual, started):
    expected = copy.deepcopy(old)
    retained = {m["Destination"] for m in old["Mounts"]}
    extra = [m for m in actual["Mounts"] if m["Destination"] not in retained]
    sources = {(str(CREDENTIAL), CREDENTIAL_TARGET), (str(WORK / "merged-trust.p12"), TRUST_TARGET),
               (str(WORK / "java.args"), ARGS_TARGET)}
    require(len(extra) == 3 and all(m["Type"] == "bind" and m["RW"] is False for m in extra)
            and {(m["Source"], m["Destination"]) for m in extra} == sources, "NEW_READONLY_BIND_SET_CHANGED")
    expected["Mounts"] += extra
    rollout.verify_replacement(expected, request, actual, started)


def restore(rollout, old, manifest, digest, new_id):
    deadline = time.monotonic() + RESTORE_SECONDS
    name, retained = manifest["newContainer"]["name"], manifest["retainedName"]
    candidate = inspect(deadline, new_id or name, allow_absent=True)
    if candidate is not None and candidate["Id"] != OLD:
        require(candidate["Name"] == "/" + name and candidate["Image"] == IMAGE
                and candidate["Config"]["Labels"].get(LABEL) == digest, "RESTORE_CANDIDATE_OWNERSHIP_UNPROVEN")
        cid = candidate["Id"]
        action(deadline, cid, "stop?t=12")
        candidate = inspect(deadline, cid)
        require(not candidate["State"]["Running"] and candidate["State"]["Pid"] == 0, "RESTORE_CANDIDATE_STOP_UNPROVEN")
        networks = candidate["NetworkSettings"]["Networks"]
        require(set(networks) <= {NETWORK}, "RESTORE_CANDIDATE_NETWORK_CHANGED")
        if NETWORK in networks:
            engine(deadline, "POST", f"/networks/{NETWORK_ID}/disconnect", {"Container": cid, "Force": False})
        require(inspect(deadline, cid)["NetworkSettings"]["Networks"] == {}, "RESTORE_CANDIDATE_DETACH_UNPROVEN")
        action(deadline, cid, "rename?name=" + manifest["failureName"])
    actual = inspect(deadline, OLD)
    require(actual["Image"] == IMAGE and actual["HostConfig"] == old["HostConfig"]
            and rollout.mounts(actual) == rollout.mounts(old)
            and actual["Name"] in {"/" + name, "/" + retained}, "RESTORE_OLD_IDENTITY_CHANGED")
    if not actual["State"]["Running"]:
        require(actual["State"]["Pid"] == 0, "RESTORE_OLD_STOP_UNPROVEN")
        if actual["Name"] == "/" + retained:
            action(deadline, OLD, "rename?name=" + name)
        if not actual["NetworkSettings"]["Networks"]:
            original = old["NetworkSettings"]["Networks"][NETWORK]
            settings = {"IPAMConfig": {"IPv4Address": ADDRESS}, "MacAddress": MAC,
                        "Aliases": original["Aliases"]}
            for field in ("Links", "DriverOpts"):
                if original.get(field):
                    settings[field] = original[field]
            # Older API versions silently discard a requested MAC on network connect.
            engine(deadline, "POST", f"/networks/{NETWORK_ID}/connect",
                   {"Container": OLD, "EndpointConfig": settings}, api=RECONNECT_API)
        else:
            require(set(actual["NetworkSettings"]["Networks"]) == {NETWORK}, "RESTORE_OLD_NETWORK_CHANGED")
        action(deadline, OLD, "start")
        gate = inspect(deadline, OLD)
        rollout.gate_running(gate)
        action(deadline, OLD, "kill?signal=USR1")
    await_health(deadline, OLD, manifest["observedGateway"], rollout)
    live = inspect(deadline, OLD)
    config = copy.deepcopy(live["Config"])
    expected_config = copy.deepcopy(old["Config"])
    if "MacAddress" not in config:
        expected_config.pop("MacAddress", None)
    require(config == expected_config, "RESTORE_FINAL_CONFIG_CHANGED")
    require(live["Name"] == "/" + name, "RESTORE_FINAL_NAME_CHANGED")
    require(set(live["NetworkSettings"]["Networks"]) == {NETWORK}, "RESTORE_FINAL_NETWORK_CHANGED")
    endpoint = live["NetworkSettings"]["Networks"][NETWORK]
    require(endpoint["IPAddress"] == ADDRESS, "RESTORE_FINAL_IP_CHANGED")
    require(endpoint["MacAddress"] == MAC, "RESTORE_FINAL_MAC_CHANGED")
    require(set(endpoint["Aliases"]) == set(old["NetworkSettings"]["Networks"][NETWORK]["Aliases"]),
            "RESTORE_FINAL_ALIASES_CHANGED")
    require(endpoint["EndpointID"], "RESTORE_FINAL_ENDPOINT_MISSING")


def apply(rollout, mac, planned, report):
    manifest, digest, old, request, merged, args, credential_digest = planned
    WORK.mkdir(mode=0o700)
    save("manifest.json", canonical({"planSha256": digest, "manifest": manifest}))
    save("merged-trust.p12", merged, group=10001, mode=0o440)
    save("java.args", args, group=10001, mode=0o440)
    request["Labels"][LABEL] = digest
    save("creation-request.private.json", canonical(request))
    deadline = time.monotonic() + START_SECONDS
    require(inspect(deadline, OLD) == old, "SEMANTIC_CHANGED_BEFORE_STOP")
    new_id = None
    report["rollbackOnFailure"] = True
    try:
        action(deadline, OLD, "stop?t=15")
        stopped = inspect(deadline, OLD)
        require(not stopped["State"]["Running"] and stopped["State"]["Pid"] == 0
                and stopped["Config"] == old["Config"] and stopped["HostConfig"] == old["HostConfig"]
                and rollout.mounts(stopped) == rollout.mounts(old), "OLD_STOP_FRAME_CHANGED")
        engine(deadline, "POST", f"/networks/{NETWORK_ID}/disconnect", {"Container": OLD, "Force": False})
        rollout.detached(mac, old, inspect(deadline, OLD), old["Name"])
        action(deadline, OLD, "rename?name=" + manifest["retainedName"])
        rollout.detached(mac, old, inspect(deadline, OLD), "/" + manifest["retainedName"])
        result = engine(deadline, "POST", "/containers/create?name=" + manifest["newContainer"]["name"], request)
        require(re.fullmatch(r"[0-9a-f]{64}", result["Id"]), "NEW_SEMANTIC_ID_UNPROVEN")
        new_id = result["Id"]
        report["replacementContainerId"] = new_id
        save("created.json", canonical({"containerId": new_id}))
        verify_new(rollout, old, request, inspect(deadline, new_id), False)
        action(deadline, new_id, "start")
        gated = inspect(deadline, new_id)
        verify_new(rollout, old, request, gated, True)
        rollout.gate_running(gated)
        for source, expected, limit in ((CREDENTIAL, credential_digest, 4096),
                                        (WORK / "merged-trust.p12", sha(merged), 1048576),
                                        (WORK / "java.args", sha(args), 4096)):
            require(sha(private_input(source, uid=0, gid=10001, mode=0o440, limit=limit)) == expected,
                    "CUTOVER_BIND_CONTENT_CHANGED")
        action(deadline, new_id, "kill?signal=USR1")
        await_health(min(deadline, time.monotonic() + HEALTH_SECONDS), new_id, manifest["observedGateway"], rollout)
        verify_new(rollout, old, request, inspect(deadline, new_id), True)
        rollout.detached(mac, old, inspect(deadline, OLD), "/" + manifest["retainedName"])
        save("complete.json", canonical({"containerId": new_id, "oldContainerId": OLD, "planSha256": digest}))
        report["status"] = "SEMANTIC_PROVIDER_CUTOVER_READY"
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            http.client.HTTPException) as error:
        report["reason"] = code(error)
        try:
            restore(rollout, old, manifest, digest, new_id)
            report["status"] = "SEMANTIC_PREVIOUS_CONTAINER_RESTORED"
            save("restored.json", canonical({"restoredContainerId": OLD, "reason": report["reason"],
                                             "planSha256": digest}))
        except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
                http.client.HTTPException) as restore_error:
            report["status"] = "HELD"
            report["restoreReason"] = code(restore_error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", help="planSha256 from the PLAN_READY receipt")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.apply and not re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256 or ""):
        parser.error("--apply requires --plan-sha256 from PLAN_READY")
    if args.plan and args.plan_sha256 is not None:
        parser.error("--plan-sha256 is only accepted with --apply")
    report = {"schema": "ouf.semantic-provider-cutover.v1", "status": "HELD",
              "credentialValuesEmitted": False, "providerProbes": 0, "replayAllowed": False}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated, "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        rollout, mac, trust = load_helpers()
        planned = plan(rollout, mac, trust)
        report.update(manifest=planned[0], planSha256=planned[1])
        if args.plan:
            report["status"] = "PLAN_READY"
        else:
            require(args.plan_sha256 == planned[1], "PLAN_DIGEST_CHANGED")
            apply(rollout, mac, planned, report)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            http.client.HTTPException) as error:
        report["reason"] = code(error)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in ("PLAN_READY", "SEMANTIC_PROVIDER_CUTOVER_READY") else 1


if __name__ == "__main__":
    raise SystemExit(main())
