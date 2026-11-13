#!/usr/bin/env python3
"""D-022: reconstruct, plan and recreate exactly one never-started successor.

Standalone copy of the original request compiler; no external readers or imports.
Docker calls use only API 1.44. No start, restart, detach, force or volume removal.
"""

import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

DOCKER_SOCKET = None  # mandatory CLI input, never an implicit operational default
FRAME_FIELDS = ("Id", "Image", "Config", "HostConfig", "Mounts", "Path", "Args", "NetworkSettings")
STATE_FIELDS = ("Running", "Restarting", "Paused", "Status", "Pid", "StartedAt", "FinishedAt")
ADAPTER = "ouf-semantic-provider-v2"
SOUTHBOUND = "ouf-semantic-southbound-v2"
OWNER_LABEL = "ouf.semantic.provider.successor.creation"
HISTORICAL_FRAMES = {
    ADAPTER: "d1bcd2f2a288eeb22fcfaae01a86275d5e3371c56ebf353f8bdeb73852a6adbf",
    SOUTHBOUND: "446e80d16964a334e528243309c74c330f896642957fea9b247522f17fb8c9de",
}
ENDPOINTS = {
    ADAPTER: {"ouf-semantic-provider-internal": ("172.21.0.3", "02:42:ac:15:00:03"),
              "ouf-semantic-provider-egress": ("172.22.0.3", "02:42:ac:16:00:03")},
    SOUTHBOUND: {"ouf-backend": ("172.18.0.14", "02:42:ac:12:00:0e"),
                 "ouf-semantic-provider-internal": ("172.21.0.2", "02:42:ac:15:00:02"),
                 "ouf-semantic-provider-egress": ("172.22.0.2", "02:42:ac:16:00:02")},
}
HMAC_SOURCE = Path("/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-vf7B4SM5/southbound/provider-receipt.key")
HMAC_TARGET = "/run/ouf-semantic-provider/southbound-receipt.key"
ROUTES = "/usr/local/apisix/conf/apisix.yaml"
ROUTES_SOURCE = "/run/ouf-semantic-provider/historical-apisix.yaml"
ROUTES_SHA = "dd340bd652bd5c7763ea47fd53573626bc3541b0a2d97415a113c4877e2c7e80"
CONFIG_SHA = "77342a509b0b0e9498728fa366f50ce031c19d78a636d4225de5e95e1ba97140"
RUNTIME_DIRECTORY = "/run/ouf-southbound-runtime"
OIDC_ENV = "OUF_GATEWAY_OIDC_CLIENT_SECRET"
HMAC_ENV = "OUF_SEMANTIC_PROVIDER_OWNER_KEY"
SECRET_FIELD = b'"client_secret":"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET",'
SOUTHBOUND_STARTUP = r'''set -eu
unset OUF_GATEWAY_OIDC_CLIENT_SECRET OUF_SEMANTIC_PROVIDER_OWNER_KEY
(
    umask 077
    sed 's|"client_secret":"\$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET",||g' \
        /run/ouf-semantic-provider/historical-apisix.yaml > /run/ouf-southbound-runtime/apisix.yaml
    if grep -q 'OUF_GATEWAY_OIDC_CLIENT_SECRET' /run/ouf-southbound-runtime/apisix.yaml; then
        exit 78
    fi
)
if ! ln -sfnT /run/ouf-southbound-runtime/apisix.yaml /usr/local/apisix/conf/apisix.yaml; then
    printf '%s\n' 'OUF_SOUTHBOUND_APISIX_CONFIG_LINK_FAILED' >&2
    exit 78
fi
ouf_receipt_key=$(cat /run/ouf-semantic-provider/southbound-receipt.key)
case "$ouf_receipt_key" in
    ""|*[!0123456789abcdefABCDEF]*) exit 78 ;;
esac
[ "${#ouf_receipt_key}" -eq 64 ] || exit 78
export OUF_SEMANTIC_PROVIDER_OWNER_KEY="$ouf_receipt_key"
unset ouf_receipt_key
exec /docker-entrypoint.sh docker-start
'''


class Held(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Held(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class LocalEngine(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DOCKER_SOCKET)


def engine(method, path, payload=None):
    inspect_path = re.fullmatch(r"/containers/[0-9a-f]{64}/json", path)
    require((method == "GET" and (
        path in {"/info", "/containers/json?all=1"} or inspect_path
        or re.fullmatch(r"/images/sha256:[0-9a-f]{64}/json", path)
        or path in {f"/networks/{n}" for n in ENDPOINTS[SOUTHBOUND]}))
        or (method == "DELETE" and re.fullmatch(r"/containers/[0-9a-f]{64}", path))
        or (method == "POST" and path == f"/containers/create?name={SOUTHBOUND}-successor"),
        "ENGINE_OPERATION_OUT_OF_SCOPE")
    conn = LocalEngine("localhost", timeout=25)
    try:
        conn.request(method, "/v1.44" + path,
                     body=None if payload is None else canonical(payload),
                     headers={"Content-Type": "application/json"})
        with conn.getresponse() as response:
            raw = response.read(2_097_153)
            require(len(raw) <= 2_097_152, "ENGINE_RESPONSE_TOO_LARGE")
            if method == "GET" and inspect_path and response.status == 404:
                return None
            require(response.status == {"GET": 200, "POST": 201, "DELETE": 204}[method],
                    "ENGINE_RESPONSE_UNPROVEN")
        return None if method == "DELETE" else json.loads(raw)
    finally:
        conn.close()


def protected_file(path, expected_owner):
    require(path.is_absolute() and not path.is_symlink(), "PROTECTED_FILE_PATH_REQUIRED")
    for parent in path.parents:
        entry = parent.lstat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022,
                "PROTECTED_PARENT_REQUIRED")
    entry = path.lstat()
    require(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1
            and (entry.st_uid, entry.st_gid, stat.S_IMODE(entry.st_mode)) == expected_owner,
            "PROTECTED_FILE_METADATA_CHANGED")


def verify_routes(path, local_config):
    protected_file(path, (636, 636, 0o600))
    protected_file(local_config, (636, 636, 0o600))
    raw = path.read_bytes()
    require(sha(raw) == ROUTES_SHA and sha(local_config.read_bytes()) == CONFIG_SHA,
            "SOUTHBOUND_CONFIGURATION_CHANGED")
    doc, trailer = raw.rsplit(b"#END", 1)
    require(trailer == b"\n" and doc.count(SECRET_FIELD) == 2, "SOUTHBOUND_SECRET_REFERENCE_DRIFT")
    original = json.loads(doc)
    require(len(original["routes"]) == 2, "SOUTHBOUND_ROUTE_COUNT_DRIFT")
    for route in original["routes"]:
        config = route["plugins"]["openid-connect"]
        require(config["client_secret"] == "$ENV://" + OIDC_ENV
                and all(config.get(key) is True for key in ("bearer_only", "use_jwks", "ssl_verify"))
                and config["unauth_action"] == "deny" and not config.get("introspection_endpoint"),
                "JWKS_ONLY_ADMISSION_REQUIRED")
        del config["client_secret"]
    require(json.loads(doc.replace(SECRET_FIELD, b"")) == original, "OIDC_REMOVAL_CHANGED_ROUTE")


def environment_map(entries):
    result = {}
    for entry in entries:
        name, sep, value = entry.partition("=")
        require(sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in result,
                "ENV_NAME_INVALID_OR_DUPLICATE")
        result[name] = value
    return result


def build_request(historical_ids, name, noswap=True):
    historical_cid = historical_ids[name]
    old = engine("GET", f"/containers/{historical_cid}/json")
    frame = {key: old.get(key) for key in FRAME_FIELDS}
    frame["State"] = {key: old["State"].get(key) for key in STATE_FIELDS}
    require(sha(canonical(frame) + b"\n") == HISTORICAL_FRAMES[name], "HISTORICAL_FRAME_CHANGED")

    image = engine("GET", f"/images/{old['Image']}/json")
    require(image["Id"] == old["Image"], "BOUND_IMAGE_NOT_PRESENT")
    config = image["Config"]
    env = config.get("Env") or []
    require(not any(row.partition("=")[0] in {OIDC_ENV, HMAC_ENV}
                    or re.search(r"SECRET|TOKEN|PASSWORD|PASSPHRASE|PRIVATE_KEY", row.partition("=")[0], re.I)
                    for row in env), "IMAGE_ENV_REQUIRES_REVIEW")
    require(not config.get("Volumes"), "UNEXPECTED_IMAGE_VOLUME")
    old_config = old["Config"]
    historical_env = environment_map(old_config.get("Env") or [])
    image_env = environment_map(env)
    removed = {OIDC_ENV, HMAC_ENV} if name == SOUTHBOUND else set()
    require(set(historical_env) == image_env.keys() | removed
            and all(historical_env[key] == value for key, value in image_env.items()),
            "HISTORICAL_ENV_DELTA_REQUIRES_REVIEW")
    host = copy.deepcopy(old["HostConfig"])
    require(host["RestartPolicy"]["Name"] == "no" and not host["Privileged"]
            and host["CapDrop"] == ["ALL"] and not host.get("CapAdd")
            and host["SecurityOpt"] == ["no-new-privileges:true"]
            and not host.get("PortBindings") and not host.get("PublishAllPorts")
            and not host.get("VolumesFrom") and not host.get("AutoRemove"),
            "HISTORICAL_ISOLATION_CHANGED")
    mounts = []
    old_sources = {}
    for mount in old["Mounts"]:
        require(mount["Type"] == "bind" and mount["RW"] is False and mount["Destination"] not in old_sources,
                "READ_ONLY_HISTORICAL_BIND_REQUIRED")
        old_sources[mount["Destination"]] = Path(mount["Source"])
        target = ROUTES_SOURCE if name == SOUTHBOUND and mount["Destination"] == ROUTES else mount["Destination"]
        mounts.append({"Type": "bind", "Source": mount["Source"], "Target": target, "ReadOnly": True,
                       "BindOptions": {"Propagation": mount["Propagation"] or "rprivate"}})
    request = {key: old_config[key] for key in ("User", "WorkingDir", "Entrypoint", "Cmd", "Healthcheck")
               if key in old_config}
    request.update(Image=image["Id"], Env=env, HostConfig=host)
    if name == SOUTHBOUND:
        require(old_config["User"] == "636:636" and old_config["Entrypoint"] == ["/docker-entrypoint.sh"]
                and old_config["Cmd"] == ["docker-start"] and not host["ReadonlyRootfs"],
                "SOUTHBOUND_ENTRYPOINT_OR_UID_CHANGED")
        verify_routes(old_sources[ROUTES], old_sources["/usr/local/apisix/conf/config.yaml"])
        protected_file(HMAC_SOURCE, (636, 636, 0o600))
        mounts.append({"Type": "bind", "Source": str(HMAC_SOURCE), "Target": HMAC_TARGET, "ReadOnly": True})
        require(not host.get("Tmpfs"), "UNEXPECTED_HISTORICAL_TMPFS")
        flags = "rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m"
        host["Tmpfs"] = {RUNTIME_DIRECTORY: flags + (",noswap" if noswap else "")}
        request.update(Entrypoint=["/bin/sh", "-c"], Cmd=[SOUTHBOUND_STARTUP])

    host["Binds"] = None
    host["Mounts"] = mounts
    host["NetworkMode"] = next(iter(ENDPOINTS[name]))
    request["NetworkingConfig"] = {"EndpointsConfig": {
        network: {"IPAMConfig": {"IPv4Address": ip}, "Aliases": [name], "MacAddress": mac}
        for network, (ip, mac) in ENDPOINTS[name].items()
    }}
    return request


def frame_digest(doc):
    # Same API view throughout. Preserve Config.MacAddress, including presence/type.
    return sha(canonical({key: doc.get(key) for key in
                          (*FRAME_FIELDS, "State", "RestartCount", "Name")}))


def mac_profile(doc, name):
    config = doc["Config"]
    if "MacAddress" not in config:
        return {"presence": "ABSENT"}
    value = config["MacAddress"]
    require(isinstance(value, str) and value in {mac for _, mac in ENDPOINTS[name].values()},
            "CONFIG_LEGACY_MAC_PROFILE_UNPROVEN")
    return {"presence": "PRESENT", "type": "string", "value": value,
            "matchesEndpoint": True}


def inspect_created(cid, name, request, transaction, expected_runtime):
    doc = engine("GET", f"/containers/{cid}/json")
    require(doc is not None, "CANDIDATE_MISSING")
    config, state, host = doc["Config"], doc["State"], doc["HostConfig"]
    require(doc["Id"] == cid and doc["Name"] == f"/{name}-successor"
            and doc["Image"] == request["Image"]
            and state["Status"] == "created" and state["Running"] is False
            and state.get("Restarting") is False and state.get("Paused") is False
            and state["Pid"] == 0 and state["StartedAt"] == "0001-01-01T00:00:00Z"
            and doc["RestartCount"] == 0
            and config["Labels"].get(OWNER_LABEL) == transaction,
            "CANDIDATE_IDENTITY_OR_STOPPED_STATE_CHANGED")
    require(host["RestartPolicy"]["Name"] == "no"
            and host["Runtime"] == expected_runtime == request["HostConfig"]["Runtime"]
            and (config.get("Env") or []) == request["Env"]
            and all(config.get(key) == request.get(key) for key in
                    ("User", "WorkingDir", "Entrypoint", "Cmd", "Healthcheck")),
            "CANDIDATE_PROCESS_CONFIGURATION_CHANGED")
    # NO HostConfig normalization is admitted. The compiler copied the complete
    # historical HostConfig, then changed explicit fields. No engine-added delta
    # has been demonstrated for this lifecycle/API. Compare field presence AND
    # canonical values (including nested fields, null vs absent and list order).
    require(set(host) == set(request["HostConfig"])
            and all(canonical(host[key]) == canonical(value)
                    for key, value in request["HostConfig"].items()),
            "CANDIDATE_FULL_HOSTCONFIG_CHANGED")
    expected_mounts = sorted((m["Source"], m["Target"], m["Type"], m["ReadOnly"],
                              m.get("BindOptions", {}).get("Propagation", "rprivate"))
                             for m in host["Mounts"])
    actual_mounts = sorted((m["Source"], m["Destination"], m["Type"], not m["RW"],
                            m["Propagation"] or "rprivate")
                           for m in doc["Mounts"] if m["Type"] != "tmpfs")
    require(expected_mounts == actual_mounts, "CANDIDATE_MOUNT_CONFIGURATION_CHANGED")
    endpoints = doc["NetworkSettings"]["Networks"]
    require(set(endpoints) == set(ENDPOINTS[name]), "CANDIDATE_NETWORK_SET_CHANGED")
    for network, (ip, mac) in ENDPOINTS[name].items():
        endpoint = endpoints[network]
        require(endpoint["IPAMConfig"]["IPv4Address"] == ip
                and name in endpoint["Aliases"]
                and not endpoint.get("EndpointID") and not endpoint.get("IPAddress")
                and not endpoint.get("GlobalIPv6Address")
                and endpoint.get("MacAddress") == mac,
                "CANDIDATE_ENDPOINT_METADATA_CHANGED")
    mac_profile(doc, name)
    return doc


def derive_request(original):
    updated = copy.deepcopy(original)
    old_flags = "rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m,noswap"
    new_flags = old_flags.removesuffix(",noswap")
    require(original["HostConfig"]["Tmpfs"] == {RUNTIME_DIRECTORY: old_flags},
            "ORIGINAL_TMPFS_UNEXPECTED")
    updated["HostConfig"]["Tmpfs"][RUNTIME_DIRECTORY] = new_flags
    # Reverse the single authorized edit and compare the ENTIRE request.
    reversed_edit = copy.deepcopy(updated)
    reversed_edit["HostConfig"]["Tmpfs"][RUNTIME_DIRECTORY] = old_flags
    require(canonical(reversed_edit) == canonical(original)
            and canonical(updated) != canonical(original), "REQUEST_DELTA_NOT_EXACT")
    return updated


def check_networks(allowed_id):
    """Network inspect alone omits stopped requested IP/alias reservations.

    Inspect every listed container too, and the union of network peers. Never
    infer an empty array from a missing Containers/Networks field.
    """
    networks = {}
    peers = set()
    for network, (ip, mac) in ENDPOINTS[SOUTHBOUND].items():
        doc = engine("GET", f"/networks/{network}")
        require(doc["Name"] == network and isinstance(doc["Containers"], dict),
                "NETWORK_READBACK_UNPROVEN")
        networks[network] = doc
        for cid, endpoint in doc["Containers"].items():
            peers.add(cid)
            if cid == allowed_id:
                continue
            require(endpoint["IPv4Address"].split("/")[0] != ip
                    and endpoint["MacAddress"].lower() != mac
                    and endpoint["Name"] not in {SOUTHBOUND, SOUTHBOUND + "-successor"},
                    "SOUTHBOUND_NETWORK_RESOURCE_OCCUPIED")
    listed = engine("GET", "/containers/json?all=1")
    require(isinstance(listed, list), "CONTAINER_INVENTORY_UNPROVEN")
    peers.update(row["Id"] for row in listed)
    for cid in sorted(peers):
        require(re.fullmatch(r"[0-9a-f]{64}", cid), "NETWORK_PEER_ID_UNPROVEN")
        if cid == allowed_id:
            continue
        doc = engine("GET", f"/containers/{cid}/json")
        require(doc is not None, "NETWORK_PEER_DISAPPEARED")
        require(doc["Name"] != f"/{SOUTHBOUND}-successor", "SUCCESSOR_NAME_OCCUPIED")
        for network, (ip, mac) in ENDPOINTS[SOUTHBOUND].items():
            endpoint = doc["NetworkSettings"]["Networks"].get(network)
            if endpoint is None:
                continue
            requested = (endpoint.get("IPAMConfig") or {}).get("IPv4Address")
            aliases = (endpoint.get("Aliases") or []) + (endpoint.get("DNSNames") or [])
            require(ip not in {requested, endpoint.get("IPAddress")}
                    and (endpoint.get("MacAddress") or "").lower() != mac
                    and not {SOUTHBOUND, SOUTHBOUND + "-successor"}.intersection(aliases),
                    "SOUTHBOUND_NETWORK_RESOURCE_OCCUPIED")
    return sha(canonical(networks))


def validate_output(args):
    root = args.output_root
    require(root.is_absolute() and not root.is_symlink(), "OUTPUT_ROOT_INVALID")
    for path in (root, *root.parents):
        entry = path.lstat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0
                and not entry.st_mode & 0o022, "OUTPUT_ROOT_NOT_PROTECTED")
    require(not os.path.lexists(root / args.output_name), "OUTPUT_ALREADY_EXISTS")


def observe(args):
    validate_output(args)
    requests = {name: build_request({ADAPTER: args.historical_adapter_id,
                                     SOUTHBOUND: args.historical_southbound_id}, name, True)
                for name in ENDPOINTS}
    reconstructed_sha = sha(canonical(requests))
    require(reconstructed_sha.startswith(args.creation_plan_prefix),
            "CREATION_REQUEST_RECONSTRUCTION_MISMATCH")
    runtimes = engine("GET", "/info")["Runtimes"]
    require(args.expected_runtime not in {"", "runc", "io.containerd.runc.v2"}
            and args.expected_runtime in runtimes, "GOVERNED_RUNTIME_MISSING")
    current = {}
    try:
        for name, cid in ((ADAPTER, args.current_adapter_id),
                          (SOUTHBOUND, args.current_southbound_id)):
            current[name] = inspect_created(cid, name, requests[name],
                                            args.creation_transaction, args.expected_runtime)
    except (Held, KeyError, TypeError, ValueError) as error:
        detail = str(error) if isinstance(error, Held) else type(error).__name__
        raise Held("CURRENT_SUCCESSOR_REQUEST_MISMATCH:" + detail) from None
    network_digest = check_networks(args.current_southbound_id)
    new_request = derive_request(requests[SOUTHBOUND])
    plan = {
        "schema": "ouf.semantic-southbound-successor-recreation-plan.v1",
        "inputs": {key: str(value) if isinstance(value, Path) else value
                   for key, value in vars(args).items()
                   if key not in {"plan", "apply", "plan_sha256"}},
        "reconstructedRequestsSha256": reconstructed_sha,
        "reconstructedRequestDigests": {n: sha(canonical(r)) for n, r in requests.items()},
        "verifiedCreationPlanPrefix": args.creation_plan_prefix,
        "currentFrameDigests": {n: frame_digest(d) for n, d in current.items()},
        "currentMacProfiles": {n: mac_profile(d, n) for n, d in current.items()},
        "networkReadbackSha256": network_digest,
        "newSouthboundRequest": new_request,
        "creationLabel": {"key": OWNER_LABEL, "valueSource": "os.urandom(16).hex() at apply"},
        "operations": {"deleteRequests": 1, "createRequests": 1, "containerStarts": 0},
        "startAuthorized": False,
    }
    return plan, requests, current


def reserve_output(args):
    # Recheck before the atomic mkdir. A reserved name is never cleaned up.
    validate_output(args)
    root_fd = os.open(args.output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(args.output_name, mode=0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        return os.open(args.output_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                       dir_fd=root_fd)
    finally:
        os.close(root_fd)


def write_receipt(directory_fd, report):
    fd = os.open("result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(report) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory_fd)


def run(args):
    report = {"schema": "ouf.semantic-southbound-successor-recreation.v1", "status": "HELD",
              "oldCid": args.current_southbound_id, "newCid": None,
              "oldRemoved": False, "newCreated": False, "containerStarts": 0,
              "deleteRequests": 0, "createRequests": 0, "noswapRemoved": False,
              "startAuthorized": False, "doNotRerunApply": False}
    directory_fd = None
    try:
        plan, requests, current = observe(args)
        digest = sha(canonical(plan))
        report.update(planSha256=digest, plan=plan)
        if args.plan:
            report["status"] = "PLAN_READY"
            return report
        require(args.plan_sha256 == digest, "PLAN_DIGEST_CHANGED")
        directory_fd = reserve_output(args)
        # Last bounded re-observation immediately before the sole DELETE.
        for name, cid in ((ADAPTER, args.current_adapter_id),
                          (SOUTHBOUND, args.current_southbound_id)):
            latest = inspect_created(cid, name, requests[name], args.creation_transaction,
                                     args.expected_runtime)
            require(frame_digest(latest) == frame_digest(current[name]), "LAST_FRAME_CHANGED")
        require(check_networks(args.current_southbound_id) == plan["networkReadbackSha256"],
                "LAST_NETWORK_READBACK_CHANGED")
        transaction = os.urandom(16).hex()
        request = copy.deepcopy(plan["newSouthboundRequest"])
        request["Labels"] = {OWNER_LABEL: transaction}
        report.update(newTransaction=transaction, newRequestSha256=sha(canonical(request)),
                      noswapRemoved=True, doNotRerunApply=True)
        report["deleteRequests"] = 1
        # No query parameters: neither force nor v can be sent.
        engine("DELETE", f"/containers/{args.current_southbound_id}")
        report["oldRemoved"] = engine("GET", f"/containers/{args.current_southbound_id}/json") is None
        require(report["oldRemoved"], "OLD_REMOVAL_UNPROVEN")
        check_networks(None)
        report["createRequests"] = 1
        response = engine("POST", f"/containers/create?name={SOUTHBOUND}-successor", request)
        report["newCreated"] = True
        cid = response["Id"]
        report["newCid"] = cid
        require(isinstance(cid, str) and re.fullmatch(r"[0-9a-f]{64}", cid)
                and cid not in {args.historical_adapter_id, args.historical_southbound_id,
                                args.current_adapter_id, args.current_southbound_id},
                "CREATED_ID_UNPROVEN")
        new = inspect_created(cid, SOUTHBOUND, plan["newSouthboundRequest"], transaction,
                              args.expected_runtime)
        require(mac_profile(new, SOUTHBOUND) == mac_profile(current[SOUTHBOUND], SOUTHBOUND),
                "NEW_LEGACY_MAC_PROFILE_CHANGED")
        check_networks(cid)
        report.update(status="SOUTHBOUND_RECREATED_STOPPED", newFrameSha256=frame_digest(new))
    except (Exception, KeyboardInterrupt) as error:
        report["reason"] = str(error) if isinstance(error, Held) else type(error).__name__
        if report["deleteRequests"]:
            report["status"] = "PARTIAL"
            report["doNotRerunApply"] = True
            # A lost HTTP response is not proof that a mutation did not happen.
            if not report["oldRemoved"] and report.get("reason") != "OLD_REMOVAL_UNPROVEN":
                report["oldRemoved"] = None
            if report["createRequests"] and not report["newCreated"]:
                report["newCreated"] = None
    finally:
        # Verify the untouched role after every mutation path, even when CREATE
        # or the new readback failed. Preserve the primary failure separately.
        if report["deleteRequests"]:
            report["adapterUnchanged"] = None
            try:
                adapter = inspect_created(args.current_adapter_id, ADAPTER, requests[ADAPTER],
                                          args.creation_transaction, args.expected_runtime)
                report["adapterUnchanged"] = frame_digest(adapter) == frame_digest(current[ADAPTER])
                require(report["adapterUnchanged"], "ADAPTER_FRAME_CHANGED")
            except (Exception, KeyboardInterrupt) as error:
                detail = str(error) if isinstance(error, Held) else type(error).__name__
                report.update(status="PARTIAL", adapterVerificationError=detail,
                              doNotRerunApply=True)
                report.setdefault("reason", "ADAPTER_POST_VERIFICATION_FAILED")
        if directory_fd is not None:
            try:
                write_receipt(directory_fd, report)
            except (Exception, KeyboardInterrupt) as error:
                report.update(status="PARTIAL" if report["deleteRequests"] else "HELD",
                              receiptError=type(error).__name__, doNotRerunApply=True)
            finally:
                os.close(directory_fd)
    return report


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    for name in ("historical-adapter-id", "historical-southbound-id", "current-adapter-id",
                 "current-southbound-id", "creation-transaction", "creation-plan-prefix",
                 "expected-runtime", "docker-socket", "output-root", "output-name"):
        parser.add_argument("--" + name, required=True,
                            type=Path if name in {"docker-socket", "output-root"} else str)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    for name, length in (("historical_adapter_id", 64), ("historical_southbound_id", 64),
                         ("current_adapter_id", 64), ("current_southbound_id", 64),
                         ("creation_transaction", 32), ("creation_plan_prefix", 8)):
        if not re.fullmatch(r"[0-9a-f]{%d}" % length, getattr(args, name)):
            parser.error("invalid --" + name.replace("_", "-"))
    if len({args.historical_adapter_id, args.historical_southbound_id,
            args.current_adapter_id, args.current_southbound_id}) != 4:
        parser.error("all four container IDs must be distinct")
    if not args.docker_socket.is_absolute() or not args.output_root.is_absolute():
        parser.error("socket and output root must be absolute")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.output_name):
        parser.error("invalid --output-name")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.expected_runtime):
        parser.error("invalid --expected-runtime")
    if args.apply and not re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256 or ""):
        parser.error("--apply requires --plan-sha256")
    if args.plan and args.plan_sha256 is not None:
        parser.error("--plan-sha256 is only valid with --apply")
    return args


def main():
    args = arguments()
    os.umask(0o077)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print(json.dumps({"schema": "ouf.semantic-southbound-successor-recreation.v1",
                          "status": "HELD", "reason": "ROOT_REQUIRED"}))
        return 1
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        print(json.dumps({"schema": "ouf.semantic-southbound-successor-recreation.v1",
                          "status": "HELD", "reason": "PYTHON_ISOLATED_NO_BYTECODE_REQUIRED"}))
        return 1
    global DOCKER_SOCKET
    DOCKER_SOCKET = str(args.docker_socket)
    report = run(args)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in {"PLAN_READY", "SOUTHBOUND_RECREATED_STOPPED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
