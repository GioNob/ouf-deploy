#!/usr/bin/env python3
"""Prepare an API 1.44 CREATE for each stopped successor, with bounded readback."""

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
import types


PREFLIGHT_SHA = "90524a905926e37fce9445adfab6928ada42989093f9b66d80abcb8de6a4b3f7"
IMAGE_REVIEW_SHA = "f557cf37dcc4b5b7d0a4cf65927204b9a135d146d3d8f06099544f52c0394a5e"
DOCKER_READBACK_SHA = "32e8d5251c68f2d4c0b4b1f0ffe03d550f28bb0d34c50c5da6794486706f1105"
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
ln -sfn /run/ouf-southbound-runtime/apisix.yaml /usr/local/apisix/conf/apisix.yaml
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
        self.sock.settimeout(25)
        self.sock.connect("/var/run/docker.sock")


def engine(method, path, payload=None):
    require((method == "GET" and (path == "/info" or re.fullmatch(r"/(?:containers|images)/[0-9a-f:]+/json", path)))
            or (method == "POST" and path in {f"/containers/create?name={name}-successor" for name in ENDPOINTS})
            or (method == "DELETE" and re.fullmatch(r"/containers/[0-9a-f]{64}", path)),
            "ENGINE_OPERATION_OUT_OF_SCOPE")
    with LocalEngine("localhost", timeout=25) as conn:
        conn.request(method, "/v1.44" + path, body=None if payload is None else canonical(payload),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(2_097_153)
        require(response.status == {"GET": 200, "POST": 201, "DELETE": 204}[method] and len(raw) <= 2_097_152,
                "ENGINE_RESPONSE_UNPROVEN")
        return None if method == "DELETE" else json.loads(raw)


def load_reader(path, expected_hash):
    raw = path.read_bytes()
    require(sha(raw) == expected_hash, "READER_SOURCE_CHANGED")
    module = types.ModuleType("reviewed_reader")
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


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


def build_request(preflight, name, transaction, noswap):
    historical_cid, _ = preflight.HISTORICAL[name]
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
    request.update(Image=image["Id"], Env=env, Labels={OWNER_LABEL: transaction}, HostConfig=host)
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
    host["NetworkMode"] = preflight.NETWORKS[next(iter(ENDPOINTS[name]))][0]
    request["NetworkingConfig"] = {"EndpointsConfig": {
        preflight.NETWORKS[network][0]: {"IPAMConfig": {"IPv4Address": ip}, "Aliases": [name], "MacAddress": mac}
        for network, (ip, mac) in ENDPOINTS[name].items()
    }}
    return request


def inspect_created(cid, name, request, transaction):
    doc = engine("GET", f"/containers/{cid}/json")
    config, state = doc["Config"], doc["State"]
    require(doc["Id"] == cid and doc["Name"] == f"/{name}-successor" and doc["Image"] == request["Image"]
            and state["Status"] == "created" and state["Running"] is False and state["Pid"] == 0
            and state["StartedAt"].startswith("0001-") and doc["RestartCount"] == 0
            and config["Labels"].get(OWNER_LABEL) == transaction, "CANDIDATE_IDENTITY_OR_STOPPED_STATE_CHANGED")
    require(doc["HostConfig"]["RestartPolicy"]["Name"] == "no"
            and doc["HostConfig"]["Runtime"] == request["HostConfig"]["Runtime"]
            and doc["HostConfig"].get("Tmpfs") == request["HostConfig"].get("Tmpfs")
            and (config.get("Env") or []) == request["Env"]
            and all(config.get(key) == request.get(key) for key in ("User", "WorkingDir", "Entrypoint", "Cmd")),
            "CANDIDATE_PROCESS_CONFIGURATION_CHANGED")
    expected_mounts = sorted((m["Source"], m["Target"], m["Type"], m["ReadOnly"])
                             for m in request["HostConfig"]["Mounts"])
    actual_mounts = sorted((m["Source"], m["Destination"], m["Type"], not m["RW"])
                           for m in doc["Mounts"] if m["Type"] != "tmpfs")
    require(expected_mounts == actual_mounts, "CANDIDATE_MOUNT_CONFIGURATION_CHANGED")
    endpoints = doc["NetworkSettings"]["Networks"]
    require(set(endpoints) == set(ENDPOINTS[name]), "CANDIDATE_NETWORK_SET_CHANGED")
    bindings = {}
    for network, (ip, mac) in ENDPOINTS[name].items():
        endpoint = endpoints[network]
        require(endpoint["IPAMConfig"]["IPv4Address"] == ip and name in endpoint["Aliases"]
                and not endpoint.get("EndpointID") and not endpoint.get("IPAddress")
                and endpoint.get("MacAddress") == mac, "CANDIDATE_ENDPOINT_METADATA_CHANGED")
        bindings[network] = {"requestedIPv4": ip, "assignedIPv4": None, "aliases": endpoint["Aliases"],
                             "requestedMacAddress": mac}
    return {"id": cid, "name": doc["Name"].lstrip("/"), "state": "created", "pid": 0, "neverStarted": True,
            "networks": bindings}


def guard(preflight, created=None):
    units, pointer, profile, quiesced = preflight.boot_units()
    require(all(units.values()) and pointer and profile and quiesced
            and preflight.service_references() == ([], []), "BOOT_CONFIGURATION_CHANGED")
    observed = preflight.read_docker()
    if created:
        cid = created["id"]
        role = created["name"].removesuffix("-successor")
        allowed = {f"new_name:/{created['name']}:in_use"}
        for network, (ip, _) in ENDPOINTS[role].items():
            data = observed["networks"][network]
            own_aliases = [row for row in data["aliasClaims"] if row["id"] == cid]
            own_claims = [row for row in data["targets"][ip]["containerClaims"] if row["id"] == cid]
            require(len(own_aliases) == len(own_claims) == 1 and not own_aliases[0]["live"]
                    and own_claims[0]["requestedIPv4"] == ip and not own_claims[0]["assignedIPv4"]
                    and not own_claims[0]["endpointId"], "FIRST_CANDIDATE_NETWORK_STATE_CHANGED")
            data["aliasClaims"].remove(own_aliases[0])
            data["targets"][ip]["containerClaims"].remove(own_claims[0])
            allowed.update((f"alias:{network}:{cid}:active_or_foreign", f"ip:{ip}:reservation_endpoint_or_request"))
        observed["blockers"] = [item for item in observed["blockers"] if item not in allowed]
    require(not observed["blockers"] and sha(canonical(observed)) == DOCKER_READBACK_SHA,
            "IP_OR_ALIAS_READBACK_CHANGED")


def remove_first(preflight, cid, transaction):
    require(re.fullmatch(r"[0-9a-f]{64}", cid) and re.fullmatch(r"[0-9a-f]{32}", transaction)
            and cid not in {row[0] for row in preflight.HISTORICAL.values()}, "CLEANUP_IDENTITY_INVALID")
    doc = engine("GET", f"/containers/{cid}/json")
    state = doc["State"]
    require(doc["Id"] == cid and doc["Name"] == f"/{ADAPTER}-successor"
            and doc["Config"]["Labels"].get(OWNER_LABEL) == transaction
            and state["Status"] == "created" and state["Running"] is False and state["Pid"] == 0
            and state["StartedAt"].startswith("0001-") and doc["RestartCount"] == 0
            and doc["HostConfig"]["RestartPolicy"]["Name"] == "no"
            and all(not endpoint.get("EndpointID") and not endpoint.get("IPAddress")
                    for endpoint in doc["NetworkSettings"]["Networks"].values()), "CLEANUP_OWNERSHIP_UNPROVEN")
    require(all(row["name"] != f"/{SOUTHBOUND}-successor" for row in preflight.containers()),
            "SECOND_CANDIDATE_PRESENT_REVIEW_REQUIRED")
    engine("DELETE", f"/containers/{cid}")
    require(all(row["id"] != cid for row in preflight.containers()), "FIRST_CANDIDATE_REMOVAL_UNPROVEN")
    return cid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--image-review", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="create the approved stopped candidates")
    mode.add_argument("--remove-first", nargs=2, metavar=("CID", "TRANSACTION"),
                      help="remove only the separately approved, never-started first candidate")
    args = parser.parse_args()
    report = {"schema": "ouf.discovery-stopped-creation.v1", "status": "HELD", "createRequests": 0,
              "containerStarts": 0, "nftWrites": 0, "semanticChanged": False, "credentialValuesEmitted": False,
              "candidates": []}
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        preflight = load_reader(args.preflight, PREFLIGHT_SHA)
        if args.remove_first:
            report["removedCandidate"] = remove_first(preflight, *args.remove_first)
            report["status"] = "FIRST_STOPPED_CANDIDATE_REMOVED"
            print(json.dumps(report, sort_keys=True))
            return 0
        require(args.image_review is not None, "IMAGE_REVIEW_READER_REQUIRED")
        reviewer = load_reader(args.image_review, IMAGE_REVIEW_SHA)
        image = reviewer.image_review()
        require(image["checkSchemaAllowsBearerJwksWithoutSecret"]
                and image["uid636WriteSearchOnRetainedRootfs"], "SOUTHBOUND_IMAGE_REVIEW_UNPROVEN")
        kernel = reviewer.kernel_review()
        report["southboundImage"] = image
        report["kernel"] = kernel
        transaction = os.urandom(16).hex()
        report["transaction"] = transaction
        requests = {name: build_request(preflight, name, transaction, kernel["noswapByKernelVersion"])
                    for name in ENDPOINTS}
        runtimes = engine("GET", "/info")["Runtimes"]
        require(all(request["HostConfig"]["Runtime"] not in ("", "runc", "io.containerd.runc.v2")
                    and request["HostConfig"]["Runtime"] in runtimes for request in requests.values()),
                "GOVERNED_RUNTIME_MISSING")
        for name, request in requests.items():
            first = report["candidates"][0] if report["candidates"] else None
            if first:
                inspect_created(first["id"], ADAPTER, requests[ADAPTER], transaction)
            guard(preflight, first)
            report["createRequests"] += 1
            response = engine("POST", f"/containers/create?name={name}-successor", request)
            cid = response["Id"]
            require(re.fullmatch(r"[a-f0-9]{64}", cid), "CREATED_ID_UNPROVEN")
            row = {"id": cid, "name": name + "-successor", "state": "unverified"}
            report["candidates"].append(row)
            row.update(inspect_created(cid, name, request, transaction))
        report["status"] = "DISCOVERY_CANDIDATES_CREATED_STOPPED"
    except (Held, OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
        report["reason"] = str(error) if type(error) is Held else type(error).__name__
        report["replayAllowed"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "DISCOVERY_CANDIDATES_CREATED_STOPPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
