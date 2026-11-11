#!/usr/bin/env python3
"""Observe the live Semantic peer and stage an inactive, hash-bound input for B."""

import argparse
from contextlib import suppress
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


SEMANTIC = "43a294defebd354b1c357e78d8b8807c2575291e8ec25540a23c901518649d7b"
CUTOVER_PLAN = "289a1e2d97ac93cce4318d6edf56dcfadfc244a12b02f5e55c2b5ee7139e3afb"
WORK = Path("/var/lib/ouf-storage-migration/semantic-provider-preparation-a-20261111")
SOUTHBOUND_HOST = "ouf-semantic-southbound-v2"
IP = "/usr/sbin/ip"
NSENTER = "/usr/bin/nsenter"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
MISMATCH = "SOUTHBOUND_SERVED_CERTIFICATE_MISMATCH"
OUTPUTS = ("manifest.json", "semantic-peer.json", "successors.json", "result.json")
FRAME_FIELDS = ("Id", "Name", "Image", "State", "RestartCount", "Config", "HostConfig", "Mounts", "NetworkSettings")


class Held(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise Held(code)


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def module(name, filename, expected):
    path = Path(__file__).parent / filename
    raw = path.read_bytes()
    require(sha(raw) == expected, "DEPENDENCY_SOURCE_CHANGED")
    selected = types.ModuleType(name)
    selected.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), selected.__dict__)
    return selected


def helpers():
    cutover = module("cutover_d", "cutover-semantic-provider-20261111.py",
                     "ec69f0d86d337596ad562078eee18f87189310bb08f44a4f2b3550122b0366d9")
    rollout = module("rollout", "upgrade-semantic-application-20261108.py",
                     "2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1")
    return cutover, rollout


def unique_pairs(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "DUPLICATE_JSON_FIELD")
    return result


def one_certificate(pem):
    require(re.fullmatch(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
                         rb"-----END CERTIFICATE-----", pem.strip()) is not None, MISMATCH)
    return ssl.PEM_cert_to_DER_cert(pem.strip().decode("ascii"))


def verify_served_certificate(routes, leaf):
    try:
        document, marker, trailer = routes.rpartition(b"#END")
        require(marker and trailer == b"\n", MISMATCH)
        ssls = json.loads(document, object_pairs_hook=unique_pairs)["ssls"]
        require(type(ssls) is list and len(ssls) == 1, MISMATCH)
        resource = ssls[0]
        require(resource["type"] == "server" and type(resource["status"]) is int and resource["status"] == 1
                and resource["snis"] == [SOUTHBOUND_HOST] and "certs" not in resource, MISMATCH)
        require(one_certificate(resource["cert"].encode("ascii")) == one_certificate(leaf), MISMATCH)
    except (Held, AttributeError, TypeError, KeyError, ValueError) as error:
        raise Held(MISMATCH) from error


def native_json(cutover, deadline, *command, descriptors=()):
    result = subprocess.run(command, pass_fds=descriptors, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=cutover.remaining(deadline, 5), env=ENV)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 131072, "NATIVE_LINK_READ_FAILED")
    return json.loads(result.stdout)


def generation(pid, netns_fd):
    proc = Path("/proc", str(pid))
    raw = (proc / "stat").read_bytes()
    require(len(raw) <= 8192 and raw.startswith(f"{pid} (".encode()) and b") " in raw,
            "PROCESS_GENERATION_UNPROVEN")
    ticks = int(raw.rsplit(b") ", 1)[1].split()[19])
    namespace = (proc / "ns/net").stat()
    pinned = os.fstat(netns_fd)
    require((namespace.st_dev, namespace.st_ino) == (pinned.st_dev, pinned.st_ino) and ticks > 0,
            "PROCESS_NETWORK_NAMESPACE_CHANGED")
    return {"pid": pid, "startTicks": ticks, "namespaceInode": namespace.st_ino,
            "namespaceDevice": namespace.st_dev}


def reciprocal_link(child_rows, host_lookup, address, mac, bridge):
    links = [row for row in child_rows if row.get("ifname") != "lo"]
    require(len(links) == 1, "SEMANTIC_BACKEND_INTERFACE_UNPROVEN")
    child = links[0]
    ips = child["addr_info"]
    require(child["ifname"] == "eth0" and child["address"] == mac
            and child.get("linkinfo", {}).get("info_kind") == "veth"
            and [(ip["family"], ip["local"]) for ip in ips] == [("inet", address)],
            "SEMANTIC_NATIVE_ADDRESS_CHANGED")
    child_index, host_index = child["ifindex"], child["link_index"]
    require(type(child_index) is int and type(host_index) is int and min(child_index, host_index) > 1,
            "SEMANTIC_VETH_INDEX_UNPROVEN")
    host = host_lookup(host_index)
    require(host["ifindex"] == host_index and host["link_index"] == child_index and host["master"] == bridge
            and host.get("linkinfo", {}).get("info_kind") == "veth"
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", host["ifname"]), "SEMANTIC_VETH_PEER_CHANGED")
    return {"interface": "eth0", "ipv4": address, "mac": mac, "bridge": bridge,
            "workloadRef": "ouf-semantic-registry", "bindingRef": "semantic-backend",
            "childIfindex": child_index, "hostIfindex": host_index, "hostInterface": host["ifname"]}


def observe_peer(cutover, deadline, current):
    pid = current["State"]["Pid"]
    require(type(pid) is int and pid > 1, "SEMANTIC_PROCESS_UNPROVEN")
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = generation(pid, fd)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot), "BOOT_ID_UNPROVEN")

        def host_lookup(index):
            name = socket.if_indextoname(index)
            rows = native_json(cutover, deadline, IP, "-j", "-d", "link", "show", "dev", name)
            require(len(rows) == 1 and rows[0]["ifname"] == name, "SEMANTIC_HOST_VETH_UNPROVEN")
            return rows[0]

        def observe():
            rows = native_json(cutover, deadline, NSENTER, f"--net=/proc/self/fd/{fd}",
                               IP, "-j", "-d", "addr", "show", descriptors=(fd,))
            return reciprocal_link(rows, host_lookup, cutover.ADDRESS, cutover.MAC, "br-" + cutover.NETWORK_ID[:12])

        first = observe()
        require(observe() == first and generation(pid, fd) == before
                and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot,
                "SEMANTIC_PEER_CHANGED_DURING_READ")
    finally:
        os.close(fd)
    return {"schema": "ouf.semantic-provider-preparation-a.peer.v1",
            "containerId": current["Id"], "image": current["Image"], "startedAt": current["State"]["StartedAt"],
            "generation": before, "bootId": boot, "networkId": cutover.NETWORK_ID,
            "endpointId": current["NetworkSettings"]["Networks"][cutover.NETWORK]["EndpointID"], "binding": first}


def read_cutover(cutover, inputs):
    files = {}
    for name in ("result.json", "manifest.json", "complete.json", "creation-request.private.json"):
        path = cutover.WORK / name
        raw = cutover.private_input(path, uid=0, gid=0, mode=0o600, limit=1048576)
        inputs[str(path)] = sha(raw)
        files[name] = json.loads(raw, object_pairs_hook=unique_pairs)
    result, receipt = files["result.json"], files["manifest.json"]
    require(result["schema"] == "ouf.semantic-provider-cutover.v1"
            and result["status"] == "SEMANTIC_PROVIDER_CUTOVER_READY"
            and result["planSha256"] == receipt["planSha256"] == CUTOVER_PLAN
            and result["replacementContainerId"] == SEMANTIC and result["southboundIssuerMatch"] is True
            and result["manifest"] == receipt["manifest"]
            and files["complete.json"] == {"containerId": SEMANTIC, "oldContainerId": cutover.OLD,
                                           "planSha256": CUTOVER_PLAN},
            "CUTOVER_D_RECEIPT_UNPROVEN")
    request = files["creation-request.private.json"]
    require(request["Labels"][cutover.LABEL] == CUTOVER_PLAN
            and not os.path.lexists(cutover.WORK / "restored.json"), "CUTOVER_D_REQUEST_UNPROVEN")
    return result["manifest"], request


def frame(doc):
    return {key: doc[key] for key in FRAME_FIELDS}


def backend_network(cutover, deadline, current):
    ep = current["NetworkSettings"]["Networks"][cutover.NETWORK]
    network = cutover.engine(deadline, "GET", "/networks/" + cutover.NETWORK_ID)
    row = network["Containers"][SEMANTIC]
    require(network["Id"] == cutover.NETWORK_ID and network["Name"] == cutover.NETWORK
            and network["Driver"] == "bridge" and network["EnableIPv6"] is False
            and row["EndpointID"] == ep["EndpointID"] and ep["NetworkID"] == cutover.NETWORK_ID
            and re.fullmatch("[a-f0-9]{64}", ep["EndpointID"]) and row["MacAddress"] == cutover.MAC
            and [cid for cid, node in network["Containers"].items()
                 if node["IPv4Address"].split("/")[0] == cutover.ADDRESS] == [SEMANTIC],
            "SEMANTIC_BACKEND_ENDPOINT_UNPROVEN")
    return row


def stopped_successors(cutover, deadline):
    observed = {}
    for cid in cutover.SUCCESSORS:
        doc = cutover.inspect(deadline, cid)
        state, host = doc["State"], doc["HostConfig"]
        require(doc["Id"] == cid and state["Status"] == "created" and state["Pid"] == 0
                and state["Running"] is False and state["StartedAt"].startswith("0001-")
                and doc["RestartCount"] == 0 and host["RestartPolicy"]["Name"] == "no"
                and host["Runtime"] == "ouf-semantic-admitted-v2"
                and doc["Config"]["Labels"].get("ouf.semantic.provider.successor.creation")
                == cutover.SUCCESSOR_TRANSACTION
                and not any(e.get("EndpointID") or e.get("IPAddress")
                            for e in doc["NetworkSettings"]["Networks"].values()), "SUCCESSOR_NOT_STOPPED")
        observed[cid] = frame(doc)
    return observed


def check_work_parent():
    for parent in WORK.parents:
        entry = parent.lstat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022,
                "PREPARATION_DIRECTORY_PARENT_UNPROVEN")
    require(not os.path.lexists(WORK), "PREPARATION_SCOPE_ALREADY_EXISTS")


def plan(cutover, rollout):
    check_work_parent()
    deadline = time.monotonic() + 55
    inputs = {}
    historical, request = read_cutover(cutover, inputs)
    info = cutover.engine(deadline, "GET", "/info")
    require((info["ServerVersion"], info["Driver"], info["CgroupDriver"], info["DockerRootDir"])
            == ("29.8.1", "overlayfs", "systemd", "/var/lib/docker"), "ENGINE_PROFILE_CHANGED")
    old = cutover.inspect(deadline, cutover.OLD)
    current = cutover.inspect(deadline, SEMANTIC)
    require(old["Name"] == "/" + historical["retainedName"] and old["State"]["Status"] == "exited"
            and old["State"]["Pid"] == 0 and not old["NetworkSettings"]["Networks"]
            and current["Id"] == SEMANTIC and current["Name"] == "/" + historical["newContainer"]["name"]
            and current["State"]["Status"] == "running" and current["RestartCount"] == 0
            and current["State"]["Paused"] is False and current["State"]["Restarting"] is False
            and cutover.process(deadline, current) == rollout.JAVA, "CUTOVER_D_GENERATION_UNPROVEN")
    expected = old | {"NetworkSettings": {"Networks": {cutover.NETWORK: {
        "DNSNames": historical["network"]["dnsNames"],
    }}}}
    cutover.verify_new(rollout, expected, request, current, True)
    backend = backend_network(cutover, deadline, current)
    before = stopped_successors(cutover, deadline)
    southbound = before[cutover.SOUTHBOUND_SUCCESSOR]
    binds = [m for m in southbound["Mounts"] if m["Destination"] == cutover.SOUTHBOUND_ROUTES_TARGET]
    require(len(binds) == 1 and binds[0]["Type"] == "bind" and binds[0]["RW"] is False
            and binds[0]["Source"] == str(cutover.SOUTHBOUND_ROUTES), MISMATCH)
    routes = cutover.private_input(cutover.SOUTHBOUND_ROUTES, uid=636, gid=636, mode=0o600, limit=1048576)
    leaf = cutover.private_input(cutover.SOUTHBOUND_LEAF, uid=636, gid=636, mode=0o600, limit=65536)
    verify_served_certificate(routes, leaf)
    require(sha(leaf) == cutover.SOUTHBOUND_LEAF_SHA, MISMATCH)
    peer = observe_peer(cutover, deadline, current)
    require(frame(cutover.inspect(deadline, SEMANTIC)) == frame(current)
            and backend_network(cutover, deadline, current) == backend
            and stopped_successors(cutover, deadline) == before, "DISCOVERY_GENERATION_CHANGED_DURING_READ")
    # Compare the public certificate again and do not bind or expose the private key.
    verify_served_certificate(cutover.private_input(cutover.SOUTHBOUND_ROUTES, uid=636, gid=636, mode=0o600,
                                                    limit=1048576), leaf)
    peer["dockerFrameSha256"] = sha(canonical(frame(current)))
    peer["proposedIngress"] = {"kind": "BRIDGE_PORT", "ifindex": peer["binding"]["hostIfindex"],
                               "sourceIpv4": cutover.ADDRESS, "destinationIpv4": "172.18.0.14",
                               "destinationPort": 10443, "protocol": "tcp"}
    successors = {"transaction": cutover.SUCCESSOR_TRANSACTION, "containers": [
        {"containerId": cid, "name": doc["Name"], "image": doc["Image"],
         "status": "created", "runtime": doc["HostConfig"]["Runtime"], "dockerFrameSha256": sha(canonical(doc))}
        for cid, doc in before.items()],
        "southboundCertificate": {"configuredDerMatches": True, "sni": SOUTHBOUND_HOST,
                                  "liveTlsObserved": False}}
    staged = {"semantic-peer.json": peer, "successors.json": successors}
    manifest = {"schema": "ouf.semantic-provider-preparation-a.manifest.v1",
                "cutoverDPlanSha256": CUTOVER_PLAN, "semanticPeer": peer, "successors": successors,
                "inputFiles": [*inputs, str(cutover.SOUTHBOUND_ROUTES), str(cutover.SOUTHBOUND_LEAF),
                               f"/proc/{peer['generation']['pid']}/stat", f"/proc/{peer['generation']['pid']}/ns/net",
                               f"/proc/{peer['generation']['pid']}/cmdline", "/proc/sys/kernel/random/boot_id"],
                "directory": {"path": str(WORK), "mode": "0700", "uid": 0, "gid": 0},
                "filesCreated": [{"path": str(WORK / name), "mode": "0600", "uid": 0, "gid": 0}
                                 | ({"sha256": sha(canonical(staged[name]) + b"\n")} if name in staged else {})
                                 for name in OUTPUTS],
                "runtimeObjectsCreated": [], "runtimeObjectsModified": [], "wrapperPrepared": False}
    return manifest, sha(canonical({"manifest": manifest, "cutoverInputHashes": inputs})), staged


def write(directory, name, value):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, 0)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory)


def stage(manifest, digest, staged, report):
    check_work_parent()
    WORK.mkdir(mode=0o700)
    parent = os.open(WORK.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    directory = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchown(directory, 0, 0)
        os.fchmod(directory, 0o700)
        for name in ("semantic-peer.json", "successors.json"):
            write(directory, name, staged[name])
        write(directory, "manifest.json", {"manifest": manifest, "planSha256": digest})
        report["status"] = "SEMANTIC_PROVIDER_PREPARATION_A_STAGED"
        write(directory, "result.json", report)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    args = parser.parse_args()
    if args.apply != bool(args.plan_sha256 and re.fullmatch(r"[a-f0-9]{64}", args.plan_sha256)):
        parser.error("--apply requires an exact --plan-sha256")
    if args.plan and args.plan_sha256 is not None:
        parser.error("--plan accepts no --plan-sha256")
    report = {"schema": "ouf.semantic-provider-preparation-a.v1", "status": "HELD",
              "providerProbes": 0, "credentialValuesEmitted": False, "replayAllowed": False}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated, "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        cutover, rollout = helpers()
        manifest, digest, staged = plan(cutover, rollout)
        report.update(manifest=manifest, planSha256=digest)
        if args.plan:
            report["status"] = "PLAN_READY"
        else:
            require(args.plan_sha256 == digest, "PLAN_DIGEST_CHANGED")
            stage(manifest, digest, staged, report)
    except (RuntimeError, OSError, ValueError, KeyError, IndexError, TypeError, AttributeError,
            subprocess.SubprocessError, http.client.HTTPException) as error:
        reason = str(error) if isinstance(error, RuntimeError) else ""
        report.update(status="HELD", reason=reason if re.fullmatch(r"[A-Z][A-Z_0-9]{0,110}", reason)
                      else type(error).__name__)
    with suppress(OSError):
        output = memoryview(canonical(report) + b"\n")
        while output:
            output = output[os.write(1, output):]
    return 0 if report["status"] in ("PLAN_READY", "SEMANTIC_PROVIDER_PREPARATION_A_STAGED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
