#!/usr/bin/env python3
"""Discover and publish the stable parameters of one existing OUF installation."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import time
from urllib.parse import quote, urlsplit


SCHEMA = "ouf.semantic-provider-installation.v1"
FRAME_FIELDS = ("Id", "Name", "Image", "State", "RestartCount", "Config", "HostConfig", "Mounts", "NetworkSettings")
HEX = re.compile(r"[0-9a-f]{64}")
REF = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
DNS = re.compile(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class Held(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Held(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), "DUPLICATE_INPUT_FIELD")
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def absolute(value):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == str(value), "INPUT_PATH_UNPROVEN")
    return path


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "DIRECTORY_CUSTODY_UNPROVEN")


def identity(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                                                "st_size", "st_mtime_ns", "st_ctime_ns"))


class Reader:
    def __init__(self):
        self.inputs = {}
        self.deadline = time.monotonic() + 75

    def remaining(self):
        value = min(8, self.deadline - time.monotonic())
        require(value > 0, "PROFILE_READ_DEADLINE_EXCEEDED")
        return value

    def read(self, name, expected=None, *, uid=0, gid=0, mode=0o600, minimum=1, maximum=2097152):
        path = absolute(name)
        for parent in path.parents:
            directory(parent)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid
                    and info.st_nlink == 1 and minimum <= info.st_size <= maximum
                    and stat.S_IMODE(info.st_mode) == mode, "FILE_CUSTODY_UNPROVEN")
            raw = stream.read(maximum + 1)
            require(len(raw) == info.st_size and identity(info) == identity(os.fstat(stream.fileno()))
                    == identity(path.lstat()), "FILE_CHANGED_DURING_PROFILE_READ")
        pin = digest(raw)
        require(expected is None or pin == expected, "BOUND_INPUT_HASH_CHANGED")
        observed = (identity(info), pin)
        require(path not in self.inputs or self.inputs[path] == observed, "PROFILE_INPUT_CHANGED_DURING_READ")
        self.inputs[path] = observed
        return raw

    def document(self, path, expected=None, **options):
        return decode(self.read(path, expected, **options))

    def binary(self, name, expected=None):
        path = absolute(name).resolve(strict=True)
        mode = stat.S_IMODE(path.lstat().st_mode)
        require(mode in (0o555, 0o755), "EXECUTABLE_CUSTODY_UNPROVEN")
        self.read(path, expected, mode=mode, maximum=67108864)
        return str(path)

    def command_json(self, executable, *args):
        run = subprocess.run((executable, *args), capture_output=True, stdin=subprocess.DEVNULL,
                             timeout=self.remaining(), env=ENV)
        require(run.returncode == 0 and 0 < len(run.stdout) <= 2097152, "NATIVE_READ_UNPROVEN")
        return decode(run.stdout)

    def verify(self):
        require(all(identity(path.lstat()) == value[0] for path, value in self.inputs.items()),
                "PROFILE_INPUT_CHANGED_DURING_READ")
        return {str(path): value[1] for path, value in self.inputs.items()}


class Docker:
    def __init__(self, reader, path):
        self.reader, self.path = reader, absolute(path)
        for parent in self.path.parents:
            directory(parent)
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0, "DOCKER_SOCKET_UNPROVEN")
        self.identity = identity(info)

    def get(self, resource):
        require(resource == "/info" or re.fullmatch(r"/containers/[0-9a-f]{64}/json|/networks/[a-zA-Z0-9_.%~-]+", resource),
                "READ_ONLY_DOCKER_SCOPE_REQUIRED")
        path = self.path
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(str(path))
                peer = struct.unpack("3i", connection.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(peer[0] > 1 and peer[1] == 0, "DOCKER_PEER_UNPROVEN")
        require(identity(path.lstat()) == self.identity, "DOCKER_SOCKET_CHANGED")
        connection = Connection("localhost", timeout=self.reader.remaining())
        try:
            connection.request("GET", "/v1.44" + resource, headers={"Connection": "close"})
            with connection.getresponse() as response:
                raw = response.read(2097153)
                require(response.status == 200 and 0 < len(raw) <= 2097152, "DOCKER_READ_UNPROVEN")
        finally:
            connection.close()
        require(identity(path.lstat()) == self.identity, "DOCKER_SOCKET_CHANGED")
        return decode(raw)

    def inspect(self, cid):
        return self.get(f"/containers/{cid}/json")


def receipt_a(reader, path, expected):
    root = absolute(path)
    result = reader.document(root / "result.json")
    manifest = reader.document(root / "manifest.json")
    require(result["status"] == "SEMANTIC_PROVIDER_PREPARATION_A_STAGED"
            and result["planSha256"] == manifest["planSha256"] == expected
            and result["manifest"] == manifest["manifest"] and result["replayAllowed"] is False,
            "PREPARATION_A_RECEIPT_UNPROVEN")
    body = result["manifest"]
    require(body["directory"]["path"] == str(root) and body["schema"] == "ouf.semantic-provider-preparation-a.manifest.v1",
            "PREPARATION_A_SCOPE_CHANGED")
    pins = {row["path"]: row.get("sha256") for row in body["filesCreated"]}
    def read(name, key):
        full = str(root / name)
        require(isinstance(pins[full], str) and HEX.fullmatch(pins[full]), "PREPARATION_A_PIN_UNPROVEN")
        value = reader.document(full, pins[full])
        require(value == body[key], "PREPARATION_A_ARTIFACT_CHANGED")
        return value
    return read("semantic-peer.json", "semanticPeer"), read("successors.json", "successors")


def frame(doc):
    return digest(canonical({key: doc[key] for key in FRAME_FIELDS}))


def read_roles(docker, peer, successors):
    semantic = docker.inspect(peer["containerId"])
    require(semantic["State"]["Running"] is True and semantic["State"]["Pid"] == peer["generation"]["pid"]
            and semantic["State"]["StartedAt"] == peer["startedAt"] and frame(semantic) == peer["dockerFrameSha256"],
            "SEMANTIC_FRAME_DIFFERS_FROM_A")
    sni = successors["southboundCertificate"]["sni"]
    require(successors["southboundCertificate"]["configuredDerMatches"] is True
            and len(successors["containers"]) == 2, "SUCCESSOR_RECEIPT_A_UNPROVEN")
    roles = {"semantic": semantic}
    for selected in successors["containers"]:
        doc = docker.inspect(selected["containerId"])
        require(doc["State"]["Status"] == "created" and doc["State"]["Running"] is False
                and doc["State"]["Pid"] == 0 and frame(doc) == selected["dockerFrameSha256"],
                "SUCCESSOR_FRAME_DIFFERS_FROM_A")
        endpoints = doc["NetworkSettings"]["Networks"]
        role = "southbound" if any(sni in (ep.get("Aliases") or []) for ep in endpoints.values()) else "adapter"
        require(role not in roles, "SUCCESSOR_ROLE_UNPROVEN")
        roles[role] = doc
    return roles


def verify_peer(reader, ip, peer, semantic):
    proof = peer["generation"]
    pid = proof["pid"]
    require(type(pid) is int and pid > 1, "PROCESS_GENERATION_UNPROVEN")
    proc = Path("/proc", str(pid))
    raw = (proc / "stat").read_bytes()
    require(0 < len(raw) <= 8192 and raw.startswith(f"{pid} (".encode()) and b") " in raw,
            "PROCESS_GENERATION_UNPROVEN")
    ns = (proc / "ns/net").stat()
    binding = peer["binding"]
    rows = reader.command_json(ip, "-j", "-d", "link", "show", "dev", binding["hostInterface"])
    matches = [ep for ep in semantic["NetworkSettings"]["Networks"].values() if ep["EndpointID"] == peer["endpointId"]]
    require(int(raw.rsplit(b") ", 1)[1].split()[19]) == proof["startTicks"]
            and (ns.st_dev, ns.st_ino) == (proof["namespaceDevice"], proof["namespaceInode"])
            and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == peer["bootId"]
            and len(rows) == 1 and rows[0]["ifindex"] == binding["hostIfindex"]
            and rows[0]["ifname"] == binding["hostInterface"] and rows[0]["link_index"] == binding["childIfindex"]
            and rows[0]["master"] == binding["bridge"] and rows[0]["linkinfo"]["info_kind"] == "veth"
            and len(matches) == 1 and matches[0]["NetworkID"] == peer["networkId"]
            and matches[0]["IPAddress"] == binding["ipv4"] and matches[0]["MacAddress"] == binding["mac"],
            "SEMANTIC_GENERATION_DIFFERS_FROM_A")


def observed_networks(reader, docker, ip, docs):
    result = {}
    names = {name for doc in docs.values() for name in doc["NetworkSettings"]["Networks"]}
    for name in sorted(names):
        require(REF.fullmatch(name), "DOCKER_NETWORK_NAME_UNPROVEN")
        net = docker.get("/networks/" + quote(name, safe=""))
        require(net["Name"] == name and HEX.fullmatch(net["Id"]) and net["Driver"] == "bridge"
                and net["Scope"] == "local" and type(net["Internal"]) is bool, "DOCKER_BRIDGE_UNPROVEN")
        bridge = (net.get("Options") or {}).get("com.docker.network.bridge.name") or "br-" + net["Id"][:12]
        require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", bridge), "LINUX_BRIDGE_NAME_UNPROVEN")
        link = reader.command_json(ip, "-j", "-d", "link", "show", "dev", bridge)
        require(len(link) == 1 and link[0]["ifname"] == bridge and link[0]["linkinfo"]["info_kind"] == "bridge",
                "LINUX_BRIDGE_UNPROVEN")
        pools = sorted(str(ipaddress.ip_network(v["Subnet"])) for v in net["IPAM"]["Config"])
        require(pools and len(pools) == len(set(pools)), "DOCKER_SUBNETS_UNPROVEN")
        result[name] = (net["Id"], {"bridge": bridge, "internal": net["Internal"], "subnets": pools})
    return result


def stable_dns(values):
    result = []
    for value in values:
        require(isinstance(value, str) and DNS.fullmatch(value), "ROLE_DNS_NAME_UNPROVEN")
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}", value):
            result.append(value)
    return sorted(set(result))


def role_profiles(docs, networks):
    output = {}
    for role, doc in docs.items():
        name = doc["Name"].removeprefix("/")
        require(REF.fullmatch(name) and stable_dns([name]), "ROLE_CONTAINER_NAME_UNPROVEN")
        bindings = {}
        for network, endpoint in doc["NetworkSettings"]["Networks"].items():
            observed_id, facts = networks[network]
            if role == "semantic":
                address = endpoint["IPAddress"]
                require(endpoint["NetworkID"] == observed_id, "SEMANTIC_NETWORK_ID_CHANGED")
            else:
                address = endpoint["IPAMConfig"]["IPv4Address"]
                require(not endpoint.get("EndpointID") and not endpoint.get("IPAddress")
                        and endpoint.get("NetworkID") in ("", None, observed_id), "SUCCESSOR_NETWORK_STATE_CHANGED")
            ipv4 = ipaddress.IPv4Address(address)
            mac = endpoint["MacAddress"]
            require(sum(ipv4 in ipaddress.ip_network(subnet) for subnet in facts["subnets"]) == 1
                    and MAC.fullmatch(mac) and not int(mac[:2], 16) & 1 and int(mac.replace(":", ""), 16) > 0,
                    "ROLE_IP_MAC_BINDING_UNPROVEN")
            aliases = stable_dns(endpoint.get("Aliases") or [])
            names = stable_dns([name, *aliases, *(endpoint.get("DNSNames") or [])])
            bindings[network] = {"ipv4": str(ipv4), "mac": mac, "aliases": aliases, "dnsNames": names}
        output[role] = {"containerName": name, "networks": bindings}
    return output


def authority(reader, args):
    value = reader.document(args.authority_profile, args.authority_sha256)
    identities = value["authorities"]
    require(identities["installationRef"] == args.installation_ref and REF.fullmatch(identities["entityRef"]),
            "INSTALLATION_REFERENCE_DIFFERS_FROM_AUTHORITY")
    keys = {role: str(absolute(value["keyBindings"][role]["path"])) for role in ("installer", "attestor")}
    require(len(set(keys.values())) == 2, "AUTHORITY_KEY_PATHS_UNPROVEN")
    reader.read(args.trust_policy, args.trust_policy_sha256)
    return identities["entityRef"], keys


def boot_guard(reader, args):
    pointer = reader.document(args.guard_pointer)
    require(pointer["schema"] == "ouf.semantic-coordinated-boot-pointer.v1", "GUARD_POINTER_UNPROVEN")
    receipt = reader.document(pointer["receiptFile"], pointer["receiptHash"])
    require(receipt["schema"] == "ouf.discovery-successor-boot-installation.v1" and receipt["state"] == "INSTALLED"
            and receipt["leaseAuthorized"] is False and receipt["startAuthorized"] is False
            and receipt["observerHash"] == pointer["observerHash"], "INSTALLED_GUARD_UNPROVEN")
    reader.read(pointer["observerFile"], pointer["observerHash"])
    stage = absolute(receipt["stageDirectory"])
    profile = reader.document(stage / "boot-profile.json", receipt["bootProfileHash"])
    owner = reader.document(profile["coordinatedConfiguration"], receipt["configurationHash"])
    boot = reader.document(profile["bootConfiguration"], profile["bootConfigurationHash"])
    require(profile["coordinatedConfigurationHash"] == receipt["configurationHash"]
            and owner["kernel"] == boot["kernel"] and owner["commonLockFile"] == boot["lockFile"],
            "GUARD_OWNER_BINDING_UNPROVEN")
    journal = reader.document(owner["journalFile"])
    require(journal["state"] == "QUIESCED" and journal["leaseAuthorized"] is False
            and journal["startAuthorized"] is False and journal["leaseAddresses"] == [[], []]
            and all(journal[key] == value for key, value in owner["binding"].items()),
            "QUIESCED_COORDINATION_JOURNAL_REQUIRED")
    reader.read(boot["journalFile"])
    require(reader.read(owner["commonLockFile"], minimum=0, maximum=4096) == b"", "GUARD_LOCK_SCOPE_UNPROVEN")
    return owner, boot, {"pointer": str(absolute(args.guard_pointer)), "receipt": pointer["receiptFile"],
                         "profile": str(stage / "boot-profile.json"), "ownerConfiguration": profile["coordinatedConfiguration"],
                         "bootConfiguration": profile["bootConfiguration"], "coordinationJournal": owner["journalFile"],
                         "bootJournal": boot["journalFile"], "lock": owner["commonLockFile"],
                         "snapshotRoot": str(stage.parent)}


def historical_templates(reader, args, owner):
    receipt = reader.document(args.generation_receipt, args.generation_receipt_sha256)
    require(receipt["status"] == "DISCOVERY_GENERATION_INPUTS_PREPARED" and receipt["phase"] == "COMPLETE"
            and receipt["runtimeWrapperChanged"] is False, "SEALED_GENERATION_INPUTS_REQUIRED")
    root = absolute(receipt["preparationDirectory"])
    selection = {"kernel": owner["kernel"], "dns": owner["dns"], "coordinationBinding": owner["binding"],
                 "coordinationJournal": owner["journalFile"], "lockFile": owner["commonLockFile"]}
    templates = {}
    for role in ("adapter", "southbound"):
        name = role + "-inputs.private.json"
        value = reader.document(root / name, receipt["fileHashes"][name])
        require(value["role"] == role and value["successorCoordination"] == selection, "GENERATION_GUARD_DRIFT")
        templates[role] = value["historicalTemplate"]
    return templates


def runtime(reader, info, docs):
    name = docs["southbound"]["HostConfig"]["Runtime"]
    require(REF.fullmatch(name) and docs["adapter"]["HostConfig"]["Runtime"] == name,
            "SUCCESSOR_RUNTIME_DISAGREEMENT")
    wrapper = absolute(info["Runtimes"][name]["path"])
    raw = reader.read(wrapper, mode=0o755, maximum=131072)
    match = re.fullmatch(rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+) --configuration (/[A-Za-z0-9_./-]+) "\$@"\n', raw)
    require(match is not None, "RUNTIME_WRAPPER_SHAPE_UNPROVEN")
    python, source, config_path = (part.decode("ascii") for part in match.groups())
    config = reader.document(config_path)
    require(config["schema"] == "ouf.semantic-docker-runtime-adapter.v4" and config["pythonPath"] == python,
            "RUNTIME_CONFIGURATION_UNPROVEN")
    source_mode = stat.S_IMODE(absolute(source).lstat().st_mode)
    require(source_mode in (0o600, 0o644, 0o755), "RUNTIME_SOURCE_CUSTODY_UNPROVEN")
    reader.read(source, config["sourceHash"], mode=source_mode)
    reader.binary(python, config["pythonSha256"])
    reader.binary(config["runtimePath"], config["runtimeSha256"])
    return {"name": name, "wrapper": str(wrapper), "runtimeStateRoot": str(absolute(config["runtimeStateRoot"])),
            "runtimeExecutable": config["runtimePath"], "pythonExecutable": python,
            "dockerDataRoot": str(absolute(info["DockerRootDir"]))}


def empty_nft(reader, nft, kernel):
    table = kernel["tableName"]
    require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}", table), "NFT_TABLE_NAME_UNPROVEN")
    flows = kernel["providerFlows"]
    require(len(flows) == 2 and all(f["addresses"] == [] for f in flows), "CONFIGURED_EGRESS_MUST_BE_EMPTY")
    expected = {f"provider_{index}" for index in range(len(flows))}
    for family in ("inet", "bridge"):
        rows = reader.command_json(nft, "-j", "list", "table", family, table)["nftables"]
        actual = [row["set"] for row in rows if "set" in row]
        require(len(actual) == len(expected) and {row["name"] for row in actual} == expected
                and all(row["family"] == family and row["table"] == table and row.get("elem", []) == [] for row in actual)
                and not any("element" in row for row in rows)
                and sum(row.get("table", {}).get("name") == table and row["table"]["family"] == family for row in rows) == 1,
                "NFT_EGRESS_SETS_NOT_EMPTY")


def stable_transport(documents, roles, templates, owner, peer, sni, adapter, southbound):
    def https(value):
        url = urlsplit(value)
        require(url.scheme == "https" and url.hostname and DNS.fullmatch(url.hostname)
                and url.username is None and url.password is None and not url.query and not url.fragment,
                "HTTPS_ENDPOINT_UNPROVEN")
        port = url.port if url.port is not None else socket.getservbyname("https", "tcp")
        require(1 <= port <= 65535, "HTTPS_PORT_UNPROVEN")
        return {"host": url.hostname, "port": port}

    def environment(name):
        prefix = name + "="
        selected = [entry[len(prefix):] for entry in documents["semantic"]["Config"]["Env"] if entry.startswith(prefix)]
        require(len(selected) == 1, "SEMANTIC_ENDPOINT_ENV_UNPROVEN")
        return selected[0]

    def addresses(role):
        return {binding["ipv4"] for binding in roles[role]["networks"].values()}

    flows = {}
    for template in templates.values():
        for row in template["candidate"]["transport"]:
            shape = {key: row[key] for key in ("purpose", "source", "destination", "protocol", "port")}
            require(row["purpose"] not in flows or flows[row["purpose"]] == shape, "HISTORICAL_FLOW_DISAGREEMENT")
            flows[row["purpose"]] = shape
    workload, relay = (flows[key] for key in ("WORKLOAD_GATEWAY", "GATEWAY_ADAPTER"))
    require(set(flows) == {"WORKLOAD_GATEWAY", "GATEWAY_ADAPTER"}
            and all(f["protocol"] == "tcp" and type(f["port"]) is int and 1 <= f["port"] <= 65535 for f in flows.values())
            and workload["source"] in addresses("semantic") and workload["destination"] in addresses("southbound")
            and relay["source"] in addresses("southbound") and relay["destination"] in addresses("adapter"),
            "ROLE_TRANSPORT_DIFFERS_FROM_OBSERVED_ADDRESSES")
    ingress = peer["proposedIngress"]
    require((workload["source"], workload["destination"], workload["port"]) ==
            (ingress["sourceIpv4"], ingress["destinationIpv4"], ingress["destinationPort"]),
            "WORKLOAD_FLOW_DIFFERS_FROM_A")
    require(southbound["port"] == workload["port"] and southbound["ip"] in (workload["destination"], "0.0.0.0")
            and adapter["listenPort"] == relay["port"]
            and adapter["listenAddress"] in (relay["destination"], "0.0.0.0")
            and https(environment("OUF_SCHEMA_GOV_GATEWAY_BASE_URL")) == {"host": sni, "port": workload["port"]}
            and any(sni in binding["dnsNames"] for binding in roles["southbound"]["networks"].values()),
            "OBSERVED_LISTENER_OR_SERVICE_ENDPOINT_CHANGED")
    expected = {"provider": ("adapter", https(adapter["provider"]["endpoint"])),
                "iam": ("southbound", https(environment("OUF_SCHEMA_GOV_TOKEN_ENDPOINT")))}
    provider_flows = owner["kernel"]["providerFlows"]
    endpoints = {}
    for key, (role, destination) in expected.items():
        matches = [flow for flow in provider_flows if https(flow["endpoint"]) == destination
                   and flow["source"] in addresses(role)]
        require(len(matches) == 1, "GUARD_EXTERNAL_FLOW_UNPROVEN")
        endpoints[key] = destination | {"sourceRole": role}
    require(endpoints["provider"]["host"] != endpoints["iam"]["host"], "DISTINCT_EXTERNAL_HOSTS_REQUIRED")
    return {"southbound": workload["port"], "adapter": relay["port"]}, endpoints


def mounted_configuration(reader, doc, filename, uid):
    rows = [m for m in doc["Mounts"] if Path(m["Source"]).name == filename]
    require(len(rows) == 1 and rows[0]["Type"] == "bind" and rows[0]["RW"] is False,
            "ROLE_CONFIGURATION_BIND_UNPROVEN")
    return reader.document(rows[0]["Source"], uid=uid, gid=uid)


def output_plan(args):
    base = absolute(args.installation_root)
    require(REF.fullmatch(args.installation_ref) and args.installation_ref not in (".", ".."),
            "INSTALLATION_REFERENCE_UNPROVEN")
    for path in base.parents:
        directory(path)
    parent = base / args.installation_ref
    absent = []
    for path in (base, parent):
        if os.path.lexists(path):
            directory(path)
        else:
            absent.append(str(path))
    destination = parent / "semantic-provider.json"
    require(not os.path.lexists(destination), "INSTALLATION_PROFILE_ALREADY_EXISTS")
    return destination, absent


def observe(args):
    destination, absent = output_plan(args)
    reader = Reader()
    entity, keys = authority(reader, args)
    peer, successors = receipt_a(reader, args.a_root, args.a_plan_sha256)
    owner, boot, guard = boot_guard(reader, args)
    templates = historical_templates(reader, args, owner)
    adapter_tools = templates["adapter"]["commands"]
    ip = reader.binary(adapter_tools["ip"], templates["adapter"]["commandHashes"]["ip"])
    nft = reader.binary(owner["nftPath"], owner["nftSha256"])
    docker = Docker(reader, args.docker_socket)
    engine = docker.get("/info")
    docs = read_roles(docker, peer, successors)
    verify_peer(reader, ip, peer, docs["semantic"])
    networks = observed_networks(reader, docker, ip, docs)
    roles = role_profiles(docs, networks)
    for role in ("adapter", "southbound"):
        expected = {(b["bridge"], b["ipv4"], b["mac"]) for b in templates[role]["candidate"]["networkBindings"]}
        actual = {(networks[n][1]["bridge"], b["ipv4"], b["mac"]) for n, b in roles[role]["networks"].items()}
        require(expected == actual, "PROVIDER_NICS_DIFFERS_FROM_BOUND_RECIPE")
    adapter = mounted_configuration(reader, docs["adapter"], "adapter.json", 10006)
    listeners = mounted_configuration(reader, docs["southbound"], "config.yaml", 636)["apisix"]["ssl"]["listen"]
    require(len(listeners) == 1, "SOUTHBOUND_LISTENER_UNPROVEN")
    ports, endpoints = stable_transport(docs, roles, templates, owner, peer,
                                         successors["southboundCertificate"]["sni"], adapter, listeners[0])
    runtime_profile = runtime(reader, engine, docs)
    tables = {"guard": owner["kernel"]["tableName"],
              **{role: templates[role]["candidate"]["tableName"] for role in ("adapter", "southbound")}}
    require(len(set(tables.values())) == 3 and all(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}", name)
                                                for name in tables.values()), "NFT_TABLE_SCOPE_UNPROVEN")
    empty_nft(reader, nft, owner["kernel"])
    commands = {"nft": nft, "ip": ip}
    for name in ("nsenter", "unshare", "mount", "umount"):
        commands[name] = reader.binary(adapter_tools[name], templates["adapter"]["commandHashes"][name])
    for name in ("docker", "openssl", "systemctl"):
        path = shutil.which(name, path=ENV["PATH"])
        require(path is not None, "REQUIRED_EXECUTABLE_MISSING")
        commands[name] = reader.binary(path)
    profile = {"schema": SCHEMA, "installationRef": args.installation_ref, "entityRef": entity,
               "networks": {name: details for name, (_, details) in networks.items()}, "roles": roles,
               "ports": ports, "externalEndpoints": endpoints, "nftTables": tables, "runtime": runtime_profile,
               "paths": {"snapshotRoot": guard.pop("snapshotRoot"), "stateRoot": str(absolute(args.a_root).parent),
                         "dockerSocket": str(docker.path), "guard": guard, "binaries": commands,
                         "authorityProfile": str(absolute(args.authority_profile)), "trustPolicy": str(absolute(args.trust_policy))},
               "keyPaths": keys}
    current = read_roles(docker, peer, successors)
    verify_peer(reader, ip, peer, current["semantic"])
    require(observed_networks(reader, docker, ip, current) == networks and output_plan(args) == (destination, absent),
            "PROFILE_OBSERVATION_CHANGED_DURING_READ")
    empty_nft(reader, nft, owner["kernel"])
    writes = {"profileFile": str(destination), "owner": "root:root", "mode": "0600", "directoriesIfMissing": absent}
    raw = canonical(profile) + b"\n"
    result = {"profile": profile, "profileSha256": digest(raw), "writes": writes}
    plan = {"projection": result, "inputHashes": reader.verify(), "aPlanSha256": args.a_plan_sha256,
            "networkIds": {name: item[0] for name, item in networks.items()}}
    return result | {"planSha256": digest(canonical(plan))}


def publish(writes, raw):
    destination = absolute(writes["profileFile"])
    for name in writes["directoriesIfMissing"]:
        path = absolute(name)
        path.mkdir(mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    for parent in destination.parents:
        directory(parent)
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    tmp = ".semantic-provider-" + secrets.token_hex(16)
    created = False
    try:
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd), "wb") as out:
            created = True
            os.fchown(out.fileno(), 0, 0)
            os.fchmod(out.fileno(), 0o600)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.link(tmp, destination.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    finally:
        try:
            if created:
                os.unlink(tmp, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("installation-ref", "installation-root", "a-root", "a-plan-sha256", "guard-pointer",
                 "docker-socket", "generation-receipt", "generation-receipt-sha256", "authority-profile",
                 "authority-sha256", "trust-policy", "trust-policy-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require_hashes = (args.a_plan_sha256, args.generation_receipt_sha256, args.authority_sha256, args.trust_policy_sha256)
    if any(not HEX.fullmatch(value) for value in require_hashes) or (
            args.apply and not HEX.fullmatch(args.plan_sha256 or "")) or (args.plan and args.plan_sha256 is not None):
        parser.error("expected exact lowercase SHA-256 bindings")
    report = {"schema": "ouf.semantic-provider-installation.plan.v1", "status": "HELD", "privateKeysRead": 0}
    try:
        require(os.geteuid() == 0 and os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        os.umask(0o077)
        proposal = observe(args)
        report.update(proposal)
        if args.plan:
            report["status"] = "PLAN_READY"
        else:
            require(args.plan_sha256 == proposal["planSha256"], "PLAN_DIGEST_CHANGED")
            publish(proposal["writes"], canonical(proposal["profile"]) + b"\n")
            report["status"] = "SEMANTIC_PROVIDER_INSTALLATION_PROFILE_PUBLISHED"
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            subprocess.SubprocessError, http.client.HTTPException) as error:
        reason = str(error) if isinstance(error, Held) else type(error).__name__
        report.update(status="HELD", reason=reason)
    print(canonical(report).decode(), flush=True)
    return 0 if report["status"] != "HELD" else 1


if __name__ == "__main__":
    raise SystemExit(main())
