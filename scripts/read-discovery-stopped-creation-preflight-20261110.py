#!/usr/bin/env python3
"""Read Docker and systemd metadata before creating two stopped candidates."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone


DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
NETWORKS = {
    "ouf-backend": ("113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3",
                    {"172.18.0.14": "ouf-semantic-southbound-v2"}),
    "ouf-semantic-provider-internal": ("2a6652422b45db6f359d94d779ab8625b1ad99b1750bb54582b4b8c4e8aa9307",
                                      {"172.21.0.2": "ouf-semantic-southbound-v2", "172.21.0.3": "ouf-semantic-provider-v2"}),
    "ouf-semantic-provider-egress": ("db8bc9f8feccc3c14f2818a5c843f5c08e5eb2e192530858d88a70ce1cc0a86d",
                                    {"172.22.0.2": "ouf-semantic-southbound-v2", "172.22.0.3": "ouf-semantic-provider-v2"}),
}
HISTORICAL = {
    "ouf-semantic-provider": ("10a6237447b83c6e67e134e9266a74f5247fb1fa1fbe2c4528ff92fd663f767b", "created"),
    "ouf-semantic-provider-v2": ("f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67", "exited"),
    "ouf-semantic-southbound-v2": ("1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916", "exited"),
}
NEW_NAMES = {"ouf-semantic-provider-v2-successor", "ouf-semantic-southbound-v2-successor"}
PROFILE = Path("/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny")
PROFILE_SHA = "8135b9839e8ba5dc2e98068c0dd6f631d56f1fd7b91e2e4d456ea3f5d1a35fb7"
BOOT_RECEIPT = Path("/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-successor-b3c3uwwt/installation-receipt.json")
BOOT_COMMAND = (f"/usr/bin/python3 -I -B {PROFILE}/source/scripts/run_semantic_coordinated_boot_guard.py "
                f"--configuration {PROFILE}/boot-profile.json --configuration-sha256 {PROFILE_SHA}")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
CONTAINER_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State.Status}},'
    '"pid":{{json .State.Pid}},"running":{{json .State.Running}},'
    '"restartPolicy":{{json .HostConfig.RestartPolicy.Name}},'
    '"composeProject":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"composeService":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"networks":{{json .NetworkSettings.Networks}}}'
)
UNIT_TARGET = re.compile(r"(?<![\w-])(?:" + "|".join(
    re.escape(value) for value in (*HISTORICAL, *(cid[:12] for cid, _ in HISTORICAL.values()),
                                   *(cid for cid, _ in HISTORICAL.values()))
) + r")(?![\w-])")
COMPOSE = re.compile(r"(?:\bdocker(?:\.io)?\s+compose\b|\bdocker-compose\b)")


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30,
                          env=ENV, stdin=subprocess.DEVNULL).stdout


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def address(value):
    return (value or "").split("/", 1)[0]


def containers():
    ids = sorted(command(*DOCKER, "container", "ls", "-aq", "--no-trunc").split())
    if not ids or len(ids) > 1024 or any(not re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids):
        raise ValueError("DOCKER_CONTAINER_LIST_INVALID")
    rows = [json.loads(line) for line in command(
        *DOCKER, "container", "inspect", "--format", CONTAINER_FORMAT, *ids
    ).splitlines()]
    if sorted(row["id"] for row in rows) != ids:
        raise ValueError("DOCKER_CONTAINER_LIST_CHANGED")
    return rows


def read_docker():
    rows = containers()
    networks = json.loads(command(*DOCKER, "network", "inspect", *NETWORKS))
    by_name = {net["Name"]: net for net in networks}
    if len(networks) != len(NETWORKS) or set(by_name) != NETWORKS.keys():
        raise ValueError("DOCKER_NETWORK_LIST_CHANGED")

    blockers = []
    history = {}
    by_container = {row["id"]: row for row in rows}
    for name, (cid, state) in HISTORICAL.items():
        row = by_container.get(cid)
        if not row:
            history[name] = {"id": cid, "present": False}
            blockers.append(f"historical:{name}:missing")
            continue
        history[name] = {key: row[key] for key in ("id", "name", "state", "pid", "running", "restartPolicy")}
        managed = bool(row["composeProject"] or row["composeService"])
        history[name]["composeManaged"] = managed
        if (row["name"], row["state"], row["pid"], row["running"], row["restartPolicy"], managed) != (
            "/" + name, state, 0, False, "no", False
        ):
            blockers.append(f"historical:{name}:state_restart_or_compose")
        if any(info.get("EndpointID") or info.get("IPAddress") or info.get("GlobalIPv6Address")
               for info in (row["networks"] or {}).values()):
            blockers.append(f"historical:{name}:assigned_endpoint")

    for row in rows:
        if row["name"].lstrip("/") in NEW_NAMES:
            blockers.append(f"new_name:{row['name']}:in_use")

    output = {}
    for name, (network_id, targets) in NETWORKS.items():
        net = by_name[name]
        ipam = net["IPAM"]
        if (net["Id"], net["Driver"], net["Scope"], ipam["Driver"]) != (network_id, "bridge", "local", "default"):
            blockers.append(f"network:{name}:identity_or_driver")
        pools = ipam["Config"] or []
        subnets = [ipaddress.ip_network(pool["Subnet"]) for pool in pools if pool.get("Subnet")]
        reserved = {}
        for pool in pools:
            reserved.setdefault(address(pool.get("Gateway")), set()).add("gateway")
            for value in (pool.get("AuxiliaryAddresses") or {}).values():
                reserved.setdefault(address(value), set()).add("auxiliary_address")
        for subnet in subnets:
            reserved.setdefault(str(subnet.network_address), set()).add("subnet_address")
            reserved.setdefault(str(subnet.broadcast_address), set()).add("broadcast_address")
        endpoints = net["Containers"] or {}
        if endpoints.keys() - by_container.keys():
            blockers.append(f"network:{name}:unresolved_endpoint")
        if set(endpoints) & {cid for cid, _ in HISTORICAL.values()}:
            blockers.append(f"network:{name}:historical_live_endpoint")

        target_rows = {}
        for ip, historical_name in targets.items():
            live = sorted(cid for cid, info in endpoints.items() if address(info.get("IPv4Address")) == ip)
            claims = []
            for row in rows:
                info = (row["networks"] or {}).get(name) or {}
                requested = address((info.get("IPAMConfig") or {}).get("IPv4Address"))
                assigned = address(info.get("IPAddress"))
                if ip in (requested, assigned):
                    claims.append({"id": row["id"], "name": row["name"], "requestedIPv4": requested or None,
                                   "assignedIPv4": assigned or None, "endpointId": info.get("EndpointID") or None})
            foreign_or_active = any(
                row["id"] != HISTORICAL[historical_name][0] or row["assignedIPv4"] or row["endpointId"]
                for row in claims
            )
            target_rows[ip] = {"containerClaims": claims, "liveEndpointContainerIds": live,
                               "ipamReservationSources": sorted(reserved.get(ip, ()))}
            if ip in reserved or live or foreign_or_active or not any(ipaddress.ip_address(ip) in n for n in subnets):
                blockers.append(f"ip:{ip}:reservation_endpoint_or_request")

        alias_rows = []
        for row in rows:
            info = (row["networks"] or {}).get(name) or {}
            aliases = sorted((set(info.get("Aliases") or []) | set(info.get("DNSNames") or [])
                              | {row["name"].lstrip("/")}) & HISTORICAL.keys())
            if not info or not aliases:
                continue
            live = bool(info.get("EndpointID") or info.get("IPAddress") or row["id"] in endpoints)
            alias_rows.append({"id": row["id"], "name": row["name"], "aliases": aliases, "live": live})
            if live or any(row["id"] != HISTORICAL[alias][0] for alias in aliases):
                blockers.append(f"alias:{name}:{row['id']}:active_or_foreign")

        output[name] = {"id": net["Id"], "ipamDriver": ipam["Driver"], "targets": target_rows,
                        "ipamSubnets": [str(subnet) for subnet in subnets],
                        "ipamDynamicRanges": [pool["IPRange"] for pool in pools if pool.get("IPRange")],
                        "aliasClaims": alias_rows}
    return {"historical": history, "networks": output, "blockers": sorted(set(blockers))}


def boot_units():
    units = {}
    for unit, directive in (("ouf-semantic-boot-guard.service", "ExecStart"), ("docker.service", "ExecStartPre")):
        args = ("/usr/bin/systemctl", "show", "--no-pager", unit,
                "--property=LoadState,NeedDaemonReload,ControlPID," + directive)
        values = dict(line.split("=", 1) for line in command(*args).splitlines() if "=" in line)
        commands = re.findall(r"argv\[\]=(.*?) ;", values.get(directive, ""))
        units[unit] = (
            values.get("LoadState") == "loaded" and values.get("NeedDaemonReload") == "no"
            and values.get("ControlPID") == "0" and commands.count(BOOT_COMMAND) == 1
            and not any("run_semantic_coordinated_boot_guard.py" in cmd and cmd != BOOT_COMMAND for cmd in commands)
            and (unit == "docker.service" or commands == [BOOT_COMMAND])
        )

    pointer = json.loads(Path("/etc/ouf/coordinated-boot-installation.json").read_bytes())
    receipt_raw = BOOT_RECEIPT.read_bytes()
    receipt = json.loads(receipt_raw)
    pointer_ok = (pointer.get("receiptFile") == str(BOOT_RECEIPT) and pointer.get("receiptHash") == sha(receipt_raw)
                  and receipt.get("state") == "INSTALLED" and receipt.get("guardCommand") == BOOT_COMMAND
                  and receipt.get("bootProfileHash") == PROFILE_SHA)
    profile_ok = sha((PROFILE / "boot-profile.json").read_bytes()) == PROFILE_SHA
    journal = json.loads((PROFILE / "coordination-journal.json").read_bytes())
    quiesced = (journal.get("state") == "QUIESCED" and journal.get("leaseAuthorized") is False
                and journal.get("startAuthorized") is False)
    return units, pointer_ok, profile_ok, quiesced


def service_references():
    direct, compose = set(), set()
    paths = set()
    for root in map(Path, command("/usr/bin/systemd-analyze", "unit-paths").splitlines()):
        if root.is_dir():
            paths.update(root.glob("*.service"))
            paths.update(root.glob("*.service.d/*.conf"))
            paths.update(root.glob("service.d/*.conf"))
    if not paths:
        raise ValueError("SYSTEMD_SERVICE_FILES_NOT_FOUND")
    for path in sorted(paths):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").replace("\\\n", " ")
        for line in text.splitlines():
            if not re.match(r"^\s*Exec(?:Condition|Start(?:Pre|Post)?)\s*=", line):
                continue
            if UNIT_TARGET.search(line):
                direct.add(str(path))
            if COMPOSE.search(line):
                compose.add(str(path))
    return sorted(direct), sorted(compose)


def main():
    report = {"schema": "ouf.discovery-stopped-creation-preflight.v1", "status": "HELD",
              "observedAt": datetime.now(timezone.utc).isoformat(), "readOnly": True,
              "snapshotAtomic": False, "containerCreates": 0, "containerStarts": 0, "nftWrites": 0,
              "semanticChanged": False, "historicalContainersChanged": False,
              "credentialValuesEmitted": False, "allocatorInternalsRead": False}
    try:
        before = read_docker()
        units, pointer_ok, profile_ok, quiesced = boot_units()
        direct, compose = service_references()
        after = read_docker()
        boot_stable = (units, pointer_ok, profile_ok, quiesced) == boot_units()
        report.update(after)
        report["systemd"] = {"loadedSuccessorCommands": units, "bootPointerMatched": pointer_ok,
                             "bootProfileHashMatched": profile_ok,
                             "coordinatorQuiesced": quiesced, "directHistoricalReferences": direct,
                             "composeStartupReferences": compose}
        if before != after or not boot_stable:
            report["blockers"].append("metadata_changed_during_read")
        if not all(units.values()) or not pointer_ok or not profile_ok or not quiesced:
            report["blockers"].append("boot_successor_not_proven_quiesced")
        if direct or compose:
            report["blockers"].append("startup_reference_requires_review")
        report["dockerReadbackSha256"] = sha(json.dumps(after, sort_keys=True, separators=(",", ":")).encode())
        if not report["blockers"]:
            report["status"] = "PREFLIGHT_PASSED"
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        # Never emit Docker fields or command output from exceptions.
        report["reason"] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch(r"[A-Z_]+", str(error)):
            report["reason"] = str(error)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PREFLIGHT_PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
