#!/usr/bin/env python3
"""Read the retained MCP runtime for a semantic-budget image replacement; no service changes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path("/var/lib/ouf-storage-migration")
PLAN = ROOT / "cold-host-bound-20261107-v1/plan.private.json"
PLAN_SHA = "f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d"
DOCKER = ("/usr/bin/docker", "--host", "unix:///run/docker.sock", "--config", "/nonexistent")


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def docker_json(*args):
    result = subprocess.run((*DOCKER, *args), capture_output=True, timeout=30, check=False)
    require(result.returncode == 0, "DOCKER_READ_FAILED")
    return json.loads(result.stdout)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def frame(doc):
    return {**{key: doc.get(key) for key in ("Id", "Image", "Config", "HostConfig", "Mounts", "Path", "Args", "NetworkSettings")},
            "StartedAt": doc["State"]["StartedAt"], "Running": doc["State"]["Running"]}


def mac_shape(doc):
    config = doc["Config"]
    value = config.get("MacAddress")
    kind = "ABSENT" if "MacAddress" not in config else "NULL" if value is None else "EMPTY_STRING" if value == "" else "STRING" if isinstance(value, str) else "OTHER"
    valid = isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value) is not None
    endpoints = [n.get("MacAddress") for n in doc["NetworkSettings"].get("Networks", {}).values()]
    return {"kind": kind, "formatValid": valid,
            "unicastNonzero": bool(valid and int(value.replace(":", ""), 16) and not (int(value[:2], 16) & 1)),
            "matchesAnEndpoint": bool(valid and any(isinstance(x, str) and x.lower() == value.lower() for x in endpoints))}


def main():
    report = {"schema": "ouf.mcp-budget-runtime-read.v1", "status": "READ_INCOMPLETE",
              "credentialValuesEmitted": False, "credentialFilesRead": 0,
              "serviceConfigurationChanged": False, "serviceStops": 0,
              "databaseRequests": 0, "businessRequestsIssued": 0, "s3Requests": 0}
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        raw = PLAN.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == PLAN_SHA, "RETAINED_PLAN_MISMATCH")
        role = json.loads(raw)["roles"]["mcp"]
        cid = role["containerId"]
        require(re.fullmatch("[a-f0-9]{64}", cid) is not None, "RETAINED_ID_INVALID")
        originals = json.loads((PLAN.parent / "stop/command-182.private").read_bytes())
        baseline = next(doc for doc in originals if doc["Id"] == cid)
        current = docker_json("container", "inspect", cid)[0]
        image = docker_json("image", "inspect", current["Image"])[0]
        require(current["Id"] == cid and baseline["Image"] == role["nativeImage"], "RETAINED_IDENTITY_MISMATCH")
        work = Path(tempfile.mkdtemp(prefix="mcp-budget-read-", dir=ROOT))
        os.chmod(work, 0o700)
        for name, value in (("container.private.json", current), ("image.private.json", image)):
            target = work / name
            with target.open("x", encoding="utf-8") as stream:
                os.chmod(target, 0o600)
                json.dump(value, stream, sort_keys=True)
                stream.write("\n")
        config, host = current["Config"], current["HostConfig"]
        env = {item.partition("=")[0]: item.partition("=")[2] for item in config.get("Env", [])}
        before_env = {item.partition("=")[0]: item.partition("=")[2] for item in baseline["Config"].get("Env", [])}
        networks = current["NetworkSettings"].get("Networks", {})
        final = docker_json("container", "inspect", cid)[0]
        report.update(
            status="MCP_RUNTIME_READ_COMPLETE", observedAt=datetime.now(timezone.utc).isoformat(),
            privateEvidenceDirectory=str(work), currentFrameSha256=digest(frame(current)),
            runtimeUnchangedDuringRead=frame(current) == frame(final),
            containerId=cid, imageId=current["Image"], imageMatchesRetained=current["Image"] == role["nativeImage"],
            running=current["State"]["Running"], restartPolicy=host.get("RestartPolicy"),
            user=config.get("User"), privileged=host.get("Privileged"), readOnlyRootfs=host.get("ReadonlyRootfs"),
            networkMode=host.get("NetworkMode"), publishedPortBindings=host.get("PortBindings"),
            mountBindings=[{"destination": m["Destination"], "type": m["Type"], "readOnly": not m["RW"]} for m in current["Mounts"]],
            networks={name: {"aliases": node.get("Aliases"), "endpointPresent": bool(node.get("EndpointID")),
                             "ipAssigned": bool(node.get("IPAddress")), "macAssigned": bool(node.get("MacAddress"))} for name, node in networks.items()},
            currentLegacyMac=mac_shape(current), retainedLegacyMac=mac_shape(baseline),
            environmentKeys=sorted(env),
            changedEnvironmentKeys=sorted(k for k in set(env) | set(before_env) if env.get(k) != before_env.get(k)),
            changedConfigFields=sorted(k for k in set(config) | set(baseline["Config"]) if config.get(k) != baseline["Config"].get(k)),
            changedHostConfigFields=sorted(k for k in set(host) | set(baseline["HostConfig"]) if host.get(k) != baseline["HostConfig"].get(k)),
            mountsMatchRetained=current["Mounts"] == baseline["Mounts"],
            launchMatchesRetained=(current["Path"], current["Args"]) == (baseline["Path"], baseline["Args"]),
            entrypointMatchesImage=config.get("Entrypoint") == image["Config"].get("Entrypoint"),
            commandMatchesImage=config.get("Cmd") == image["Config"].get("Cmd"),
            commandIsServer=config.get("Cmd") == ["server"],
            entrypointIsInstalledMcp=config.get("Entrypoint") == ["/usr/local/bin/ouf-mcp"])
    except (OSError, ValueError, KeyError, IndexError, StopIteration, RuntimeError, subprocess.TimeoutExpired) as exc:
        report["reason"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
