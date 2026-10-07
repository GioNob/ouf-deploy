#!/usr/bin/env python3
"""Read bounded deployment readiness; never emit inspect/env payloads or credentials."""
import json
import subprocess

def run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None

prefix = None
for candidate in (["docker"], ["sudo", "-n", "docker"]):
    result = run(candidate + ["version", "--format", "{{.Server.Version}}"])
    if result is not None and result.returncode == 0:
        prefix = candidate
        break

report = {
    "schema": "ouf.deployment.readiness.v1",
    "containerLifecycleOperations": 0,
    "configurationWrites": 0,
    "secretValuesPrinted": False,
    "dockerAccess": "UNAVAILABLE" if prefix is None else ("DIRECT" if prefix == ["docker"] else "NONINTERACTIVE_SUDO"),
    "components": [],
}
if prefix is not None:
    listed = run(prefix + ["ps", "-a", "--format", "{{.Names}}"])
    if listed is None or listed.returncode:
        report["status"] = "CONTAINER_LIST_UNAVAILABLE"
    else:
        names = sorted(name for name in listed.stdout.splitlines() if name.startswith("ouf-") and len(name) <= 128)
        for name in names[:40]:
            inspected = run(prefix + ["inspect", name])
            if inspected is None or inspected.returncode:
                report["components"].append({"name": name, "inspectAvailable": False})
                continue
            try:
                data = json.loads(inspected.stdout)[0]
                report["components"].append({
                    "name": name,
                    "running": bool(data.get("State", {}).get("Running")),
                    "imageId": data.get("Image"),
                    "configuredImage": data.get("Config", {}).get("Image"),
                    "mounts": [{"destination": m.get("Destination"), "type": m.get("Type"), "readOnly": not bool(m.get("RW"))} for m in data.get("Mounts", [])],
                })
            except (ValueError, KeyError, IndexError, TypeError):
                report["components"].append({"name": name, "inspectAvailable": False})
        report["status"] = "READ_ONLY_READY"
else:
    report["status"] = "DOCKER_PERMISSION_REQUIRED"
print("OUF_RELEASE_READINESS=" + json.dumps(report, sort_keys=True))
