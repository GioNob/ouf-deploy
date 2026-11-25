"""Commands installed under fixture names in a temporary PATH."""
import json
import os
from pathlib import Path
import sys
import time

name = Path(__file__).name
args = sys.argv[1:]
if name == "fake_tool.py":  # Windows cmd launcher
    name = args.pop(0)

assert os.environ["LC_ALL"] == "C"
secret = "private-fixture-sentinel"
if name == "docker":
    rows = [
        {"Name": "/service-a", "Id": "a" * 64, "State": {"Status": "running"}},
        {"Name": "/spare", "Id": "b" * 64, "State": {"Status": "exited"}},
    ]
    if args == ["ps", "-a", "--no-trunc", "-q"]:
        print(*(row["Id"] for row in rows), sep="\n")
    else:
        assert len(args) == 4 and args[:2] == ["inspect", "--format"]
        row = next(row for row in rows if row["Id"] == args[3])
        row.update(Image="sha256:" + "f" * 64, Config={"Env": ["KEY=" + secret],
                   "Cmd": [secret], "Labels": {"private": secret}}, Mounts=[{"Source": secret}],
                   HostConfig={"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
                   NetworkSettings={"Networks": {"net-a": {"EndpointID": secret}}})
        row["State"]["StartedAt"] = "2026-01-01T00:00:00Z"
        fields = args[2].split("\t")
        expected = ["Name", "Id", "Image", "State.Status", "State.StartedAt", "HostConfig.RestartPolicy"]
        assert fields[:6] == ["{{json ." + field + "}}" for field in expected]
        assert fields[6:] == ["{{range $name, $_ := .NetworkSettings.Networks}}{{json $name}}", "{{end}}"]
        values = []
        for field in expected:
            value = row
            for key in field.split("."):
                value = value[key]
            values.append(value)
        print("\t".join(json.dumps(v) for v in [*values, *row["NetworkSettings"]["Networks"]]))
elif name == "systemctl":
    assert args[:2] == ["show", "--all"] and args[-2:] == ["--", "runner.service"]
    print("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled")
    print("ActiveEnterTimestamp=Thu 2026-01-01 00:00:00 UTC")
elif name == "dpkg-query":
    assert args == ["-W", r"-f=${Package}\t${Architecture}\t${Version}\t${db:Status-Status}\n"]
    print("linux-image-6.1.0-test\tamd64\t1\tinstalled\nlinux-image-old\tamd64\t1\tconfig-files")
    print("docker-ce\tamd64\t1:2\tinstalled\ncontainerd.io\tamd64\t3\tinstalled")
elif name == "apt-mark":
    assert args == ["showhold"]
    print("docker-ce\ncontainerd.io\nother")
elif name == "r3-status":
    assert args == ["status marker"]
    if os.environ.get("FIXTURE_DELAY"):
        time.sleep(3)
    epoch = int(os.environ.get("FIXTURE_EPOCH", "2"))
    for role in ("adapter", "southbound"):
        print(json.dumps({"step": "role", "role": role, "docker": {"private": secret},
                          "epoch": {"epoch": epoch, "state": "STARTED", "live": True, "failure": secret}}))
    print(json.dumps({"step": "supervisor", "state": "ACTIVE", "epochs": {"adapter": epoch, "southbound": epoch},
                      "leaseRecovery": {"private": secret}}))
    print(json.dumps({"step": "lease", "state": "ACTIVE", "extra": secret}))
    print(json.dumps({"step": "tables", "tables": [secret]}))
else:
    sys.exit(2)
