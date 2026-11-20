"""Local Engine adapter. Project inspect fields inside Docker's formatter."""
import hashlib
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import time

from .profile import HEX, Held, custody, require

# A header followed by one record per endpoint. IPAMConfig survives stop.
INSPECT = (
    '[{{json .Id}},{{json .Name}},{{json .State.Status}},{{json .State.Running}},'
    '{{json .State.Restarting}},{{json .State.StartedAt}},'
    '[{{json .HostConfig.RestartPolicy.Name}},{{json .HostConfig.RestartPolicy.MaximumRetryCount}}],'
    '{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}]'
    '{{range $n,$e := .NetworkSettings.Networks}}{{println}}'
    '[{{json $n}},{{json (index $e "IPAddress")}},'
    '{{with index $e "IPAMConfig"}}{{json (index . "IPv4Address")}}{{else}}null{{end}}]{{end}}'
)


class Docker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.identity = None

    def verify(self):
        binding = self.cfg["docker"]
        path = Path(binding["path"])
        custody(path)
        info = path.stat()
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns)
        if self.identity != identity:
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(digest == binding["sha256"], "DOCKER_HASH_CHANGED")
            self.identity = identity
        custody(self.cfg["dockerSocket"], stat.S_ISSOCK)

    def command(self, *args, deadline=None):
        require(args[0] in {"inspect", "ps", "start", "stop"}, "COMMAND_DENIED")
        self.verify()
        timeout = 30 + (self.cfg["stopTimeoutSeconds"] if args[0] == "stop" else 0)
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
        require(timeout > 0, "LEVEL_TIMEOUT")
        try:
            return subprocess.check_output(
                [self.cfg["docker"]["path"], "--host", "unix://" + self.cfg["dockerSocket"], *args],
                stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout,
                env={"LC_ALL": "C", "DOCKER_CONFIG": self.cfg["receipts"]}, text=True, encoding="utf-8")
        except subprocess.TimeoutExpired:
            raise Held("DOCKER_TIMEOUT") from None
        except (OSError, subprocess.CalledProcessError, UnicodeError):
            raise Held("DOCKER_COMMAND_FAILED") from None

    def inspect(self, cid, deadline=None):
        require(HEX.fullmatch(cid), "INVALID_CID")
        lines = self.command("inspect", "--type", "container", "--format", INSPECT, cid,
                             deadline=deadline).splitlines()
        try:
            header, *networks = (json.loads(line) for line in lines)
            found, name, status, running, restarting, since, policy, health = header
            policy_name, retry_count = policy
            require(found == cid and isinstance(name, str) and name.startswith("/")
                    and type(running) is bool and type(restarting) is bool
                    and type(policy_name) is str and type(retry_count) is int, "INSPECT_INVALID")
            endpoints = {}
            for network, live, static in networks:
                require(network not in endpoints, "INSPECT_INVALID")
                endpoints[network] = {
                    k: str(ipaddress.IPv4Address(v)) if v else None
                    for k, v in (("live", live), ("static", static))}
            return dict(cid=cid, name=name[1:], status=status, running=running, restarting=restarting,
                        startedAt=since, restartPolicy=dict(name=policy_name, maximumRetryCount=retry_count),
                        health=health, networks=endpoints)
        except (TypeError, ValueError):
            raise Held("INSPECT_INVALID") from None

    def inventory(self, targets):
        deadline = time.monotonic() + self.cfg["inventoryTimeoutSeconds"]
        lines = self.command("ps", "--all", "--no-trunc", "--format",
                             "{{.ID}} {{.Names}} {{.State}}", deadline=deadline).splitlines()
        rows = []
        for line in lines:
            parts = line.split()
            require(len(parts) == 3, "INVENTORY_INVALID")
            cid, name, state = parts
            if name in targets or state not in ("created", "exited", "dead"):
                row = self.inspect(cid, deadline)
                require(row["name"] == name, "INVENTORY_CHANGED")
                rows.append(row)
        return rows

    def change(self, action, cid, deadline):
        require(HEX.fullmatch(cid), "INVALID_CID")
        if action == "stop":
            self.command("stop", "--time", str(self.cfg["stopTimeoutSeconds"]), cid, deadline=deadline)
        else:
            require(action == "start", "ACTION_INVALID")
            self.command("start", cid, deadline=deadline)
