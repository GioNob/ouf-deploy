"""Local Engine adapter. Project inspect fields inside Docker's formatter."""
import hashlib
import http.client
import socket
import ipaddress
import json
import os
from pathlib import Path
import signal
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

GATE_INSPECT = ('[{{json .Id}},{{json .Name}},{{json .State.Status}},{{json .State.StartedAt}},'
                '{{json .State.Pid}},{{json .Image}},{{json .Config.Entrypoint}},{{json .Config.Cmd}}]')


class GateHeld(Held):
    def __init__(self, detail):
        super().__init__("GATE_HELD")
        self.detail = detail


def pid1_state(pid, gate):
    """Read only PID 1's identity, argv and installed signal handler from host procfs."""
    proc = Path("/proc") / str(pid)
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    if status.get("NSpid", "").split()[-1:] != ["1"]:
        raise GateHeld("PID1_UNVERIFIED")
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    expected = [os.fsencode(arg) for arg in gate["command"]] + [b""]
    if argv == [os.fsencode(arg) for arg in gate["entrypoint"]] + expected:
        caught = int(status["SigCgt"], 16) & (1 << (signal.SIGUSR1 - 1))
        return "armed" if caught else "arming"
    if argv == expected:
        command = gate["command"][0]
        exe = (proc / "exe").readlink()
        if (exe.as_posix() if command.startswith("/") else exe.name) == command:
            return "application"
    raise GateHeld("PID1_COMMAND_MISMATCH")


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
        signal_command = (len(args) == 3 and args[:2] == ("kill", "--signal=USR1")
                          and isinstance(args[2], str) and HEX.fullmatch(args[2]))
        require(args and (args[0] in {"inspect", "ps", "start", "stop"} or signal_command), "COMMAND_DENIED")
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

    def release_launch(self, cid):
        require(isinstance(cid, str) and HEX.fullmatch(cid), "INVALID_CID")
        raw = self.command("inspect", "--type", "container", "--format", GATE_INSPECT, cid)
        found, name, _, _, _, image, entry, cmd = json.loads(raw)
        return dict(Id=found, Name=name, Image=image, Config=dict(Entrypoint=entry, Cmd=cmd))

    def release_frame(self, cid):
        # Rehydrate the immutable fields for the producer's API 1.44 snapshot.
        # The complete private document stays in memory.
        require(isinstance(cid, str) and HEX.fullmatch(cid), "INVALID_CID")
        self.verify()
        conn = http.client.HTTPConnection("localhost", timeout=self.cfg["inventoryTimeoutSeconds"])
        try:
            conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.sock.settimeout(conn.timeout)
            conn.sock.connect(self.cfg["dockerSocket"])
            conn.request("GET", "/v1.44/containers/" + cid + "/json", headers={"Connection": "close"})
            response = conn.getresponse()
            raw = response.read((4 << 20) + 1)
            require(response.status == 200 and len(raw) <= 4 << 20, "RELEASE_FRAME_UNAVAILABLE")
            return json.loads(raw)
        except (http.client.HTTPException, OSError, ValueError):
            raise Held("RELEASE_FRAME_UNAVAILABLE") from None
        finally:
            conn.close()

    def gate_state(self, step, gate, deadline):
        cid = step["observation"]["cid"]
        require(HEX.fullmatch(cid), "INVALID_CID")
        try:
            raw = self.command("inspect", "--type", "container", "--format", GATE_INSPECT, cid, deadline=deadline)
            found, name, status, since, pid, image, entry, cmd = json.loads(raw)
            if found != cid or name != "/" + step["containerName"]:
                raise GateHeld("CONTAINER_MISMATCH")
            if image != gate["imageId"]:
                raise GateHeld("IMAGE_MISMATCH")
            if entry != gate["entrypoint"] or cmd != gate["command"]:
                raise GateHeld("LAUNCH_CONFIG_MISMATCH")
            if status != "running" or type(pid) is not int or pid <= 1 or not isinstance(since, str) or not since:
                raise GateHeld("RUNNING_GENERATION_UNVERIFIED")
            return (since, pid), pid1_state(pid, gate)
        except GateHeld:
            raise
        except OSError:
            raise GateHeld("PROCESS_UNAVAILABLE") from None
        except (KeyError, TypeError, ValueError, Held):
            raise GateHeld("GATE_OBSERVATION_FAILED") from None
