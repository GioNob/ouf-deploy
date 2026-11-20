"""Narrow Linux adapter for the local Docker Engine API 1.44 and namespace probe."""

import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import quote

from .contract import ENTRY, Held, require, verify_labels
from .postgres import database_snapshot


PROBE = """
import http.client, sys
conn = http.client.HTTPConnection('127.0.0.1', int(sys.argv[1]), timeout=2)
conn.request('GET', sys.argv[2])
response = conn.getresponse()
body = response.read(65537)
if len(body) > 65536:
    sys.exit(1)
sys.stdout.buffer.write(str(response.status).encode() + b'\\n' + body)
"""


class Docker:
    def __init__(self, profile):
        self.p = profile

    def api(self, method, path, body=None, *, archive=None, missing=False):
        sock = self.p["dockerSocket"]

        class LocalConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(sock)

        connection = LocalConnection("localhost", timeout=240 if archive else 45)
        try:
            headers = {"Content-Type": "application/json"}
            payload = None if body is None else json.dumps(body).encode()
            if archive is not None:
                payload = archive
                headers = {"Content-Type": "application/x-tar", "Content-Length": str(os.fstat(archive.fileno()).st_size)}
            connection.request(method, "/v1.44" + path, payload, headers)
            res = connection.getresponse()
            if missing and res.status == 404:
                return None
            raw = res.read((4 << 20) + 1)
            require(res.status in (200, 201, 204) and len(raw) <= 4 << 20, "ENGINE_REQUEST_FAILED")
            if archive is not None:
                require(raw and all("error" not in json.loads(line) for line in raw.splitlines()),
                        "IMAGE_LOAD_FAILED")
            elif raw:
                return json.loads(raw)
        finally:
            connection.close()

    def inspect(self, identity, *, missing=False):
        return self.api("GET", "/containers/" + quote(identity, safe="") + "/json", missing=missing)

    def load(self, archive, package):
        self.api("POST", "/images/load?quiet=1", archive=archive)
        image = self.api("GET", "/images/" + quote(package["imageTag"], safe="") + "/json")
        require(image["Id"] == self.p["ci"]["imageId"], "LOADED_IMAGE_CHANGED")
        ci = self.p["ci"]
        verify_labels(image["Config"].get("Labels") or {}, ci["repository"], package["testedCommit"],
                      optional=ci.get("publisherFormat") == "acquisition-mcp")

    def database(self, old):
        binding = self.p["migration"]["database"]
        return database_snapshot(self.p["dockerSocket"], binding, old, self.inspect(binding["postgresCid"]))

    def stop(self, cid):
        self.api("POST", "/containers/" + cid + "/stop?t=20")

    def start(self, cid):
        self.api("POST", "/containers/" + cid + "/start")

    def rename(self, cid, name):
        self.api("POST", "/containers/" + cid + "/rename?name=" + quote(name, safe=""))

    def create(self, name, request):
        return self.api("POST", "/containers/create?name=" + quote(name, safe=""), request)["Id"]

    def disconnect(self, cid, network):
        self.api("POST", "/networks/" + network + "/disconnect", {"Container": cid, "Force": False})

    def connect(self, cid, network, settings):
        self.api("POST", "/networks/" + network + "/connect", {"Container": cid, "EndpointConfig": settings})

    def process(self, doc, gated):
        command = self.p["gate"]["command"]
        pid = doc["State"]["Pid"]
        if not doc["State"]["Running"] or pid <= 0:
            return False
        root = Path("/proc", str(pid))
        try:
            actual = (root / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            exe = os.readlink(root / "exe")
            if not gated:
                expected = self.p["gate"].get("executable", command[0])
                identity = exe == expected if "/" in expected else Path(exe).name == expected
                return actual == command and identity
            # /bin/sh may resolve to dash or busybox in the container.
            mask = re.search(r"^SigCgt:\s*([0-9a-fA-F]+)$", (root / "status").read_text(), re.M)
            return (actual == ENTRY + command and (root / "exe").samefile(root / "root/bin/sh")
                    and mask is not None and bool(int(mask[1], 16) & (1 << (signal.SIGUSR1 - 1))))
        except (FileNotFoundError, ProcessLookupError):
            return False

    def signal(self, cid):
        self.api("POST", "/containers/" + cid + "/kill?signal=USR1")

    def migrate(self, cid, command):
        obj = self.api("POST", "/containers/" + cid + "/exec", {"Cmd": command, "AttachStdout": False,
                                                               "AttachStderr": False, "Tty": False})
        path = "/exec/" + obj["Id"]
        self.api("POST", path + "/start", {"Detach": True, "Tty": False})
        for _ in range(self.p["readiness"]["attempts"]):
            status = self.api("GET", path + "/json")
            require(status["ContainerID"] == cid, "MIGRATION_IDENTITY_CHANGED")
            if not status["Running"]:
                require(status["ExitCode"] == 0, "MIGRATION_FAILED")
                return
            time.sleep(1)
        raise Held("MIGRATION_TIMEOUT")

    def probe(self, doc):
        r = self.p["readiness"]
        args = [self.p["nsenter"], "--target", str(doc["State"]["Pid"]), "--net", sys.executable,
                "-I", "-S", "-B", "-c", PROBE, str(r["port"]), r["path"]]
        try:
            run = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4)
        except subprocess.TimeoutExpired:
            return None, b""
        if run.returncode:
            return None, b""
        status, body = run.stdout.split(b"\n", 1)
        return int(status), body

    def pause(self):
        time.sleep(1)
