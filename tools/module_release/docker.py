"""Narrow Linux adapter for the local Docker Engine API 1.44 and namespace probe."""

from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import quote

from .contract import ENTRY, Held, candidate_command, require, verify_labels
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


TLS_PROBE = """
import http.client, json, socket, ssl, sys

tls = json.load(sys.stdin)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations(cafile=tls['caFile'])
if 'clientCertFile' in tls:
    context.load_cert_chain(tls['clientCertFile'], tls['clientKeyFile'], password=b'')

port = int(sys.argv[1])
conn = http.client.HTTPSConnection(tls['serverName'], port, timeout=2, context=context)
with socket.create_connection((tls['address'], port), timeout=2) as raw:
    with context.wrap_socket(raw, server_hostname=conn.host) as secured:
        conn.sock = secured
        conn.request('GET', sys.argv[2])
        response = conn.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            sys.exit(1)
        sys.stdout.buffer.write(str(response.status).encode() + b'\\n' + body)
"""


def gate_shell_matches(proc):
    """Compare the live executable inode to /bin/sh in this process's root."""
    # Pin each component before inspecting it. An absolute link restarts at
    # the container root, and ".." at that root stays there.
    with ExitStack() as opened:
        root = os.open(proc / "root", os.O_PATH | os.O_DIRECTORY)
        opened.callback(os.close, root)
        ancestry = [root]
        pending = ["bin", "sh"]
        links = 0
        while pending:
            part, *pending = pending
            if part in ("", "."):
                continue
            if part == "..":
                if len(ancestry) > 1:
                    ancestry.pop()
                continue
            fd = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=ancestry[-1])
            opened.callback(os.close, fd)
            info = os.fstat(fd)
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    return False
                target = os.readlink("", dir_fd=fd)
                if target.startswith("/"):
                    ancestry = [root]
                pending = target.split("/") + pending
            elif pending:
                if not stat.S_ISDIR(info.st_mode):
                    return False
                ancestry.append(fd)
            else:
                return os.path.samestat(info, (proc / "exe").stat())
        return False


class Docker:
    def __init__(self, profile):
        self.p = profile
        self.flyway_peer = None

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

    def image_defaults(self, image_id):
        image = self.api("GET", "/images/" + quote(image_id, safe="") + "/json")
        require(image["Id"] == image_id, "LOADED_IMAGE_CHANGED")
        return image["Config"]

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
        if "candidate" in self.p and (self.is_candidate(doc) if "configDelta" in self.p else doc["Image"] == self.p["ci"]["imageId"]):
            command = candidate_command(command, self.p["candidate"])
        pid = doc["State"]["Pid"]
        if not doc["State"]["Running"] or pid <= 0:
            return False
        root = Path("/proc", str(pid))
        try:
            expected_argv = ENTRY + command if gated else command
            if (root / "cmdline").read_bytes() != b"\0".join(arg.encode() for arg in expected_argv) + b"\0":
                return False
            if not gated:
                exe = os.readlink(root / "exe")
                expected = self.p["gate"].get("executable", command[0])
                return exe == expected if "/" in expected else Path(exe).name == expected
            # /bin/sh may resolve to dash or busybox in the container.
            mask = re.search(r"^SigCgt:\s*([0-9a-fA-F]+)$", (root / "status").read_text(), re.M)
            return (mask is not None and bool(int(mask[1], 16) & (1 << (signal.SIGUSR1 - 1)))
                    and gate_shell_matches(root))
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
        program = PROBE
        options = {}
        if "tls" in r:
            program = TLS_PROBE
            # --net preserves the executor's mount namespace. Only host paths
            # and peer coordinates cross stdin; OpenSSL opens the files locally.
            options["input"] = json.dumps(r["tls"]).encode("ascii")
        args = [self.p["nsenter"], "--target", str(doc["State"]["Pid"]), "--net", sys.executable,
                "-I", "-S", "-B", "-c", program, str(r["port"]), r["path"]]
        try:
            run = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4, **options)
        except subprocess.TimeoutExpired:
            return None, b""
        if run.returncode:
            return None, b""
        status, body = run.stdout.split(b"\n", 1)
        return int(status), body

    def pause(self):
        time.sleep(1)

    def is_candidate(self, doc):
        return doc["Id"] == getattr(self, "candidate_cid", None)
