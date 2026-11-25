"""DEP-58K-01 through DEP-58K-09. Readiness contract and HTTPS requests over loopback."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import shutil
from socketserver import TCPServer
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from tools.module_release.contract import Held, validate
from tools.module_release.docker import Docker


DOC = {"State": {"Pid": 42}}
SERVER_NAME = "readiness.test"
FIXTURE = Path(__file__).parent / "fixtures/module-release/onboarding.example.json"


class ReadinessContract(unittest.TestCase):
    def test_dep_58k_01_http_invocation(self):
        legacy_probe = """
import http.client, sys
conn = http.client.HTTPConnection('127.0.0.1', int(sys.argv[1]), timeout=2)
conn.request('GET', sys.argv[2])
response = conn.getresponse()
body = response.read(65537)
if len(body) > 65536:
    sys.exit(1)
sys.stdout.buffer.write(str(response.status).encode() + b'\\n' + body)
"""
        ready = {"port": 8080, "path": "/ready"}
        with patch("tools.module_release.docker.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"200\nup")
            self.assertEqual(Docker({"nsenter": "nsenter", "readiness": ready}).probe(DOC), (200, b"up"))
        run.assert_called_once_with(
            ["nsenter", "--target", "42", "--net", sys.executable, "-I", "-S", "-B", "-c",
             legacy_probe, "8080", "/ready"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4)

    def test_dep_58k_02_profile(self):
        p = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for field in ("inbox", "journal", "dockerSocket", "nsenter"):
            p[field] = str(FIXTURE.resolve().with_name(field))
        p.update(oldImage="sha256:" + "a" * 64)
        p["ci"].update(runId=1, runAttempt=1, artifactId=1, zipSha256="b" * 64, imageId="sha256:" + "c" * 64)
        for i, net in enumerate(p["networks"].values(), 1):
            net["ipv4"] = f"127.0.0.{i}"
        tls = {"address": "127.0.0.2", "serverName": SERVER_NAME, "caFile": str(FIXTURE.resolve().with_name("ca"))}
        client = {k: str(FIXTURE.resolve().with_name(k)) for k in ("clientCertFile", "clientKeyFile")}
        for valid in (tls, tls | client):
            p["readiness"]["tls"] = valid
            validate(p)

        invalid = [None, [], {}, tls | {"extra": True}, tls | {"address": "127.0.0.3"},
                   tls | {"address": "::1"}, tls | {"address": 42}, tls | {"serverName": ""},
                   tls | {"serverName": "https://readiness.test"}, tls | {"serverName": "bad\nname"},
                   tls | {"caFile": None}, tls | {"caFile": "relative/path"}]
        for field in tls:
            invalid.append({k: v for k, v in tls.items() if k != field})
        for field in client:
            invalid.extend([tls | {field: client[field]}, tls | client | {field: "relative"}])
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(Held, "^INVALID_READINESS_TLS$"):
                p["readiness"]["tls"] = value
                validate(p)


@unittest.skipUnless(shutil.which("openssl") and ssl.HAS_TLSv1_3, "requires openssl CLI and Python TLS 1.3")
class ReadinessHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.root, check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        key_args = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        for ca in ("ca", "other-ca"):
            openssl("req", "-x509", *key_args, "-days", "1", "-subj", "/CN=" + ca,
                    "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca + ".key", "-out", ca + ".pem")
        for cert, usage in (("server", "serverAuth"), ("client", "clientAuth")):
            extensions = "extendedKeyUsage=" + usage + "\n"
            if cert == "server":
                extensions += "subjectAltName=DNS:" + SERVER_NAME + "\n"
            (cls.root / "extensions").write_text(extensions, encoding="ascii")
            openssl("req", "-new", *key_args, "-subj", "/CN=" + cert, "-keyout", cert + ".key", "-out", cert + ".csr")
            openssl("x509", "-req", "-in", cert + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                    "-days", "1", "-extfile", "extensions", "-out", cert + ".pem")

    @contextmanager
    def listener(self, *, version=ssl.TLSVersion.TLSv1_3, mtls=False, status=204, body=b""):
        requests = []
        names = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers["Host"]))
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(self.root / "server.pem", self.root / "server.key")
        context.set_servername_callback(lambda sock, name, ctx: names.append(name))
        if mtls:
            context.load_verify_locations(self.root / "ca.pem")
            context.verify_mode = ssl.CERT_REQUIRED
        with TCPServer(("127.0.0.1", 0), Handler) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
            thread.start()
            try:
                yield server.server_address[1], requests, names
            finally:
                server.shutdown()
                thread.join()

    def probe(self, port, **overrides):
        tls = {"address": "127.0.0.1", "serverName": SERVER_NAME, "caFile": str(self.root / "ca.pem"), **overrides}
        ready = {"port": port, "path": "/ready", "tls": tls}
        run = subprocess.run

        def on_loopback(args, **kwargs):
            self.assertEqual(args[:5], ["nsenter", "--target", "42", "--net", sys.executable])
            self.assertEqual(json.loads(kwargs["input"]), tls)
            self.assertNotIn(str(self.root), " ".join(args))
            self.assertNotIn("env", kwargs)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 4)
            return run(args[4:], **kwargs)

        with patch("tools.module_release.docker.subprocess.run", side_effect=on_loopback):
            return Docker({"nsenter": "nsenter", "readiness": ready}).probe(DOC)

    def test_dep_58k_03_tls13_204(self):
        with self.listener() as (port, requests, names):
            self.assertEqual(self.probe(port), (204, b""))
            self.assertEqual(names, [SERVER_NAME])
            self.assertEqual(requests, [("/ready", f"{SERVER_NAME}:{port}")])

    def test_dep_58k_04_wrong_ca(self):
        with self.listener() as (port, requests, _):
            self.assertEqual(self.probe(port, caFile=str(self.root / "other-ca.pem")), (None, b""))
            self.assertEqual(requests, [])

    def test_dep_58k_05_wrong_name(self):
        with self.listener() as (port, requests, _):
            self.assertEqual(self.probe(port, serverName="wrong.test"), (None, b""))
            self.assertEqual(requests, [])

    def test_dep_58k_06_server_tls12_only(self):
        with self.listener(version=ssl.TLSVersion.TLSv1_2) as (port, requests, _):
            self.assertEqual(self.probe(port), (None, b""))
            self.assertEqual(requests, [])

    def test_dep_58k_07_mtls(self):
        with self.listener(mtls=True) as (port, requests, _):
            self.assertEqual(self.probe(port), (None, b""))
            self.assertEqual(requests, [])
            self.assertEqual(self.probe(port, clientCertFile=str(self.root / "client.pem"),
                                        clientKeyFile=str(self.root / "client.key")), (204, b""))

    def test_dep_58k_08_body_limit(self):
        for size in (65536, 65537):
            body = b"x" * size
            with self.subTest(size=size), self.listener(status=200, body=body) as (port, _, _):
                self.assertEqual(self.probe(port), (200, body) if size == 65536 else (None, b""))

    def test_dep_58k_09_no_redirect(self):
        with self.listener(status=302) as (port, requests, _):
            self.assertEqual(self.probe(port), (302, b""))
            self.assertEqual(requests, [("/ready", f"{SERVER_NAME}:{port}")])
