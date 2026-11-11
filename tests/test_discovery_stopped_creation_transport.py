"""Exercise the stopped discovery controller against a local HTTP Unix socket."""

from collections import deque
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler
import io
import json
from pathlib import Path
import runpy
from socketserver import UnixStreamServer
import subprocess
import sys
import tempfile
from threading import Event, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/create-discovery-stopped-candidates-20261111.py"
CONTROLLER = runpy.run_path(str(SOURCE))
GLOBALS = CONTROLLER["engine"].__globals__
CID = "a" * 64


class EngineHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(4)
        super().setup()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, self.path, body))
        status, payload = self.server.responses.popleft()
        self.send_response_only(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = respond

    def finish(self):
        super().finish()
        self.server.connection_closed.set()

    def log_message(self, format, *args):
        pass


class StoppedCreationTransportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ouf-engine-")
        self.addCleanup(directory.cleanup)
        address = str(Path(directory.name) / "engine.sock")
        server = UnixStreamServer(address, EngineHandler)
        self.server = server
        self.addCleanup(server.server_close)
        server.responses = deque()
        server.requests = []
        server.connection_closed = Event()
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        self.enterContext(patch.dict(GLOBALS, DOCKER_SOCKET=address))

    def test_inspect_over_unix_http_and_close_keepalive(self):
        path = f"/containers/{CID}/json"
        self.server.responses.append((200, json.dumps({"Id": CID}).encode()))
        self.assertEqual(CONTROLLER["engine"]("GET", path), {"Id": CID})
        self.assertEqual(self.server.requests, [("GET", "/v1.44" + path, b"")])
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_create_payload_and_empty_delete_response(self):
        path = f"/containers/create?name={CONTROLLER['ADAPTER']}-successor"
        self.server.responses.extend(((201, json.dumps({"Id": CID}).encode()), (204, b"")))
        self.assertEqual(CONTROLLER["engine"]("POST", path, {"Image": "fixture"}), {"Id": CID})
        self.assertIsNone(CONTROLLER["engine"]("DELETE", f"/containers/{CID}"))
        self.assertEqual(self.server.requests, [
            ("POST", "/v1.44" + path, b'{"Image":"fixture"}'),
            ("DELETE", f"/v1.44/containers/{CID}", b""),
        ])

    def test_engine_rejection_closes_connection(self):
        self.server.responses.append((503, b'{"message":"fixture"}'))
        with self.assertRaisesRegex(CONTROLLER["Held"], "^ENGINE_RESPONSE_UNPROVEN$"):
            CONTROLLER["engine"]("GET", "/info")
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_invalid_json_closes_connection(self):
        self.server.responses.append((200, b"{"))
        with self.assertRaises(json.JSONDecodeError):
            CONTROLLER["engine"]("GET", "/info")
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_subprocess_failure_after_first_create_retains_id(self):
        runtime = "ouf-test-runtime"
        self.server.responses.extend((
            (200, json.dumps({"Runtimes": {runtime: {}}}).encode()),
            (201, json.dumps({"Id": CID}).encode()),
        ))
        review = SimpleNamespace(
            image_review=lambda **kwargs: {"checkSchemaAllowsBearerJwksWithoutSecret": True},
            kernel_review=lambda: {"noswapByKernelVersion": True},
        )

        def guard(_preflight, first):
            if first:
                subprocess.run([sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"],
                               check=True, capture_output=True)

        with patch.dict(GLOBALS, load_reader=lambda *_: review, guard=guard,
                        build_request=lambda *_: {"HostConfig": {"Runtime": runtime}},
                        inspect_created=lambda *_: {"state": "created", "neverStarted": True}):
            argv = [str(SOURCE), "--preflight", "fixture", "--image-review", "fixture", "--apply"]
            with patch.object(GLOBALS["os"], "geteuid", return_value=0), patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(CONTROLLER["main"](), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "HELD")
        self.assertEqual(report["reason"], "CalledProcessError")
        self.assertEqual(report["createRequests"], 1)
        self.assertEqual([row["id"] for row in report["candidates"]], [CID])
        self.assertFalse(report["replayAllowed"])
        self.assertEqual([method for method, _, _ in self.server.requests], ["GET", "POST"])


if __name__ == "__main__":
    unittest.main()
