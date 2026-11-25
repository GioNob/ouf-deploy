"""Offline PET. Run from checkout with python3 -I -B tests/test_installation_active_reader.py -v."""
from argparse import Namespace
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import read_installation_active as reader

TOKEN = "sentinel-private-bearer"
EXPORT = b'{"private":"export body"}\n'
CHECKSUM = hashlib.sha256(b"configuration").hexdigest()
ACTIVE = dict(installationId="fixture", revision=7, checksum=CHECKSUM, generation=9)
ETAG = f'"7:{CHECKSUM}:9"'
BASE = "/api/trusted-human/v1/installations/fixture/"
ACTIVE_PATH = BASE + "active"
EXPORT_PATH = BASE + "projection?revision=7"


def active(**changes):
    return 200, {"ETag": ETAG}, json.dumps({**ACTIVE, **changes}).encode()


class ReaderTest(unittest.TestCase):
    def owner(self, replies):
        paths = []
        def handler(request):
            paths.append(request.path)
            if request.headers.get("Authorization") != "Bearer " + TOKEN:
                status, headers, body = 401, {}, b""
            elif request.path == EXPORT_PATH and not request.headers.get("X-Correlation-ID"):
                status, headers, body = 400, {}, b""
            else:
                status, headers, body = replies[len(paths)-1] if len(paths) <= len(replies) else (404, {}, b"")
            request.send_response(status)
            for key, value in headers.items():
                request.send_header(key, value)
            request.end_headers()
            request.wfile.write(body)

        class Handler(BaseHTTPRequestHandler):
            do_GET = handler

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return server, paths

    def invoke(self, replies, *, interrupt=False):
        server, paths = self.owner(replies)
        directories = []

        def login(directory):
            directories.append(directory)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            fd = os.open(directory / "human-access.jwt", os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as bearer:
                bearer.write(TOKEN)
            if interrupt:
                raise KeyboardInterrupt(TOKEN)
            return TOKEN

        stdout, stderr = io.StringIO(), io.StringIO()
        temporary_directory = tempfile.TemporaryDirectory
        with temporary_directory() as scratch:
            def temp(*, dir, prefix):
                self.assertEqual(dir, "/run")
                return temporary_directory(dir=scratch, prefix=prefix)

            # Test-only routing of verified HTTPS to a disposable HTTP owner.
            args = ["--installation-id", ACTIVE["installationId"],
                    "--origin", f"https://127.0.0.1:{server.server_port}"]
            with (patch.object(reader.http.client, "HTTPSConnection", http.client.HTTPConnection),
                  patch.object(reader.os, "geteuid", return_value=0, create=True),
                  patch.object(reader.tempfile, "TemporaryDirectory", temp),
                  patch.object(reader, "login", login),
                  redirect_stdout(stdout), redirect_stderr(stderr)):
                status = reader.main(args)
            self.assertEqual(list(Path(scratch).iterdir()), [])
            self.assertEqual(len(directories), 1)
            self.assertFalse((directories[0] / "human-access.jwt").exists())
            self.assertFalse(directories[0].exists())
        self.assertNotIn(TOKEN, stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(EXPORT.decode().strip(), stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        return status, stdout.getvalue().splitlines(), paths

    def test_complete(self):
        """DEP-60w-01. Exact receipt, authenticated order, export hashed byte for byte."""
        export = EXPORT * 4096
        self.assertEqual(self.invoke([active(), (200, {"X-Private": TOKEN}, export), active()]),
                         (0, ["revision=7", f"checksum={CHECKSUM}", "generation=9", f"etag={ETAG}",
                              "projection_http=200", "projection_sha256=" + hashlib.sha256(export).hexdigest(),
                              "ACTIVE_READ_OK"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH]))

    def test_unauthorized_and_forbidden(self):
        """DEP-60w-02. Only the fixed outcome survives errors at any stage."""
        for status, prior in ((401, []), (403, [active()]), (401, [active(), (200, {}, EXPORT)])):
            with self.subTest(status=status, stage=len(prior)):
                self.assertEqual(self.invoke([*prior, (status, {}, TOKEN.encode())]),
                                 (1, [f"HTTP_{status}"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH][:len(prior)+1]))

    def test_inactive_export(self):
        """DEP-60w-03. The owner rejected the pinned revision."""
        self.assertEqual(self.invoke([active(), (409, {}, TOKEN.encode())]),
                         (1, ["PROJECTION_NOT_ACTIVE"], [ACTIVE_PATH, EXPORT_PATH]))

    def test_changed(self):
        """DEP-60w-04. Either revision or ETag changing discards the entire receipt."""
        for last in ((200, {"ETag": '"changed"'}, active()[2]), active(revision=8)):
            with self.subTest(last=last):
                self.assertEqual(self.invoke([active(), (200, {}, EXPORT), last]),
                                 (1, ["ACTIVE_CHANGED"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH]))

    def test_redirect(self):
        """DEP-60w-05. Location never receives another GET or bearer."""
        self.assertEqual(self.invoke([(302, {"Location": "/redirect-target"}, TOKEN.encode())]),
                         (1, ["TRANSPORT_ERROR"], [ACTIVE_PATH]))

    def test_interrupt(self):
        """DEP-60w-06. Ctrl-C unwinds credential custody before returning."""
        self.assertEqual(self.invoke([], interrupt=True), (1, ["TRANSPORT_ERROR"], []))

    def test_invalid_active_or_truncated_export(self):
        """DEP-60w-07. A malformed owner response cannot publish a receipt."""
        for first in (active(installationId="another"), active(revision=True), active(checksum=TOKEN),
                      (200, {"ETag": TOKEN}, active()[2]), (200, {}, active()[2])):
            self.assertEqual(self.invoke([first]), (1, ["TRANSPORT_ERROR"], [ACTIVE_PATH]))
        self.assertEqual(self.invoke([active(), (200, {"Content-Length": "1000"}, EXPORT)]),
                         (1, ["TRANSPORT_ERROR"], [ACTIVE_PATH, EXPORT_PATH]))

    def test_profile_and_overrides(self):
        """DEP-60w-08. Literal bundle placeholder, independent overrides, HTTPS origin only."""
        args = Namespace(profile=Path("profile.json"), installation_id=None, origin=None)
        values = {"installationId": "fixture", "revision": "unused"}
        profile = {"gateway": {"values": {**values, "gateway.publicApiHost": "api.invalid"}}}
        with patch("tools.privileged_executor.store.read", return_value=profile):
            self.assertEqual(reader.target(args), ("fixture", reader.urlsplit("https://api.invalid")))
            args.installation_id = "explicit"
            self.assertEqual(reader.target(args), ("explicit", reader.urlsplit("https://api.invalid")))
            args.installation_id, args.origin = None, "https://override.invalid"
            self.assertEqual(reader.target(args), ("fixture", reader.urlsplit("https://override.invalid")))
        args.installation_id = "explicit"
        for args.origin in ("http://api.invalid", "https://user@api.invalid", "https://api.invalid/path",
                            "https://api.invalid?query", "https://api.invalid#fragment"):
            with self.assertRaises(reader.ReadError):
                reader.target(args)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root device-flow fixture")
    def test_human_session_device_login(self):
        """DEP-60w-09. Real session, disposable loopback issuer and private credential files."""
        # Resolve the production imports before loading the fixture's own checkout paths.
        from tools.chatbot_file_cohort import human_session
        sys.path.insert(0, str(ROOT / "tests"))
        self.addCleanup(sys.path.remove, str(ROOT / "tests"))
        from test_chatbot_cohort_human_session import FixtureOpener, ISSUER, OAuthFixture

        issuer = OAuthFixture(time)
        server = HTTPServer(("127.0.0.1", 0), issuer.handler())
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        real_session = human_session.HumanSession

        def session(*args):
            human = real_session(*args)
            human.opener = FixtureOpener(server.server_port)
            return human

        answers = io.StringIO(f"{ISSUER}\nhuman-fixture\ntenant-fixture\nOK\n")
        tty, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
        def terminal(path, mode, **kwargs):
            self.assertEqual(path, "/dev/tty")
            return nullcontext(answers if mode == "r" else tty)

        with (tempfile.TemporaryDirectory(dir="/run") as tmp,
              patch.object(human_session, "HumanSession", session),
              patch.object(reader, "open", terminal, create=True),
              redirect_stdout(stdout), redirect_stderr(stderr)):
            directory = Path(tmp)
            token = reader.login(directory)
            file = directory / "human-access.jwt"
            self.assertEqual(token, file.read_text())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for item in directory.iterdir():
                self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
            self.assertEqual(issuer.polls, 1)
            self.assertIn("ENTER_DEVICE_CODE=", tty.getvalue())
            self.assertNotIn(token, tty.getvalue())
            self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertFalse(directory.exists())

    def test_profile_without_host(self):
        """DEP-60w-10. Missing placeholder requires an explicit origin before login."""
        for gateway in ({"values": {"installationId": "fixture"}},
                        {"publicApiHost": "unused.invalid", "values": {
                            "installationId": "fixture", "gatewayPublicApiHost": "unused.invalid"}}):
            with (self.subTest(gateway=gateway),
                  patch("tools.privileged_executor.store.read", return_value={"gateway": gateway}),
                  patch.object(reader.os, "geteuid", return_value=0, create=True),
                  patch.object(reader, "login") as login,
                  patch.object(reader.tempfile, "TemporaryDirectory") as temporary,
                  redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr):
                self.assertEqual(reader.main(["--profile", "profile.json"]), 1)
                self.assertEqual(stdout.getvalue().splitlines(), ["TRANSPORT_ERROR"])
                self.assertIn('gateway.values["gateway.publicApiHost"]', stderr.getvalue())
                self.assertIn("--origin", stderr.getvalue())
                temporary.assert_not_called()
                login.assert_not_called()
                args = Namespace(profile=Path("profile.json"), installation_id=None, origin="https://override.invalid")
                self.assertEqual(reader.target(args), ("fixture", reader.urlsplit(args.origin)))

    def test_sigint_during_cleanup(self):
        """DEP-60w-11. Deliver SIGINT at unlink of the JWT, then check custody and handler."""
        unlink = os.unlink
        signals_sent = []

        def interrupt_unlink(path, *args, **kwargs):
            if Path(path).name == "human-access.jwt":
                signals_sent.append(signal.SIGINT)
                signal.raise_signal(signal.SIGINT)
            return unlink(path, *args, **kwargs)

        previous = signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal, signal.SIGINT, previous)
        with patch.object(os, "unlink", interrupt_unlink):
            self.assertEqual(self.invoke([(401, {}, b"")]), (1, ["HTTP_401"], [ACTIVE_PATH]))
        self.assertEqual(signals_sent, [signal.SIGINT])
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_malformed_active_exception(self):
        """DEP-60w-12. Malformed JSON and invalid encoding expose only an unchained fixed error."""
        for body in (b'{"reflected":"' + TOKEN.encode(), TOKEN.encode() + b'\xff'):
            with self.subTest(body=body):
                server, paths = self.owner([(200, {}, body)])
                with self.assertRaises(reader.ReadError) as raised:
                    reader.get(lambda: http.client.HTTPConnection(*server.server_address), ACTIVE_PATH, TOKEN)
                self.assertEqual(paths, [ACTIVE_PATH])
                error = raised.exception
                self.assertEqual(error.args, ("TRANSPORT_ERROR",))
                self.assertEqual(vars(error), {})
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)


if __name__ == "__main__":
    unittest.main()
