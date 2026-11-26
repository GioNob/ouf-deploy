"""Offline PET. Run from checkout with python3 -I -B tests/test_installation_active_reader.py -v."""
from argparse import Namespace
import base64
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import sys
import tempfile
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

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
IDENTITY = dict(issuer="https://issuer.invalid/realms/fixture", subject="human-fixture", tenant="tenant-fixture")
CLI = ["--installation-id", "fixture", "--origin", "https://api.invalid",
       "--issuer", IDENTITY["issuer"], "--subject", IDENTITY["subject"], "--tenant", IDENTITY["tenant"]]


def active(**changes):
    return 200, {"ETag": ETAG}, json.dumps({**ACTIVE, **changes}).encode()


class ReaderTest(unittest.TestCase):
    def owner(self, replies):
        paths = []
        replies = iter(replies)

        def request(method, path, headers):
            self.assertEqual(method, "GET")
            self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
            self.assertTrue(headers["X-Correlation-ID"])
            paths.append(path)

        def response():
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            status, headers, body = reply
            head = f"HTTP/1.1 {status} Fixture\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            sock = Mock()
            sock.makefile.return_value = io.BytesIO((head + "\r\n").encode() + body)
            res = http.client.HTTPResponse(sock)
            res.begin()
            return res

        return Mock(return_value=Mock(request=request, getresponse=response)), paths

    def invoke(self, replies, *, interrupt=False):
        server, paths = self.owner(replies)
        directories = []

        def login(directory, selection):
            self.assertEqual(selection, IDENTITY)
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

            with (patch.object(reader.http.client, "HTTPSConnection", server),
                  patch.object(reader.os, "geteuid", return_value=0, create=True),
                  patch.object(reader.tempfile, "TemporaryDirectory", temp),
                  patch.object(reader, "login", login), patch("tools.privileged_executor.store.read") as profile,
                  patch.object(reader, "open", create=True) as tty,
                  redirect_stdout(stdout), redirect_stderr(stderr)):
                status = reader.main(CLI)
                profile.assert_not_called()
                tty.assert_not_called()
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
        for status, prior in ((401, []), (403, [active()]), (401, [active(), (200, {}, EXPORT)]),
                              (500, []), (503, [active()])):
            with self.subTest(status=status, stage=len(prior)):
                stage = "PROJECTION" if len(prior) == 1 else "ACTIVE"
                self.assertEqual(self.invoke([*prior, (status, {}, TOKEN.encode())]),
                                 (1, [f"{stage}_HTTP_{status}"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH][:len(prior)+1]))

    def test_inactive_export(self):
        """DEP-60w-03. The owner rejected the pinned revision."""
        self.assertEqual(self.invoke([active(), (409, {}, TOKEN.encode())]),
                         (1, ["PROJECTION_HTTP_409"], [ACTIVE_PATH, EXPORT_PATH]))

    def test_changed(self):
        """DEP-60w-04. Either revision or ETag changing discards the entire receipt."""
        for last in ((200, {"ETag": '"changed"'}, active()[2]), active(revision=8)):
            with self.subTest(last=last):
                self.assertEqual(self.invoke([active(), (200, {}, EXPORT), last]),
                                 (1, ["ACTIVE_CHANGED"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH]))

    def test_redirect(self):
        """DEP-60w-05. Location never receives another GET or bearer."""
        self.assertEqual(self.invoke([(302, {"Location": "/redirect-target"}, TOKEN.encode())]),
                         (1, ["ACTIVE_HTTP_302"], [ACTIVE_PATH]))

    def test_interrupt(self):
        """DEP-60w-06. Ctrl-C unwinds credential custody before returning."""
        self.assertEqual(self.invoke([], interrupt=True), (1, ["INTERRUPTED"], []))

    def test_invalid_active_or_truncated_export(self):
        """DEP-60w-07. A malformed owner response cannot publish a receipt."""
        for first in (active(installationId="another"), active(revision=True), active(checksum=TOKEN),
                      active(checksum=None), (200, {}, b"[]"), (200, {}, b"{}"), (200, {}, b"{" * 16385),
                      (200, {}, TOKEN.encode()), (200, {"ETag": TOKEN}, active()[2]), (200, {}, active()[2])):
            self.assertEqual(self.invoke([first]), (1, ["ACTIVE_PARSE_ERROR"], [ACTIVE_PATH]))
        self.assertEqual(self.invoke([active(), (200, {"Content-Length": "1000"}, EXPORT)]),
                         (1, ["PROJECTION_PARSE_ERROR"], [ACTIVE_PATH, EXPORT_PATH]))
        self.assertEqual(self.invoke([active(), (200, {"Transfer-Encoding": "chunked"}, TOKEN.encode())]),
                         (1, ["PROJECTION_PARSE_ERROR"], [ACTIVE_PATH, EXPORT_PATH]))
        self.assertEqual(self.invoke([active(), (200, {}, EXPORT), (200, {}, b"{}")]),
                         (1, ["ACTIVE_PARSE_ERROR"], [ACTIVE_PATH, EXPORT_PATH, ACTIVE_PATH]))

    def test_profile_and_overrides(self):
        """DEP-60w-08. Literal bundle placeholder, independent overrides, HTTPS origin only."""
        args = Namespace(profile=Path("profile.json"), installation_id=None, origin=None)
        values = {"installationId": "fixture", "revision": "unused"}
        profile = {"gateway": {"values": {**values, "gateway.publicApiHost": "api.invalid"}}}
        values = profile["gateway"]["values"]
        self.assertEqual(reader.target(args, values), ("fixture", reader.urlsplit("https://api.invalid")))
        args.installation_id = "explicit"
        self.assertEqual(reader.target(args, values), ("explicit", reader.urlsplit("https://api.invalid")))
        args.installation_id, args.origin = None, "https://override.invalid"
        self.assertEqual(reader.target(args, values), ("fixture", reader.urlsplit("https://override.invalid")))
        args.installation_id = "explicit"
        for args.origin in ("http://api.invalid", "https://user@api.invalid", "https://api.invalid/path",
                            "https://api.invalid?query", "https://api.invalid#fragment"):
            with self.assertRaises(reader.ReadError):
                reader.target(args, values)

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
                self.assertEqual(stdout.getvalue().splitlines(), ["INPUT_MISSING:origin"])
                self.assertIn('gateway.values["gateway.publicApiHost"]', stderr.getvalue())
                self.assertIn("--origin", stderr.getvalue())
                temporary.assert_not_called()
                login.assert_not_called()
                args = Namespace(profile=Path("profile.json"), installation_id=None, origin="https://override.invalid")
                self.assertEqual(reader.target(args, gateway["values"]), ("fixture", reader.urlsplit(args.origin)))

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
            self.assertEqual(self.invoke([(401, {}, b"")]), (1, ["ACTIVE_HTTP_401"], [ACTIVE_PATH]))
        self.assertEqual(signals_sent, [signal.SIGINT])
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_malformed_active_exception(self):
        """DEP-60w-12. Malformed JSON and invalid encoding expose only an unchained fixed error."""
        for body in (b'{"reflected":"' + TOKEN.encode(), TOKEN.encode() + b'\xff'):
            with self.subTest(body=body):
                server, paths = self.owner([(200, {}, body)])
                with self.assertRaises(reader.ReadError) as raised:
                    reader.get(server, ACTIVE_PATH, TOKEN)
                self.assertEqual(paths, [ACTIVE_PATH])
                error = raised.exception
                self.assertEqual(error.args, ("ACTIVE_PARSE_ERROR",))
                self.assertEqual(vars(error), {})
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    def test_transport_diagnostics(self):
        """DEP-60w-13. Only the exception type can cross the command boundary."""
        for error in (ConnectionRefusedError, socket.gaierror, ssl.SSLError, TimeoutError):
            with self.subTest(error=error):
                self.assertEqual(self.invoke([error(TOKEN)]), (1, ["ORIGIN_UNREACHABLE:" + error.__name__], [ACTIVE_PATH]))
        self.assertEqual(self.invoke([RuntimeError(TOKEN)]), (1, ["TRANSPORT_ERROR:RuntimeError"], [ACTIVE_PATH]))

    def test_identity_precedence(self):
        """DEP-60w-14. Prompt only for a genuinely missing field, then resolve its tenant."""
        profile = {"gateway": {"values": {"gateway.issuerUrl": IDENTITY["issuer"], "installationId": "fixture",
                                          "gateway.publicApiHost": "api.invalid"}},
                   "queue": {"subjectTenants": {IDENTITY["subject"]: IDENTITY["tenant"]},
                             "proof": {"subject": TOKEN}}}
        for args, prompts, expected in (
                ([], ["subject"], IDENTITY),
                (["--subject", IDENTITY["subject"]], [], IDENTITY),
                (CLI[4:], [], IDENTITY),
                (["--issuer", "https://override.invalid", "--subject", IDENTITY["subject"], "--tenant", "other"],
                 [], {**IDENTITY, "issuer": "https://override.invalid", "tenant": "other"})):
            tty = io.StringIO()

            def terminal(path, mode, **kw):
                self.assertEqual(path, "/dev/tty")
                return nullcontext(tty if mode == "w" else io.StringIO(IDENTITY["subject"] + "\n"))

            with (self.subTest(args=args), patch("tools.privileged_executor.store.read", return_value=profile),
                  patch.object(reader, "open", terminal, create=True),
                  patch.object(reader.os, "geteuid", create=True, return_value=0),
                  patch.object(reader.tempfile, "TemporaryDirectory"),
                  patch.object(reader, "login", side_effect=KeyboardInterrupt(TOKEN)) as login,
                  redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout):
                self.assertEqual(reader.main(args), 1)
                self.assertEqual(stdout.getvalue(), "INTERRUPTED\n")
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(tty.getvalue().splitlines(), [f"Specificare {f} per il login HUMAN:" for f in prompts])
                self.assertEqual(login.call_args.args[1], expected)

    def test_missing_inputs(self):
        """DEP-60w-15. Missing CLI/profile/TTY inputs never start a login or echo arguments."""
        for field in ("installation-id", "origin", "issuer", "subject", "tenant"):
            args = CLI.copy()
            index = args.index("--" + field)
            del args[index:index+2]
            for argv in (args, ["--" + field]):
                with (self.subTest(field=field, argv=argv), patch("tools.privileged_executor.store.read", return_value={}),
                      patch.object(reader.os, "geteuid", create=True, return_value=0),
                      patch.object(reader, "open", create=True, side_effect=OSError(TOKEN)),
                      patch.object(reader, "login") as login,
                      redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout):
                    self.assertEqual(reader.main(argv), 1)
                    self.assertEqual(stdout.getvalue().splitlines(), ["INPUT_MISSING:" + field])
                    self.assertNotIn(TOKEN, stderr.getvalue())
                    login.assert_not_called()

    def test_input_diagnostics(self):
        """DEP-60w-18. Profile, privileges, terminal and syntax errors have fixed outcomes."""
        for argv, uid, field in (([TOKEN], 0, "arguments"), (CLI, 1, "root"), (["--profile", TOKEN], 0, "profile"),
                                 (CLI, 0, "terminal")):
            with (self.subTest(field=field), patch.object(reader.os, "geteuid", create=True, return_value=uid),
                  patch("tools.privileged_executor.store.read", side_effect=PermissionError(TOKEN)),
                  patch.object(reader.tempfile, "TemporaryDirectory"),
                  patch.object(reader, "open", create=True, side_effect=OSError(TOKEN)),
                  redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout):
                self.assertEqual(reader.main(argv), 1)
                self.assertEqual(stdout.getvalue().splitlines(), ["INPUT_MISSING:" + field])
                self.assertEqual(stderr.getvalue(), "")


class DeviceFlowTest(unittest.TestCase):
    """Exercise HumanSession's real state machine with a clock and HTTP replies in memory."""

    def setUp(self):
        if os.name != "posix":
            # Only the production journal and aggregate action imports require POSIX.
            self.enterContext(patch.dict(sys.modules, {
                "tools.semantic_lease_recovery.recovery_journal": SimpleNamespace(Journal=Mock),
                "tools.semantic_policy_token_owner.owner_installation": SimpleNamespace(AggregateAction=Mock)}))
        from tools.chatbot_file_cohort import human_session
        self.human = human_session
        self.now = 1000
        clock = SimpleNamespace(time=lambda: self.now, monotonic=lambda: self.now)
        for module in (reader, human_session):
            self.enterContext(patch.object(module, "time", clock))
        wait = SimpleNamespace(is_set=lambda: False, wait=self.advance)
        self.enterContext(patch.object(human_session, "threading", SimpleNamespace(Event=lambda: wait, RLock=threading.RLock)))

    def advance(self, delay):
        self.now += delay

    def flow(self, *, poll_errors=(), expires=90, interval=7, claims=None, start_status=200,
             challenge_urls=None, expect_prompt=True, userinfo_subject=IDENTITY["subject"],
             bad_token=False, token_response=None, native=False):
        start = self.now
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/run" if native else None)))
        human = self.human
        opener = Mock()
        if not native:
            # The portable PET replaces filesystem custody only. PET 09 uses the native journal.
            row = Mock(record=directory / "record", invocation=nullcontext)
            def init(session, selection, root, path, expiry):
                session.selection, session.directory, session.token_path = selection, root, path
                session.expires_at, session.action, session.failure = expiry, None, None
                session.journal, session._journal_mutex = row, threading.RLock()
                session.opener = opener
            def save(previous, following):
                self.assertEqual(previous, row.read.return_value)
                row.read.return_value = following
            def initialize(first):
                row.record.touch()
                row.read.return_value = first
            row.initialize.side_effect = initialize
            row.compare_and_save.side_effect = save
            self.enterContext(patch.object(human.HumanSession, "__init__", init))
            self.enterContext(patch.object(human.HumanSession, "_boot", return_value="fixture-boot"))
            self.enterContext(patch.object(human.HumanSession, "_publish",
                lambda session, state: session.token_path.write_text(state["accessToken"], encoding="ascii")))

        issuer = IDENTITY["issuer"]
        endpoints = {k: issuer + "/protocol/openid-connect/" + name for k, name in (
            ("device_authorization_endpoint", "device"), ("token_endpoint", "token"), ("userinfo_endpoint", "userinfo"))}
        poll_times = []
        tty = io.StringIO()
        pending = iter(poll_errors)
        payload = {"iss": issuer, "sub": IDENTITY["subject"], "tenant_id": IDENTITY["tenant"], "ouf_actor_type": "HUMAN",
                   "azp": human.CLIENT, "acr": "1", "aud": "ouf-api-gateway", "scope": " ".join(human.SCOPES),
                   "exp": start + 300, **(claims or {})}
        jwt = "fixture." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode() + "." + TOKEN
        def reply(status, data, headers=None):
            if isinstance(data, OSError):
                stream = io.BytesIO()
                stream.read = Mock(side_effect=data)
            else:
                stream = io.BytesIO(data if isinstance(data, bytes) else json.dumps(data).encode())
            stream.status, stream.headers = status, headers or {}
            return stream

        def http(request, timeout):
            url = request.full_url
            if url.endswith("/.well-known/openid-configuration"):
                return reply(200, {"issuer": issuer, **endpoints})
            if url == endpoints["device_authorization_endpoint"]:
                challenge = dict(verification_uri=issuer + "/verify", user_code="USER-123",
                                 device_code=TOKEN, interval=interval, expires_in=expires)
                challenge.update(challenge_urls or {})
                return reply(start_status, challenge)
            if url == endpoints["token_endpoint"]:
                self.assertIn("In attesa della conferma nel browser…", tty.getvalue())
                self.assertEqual(parse_qs(request.data.decode())["device_code"], [TOKEN])
                poll_times.append(self.now - start)
                error = next(pending, None)
                if isinstance(error, tuple):
                    status, name, headers = error
                    return reply(status, {"error": name}, headers)
                if error:
                    return reply(400, {"error": error, "error_description": TOKEN})
                if token_response is not None:
                    return reply(*token_response)
                return reply(200, dict(access_token=TOKEN if bad_token else jwt, refresh_token=TOKEN, token_type="Bearer"))
            self.assertEqual(url, endpoints["userinfo_endpoint"])
            self.assertEqual(request.get_header("Authorization"), "Bearer " + jwt)
            return reply(200, {"sub": userinfo_subject})

        opener.open.side_effect = http
        def terminal(path, mode, **kw):
            self.assertEqual((path, mode), ("/dev/tty", "w"))
            return nullcontext(tty)

        with (patch.object(human.urllib.request, "build_opener", return_value=opener),
              patch.object(reader, "open", terminal, create=True),
              redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout):
            try:
                self.assertEqual(reader.login(directory, IDENTITY), jwt)
            except reader.ReadError as error:
                self.assertIsNone(error.__context__)
                code = str(error)
            else:
                code = "OK"
                self.assertEqual((directory / "human-access.jwt").read_text(), jwt)
                if native:
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                    for item in directory.iterdir():
                        self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn(TOKEN, tty.getvalue() + code)
        if start_status == 200 and expect_prompt:
            self.assertEqual(tty.getvalue().splitlines(), [
                issuer + "/verify  Codice: USER-123  In attesa della conferma nel browser…"])
        else:
            self.assertEqual(tty.getvalue(), "")
        return code, poll_times

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root journal custody")
    def test_human_session_device_login(self):
        """DEP-60w-09. Real session and private credential files, in-memory provider."""
        self.assertEqual(self.flow(native=True), ("OK", [7]))

    def test_automatic_poll(self):
        """DEP-60w-16. The device interval and slow_down govern every poll without keyboard input."""
        self.assertEqual(self.flow(poll_errors=["authorization_pending", "slow_down"]), ("OK", [7, 14, 26]))

    def test_poll_retry_after_slow_down(self):
        """DEP-60w-19. A retry respects both the increased interval and Retry-After."""
        with patch.object(self.human.secrets, "randbelow", return_value=200):
            for transient, next_poll in (
                    ((429, "rate_limited", {}), 31),
                    ((503, "temporarily_unavailable", {}), 31),
                    ((429, "rate_limited", {"Retry-After": "20"}), 39)):
                with self.subTest(transient=transient):
                    errors = ["slow_down", transient, "authorization_pending"]
                    self.assertEqual(self.flow(poll_errors=errors), ("OK", [7, 19, next_poll, next_poll + 12]))

    def test_provider_device_expiry(self):
        """DEP-60w-20. A pending 900-second challenge expires at the provider deadline."""
        start = self.now
        outcome = self.flow(expires=900, interval=10, poll_errors=["authorization_pending"] * 90)
        self.assertEqual(outcome, ("LOGIN_FAILED:expired", list(range(10, 900, 10))))
        self.assertEqual(self.now - start, 900)

    def test_slow_down_above_initial_interval_limit(self):
        """DEP-60w-21. Every slow_down adds five seconds until the provider deadline."""
        start = self.now
        outcome = self.flow(expires=1900, interval=600, poll_errors=["slow_down"] * 3)
        self.assertEqual(outcome, ("LOGIN_FAILED:expired", [600, 1205, 1815]))
        self.assertEqual(self.now - start, 1900)

    def test_malformed_token_response(self):
        """DEP-60w-22. Unreadable HTTP 200 at the token endpoint fails in the token phase."""
        malformed = ('{"access_token":"' + TOKEN).encode()
        for status, phase in ((200, "token"), (400, "poll")):
            with self.subTest(status=status):
                self.assertEqual(self.flow(token_response=(status, malformed)), ("LOGIN_FAILED:" + phase, [7]))

    def test_device_code_in_verification_urls(self):
        """DEP-60w-23. Neither verification URL may disclose the private device code."""
        issuer = IDENTITY["issuer"]
        encoded = TOKEN.replace("-", "%2D")
        for field in ("verification_uri", "verification_uri_complete"):
            for location, suffix in (("path", "/" + TOKEN), ("query", "?format=" + TOKEN),
                                     ("fragment", "#" + TOKEN), ("encoded query", "?format=" + encoded)):
                with self.subTest(field=field, location=location):
                    urls = {field: issuer + "/verify" + suffix}
                    self.assertEqual(self.flow(challenge_urls=urls, expect_prompt=False),
                                     ("LOGIN_FAILED:device-start", []))

    def test_invalid_token_response_body(self):
        """DEP-60w-24. Invalid or oversized HTTP 200 bodies fail in the token phase."""
        cases = {
            "non-object": b"[]",
            "invalid encoding": b"\xff",
            "read failure": OSError(TOKEN),
            "oversized object": b"{}" + b" " * 65535,
        }
        for body_type, body in cases.items():
            with self.subTest(body_type=body_type):
                self.assertEqual(self.flow(token_response=(200, body)), ("LOGIN_FAILED:token", [7]))

    def test_login_failures(self):
        """DEP-60w-17. Provider, JWT, userinfo and deadline failures retain their phase only."""
        for phase, kwargs, times in (
                ("device-start", {"start_status": 403}, []),
                ("poll", {"poll_errors": ["access_denied"]}, [7]),
                ("expired", {"poll_errors": ["expired_token"]}, [7]),
                ("expired", {"expires": 3}, []),
                ("expired", {"poll_errors": ["slow_down"], "expires": 18}, [7]),
                ("token", {"bad_token": True}, [7]),
                ("subject", {"claims": {"sub": TOKEN}}, [7]),
                ("subject", {"userinfo_subject": TOKEN}, [7]),
                ("tenant", {"claims": {"tenant_id": TOKEN}}, [7]),
                ("expired", {"claims": {"exp": 0}}, [7])):
            with self.subTest(phase=phase, kwargs=kwargs):
                start = self.now
                self.assertEqual(self.flow(**kwargs), ("LOGIN_FAILED:" + phase, times))
                if "expires" in kwargs:
                    self.assertEqual(self.now - start, kwargs["expires"])


if __name__ == "__main__":
    unittest.main()
