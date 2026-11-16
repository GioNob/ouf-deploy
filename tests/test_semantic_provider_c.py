"""Offline D-049 tests: synthetic credentials and loopback TLS only."""
import base64
from contextlib import redirect_stdout
import copy
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_c import probe as C

SECRET = "synthetic-secret-C-DO-NOT-RECORD"


def jwt(exp):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp, "scope": "search fetch"}).encode()).decode().rstrip("=")
    return "e30." + payload + "." + "c3ludGhldGljLXNpZ25hdHVyZQ"


def r3():
    return {"configurationSha256": "a" * 64, "authorization": {"sequence": 11, "sha256": "b" * 64, "decision": "OPERATE"},
        "candidates": {r: {"cid": r, "epoch": {"epoch": 1, "state": "STARTED", "live": True},
                           "docker": {"Status": "running", "Running": True, "Pid": 123}} for r in C.R.ROLES},
        "supervisor": {"state": "ACTIVE", "unit": {"ActiveState": "active", "SubState": "running"},
                       "authorizationSequence": 11, "epochs": {r: 1 for r in C.R.ROLES}},
        "lease": {"state": "LEASE_READY", "leaseAuthorized": True},
        "tables": {r: {"tableName": r, "inet": True, "bridge": True} for r in C.R.ROLES}}


def state(port=443, adapter_port=9443):
    return {"r3": r3(), "semantic": {"containerId": "a" * 64, "generation": {"pid": 123}},
            "configuration": {"GATEWAY_BASE_URL": f"https://south.test:{port}", "SEARCH_PATH": "/search", "FETCH_PATH": "/fetch",
                "TOKEN_ENDPOINT": f"https://token.test:{port}/token", "CLIENT_ID": "synthetic-client",
                "WORKLOAD_SCOPE": "search fetch", "CLIENT_SECRET_FILE": "/run/secrets/client"},
            "targets": {"southboundHost": "south.test", "southboundAddress": "127.0.0.1", "southboundPort": port,
                "adapterAddress": "127.0.0.1", "adapterHost": "adapter.test", "adapterPort": adapter_port,
                "backendNetwork": "test-backend", "backendSubnets": ["127.0.0.0/8"], "tokenHost": "token.test",
                "tokenPort": port, "tokenPath": "/token", "tokenTls": True},
            "resolver": {"nameserver": "127.0.0.11", "sha256": "c" * 64}, "inputHashes": {}}


class FakeClock:
    def __init__(self):
        self.now = time.monotonic()
        self.waits = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.calls.append((self.command, self.path))
        if self.path == "/slow":
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                for _ in range(40):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(.03)
                self.wfile.write(b"\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            return
        auth = self.headers.get("Authorization")
        if self.path == "/token":
            from urllib.parse import parse_qs
            fields = parse_qs(data.decode())
            assert fields["client_secret"] == [SECRET]
            assert fields["grant_type"] == ["client_credentials"]
            status, body = 200, {"access_token": self.server.token, "token_type": "Bearer",
                                 "scope": "search fetch", "expires_in": self.server.expires}
        elif self.command == "GET" and self.path == "/search":
            status, body = 400, {"error": "METHOD"}
        elif auth != "Bearer " + self.server.token or self.server.exp < time.time():
            status, body = 401, {"error": "UNAUTHORIZED"}
        elif self.path == "/search":
            from urllib.parse import parse_qs
            form = parse_qs(data.decode("ascii"), strict_parsing=True)
            assert self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
            assert set(form) == {"query", "format"} and form["format"] == ["application/sparql-results+json"]
            assert form["query"][0].endswith(" } ORDER BY ?resource LIMIT 50")
            status, body = 200, {"results": {"bindings": [{"resource": {"type": "uri", "value": "https://example.test/item/1"}}]}}
        elif self.path.startswith("/fetch?uri="):
            status, body = 200, {"statements": []}
        else:
            status, body = 404, {}
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class LocalTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        openssl = shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("openssl required for offline test certificates")
        def run(*args):
            subprocess.run([openssl, *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=C-probe-test-CA",
            "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE")
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=south.test", "-keyout", "server.key", "-out", "server.csr")
        (root / "ext").write_text("subjectAltName=DNS:south.test,DNS:token.test,DNS:adapter.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "2", "-extfile", "ext", "-out", "server.pem")
        cls.ca = (root / "ca.pem").read_bytes()
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(str(root / "server.pem"), str(root / "server.key"))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = self.context.wrap_socket(self.server.socket, server_side=True)
        self.server.calls = []
        self.server.exp = time.time() + 3600
        self.server.expires = 3600
        self.server.token = jwt(self.server.exp)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Keep a bound but non-listening socket: deterministic adapter refusal.
        self.adapter = socket.socket()
        self.adapter.bind(("127.0.0.1", 0))
        self.input = state(self.server.server_port, self.adapter.getsockname()[1])
        self.clock = FakeClock()

    def tearDown(self):
        self.adapter.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def run_suite(self, config=None, verified=True, wall=time.time):
        original_budget = C.Budget
        clock = self.clock
        ca = self.ca
        class LocalTransport(C.Transport):
            def addresses(self, host):
                return ["127.0.0.1"]
            def __init__(self, *args):
                super().__init__(*args)
                if verified:
                    # Test-only stand-in for the host system trust store.
                    self.token_context = ssl.create_default_context(cadata=ca.decode())
        self.secret_reader = Mock(return_value=SECRET.encode())
        with patch.object(C, "Budget", lambda deadline: original_budget(deadline, clock, clock.sleep)):
            return C.suite(config or self.input, self.ca, clock() + 900,
                           self.secret_reader, LocalTransport, wall=wall)

    def test_loopback_tls_positive_negative_cases_and_redaction(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = self.run_suite()
        self.assertEqual(result["failedCases"], [], result)
        self.assertEqual(result["secretsRead"], 1)
        self.assertEqual(result["southboundHttpRequests"], 7)
        self.assertEqual(result["cases"]["P2"]["rows"], 1)
        self.assertEqual(result["cases"]["N6"]["outcome"], "REFUSED")
        self.assertEqual(result["cases"]["N7"]["outcome"], "TLS_FAILED")
        self.assertEqual(result["cases"]["N4"]["outcome"], "SKIPPED")
        self.assertEqual(result["cases"]["P1"]["bodyLength"], len(json.dumps({"access_token": self.server.token,
            "token_type": "Bearer", "scope": "search fetch", "expires_in": 3600}).encode()))
        for secret in (SECRET, self.server.token, "Authorization", "statements", "https://example.test/item/1"):
            self.assertNotIn(secret, stdout.getvalue() + C.canonical(result).decode())

    def test_expired_token_n4_is_used_after_exp_plus_five(self):
        observed = []
        # Wall clock advances independently of the synthetic pause clock. Server
        # expiry is switched only on the N4 wait, after the earlier cases.
        def wall():
            observed.append(True)
            self.server.exp = time.time() - 1
            return self.exp + 6
        self.exp = self.server.exp
        self.server.expires = 20
        result = self.run_suite(wall=wall)
        self.assertTrue(observed)
        self.assertEqual(result["failedCases"], [], result)
        self.assertEqual(result["southboundHttpRequests"], 8)
        self.assertEqual(result["cases"]["N4"]["httpStatus"], 401)

    def test_tls_preflight_failure_is_held_before_secret(self):
        self.input["targets"]["southboundHost"] = "wrong.test"
        result = self.run_suite()
        self.assertTrue(result["held"])
        self.assertEqual(result["reason"], "C_SOUTHBOUND_TLS_UNPROVEN")
        self.assertEqual(result["secretsRead"], 0)
        self.assertEqual(self.server.calls, [])
        self.secret_reader.assert_not_called()

    def test_token_https_requires_system_trust(self):
        result = self.run_suite(verified=False)
        self.assertEqual(result["cases"]["P1"]["outcome"], "TLS_FAILED")
        self.assertEqual(result["failedCases"][0], "P1")
        self.assertEqual(self.server.calls, [])

    def test_http_token_outside_backend_is_held_without_secret(self):
        self.input["targets"].update(tokenTls=False, backendSubnets=["192.0.2.0/24"])
        result = self.run_suite()
        self.assertEqual(result["reason"], "C_TOKEN_HTTP_OUTSIDE_BACKEND")
        self.secret_reader.assert_not_called()
        self.assertEqual(self.server.calls, [])

    def test_http_token_on_backend_is_recorded(self):
        # Use a separate loopback plain HTTP IAM endpoint, same handler.
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.calls, server.exp, server.expires, server.token = [], self.server.exp, 3600, self.server.token
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.input["targets"].update(tokenTls=False, tokenPort=server.server_port)
            result = self.run_suite()
            self.assertEqual(result["failedCases"], [], result)
            self.assertTrue(result["tokenTransport"]["httpBackendOnly"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_body_limit_fails_without_saving_response(self):
        with patch.object(C, "MAX_BODY", 20):
            result = self.run_suite()
        self.assertIn("P1", result["failedCases"])
        self.assertEqual(result["cases"]["P1"]["outcome"], "REQUEST_FAILED")
        self.assertNotIn(SECRET, C.canonical(result).decode())

    def test_absolute_timeout_includes_trickling_response_headers(self):
        with patch.object(C, "REQUEST_SECONDS", .15):
            budget = C.Budget(time.monotonic() + 5)
            transport = C.Transport("127.0.0.11", self.ca, budget)
            start = time.monotonic()
            result, _ = transport.request("127.0.0.1", self.server.server_port, "south.test", "GET", "/slow",
                                           context=transport.south_context, sni="south.test", southbound=True)
        self.assertEqual(result["outcome"], "TIMEOUT", result)
        self.assertTrue(result["connectionEstablished"])
        self.assertFalse(C.expected("N6", result))
        self.assertLess(time.monotonic() - start, 1)

    def test_apply_stdout_and_evidence_do_not_contain_credentials(self):
        result = self.run_suite()
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(plan=False, apply=True, plan_sha256=None,
                                   output_directory=str(Path(temp) / "evidence"))
            plan = C.proposal(args, self.input)
            args.plan_sha256 = plan["planSha256"]
            with patch.object(C, "arguments", return_value=args), patch.object(C.sys, "platform", "linux"), \
                    patch.object(C.os, "geteuid", return_value=0, create=True), patch.object(C.os, "getegid", return_value=0, create=True), \
                    patch.object(C, "deadline_guard", return_value=closing_context()), \
                    patch.object(C, "observation", return_value=(self.input, self.ca)), patch.object(C, "child_probe", return_value=result), \
                    patch.object(C.I, "module_scope", return_value=closing_context()), \
                    patch.object(C.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                    patch.object(C.I.os, "fchmod", lambda *_: None, create=True), patch.object(C.I.os, "O_NOFOLLOW", 0, create=True):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(C.main([]), 0)
            public = output.getvalue() + "".join(p.read_text() for p in Path(args.output_directory).iterdir())
            self.assertEqual(json.loads(output.getvalue())["status"], "C_PROBE_PASSED")
            for value in (SECRET, self.server.token, "Authorization", "https://example.test/item/1"):
                self.assertNotIn(value, public)


def closing_context():
    from contextlib import nullcontext
    return nullcontext()


class Contracts(unittest.TestCase):
    def test_endpoints_are_derived_from_profile_and_bound_transport(self):
        env = state()["configuration"]
        peer = {"binding": {"ipv4": "10.10.0.2", "bridge": "br-test", "hostIfindex": 9}}
        profile = {"schema": "ouf.semantic-provider-installation.v1", "ports": {"southbound": 443, "adapter": 9443},
                   "networks": {"backend": {"bridge": "br-test", "subnets": ["10.10.0.0/24"]}},
                   "roles": {"semantic": {"networks": {"backend": {"ipv4": "10.10.0.2"}}},
                       "southbound": {"networks": {"backend": {"ipv4": "10.10.0.3", "aliases": ["south.test"], "dnsNames": ["south.test"]},
                                                  "relay": {"ipv4": "10.11.0.3", "aliases": [], "dnsNames": []}}},
                       "adapter": {"containerName": "adapter.test", "networks": {"relay": {"ipv4": "10.11.0.2", "dnsNames": ["adapter.test"]}}}}}
        transport = {"transport": [{"source": "10.10.0.2", "destination": "10.10.0.3", "port": 443,
                                  "peerIngress": {"kind": "BRIDGE_PORT", "ifindex": 9}},
                                  {"source": "10.11.0.3", "destination": "10.11.0.2", "port": 9443}]}
        target = C.targets(profile, env, peer, transport)
        self.assertEqual((target["southboundAddress"], target["adapterAddress"]), ("10.10.0.3", "10.11.0.2"))
        for mutation in ("port", "alias", "ingress"):
            changed, flows = copy.deepcopy(profile), copy.deepcopy(transport)
            if mutation == "port": changed["ports"]["southbound"] = 444
            if mutation == "alias": changed["roles"]["southbound"]["networks"]["backend"].update(aliases=[], dnsNames=[])
            if mutation == "ingress": flows["transport"][0]["peerIngress"]["ifindex"] = 10
            with self.subTest(mutation=mutation), self.assertRaises(Exception):
                C.targets(changed, env, peer, flows)

    def test_delivery_hashes_are_git_blob_hashes_and_entrypoint_imports(self):
        import hashlib
        import re
        script = (ROOT / "ops/vps/c-probe.sh").read_text()
        self.assertRegex(script, r"(?m)^C=[0-9a-f]{40}$")
        self.assertIn("&& $C != 0000000000000000000000000000000000000000", script)
        rows = re.findall(r"^  fetch (\S+) ([0-9a-f]{64})$", script, re.M)
        self.assertGreater(len(rows), 3)
        with tempfile.TemporaryDirectory() as temp:
            for path, expected in rows:
                blob = subprocess.run(["git", "show", "HEAD:" + path], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                raw = blob.stdout if blob.returncode == 0 else (ROOT / path).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected, path)
                target = Path(temp) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            run = subprocess.run([sys.executable, "-I", "-B", str(Path(temp) / "scripts/probe-semantic-provider-c.py"), "--help"],
                                 capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr.decode())

    def test_container_dns_does_not_use_host_resolver(self):
        class DnsSocket:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def settimeout(self, value): self.timeout = value
            def connect(self, address): self.destination = address
            def send(self, raw): self.query = raw
            def recv(self, _):
                return self.query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + self.query[12:] + \
                       b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("192.0.2.9")
        dns = DnsSocket()
        with patch.object(C.socket, "socket", return_value=dns), patch.object(C.socket, "getaddrinfo", side_effect=AssertionError("host resolver")):
            addresses = C.resolve("south.test", "127.0.0.11", C.Budget(time.monotonic() + 20))
        self.assertEqual(addresses, ["192.0.2.9"])
        self.assertEqual(dns.destination, ("127.0.0.11", 53))
        self.assertLessEqual(dns.timeout, 10)
        for raw in (b"\xc0", b"\xff", b"\x40" + b"a" * 64):
            with self.assertRaises(Exception):
                C.dns_name(raw, 0)

    def test_all_r3_preconditions_fail_closed(self):
        C.preconditions(r3())
        changes = [("epoch", "state", "DELETED"), ("epoch", "live", False), ("docker", "Running", False)]
        fixtures = []
        for role in C.R.ROLES:
            for section, name, value in changes:
                item = r3()
                item["candidates"][role][section][name] = value
                fixtures.append(item)
        for section, name, value in (("supervisor", "state", "WAITING"), ("lease", "state", "QUIESCED"),
                                      ("lease", "leaseAuthorized", False)):
            item = r3()
            item[section][name] = value
            fixtures.append(item)
        for role in C.R.ROLES:
            for family in ("inet", "bridge"):
                item = r3()
                item["tables"][role][family] = False
                fixtures.append(item)
        for item in fixtures:
            with self.subTest(item=item), patch.object(C.R, "observe", return_value=item), patch.object(C, "installed") as loader, \
                    patch.object(C, "child_probe") as child, patch.object(C.Transport, "request") as request:
                with self.assertRaisesRegex(Exception, "C_R3_PRECONDITIONS_UNSATISFIED"):
                    C.observation(SimpleNamespace())
                loader.assert_not_called()
                child.assert_not_called()
                request.assert_not_called()

    def test_plan_observation_reads_only_resolver_and_not_secret(self):
        item = state()
        row = {"Config": {"Env": ["OUF_SCHEMA_GOV_" + k + "=" + v for k, v in item["configuration"].items()]}}
        reader = Mock()
        reader.read.side_effect = [b"profile", b"ca"]
        reader.hashes = {}
        peer = {"containerId": "a" * 64, "generation": {"pid": 123}, "bootId": "test-boot"}
        args = SimpleNamespace(installation_profile="profile", installation_profile_sha256="a" * 64,
                               southbound_ca="ca", southbound_ca_sha256="b" * 64)
        with patch.object(C.R, "observe", return_value=r3()), patch.object(C.I, "Reader", return_value=reader), \
                patch.object(C, "installed", return_value=(peer, (), {})), patch.object(C, "semantic", return_value=row), \
                patch.object(C.I.C, "document", return_value={}), patch.object(C, "targets", return_value={}), \
                patch.object(C.ssl, "create_default_context"), patch.object(C, "proc_read", return_value=b"nameserver 127.0.0.11\n") as read:
            observed, _ = C.observation(args)
            read.assert_called_once_with(123, "/etc/resolv.conf", 65536)
        self.assertEqual(observed["configuration"], item["configuration"])

    def test_configuration_does_not_copy_unrelated_secrets(self):
        env = state()["configuration"]
        row = {"Config": {"Env": ["OUF_SCHEMA_GOV_" + k + "=" + v for k, v in env.items()] + ["PASSWORD=" + SECRET]}}
        self.assertNotIn(SECRET, C.canonical(C.configuration(row)).decode())
        row["Config"]["Env"].append("OUF_SCHEMA_GOV_CLIENT_ID=duplicate")
        with self.assertRaises(Exception):
            C.configuration(row)

    def test_identity_drift_is_specific_and_does_not_inspect_secret(self):
        peer = {"containerId": "a" * 64, "generation": {"pid": 123}, "startedAt": "t", "image": "image"}
        row = {"Id": "a" * 64, "State": {"Running": True, "Status": "running", "Pid": 124, "StartedAt": "t"}, "Image": "image"}
        with patch.object(C.R, "docker", return_value=json.dumps([row]).encode()):
            with self.assertRaisesRegex(Exception, "C_SEMANTIC_IDENTITY_DRIFT"):
                C.semantic(SimpleNamespace(), peer, (), inspector=Mock())

    def test_budget_pause_request_limit_and_deadline(self):
        clock = FakeClock()
        budget = C.Budget(clock() + 900, clock, clock.sleep)
        for _ in range(12):
            budget.begin(True)
            budget.finish()
        self.assertAlmostEqual(sum(clock.waits), 11)
        with self.assertRaisesRegex(Exception, "C_SOUTHBOUND_REQUEST_LIMIT"):
            budget.begin(True)
        with self.assertRaisesRegex(Exception, "C_TOTAL_TIMEOUT"):
            budget.wait(900)
        clock.now += 901
        with self.assertRaisesRegex(Exception, "C_TOTAL_TIMEOUT"):
            budget.remaining()

    def test_results_reject_permissive_negatives_and_missing_cases(self):
        for case in C.CASES:
            self.assertFalse(C.expected(case, C.metadata()))
        for case in ("N1", "N2", "N3", "N4"):
            self.assertTrue(C.expected(case, C.metadata(401)))
            self.assertFalse(C.expected(case, C.metadata(403)))
        self.assertTrue(C.expected("P3", C.metadata(200)))
        for status in (400, 404):
            self.assertTrue(C.expected("N5", C.metadata(status)))
        self.assertFalse(C.expected("N6", C.metadata(outcome="TLS_FAILED")))
        self.assertFalse(C.expected("N7", C.metadata(outcome="TIMEOUT")))

    def test_first_uri_and_token_validation(self):
        env = state()["configuration"]
        token = jwt(time.time() + 60)
        raw = json.dumps({"access_token": token, "token_type": "bearer", "expires_in": 60}).encode()
        self.assertTrue(C.parse_token(raw, env)[3]["scopeGranted"])
        for body in (b"{}", b'{"results":{"bindings":[]}}',
                     b'{"results":{"bindings":[{"resource":{"type":"literal","value":"secret"}}]}}'):
            with self.assertRaises(Exception):
                C.first_uri(body)

    def test_exclusive_evidence_hash_drift_and_after_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(plan=False, apply=True, plan_sha256=None, output_directory=str(Path(temp) / "evidence"))
            before = state()
            plan = C.proposal(args, before)
            args.plan_sha256 = plan["planSha256"]
            success = {"failedCases": [], "cases": {name: {"passed": True} for name in C.CASES}, "secretsRead": 1}
            observe, run = Mock(return_value=(before, b"ca")), Mock(return_value=success)
            with patch.object(C.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                    patch.object(C.I.os, "fchmod", lambda *_: None, create=True), patch.object(C.I.os, "O_NOFOLLOW", 0, create=True):
                report = {}
                C.apply(args, plan, report, observe, run)
                C.I.write_once(Path(args.output_directory) / "result.json", C.canonical(report), report)
                self.assertEqual(report["status"], "C_PROBE_PASSED")
                for path in Path(args.output_directory).iterdir():
                    self.assertNotIn(SECRET, path.read_text())
                    with self.assertRaises(FileExistsError):
                        C.I.write_once(path, b"overwrite", report)
                with self.assertRaises(FileExistsError):
                    C.apply(args, plan, {}, observe, run)
            self.assertEqual(run.call_count, 1)
            args.output_directory += "-drift"
            with self.assertRaisesRegex(Exception, "C_PLAN_DIGEST_CHANGED"):
                C.apply(args, plan, {}, observe, run)
            self.assertFalse(Path(args.output_directory).exists())

    def test_changed_r3_after_probe_is_failed_even_when_cases_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            before = state()
            after = copy.deepcopy(before)
            after["r3"]["supervisor"]["epochs"]["adapter"] = 2
            args = SimpleNamespace(output_directory=str(Path(temp) / "out"), plan=False, apply=True, plan_sha256=None)
            plan = C.proposal(args, before)
            args.plan_sha256 = plan["planSha256"]
            with patch.object(C.I, "mkdir_once", side_effect=lambda path, _: path.mkdir()), patch.object(C.I, "write_once"):
                report = {}
                C.apply(args, plan, report, Mock(side_effect=[(before, b"ca"), (after, b"ca")]), Mock(return_value={"failedCases": []}))
            self.assertEqual(report["status"], "C_PROBE_FAILED")
            self.assertFalse(report["r3Unchanged"])

    def test_apply_precondition_failure_makes_zero_requests(self):
        args = SimpleNamespace(plan_sha256="a" * 64)
        run = Mock()
        with self.assertRaisesRegex(Exception, "C_R3_PRECONDITIONS_UNSATISFIED"):
            C.apply(args, {"planSha256": "a" * 64}, {},
                    Mock(side_effect=C.I.A.OperationDenied("C_R3_PRECONDITIONS_UNSATISFIED")), run)
        run.assert_not_called()

    @unittest.skipUnless(os.environ.get("OUF_C_NETNS_NATIVE") == "1", "Linux netns boundary runs separately in CI")
    def test_real_netns_child_and_parent_isolation(self):
        self.assertEqual(sys.platform, "linux")
        self.assertEqual(os.geteuid(), 0)
        original_ns = os.stat("/proc/self/ns/net").st_ino
        holder = subprocess.Popen([sys.executable, "-I", "-B", "-c",
            "import os,time;os.unshare(os.CLONE_NEWNET);print(os.getpid(),flush=True);time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            line = holder.stdout.readline()
            self.assertTrue(line, holder.stderr.read() if holder.poll() is not None else b"namespace not created")
            pid = int(line)
            ns = os.stat(f"/proc/{pid}/ns/net")
            ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            current = state()
            current["semantic"] = {"generation": {"pid": pid, "startTicks": ticks,
                "namespaceDevice": ns.st_dev, "namespaceInode": ns.st_ino},
                "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
            def inside(*_, **kwargs):
                kwargs["identity_check"]()
                return {"namespaceInode": os.stat("/proc/self/ns/net").st_ino, "childPid": os.getpid(), "secretsRead": 0}
            with patch.object(C, "suite", side_effect=inside):
                result = C.child_probe(current, b"unused", time.monotonic() + 10)
            self.assertEqual(result["namespaceInode"], ns.st_ino)
            self.assertNotEqual(result["namespaceInode"], original_ns)
            self.assertNotIn(result["childPid"], (os.getpid(), pid))
            self.assertEqual(os.stat("/proc/self/ns/net").st_ino, original_ns)
        finally:
            holder.terminate()
            holder.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
