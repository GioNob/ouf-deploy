import datetime
import errno
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "identity_lab", Path(__file__).resolve().parents[1] / "scripts/run-seaweedfs-452-identity-tls.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class IdentityLabTests(unittest.TestCase):
    def test_fixture_policy_is_exact_bucket_and_prefix_only(self):
        config = lab.fixture_config()
        bootstrap, app = config["identities"]
        self.assertEqual(bootstrap["actions"], ["Admin:" + lab.BUCKET, "Admin:" + lab.OTHER])
        self.assertNotIn("actions", app)
        policy = json.loads(config["policies"][0]["content"])
        self.assertEqual(app["policyNames"], [config["policies"][0]["name"]])
        object_rule, list_rule = policy["Statement"]
        self.assertEqual(set(object_rule["Action"]), {"s3:GetObject", "s3:PutObject"})
        self.assertEqual(object_rule["Resource"], ["arn:aws:s3:::" + lab.BUCKET + "/staging/*"])
        self.assertEqual(list_rule["Resource"], ["arn:aws:s3:::" + lab.BUCKET])
        self.assertEqual(list_rule["Action"], ["s3:ListBucket"])
        self.assertEqual(list_rule["Condition"], {"StringLike": {"s3:prefix": ["staging/*"]}})

    def test_signatures_bind_credentials_payload_and_request_target(self):
        now = datetime.datetime(2026, 11, 3, tzinfo=datetime.timezone.utc)
        base = lab.signed_headers("PUT", "/bucket/staging/a", body=b"a", now=now)
        alternatives = [
            lab.signed_headers("PUT", "/bucket/staging/a", body=b"b", now=now),
            lab.signed_headers("PUT", "/bucket/outside/a", body=b"a", now=now),
            lab.signed_headers("PUT", "/bucket/staging/a", body=b"a", credentials=(lab.APP[0], "wrong"), now=now),
        ]
        self.assertEqual(base["host"], "localhost:18333")
        self.assertIn("/20261103/us-east-1/s3/aws4_request", base["authorization"])
        self.assertTrue(all(r["authorization"] != base["authorization"] for r in alternatives))

    def test_denials_require_exact_status_and_s3_code(self):
        body = b"<Error><Code>AccessDenied</Code></Error>"
        lab.check_response(403, body, 403, "AccessDenied")
        for status, payload in ((500, body), (404, body), (200, body),
                                (403, b"<Error><Code>InternalError</Code></Error>")):
            with self.subTest(status=status, payload=payload), self.assertRaises(RuntimeError):
                lab.check_response(status, payload, 403, "AccessDenied")

    def test_permanent_readiness_error_has_no_retry(self):
        with mock.patch.object(lab, "request", return_value=(403, b"denied")) as request, \
                mock.patch.object(lab.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "PERMANENT_READINESS_HTTP_403"):
                lab.client("ready", Path("unused"))
            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()

    def test_certificate_readiness_error_has_no_retry(self):
        with mock.patch.object(lab, "request", side_effect=ssl.SSLCertVerificationError("fixture")) as request, \
                mock.patch.object(lab.time, "sleep") as sleep:
            with self.assertRaises(ssl.SSLCertVerificationError):
                lab.client("ready", Path("unused"))
            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()

    def test_ambiguous_mutation_has_no_retry(self):
        with mock.patch.object(lab, "request", side_effect=TimeoutError("ambiguous")) as request:
            with self.assertRaises(TimeoutError):
                lab.client("verify", Path("unused"))
            self.assertEqual(request.call_count, 1)
            self.assertEqual(request.call_args.args[1], "PUT")

    def test_operational_timeout_allows_first_volume_allocation_without_retry(self):
        connection = mock.Mock()
        connection.request.side_effect = TimeoutError("ambiguous")
        with mock.patch.object(lab.ssl, "create_default_context", return_value="verified-context"), \
                mock.patch.object(lab.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaises(TimeoutError):
                lab.request(Path("fixture-tls"), "PUT", "/fixture-bucket", body=b"fixture")
            factory.assert_called_once_with("localhost", 18333, timeout=30, context="verified-context")
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_late_readiness_success_does_not_exceed_budget(self):
        with mock.patch.object(lab.time, "monotonic", side_effect=[0, 0, 81]), \
                mock.patch.object(lab, "request", return_value=(200, b"")) as request:
            with self.assertRaisesRegex(RuntimeError, "TLS_READINESS_BUDGET"):
                lab.client("ready", Path("unused"))
            self.assertEqual(request.call_count, 1)
            self.assertEqual(request.call_args.kwargs["timeout"], 5)

    def test_egress_requires_kernel_route_denial(self):
        tcp, udp = mock.MagicMock(), mock.MagicMock()
        tcp.__enter__.return_value = tcp
        udp.__enter__.return_value = udp
        tcp.connect_ex.return_value = errno.ENETUNREACH
        udp.sendto.side_effect = OSError(errno.ENETUNREACH, "fixture")
        with mock.patch.object(lab.socket, "socket", side_effect=[tcp, udp]):
            records = lab.egress_probe()
        self.assertEqual([r["transport"] for r in records], ["TCP", "UDP"])
        tcp.connect_ex.assert_called_once_with(("192.0.2.1", 443))
        udp.sendto.assert_called_once()
        for code in (0, errno.ECONNREFUSED, errno.ETIMEDOUT):
            tcp.connect_ex.return_value = code
            with mock.patch.object(lab.socket, "socket", return_value=tcp), self.assertRaises(RuntimeError):
                lab.egress_probe()

    def test_non_ci_run_fails_before_side_effect(self):
        with mock.patch.dict(lab.os.environ, {}, clear=True), mock.patch.object(lab.cold, "prepare_image") as image:
            with self.assertRaisesRegex(RuntimeError, "ISOLATED_CI_ONLY"):
                lab.run(Path("absent.zip"), Path("not-created"))
            image.assert_not_called()


class TLSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.tls = lab.certificates(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def handshake(self, hostname="localhost", ca="ca.pem"):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(self.tls / "server.pem", self.tls / "server.key")
        client = ssl.create_default_context(cafile=str(self.tls / ca))
        client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
        client_tls = client.wrap_bio(client_in, client_out, server_hostname=hostname)
        server_tls = server.wrap_bio(server_in, server_out, server_side=True)
        client_done = server_done = False
        for _ in range(20):
            for session, done in ((client_tls, client_done), (server_tls, server_done)):
                if done:
                    continue
                try:
                    session.do_handshake()
                    if session is client_tls:
                        client_done = True
                    else:
                        server_done = True
                except ssl.SSLWantReadError:
                    pass
            server_in.write(client_out.read())
            client_in.write(server_out.read())
            if client_done and server_done:
                return client_tls.version()
        self.fail("bounded in-memory TLS handshake exhausted")

    def test_generated_ca_trusts_localhost(self):
        self.assertIn(self.handshake(), {"TLSv1.2", "TLSv1.3"})
        self.assertEqual((self.tls / "server.key").stat().st_mode & 0o777, 0o600)

    def test_wrong_ca_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake(ca="wrong-ca.pem")

    def test_wrong_hostname_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake(hostname="127.0.0.1")


if __name__ == "__main__":
    unittest.main()
