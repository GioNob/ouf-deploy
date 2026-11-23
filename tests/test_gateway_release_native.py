"""Real Admin API in a disposable, labelled GitHub-hosted Docker Engine."""
from contextlib import contextmanager, nullcontext
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from test_gateway_release import LEGACY_VARS, MARKER, REQ, ROOT, SECRET, artifact, bundle, mandate, operation, retirement, row, verify
from gateway_admin import Admin, AdminRequestError, connect


PUBLISHER = dict(repository="GioNob/ouf-api-gateway", workflow="ci.yml", pullRequest=93,
                 sourceCommit="80aaea4bbe6e50d965bab82ad14c2182f05a6ef5", runId=44815101705,
                 runAttempt=1, artifactId=14668284707,
                 zipSha256="ab32a0b2a218b513e0b0827eb8e0ee441e4982a553c30b2a91061d23de39dd28")
BUNDLE_ZIP = Path(__file__).with_name("fixtures") / "gateway-release-bundle-44815101705.zip"
ISSUER = "http://127.0.0.1:9081"
DISCOVERY_PATH = "/.well-known/openid-configuration"
VALUES = {
    "caddy.oidcDiscoveryUrl": ISSUER + DISCOVERY_PATH,
    "gateway.delegationKeyEnv": "FIXTURE_DELEGATION_KEY",
    "gateway.issuerUrl": ISSUER,
    "gateway.oidcClientSecretRef": SECRET,
    "gateway.requiredAudience": "fixture-gateway",
    "gateway.semanticProposalOwnerKeyEnv": "FIXTURE_SEMANTIC_KEY",
    "gateway.sourceRevisionOwnerKeyEnv": "FIXTURE_REVISION_KEY",
    "iam.workloadClients.mcpServer": "fixture-mcp",
    "installationId": "fixture",
    "revision": "fixture-revision",
    "services.bindings.ouf-onboarding": "127.0.0.1",
    "services.bindings.ouf-semantic-registry": "127.0.0.1",
    "services.ports.ouf-onboarding": 18080,
    "services.ports.ouf-semantic-registry": 18081,
}


def published_request(run):
    req = dict(REQ, run=run, sourcePr=str(PUBLISHER["pullRequest"]), sourceRun=str(PUBLISHER["runId"]),
               artifact=str(PUBLISHER["artifactId"]), sourceCommit=PUBLISHER["sourceCommit"])
    return dict(req, digest=mandate.intent(req))


@contextmanager
def local_publisher():
    # Replace only GitHub selection and transport. package() still verifies the original ZIP on each phase.
    with patch.object(bundle, "select_artifact", return_value=PUBLISHER), \
            patch.object(bundle, "download", return_value=BUNDLE_ZIP.read_bytes()):
        yield


def publisher_profile():
    return dict(source={k: PUBLISHER[k] for k in ("repository", "workflow")}, values=VALUES)


class PublishedBundle(unittest.TestCase):
    def test_verified_fixture_has_seven_plugin_routes_and_integer_ports(self):
        with local_publisher():
            _, verified = bundle.package(publisher_profile(), published_request("70"), SECRET)
        self.assertNotIn("retired", verified)
        routes = verified["resources"]
        self.assertEqual(len(routes), 7)
        for route in routes:
            with self.subTest(route=route["id"]):
                self.assertEqual(route["kind"], "routes")
                body = route["body"]
                self.assertEqual(body["plugins"]["openid-connect"]["discovery"], ISSUER + DISCOVERY_PATH)
                self.assertGreaterEqual(body["plugins"].keys(), {"limit-count", "request-validation",
                                        "serverless-pre-function", "serverless-post-function"})
                for node in body["upstream"]["nodes"]:
                    self.assertIs(type(node["port"]), int)


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=180)
    if result.returncode:
        raise AssertionError("GATEWAY_FIXTURE_DOCKER")
    return result.stdout.decode().strip()


def assert_readback(live, desired, *, exact=False):
    paths = operation.field_differences(live, desired, exact=exact)
    if paths:
        raise AssertionError("\n".join(paths))


def seed_route(admin, target):
    # A standalone route needs routing or plugin configuration in addition to its URI.
    body = {"uri": "/" + target["id"], "status": 1, "priority": 0,
            "upstream": {"type": "roundrobin", "nodes": {"127.0.0.1:8080": 1}}}
    written = admin.write(target, body)
    live = admin.get(target)
    assert_readback(written, body)
    assert_readback(live, body)
    return live


def wait_for_writable_route(profile, target):
    deadline = time.monotonic() + 60
    reason = "STARTUP"
    while time.monotonic() < deadline:
        try:
            with connect(profile) as (admin, _):
                return seed_route(admin, target)
        except AdminRequestError as error:
            if not 500 <= error.status < 600:
                raise AssertionError(f"GATEWAY_FIXTURE_ROUTE_HTTP_{error.status}") from error
            reason = f"HTTP_{error.status}"
        except OSError as error:
            reason = type(error).__name__
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise AssertionError(f"GATEWAY_FIXTURE_WRITE_READINESS {reason}")


class WriteReadiness(unittest.TestCase):
    def test_retries_startup_then_reads_back_same_route(self):
        admin = Mock()
        written = {"uri": "/target", "status": 1, "priority": 0,
                   "upstream": {"type": "roundrobin", "nodes": {"127.0.0.1:8080": 1}}}
        admin.write.side_effect = [AdminRequestError(503), written]
        admin.get.return_value = written
        with patch(__name__ + ".connect", return_value=nullcontext((admin, None))), patch.object(time, "sleep"):
            self.assertEqual(wait_for_writable_route({}, {"id": "target"}), written)
        first, retry = admin.write.call_args_list
        self.assertEqual(first, retry)
        self.assertIn("upstream", first.args[1])
        admin.get.assert_called_once_with({"id": "target"})

    def test_invalid_body_and_deadline_fail_with_http_status(self):
        for status, clock, reason in ((400, [0, 0], "ROUTE_HTTP_400"),
                                      (503, [0, 0, 59, 60], "WRITE_READINESS HTTP_503")):
            admin = Mock()
            admin.write.side_effect = AdminRequestError(status)
            with self.subTest(status=status), patch(__name__ + ".connect", return_value=nullcontext((admin, None))), \
                    patch.object(time, "monotonic", side_effect=clock), patch.object(time, "sleep"), \
                    self.assertRaisesRegex(AssertionError, reason):
                wait_for_writable_route({}, {"id": "target"})
            admin.write.assert_called_once()


@unittest.skipUnless(os.getenv("OUF_GATEWAY_RELEASE_NATIVE") == "1", "disposable APISIX opt-in")
class NativeRelease(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        labels = json.loads(docker("info", "--format", "{{json .Labels}}"))
        self.assertIn("ouf.a2.fixture=true", labels)
        private = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/root")))
        self.state = private / "state"
        self.state.mkdir(mode=0o700)
        name = "gateway-release-ci-" + str(os.getpid())
        net = docker("network", "create", name)
        self.addCleanup(docker, "network", "rm", net)
        etcd = docker("run", "-d", "--name", name+"-etcd", "--network", net, "quay.io/coreos/etcd:v3.5.17",
                      "etcd", "--listen-client-urls=http://0.0.0.0:2379",
                      "--advertise-client-urls=http://"+name+"-etcd:2379")
        self.addCleanup(docker, "rm", "-f", etcd)
        key = "synthetic-gateway-admin-secret-12345"
        keyfile = private / "admin.key"
        keyfile.write_text(key + "\n")
        keyfile.chmod(0o600)
        config = private / "config.yaml"
        # JSON is also valid YAML. No host port or public listener for the Admin API.
        # A static discovery document on the gateway's own loopback, also reachable during a PUT.
        discovery = json.dumps({"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks"})
        issuer_server = ("server { listen 127.0.0.1:9081; default_type application/json; "
                         f"location = {DISCOVERY_PATH} {{ return 200 '{discovery}'; }} "
                         """location = /jwks { return 200 '{"keys":[]}'; } }""")
        # Match the numeric profile already used by OUF on this image. Three
        # published request-validation schemas require an exact 16-digit maximum.
        assets = ROOT / "tools/chatbot_file_cohort/assets/apisix"
        config.write_text(json.dumps({"apisix": {"extra_lua_path": "/usr/local/apisix/conf/?.lua",
                                                "lua_module_hook": "ouf_json_precision"},
            "nginx_config": {"http_configuration_snippet": issuer_server}, "deployment": {
            "role": "traditional", "role_traditional": {"config_provider": "etcd"},
            "admin": {"admin_listen": {"ip": "127.0.0.1", "port": 9180}, "allow_admin": ["127.0.0.1/32"],
                      "admin_key": [{"name": "admin", "key": key, "role": "admin"}]},
            "etcd": {"host": ["http://" + name + "-etcd:2379"]}}}))
        cid = docker("run", "-d", "--network", net, "--name", name, "-v",
                     str(config)+":/usr/local/apisix/conf/config.yaml:ro",
                     "-v", str(assets / "ouf_json_precision.lua")+":/usr/local/apisix/conf/ouf_json_precision.lua:ro",
                     "-v", str(assets / "jsonschema.lua")+":/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua:ro",
                     "apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d")
        self.addCleanup(docker, "rm", "-f", cid)
        self.cid = cid
        self.profile = dict(dockerSocket="/var/run/docker.sock", container=name, host="127.0.0.1",
                            port=9180, adminPath="/apisix/admin", keyFile=str(keyfile), values={"binding": SECRET})
        self.route = row("routes", "target", {})
        self.outside = row("routes", "outside", {})
        self.plugins = row("plugin_configs", "settings", {"plugins": {"proxy-rewrite": {"uri": "/changed"}}})

        self.baseline = wait_for_writable_route(self.profile, self.route)
        with connect(self.profile) as (admin, _):
            self.foreign = seed_route(admin, self.outside)

    def phase(self, req):
        runner = operation.GatewayRelease({"gateway": self.profile}, self.state, req)
        try:
            result = runner.execute("fixture-review", SECRET)
        except mandate.Held:
            diagnostics = runner.path / ("gateway." + req["phase"] + ".diagnostics")
            if diagnostics.exists():
                for entry in json.loads(diagnostics.read_bytes()):
                    status = f" HTTP {entry['httpStatus']}" if "httpStatus" in entry else ""
                    print(f"{entry['stage']} {entry['kind']}/{entry['id']}{status}", *entry["paths"], sep="\n")
            raise
        self.assertFalse(SECRET in json.dumps(result), "private fixture value in public receipt")
        return result

    @contextmanager
    def selected(self, invalid=False, *, retired=None):
        body = dict(self.baseline, desc=MARKER, plugin_config_id="settings",
                    plugins={"limit-count": {"count": 5, "time_window": 60, "key": "remote_addr"}})
        if invalid:
            body["methods"] = "invalid-method-list"
        pair = artifact([self.plugins, row("routes", "target", body)], retired=retired)
        with patch.object(operation, "package", side_effect=lambda *_: (pair[0], verify(pair))):
            yield

    def test_apply_return_then_rejected_route_restores_plugin_config(self):
        with self.selected():
            plan = self.phase(REQ)
            self.assertEqual(plan["counts"], dict(create=1, update=1, unchanged=0))
            with self.assertRaisesRegex(mandate.Held, "PLAN_DRIFT"):
                self.phase(dict(REQ, phase="apply", digest="0"*64))
            receipt = self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
            again = dict(REQ, run="73")
            again["digest"] = mandate.intent(again)
            self.assertEqual(self.phase(again)["counts"], dict(create=0, update=0, unchanged=2))
        with connect(self.profile) as (admin, _):
            live = admin.get(self.route)
            self.assertEqual(live["plugin_config_id"], "settings")
            self.assertGreaterEqual(live["plugins"]["limit-count"].keys(), {"count", "time_window", "key"})  # APISIX may or may not materialize defaults
            assert_readback(admin.get(self.outside), self.foreign, exact=True)
        back = dict(operation="gateway-release", run="71", attempt="1", commit=REQ["commit"],
                    phase="return", releaseRun=REQ["run"], digest=receipt["digest"])
        self.assertEqual(self.phase(back)["status"], "RETURNED")
        with self.selected(invalid=True):
            req = dict(REQ, run="72")
            req["digest"] = mandate.intent(req)
            plan = self.phase(req)
            with self.assertRaisesRegex(mandate.Held, "^GATEWAY_WRITE_FAILED_RESTORED$"):
                self.phase(dict(req, phase="apply", digest=plan["digest"]))
        self.assertEqual(json.loads((self.state / "72/gateway.apply.1.intent").read_bytes()),
                         {"id": "target", "kind": "routes"})
        with connect(self.profile) as (admin, _):
            assert_readback(admin.get(self.route), self.baseline, exact=True)
            assert_readback(admin.get(self.plugins), None, exact=True)
            assert_readback(admin.get(self.outside), self.foreign, exact=True)
        self.assertEqual((self.state / "70/gateway.snapshot").stat().st_mode & 0o777, 0o600)

    def published_routes(self):
        # Verify the readback exception against the plugin shipped in this exact image.
        source = docker("exec", self.cid, "cat", "/usr/local/apisix/apisix/plugins/openid-connect.lua")
        encrypted = re.search(r"\bencrypt_fields\s*=\s*\{([^}]*)\}", source)
        self.assertIsNotNone(encrypted, "openid-connect.encrypt_fields: missing")
        self.assertTrue(re.search(r"""["']client_secret["']""", encrypted[1]) is not None,
                        "openid-connect.encrypt_fields.client_secret: missing")
        self.profile.update(publisher_profile())
        self.enterContext(local_publisher())
        with connect(self.profile):
            conn = HTTPConnection("127.0.0.1", 9081, timeout=5)
            try:
                conn.request("GET", DISCOVERY_PATH)
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.load(response)["issuer"], ISSUER)
            finally:
                conn.close()
        _, verified = bundle.package(self.profile, published_request("70"), SECRET)
        routes = verified["resources"]
        self.assertEqual(len(routes), 7)
        return routes

    def apply_readback_return(self, req, plan, routes, before, parent):
        receipt = self.phase(dict(req, phase="apply", digest=plan["digest"]))
        self.assertEqual(receipt["status"], "APPLIED")
        with connect(self.profile) as (admin, _):
            for route in routes:
                with self.subTest(route=route["id"]):
                    live = admin.get(route)
                    assert_readback(live, route["body"])
                    oidc = "openid-connect"
                    if live["plugins"][oidc]["client_secret"] != route["body"]["plugins"][oidc]["client_secret"]:
                        print(f"{route['id']} plugins.openid-connect.client_secret: changed (opaque)")
            assert_readback(admin.get(self.outside), self.foreign, exact=True)
        self.assertEqual(self.phase(published_request("73"))["counts"], dict(create=0, update=0, unchanged=7))
        back = dict(operation="gateway-release", run="71", attempt="1", commit=req["commit"],
                    phase="return", releaseRun=req["run"], digest=receipt["digest"])
        self.assertEqual(self.phase(back)["status"], "RETURNED")
        with connect(self.profile) as (admin, _):
            for route, original in zip(routes, before, strict=True):
                with self.subTest(route=route["id"]):
                    assert_readback(admin.get(route), original, exact=True)
            assert_readback(admin.get(self.outside), self.foreign, exact=True)
        self.assertEqual(json.loads((self.state / "gateway-head").read_bytes()), parent)

    def test_published_release_creates_seven_routes_then_returns_to_absence(self):
        routes = self.published_routes()
        req = published_request("70")
        plan = self.phase(req)
        self.assertEqual(plan["counts"], dict(create=7, update=0, unchanged=0))
        self.apply_readback_return(req, plan, routes, [None] * len(routes), None)

    def test_v2_delete_and_return_on_apisix(self):
        legacy = row("routes", "legacy", {})
        with connect(self.profile) as (admin, _):
            admin.write(legacy, dict(self.baseline, desc="legacy fixture", vars=LEGACY_VARS))
            before = admin.get(legacy)
        with self.selected(retired=[retirement("legacy", "target")]):
            plan = self.phase(REQ)
            self.assertEqual(plan["counts"], dict(create=1, update=1, unchanged=0, delete=1))
            receipt = self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
        back = dict(operation="gateway-release", run="71", attempt="1", commit=REQ["commit"],
                    phase="return", releaseRun=REQ["run"], digest=receipt["digest"])
        with connect(self.profile) as (admin, _):
            self.assertIsNone(admin.get(legacy))
        self.assertEqual(self.phase(back)["status"], "RETURNED")
        with connect(self.profile) as (admin, _):
            assert_readback(admin.get(legacy), before, exact=True)
            assert_readback(admin.get(self.route), self.baseline, exact=True)
            assert_readback(admin.get(self.outside), self.foreign, exact=True)

    def test_published_release_recovers_first_put_and_returns_to_original_snapshot(self):
        routes = self.published_routes()
        with connect(self.profile) as (admin, _):
            old_routes = [seed_route(admin, route) for route in routes[1:]]
        req = published_request("70")
        plan = self.phase(req)
        self.assertEqual(plan["counts"], dict(create=1, update=6, unchanged=0))

        write = Admin.write

        def interrupt_after_put(admin, route, body):
            write(admin, route, body)
            raise KeyboardInterrupt()

        with patch.object(Admin, "write", interrupt_after_put), self.assertRaises(KeyboardInterrupt):
            self.phase(dict(req, phase="apply", digest=plan["digest"]))
        pending = {"status": "PENDING", "phase": "apply", "run": req["run"]}
        self.assertEqual(json.loads((self.state / "gateway-head").read_bytes()), pending)
        with connect(self.profile) as (admin, _):
            mixed = [admin.get(route) for route in routes]
        assert_readback(mixed[0], routes[0]["body"])
        assert_readback(mixed[1:], old_routes, exact=True)

        recovery = published_request("72")
        resumed = self.phase(recovery)
        self.assertEqual(resumed["recoveringRun"], req["run"])
        self.assertEqual(resumed["counts"], dict(create=0, update=6, unchanged=1))
        self.apply_readback_return(recovery, resumed, routes, [None, *old_routes], None)
