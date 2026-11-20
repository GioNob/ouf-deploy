"""Real Admin API in a disposable, labelled GitHub-hosted Docker Engine."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from test_gateway_release import MARKER, REQ, SECRET, artifact, mandate, operation, row, verify
from gateway_admin import connect


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=180)
    if result.returncode:
        raise AssertionError("GATEWAY_FIXTURE_DOCKER")
    return result.stdout.decode().strip()


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
        config.write_text(json.dumps({"deployment": {
            "role": "traditional", "role_traditional": {"config_provider": "etcd"},
            "admin": {"admin_listen": {"ip": "127.0.0.1", "port": 9180}, "allow_admin": ["127.0.0.1/32"],
                      "admin_key": [{"name": "admin", "key": key, "role": "admin"}]},
            "etcd": {"host": ["http://" + name + "-etcd:2379"]}}}))
        cid = docker("run", "-d", "--network", net, "--name", name, "-v",
                     str(config)+":/usr/local/apisix/conf/config.yaml:ro",
                     "apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d")
        self.addCleanup(docker, "rm", "-f", cid)
        self.profile = dict(dockerSocket="/var/run/docker.sock", container=name, host="127.0.0.1",
                            port=9180, adminPath="/apisix/admin", keyFile=str(keyfile), values={"binding": SECRET})
        self.route = row("routes", "target", {})
        self.outside = row("routes", "outside", {})
        self.plugins = row("plugin_configs", "settings", {"plugins": {"proxy-rewrite": {"uri": "/changed"}}})
        deadline = time.monotonic() + 60
        while True:
            try:
                with connect(self.profile) as (admin, _):
                    admin.get(self.route)
                break
            except (OSError, mandate.Held):
                self.assertLess(time.monotonic(), deadline, "GATEWAY_FIXTURE_STARTUP")
                time.sleep(1)
        with connect(self.profile) as (admin, _):
            for target in (self.route, self.outside):
                admin.write(target, {"uri": "/" + target["id"], "status": 1, "priority": 0})
            self.baseline = admin.get(self.route)
            self.foreign = admin.get(self.outside)

    def phase(self, req):
        result = operation.GatewayRelease({"gateway": self.profile}, self.state, req).execute("fixture-review")
        self.assertNotIn(SECRET, json.dumps(result))
        return result

    @contextmanager
    def selected(self, invalid=False):
        body = dict(self.baseline, desc=MARKER, plugin_config_id="settings")
        if invalid:
            body["methods"] = "invalid-method-list"
        pair = artifact([self.plugins, row("routes", "target", body)])
        with patch.object(operation, "package", side_effect=lambda *_: (pair[0], verify(pair))):
            yield

    def test_apply_return_then_rejected_route_restores_plugin_config(self):
        with self.selected():
            plan = self.phase(REQ)
            self.assertEqual(plan["counts"], dict(create=1, update=1, unchanged=0))
            with self.assertRaisesRegex(mandate.Held, "PLAN_DRIFT"):
                self.phase(dict(REQ, phase="apply", digest="0"*64))
            receipt = self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
        with connect(self.profile) as (admin, _):
            self.assertEqual(admin.get(self.route)["plugin_config_id"], "settings")
            self.assertEqual(admin.get(self.outside), self.foreign)
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
            self.assertEqual(admin.get(self.route), self.baseline)
            self.assertIsNone(admin.get(self.plugins))
            self.assertEqual(admin.get(self.outside), self.foreign)
        self.assertEqual((self.state / "70/gateway.snapshot").stat().st_mode & 0o777, 0o600)
