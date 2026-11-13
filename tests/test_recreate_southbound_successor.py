"""Synthetic API 1.44 fixtures; no Docker daemon, network or real credential IO."""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("recreate-southbound-successor-20261113.py")
original = load("create-discovery-stopped-candidates-20261111.py")
HA, HS, CA, CS, NEW, THIRD = (digit * 64 for digit in "123456")
TRANSACTION = "a" * 32
RUNTIME = "ouf-semantic-admitted-v2"


def historical(name, cid):
    host = {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"], "PortBindings": {},
            "PublishAllPorts": False, "VolumesFrom": None, "AutoRemove": False,
            "ReadonlyRootfs": False, "Runtime": RUNTIME, "Memory": 536870912,
            "PidsLimit": 128, "Binds": ["synthetic:old:ro"], "NetworkMode": "old",
            "OomKillDisable": None, "ShmSize": 67108864}
    env = ["PATH=/usr/bin:/bin"]
    config = {"Env": env.copy(), "User": "636:636", "WorkingDir": "/work",
              "Entrypoint": ["/docker-entrypoint.sh"], "Cmd": ["docker-start"],
              "Healthcheck": {"Test": ["NONE"]}}
    mounts = []
    if name == m.SOUTHBOUND:
        config["Env"] += [m.OIDC_ENV + "=synthetic-not-a-secret", m.HMAC_ENV + "=synthetic"]
        for i, target in enumerate((m.ROUTES, "/usr/local/apisix/conf/config.yaml")):
            mounts.append({"Type": "bind", "Source": f"/synthetic/config-{i}",
                           "Destination": target, "RW": False, "Propagation": "rprivate"})
    return {"Id": cid, "Name": "/historical-" + name, "Image": "sha256:" + "f" * 64,
            "Config": config, "HostConfig": host, "Mounts": mounts,
            "Path": "/docker-entrypoint.sh", "Args": ["docker-start"],
            "NetworkSettings": {"Networks": {}}, "RestartCount": 0,
            "State": {"Running": False, "Restarting": False, "Paused": False,
                      "Status": "exited", "Pid": 0, "StartedAt": "2026-10-18T00:00:00Z",
                      "FinishedAt": "2026-10-18T01:00:00Z"}}


def created(name, cid, request, transaction, legacy=False):
    config = {key: copy.deepcopy(value) for key, value in request.items()
              if key not in {"Image", "HostConfig", "NetworkingConfig"}}
    config["Labels"] = {m.OWNER_LABEL: transaction}
    if legacy:
        config["MacAddress"] = next(iter(m.ENDPOINTS[name].values()))[1]
    mounts = [{"Source": bind["Source"], "Destination": bind["Target"],
               "Type": bind["Type"], "RW": not bind["ReadOnly"],
               "Propagation": bind.get("BindOptions", {}).get("Propagation", "rprivate")}
              for bind in request["HostConfig"]["Mounts"]]
    networks = copy.deepcopy(request["NetworkingConfig"]["EndpointsConfig"])
    for endpoint in networks.values():
        endpoint.update(EndpointID="", IPAddress="", GlobalIPv6Address="")
    host = copy.deepcopy(request["HostConfig"])
    if host.get("OomKillDisable") is None and "OomKillDisable" in host:
        host["OomKillDisable"] = False
    return {"Id": cid, "Name": f"/{name}-successor", "Image": request["Image"],
            "Config": config, "HostConfig": host,
            "Mounts": mounts, "Path": request["Entrypoint"][0], "Args": request["Cmd"],
            "NetworkSettings": {"Networks": networks}, "RestartCount": 0,
            "State": {"Running": False, "Restarting": False, "Paused": False,
                      "Status": "created", "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z",
                      "FinishedAt": "0001-01-01T00:00:00Z"}}


class FakeEngine:
    def __init__(self):
        self.docs = {HA: historical(m.ADAPTER, HA), HS: historical(m.SOUTHBOUND, HS)}
        self.calls = []
        self.fail_post = False
        self.corrupt_new = False
        self.legacy = False
        self.change_adapter = False

    def __call__(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if method == "GET":
            if path == "/info":
                return {"Runtimes": {RUNTIME: {}}}
            if path == "/containers/json?all=1":
                return [{"Id": cid} for cid in self.docs]
            if path.startswith("/images/"):
                return {"Id": "sha256:" + "f" * 64,
                        "Config": {"Env": ["PATH=/usr/bin:/bin"], "Volumes": None}}
            if path.startswith("/networks/"):
                name = path.removeprefix("/networks/")
                peers = {}
                for cid, doc in self.docs.items():
                    endpoint = doc["NetworkSettings"]["Networks"].get(name)
                    if endpoint and endpoint.get("EndpointID"):
                        peers[cid] = {"Name": doc["Name"].lstrip("/"),
                                      "IPv4Address": endpoint["IPAddress"] + "/16",
                                      "MacAddress": endpoint["MacAddress"]}
                return {"Name": name, "Id": name + "-synthetic", "Containers": peers}
            if path.startswith("/containers/") and path.endswith("/json"):
                return copy.deepcopy(self.docs.get(path.split("/")[2]))
        if method == "DELETE":
            # A query (force/v) or wrong target must fail even in the fake.
            assert path == f"/containers/{CS}"
            del self.docs[CS]
            return None
        if method == "POST":
            assert path == f"/containers/create?name={m.SOUTHBOUND}-successor"
            if self.fail_post:
                raise OSError("synthetic response loss")
            self.docs[NEW] = created(m.SOUTHBOUND, NEW, payload,
                                     payload["Labels"][m.OWNER_LABEL], self.legacy)
            if self.corrupt_new:
                self.docs[NEW]["HostConfig"]["Memory"] += 1
            if self.change_adapter:
                self.docs[CA]["Config"]["WorkingDir"] = "/changed"
            return {"Id": NEW}
        raise AssertionError((method, path))

    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]


class RecreateTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=ROOT)))
        self.fake = FakeEngine()
        frames = {}
        for name, cid in ((m.ADAPTER, HA), (m.SOUTHBOUND, HS)):
            doc = self.fake.docs[cid]
            frame = {key: doc.get(key) for key in m.FRAME_FIELDS}
            frame["State"] = {key: doc["State"].get(key) for key in m.STATE_FIELDS}
            frames[name] = m.sha(m.canonical(frame) + b"\n")
        self.stack.enter_context(patch.object(m, "HISTORICAL_FRAMES", frames))
        self.stack.enter_context(patch.object(m, "engine", self.fake))
        self.routes = self.stack.enter_context(patch.object(m, "verify_routes"))
        self.metadata = self.stack.enter_context(patch.object(m, "protected_file"))
        # Deliberately bypass Unix deployment metadata only, not request guards.
        self.stack.enter_context(patch.object(m, "validate_output", self.output_absent))
        self.requests = {name: m.build_request({m.ADAPTER: HA, m.SOUTHBOUND: HS}, name)
                         for name in m.ENDPOINTS}
        for name, cid in ((m.ADAPTER, CA), (m.SOUTHBOUND, CS)):
            self.fake.docs[cid] = created(name, cid, self.requests[name], TRANSACTION)
        self.args = argparse.Namespace(plan=True, apply=False, plan_sha256=None,
                                       historical_adapter_id=HA, historical_southbound_id=HS,
                                       current_adapter_id=CA, current_southbound_id=CS,
                                       creation_transaction=TRANSACTION,
                                       creation_plan_prefix=m.sha(m.canonical(self.requests))[:8],
                                       expected_runtime=RUNTIME, docker_socket=Path("/synthetic/docker.sock"),
                                       output_root=self.directory, output_name="synthetic-receipt")
        self.fake.calls.clear()

    @staticmethod
    def output_absent(args):
        m.require(not os.path.lexists(args.output_root / args.output_name), "OUTPUT_ALREADY_EXISTS")

    def apply(self):
        plan = m.run(self.args)
        self.assertEqual(plan["status"], "PLAN_READY", plan)
        self.args.plan, self.args.apply = False, True
        self.args.plan_sha256 = plan["planSha256"]
        self.fake.calls.clear()
        return m.run(self.args)

    def test_reconstruction_matches_original_compiler_both_roles(self):
        with patch.object(original, "engine", self.fake), \
                patch.object(original, "HISTORICAL_FRAMES", m.HISTORICAL_FRAMES), \
                patch.object(original, "verify_routes"), patch.object(original, "protected_file"):
            preflight = argparse.Namespace(HISTORICAL={m.ADAPTER: (HA, None), m.SOUTHBOUND: (HS, None)})
            expected = {n: original.build_request(preflight, n, True) for n in original.ENDPOINTS}
        self.assertEqual(m.canonical(expected), m.canonical(self.requests))
        report = m.run(self.args)
        self.assertEqual(report["status"], "PLAN_READY")
        self.assertEqual(report["planSha256"], m.sha(m.canonical(report["plan"])))
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(self.fake.writes(), [])
        self.routes.assert_called()
        self.metadata.assert_called_with(m.HMAC_SOURCE, (636, 636, 0o600))

    def test_bad_prefix_held(self):
        self.args.creation_plan_prefix = "00000000"
        report = m.run(self.args)
        self.assertEqual(report["status"], "HELD")
        self.assertEqual(report["reason"], "CREATION_REQUEST_RECONSTRUCTION_MISMATCH")
        self.assertEqual(self.fake.writes(), [])

    def test_historical_frame_mismatch_held(self):
        self.fake.docs[HS]["HostConfig"]["Memory"] += 1
        self.assertEqual(m.run(self.args)["reason"], "HISTORICAL_FRAME_CHANGED")
        self.assertEqual(self.fake.writes(), [])

    def test_oom_null_to_false_accepted_current_and_new_without_changing_post(self):
        for name, cid in ((m.ADAPTER, CA), (m.SOUTHBOUND, CS)):
            self.assertIsNone(self.requests[name]["HostConfig"]["OomKillDisable"])
            self.assertIs(self.fake.docs[cid]["HostConfig"]["OomKillDisable"], False)
        report = self.apply()
        self.assertEqual(report["status"], "SOUTHBOUND_RECREATED_STOPPED", report)
        post = next(payload for method, _, payload in self.fake.writes() if method == "POST")
        self.assertIsNone(post["HostConfig"]["OomKillDisable"])
        self.assertIs(self.fake.docs[NEW]["HostConfig"]["OomKillDisable"], False)

    def test_oom_null_to_true_rejected(self):
        self.assert_hostconfig_mismatch("OomKillDisable", None, True)

    def test_oom_false_to_null_rejected(self):
        self.assert_hostconfig_mismatch("OomKillDisable", False, None)

    def test_other_hostconfig_normalization_rejected(self):
        self.assert_hostconfig_mismatch("ShmSize", 0, 67108864)

    def assert_hostconfig_mismatch(self, key, requested, observed):
        for name, cid in ((m.ADAPTER, CA), (m.SOUTHBOUND, CS)):
            with self.subTest(role=name):
                request = copy.deepcopy(self.requests[name])
                request["HostConfig"][key] = requested
                self.fake.docs[cid]["HostConfig"][key] = observed
                with self.assertRaisesRegex(m.Held, "CANDIDATE_FULL_HOSTCONFIG_CHANGED"):
                    m.inspect_created(cid, name, request, TRANSACTION, RUNTIME)
        self.assertEqual(self.fake.writes(), [])

    def test_candidate_guards_both_roles(self):
        mutations = [lambda d: d["State"].update(Status="running", Pid=42, Running=True),
                     lambda d: d["State"].update(StartedAt="2026-11-13T00:00:00Z"),
                     lambda d: d.update(RestartCount=1),
                     lambda d: d["Config"]["Labels"].update({m.OWNER_LABEL: "b" * 32}),
                     lambda d: d.update(Name="/wrong"),
                     lambda d: d["HostConfig"].update(Runtime="runc"),
                     lambda d: d["HostConfig"].update(Memory=1),
                     lambda d: d["HostConfig"].update(EngineAddedButUnproven=False),
                     lambda d: d["HostConfig"]["RestartPolicy"].update(Name="always"),
                     lambda d: d["Config"].update(Healthcheck={"Test": ["CMD", "changed"]}),
                     lambda d: next(iter(d["NetworkSettings"]["Networks"].values())).update(EndpointID="active")]
        for cid in (CA, CS):
            saved = copy.deepcopy(self.fake.docs[cid])
            for mutate in mutations:
                with self.subTest(cid=cid, mutation=mutate):
                    self.fake.docs[cid] = copy.deepcopy(saved)
                    mutate(self.fake.docs[cid])
                    report = m.run(self.args)
                    self.assertEqual(report["status"], "HELD")
                    self.assertTrue(report["reason"].startswith("CURRENT_SUCCESSOR_REQUEST_MISMATCH"), report)
                    self.assertEqual(self.fake.writes(), [])
            self.fake.docs[cid] = saved

    def test_third_container_ip_mac_alias_active_and_stopped(self):
        network, (ip, mac) = next(iter(m.ENDPOINTS[m.SOUTHBOUND].items()))
        for active in (False, True):
            for resource in ("ip", "mac", "alias"):
                with self.subTest(active=active, resource=resource):
                    endpoint = {"IPAMConfig": {"IPv4Address": ip if resource == "ip" else "172.18.0.99"},
                                "IPAddress": ip if active and resource == "ip" else "172.18.0.99" if active else "",
                                "MacAddress": mac if resource == "mac" else "02:42:ac:12:00:63",
                                "Aliases": [m.SOUTHBOUND] if resource == "alias" else ["third"],
                                "EndpointID": "active" if active else ""}
                    self.fake.docs[THIRD] = {"Name": "/third", "NetworkSettings": {"Networks": {network: endpoint}}}
                    report = m.run(self.args)
                    self.assertEqual(report["status"], "HELD")
                    self.assertEqual(report["reason"], "SOUTHBOUND_NETWORK_RESOURCE_OCCUPIED")
                    self.assertEqual(self.fake.writes(), [])

    def test_apply_wrong_digest_has_no_mutation_or_output(self):
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, "0" * 64
        report = m.run(self.args)
        self.assertEqual(report["reason"], "PLAN_DIGEST_CHANGED")
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_apply_reobserves_changed_frame(self):
        plan = m.run(self.args)
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan["planSha256"]
        self.fake.docs[CS]["Config"]["UnrequestedField"] = "changed"
        report = m.run(self.args)
        self.assertEqual(report["reason"], "PLAN_DIGEST_CHANGED")
        self.assertEqual(self.fake.writes(), [])

    def test_full_request_diff_only_tmpfs_and_no_shared_mutation(self):
        before = copy.deepcopy(self.requests[m.SOUTHBOUND])
        updated = m.derive_request(before)
        missing = object()  # Distinguish a missing field from an explicit null.

        def diff(a, b, path=()):
            if isinstance(a, dict) and isinstance(b, dict):
                return [delta for k in sorted(a.keys() | b.keys())
                        for delta in diff(a.get(k, missing), b.get(k, missing), path + (k,))]
            return [] if a == b else [(path, a, b)]

        self.assertEqual(diff(before, updated), [(("HostConfig", "Tmpfs", m.RUNTIME_DIRECTORY),
                         "rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m,noswap",
                         "rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m")])
        self.assertEqual(before, self.requests[m.SOUTHBOUND])

    def test_success_receipt_and_exact_operations(self):
        adapter = copy.deepcopy(self.fake.docs[CA])
        report = self.apply()
        self.assertEqual(report["status"], "SOUTHBOUND_RECREATED_STOPPED", report)
        self.assertTrue(report["oldRemoved"] and report["newCreated"])
        self.assertEqual(report["newCid"], NEW)
        self.assertTrue(report["noswapRemoved"])
        self.assertFalse(report["startAuthorized"])
        writes = self.fake.writes()
        self.assertEqual([(method, path) for method, path, _ in writes],
                         [("DELETE", f"/containers/{CS}"),
                          ("POST", f"/containers/create?name={m.SOUTHBOUND}-successor")])
        request = writes[1][2]
        self.assertEqual(request.pop("Labels"), {m.OWNER_LABEL: report["newTransaction"]})
        self.assertEqual(request, m.derive_request(self.requests[m.SOUTHBOUND]))
        self.assertEqual(self.fake.docs[CA], adapter)
        receipt = self.directory / self.args.output_name / "result.json"
        self.assertEqual(json.loads(receipt.read_text()), report)
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(receipt.parent.stat().st_mode), 0o700)
        self.assertEqual(report["containerStarts"], 0)
        self.assertEqual(report["deleteRequests"], 1)
        self.assertEqual(report["createRequests"], 1)
        self.assertEqual(m.run(self.args)["reason"], "OUTPUT_ALREADY_EXISTS")

    def test_delete_then_post_failure_partial_no_rollback(self):
        self.fake.fail_post = True
        report = self.apply()
        self.assertEqual(report["status"], "PARTIAL")
        self.assertTrue(report["oldRemoved"])
        self.assertIsNone(report["newCreated"])  # response loss => unknown, not false
        self.assertIsNone(report["newCid"])
        self.assertTrue(report["doNotRerunApply"])
        self.assertTrue(report["adapterUnchanged"])
        self.assertEqual(json.loads((self.directory / self.args.output_name / "result.json").read_text()), report)
        self.assertEqual([c[0] for c in self.fake.writes()], ["DELETE", "POST"])
        self.assertNotIn(CS, self.fake.docs)

    def test_new_readback_mismatch_partial_without_second_delete(self):
        self.fake.corrupt_new = True
        report = self.apply()
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["reason"], "CANDIDATE_FULL_HOSTCONFIG_CHANGED")
        self.assertTrue(report["newCreated"] and report["doNotRerunApply"])
        self.assertTrue(report["adapterUnchanged"])
        self.assertEqual(report["newCid"], NEW)
        self.assertIn(NEW, self.fake.docs)
        self.assertEqual([c[0] for c in self.fake.writes()], ["DELETE", "POST"])

    def test_adapter_change_after_create_is_partial(self):
        self.fake.change_adapter = True
        self.assertEqual(self.apply()["status"], "PARTIAL")
        self.assertEqual([c[0] for c in self.fake.writes()], ["DELETE", "POST"])

    def test_legacy_mac_present_matching_endpoint_preserved(self):
        self.fake.legacy = True
        for name, cid in ((m.ADAPTER, CA), (m.SOUTHBOUND, CS)):
            value = next(iter(m.ENDPOINTS[name].values()))[1]
            self.fake.docs[cid]["Config"]["MacAddress"] = value
            self.assertEqual(m.mac_profile(self.fake.docs[cid], name)["presence"], "PRESENT")
        self.assertEqual(self.apply()["status"], "SOUTHBOUND_RECREATED_STOPPED")
        self.assertEqual(self.fake.docs[NEW]["Config"]["MacAddress"],
                         next(iter(m.ENDPOINTS[m.SOUTHBOUND].values()))[1])

    def test_new_legacy_mac_presence_change_is_not_normalized(self):
        self.fake.legacy = True  # current is ABSENT, new would be PRESENT
        report = self.apply()
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["reason"], "NEW_LEGACY_MAC_PROFILE_CHANGED")
        self.assertEqual([c[0] for c in self.fake.writes()], ["DELETE", "POST"])

    def test_legacy_mac_null_empty_malformed_and_foreign_held(self):
        for value in (None, "", "malformed", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "02:42:ac:12:00:63"):
            with self.subTest(value=value):
                self.fake.docs[CS]["Config"]["MacAddress"] = value
                report = m.run(self.args)
                self.assertEqual(report["status"], "HELD")
                self.assertIn("CONFIG_LEGACY_MAC_PROFILE_UNPROVEN", report["reason"])
                self.assertEqual(self.fake.writes(), [])

    def test_hmac_bytes_never_read(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("no credential bytes")):
            self.assertEqual(m.run(self.args)["status"], "PLAN_READY")
        self.metadata.assert_called_with(m.HMAC_SOURCE, (636, 636, 0o600))

    def test_last_state_check_prevents_delete(self):
        actual = m.inspect_created
        count = 0

        def inspect(*args):
            nonlocal count
            count += 1
            if count == 6:  # plan (2), apply observe (2), last check adapter/southbound (2)
                self.fake.docs[CS]["State"].update(Status="running", Pid=99, Running=True)
            return actual(*args)

        with patch.object(m, "inspect_created", side_effect=inspect):
            report = self.apply()
        self.assertEqual(report["status"], "HELD")
        self.assertEqual(self.fake.writes(), [])


class BoundaryTests(unittest.TestCase):
    def test_engine_allowlist_denies_start_and_force_without_connection(self):
        with patch.object(m, "LocalEngine", side_effect=AssertionError("must not connect")):
            for method, path in (("POST", f"/containers/{CS}/start"),
                                 ("DELETE", f"/containers/{CS}?force=1"),
                                 ("DELETE", f"/containers/{CS}?v=1"),
                                 ("POST", f"/containers/create?name={m.ADAPTER}-successor")):
                with self.subTest(method=method, path=path), self.assertRaises(m.Held):
                    m.engine(method, path)

    def test_cli_has_no_operational_defaults(self):
        with self.assertRaises(SystemExit):
            m.arguments(["--plan"])

    def test_protected_hmac_check_uses_only_lstat(self):
        entry = argparse.Namespace(st_mode=stat.S_IFREG | 0o600, st_uid=636, st_gid=636, st_nlink=1)
        parent = argparse.Namespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)

        def metadata(path):
            return entry if path == m.HMAC_SOURCE else parent

        with patch.object(Path, "lstat", metadata), patch.object(Path, "is_symlink", return_value=False), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("credential read")), \
                patch.object(Path, "open", side_effect=AssertionError("credential open")):
            m.protected_file(m.HMAC_SOURCE, (636, 636, 0o600))
            entry.st_mode = stat.S_IFREG | 0o644
            with self.assertRaises(m.Held):
                m.protected_file(m.HMAC_SOURCE, (636, 636, 0o600))

    def test_output_root_rejects_writable_metadata(self):
        args = argparse.Namespace(output_root=Path("/synthetic/protected"), output_name="receipt")
        bad = argparse.Namespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)
        with patch.object(Path, "lstat", return_value=bad), patch.object(Path, "is_symlink", return_value=False):
            with self.assertRaisesRegex(m.Held, "OUTPUT_ROOT_NOT_PROTECTED"):
                m.validate_output(args)


if __name__ == "__main__":
    unittest.main()
