"""DEP-58L-01 through DEP-58L-13 exercise isolated Engine inspect and reviewed return."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_module_release as fixture
from tools.module_release import frame, frame_spec, operation, recovery, return_operation


class DeltaEngine(fixture.Engine):
    def create(self, name, request):
        cid = super().create(name, request)
        doc = self.docs[cid]
        for bind in request["HostConfig"].get("Binds") or []:
            source, target, mode = bind.split(":")
            doc["Mounts"].append(dict(Type="bind", Source=source, Destination=target,
                                      Mode=mode, RW=mode != "ro", Propagation="rprivate"))
        return cid


class ConfigDeltaTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        p = self.p = json.loads(fixture.PROFILE.read_bytes())
        p.update(inbox=str(self.root), journal=str(self.root), nsenter=str(self.root / "nsenter"),
                 dockerSocket=str(self.root / "sock"), bindRoots=["/fixture-input"],
                 envAllowlist=["FEATURE", "KEEP", "CREDENTIAL_FILE"], showValues=["FEATURE"])
        p["ci"].update(runId=15, runAttempt=1, artifactId=17)
        p["migration"] = {"mode": "none", "rollbackCompatible": True}
        for i, net in enumerate(p["networks"].values(), 1):
            net["ipv4"] = f"192.0.2.{i}"
        p["readiness"]["attempts"] = 2
        p["oldImage"] = "sha256:" + "a" * 64
        self.rt = DeltaEngine(p, fixture.artifact(p, self.root))
        self.old = self.rt.inspect(fixture.OLD)
        self.net = next(iter(p["networks"]))
        self.change = {"name": "FEATURE", "before": None, "after": "enabled"}
        self.source_bytes = b"synthetic fixture"
        self.bind = {"source": "/fixture-input/config", "target": "/fixture-config",
                     "mode": "ro", "sha256": hashlib.sha256(self.source_bytes).hexdigest()}
        self.delta = {"env": [self.change, {"name": "KEEP", "before": "fixture", "after": None},
                              {"name": "CREDENTIAL_FILE", "before": None, "after": self.bind["target"]}],
                      "aliases": {self.net: ["fixture-alias"]}, "binds": [self.bind]}

    def install_delta(self):
        self.p["configDelta"] = self.delta
        # The Engine and host are synthetic. Exercise the common path/policy grammar
        # and content pin while substituting the POSIX root-owned file reader.
        def fixture_file(entry, roots, *, profile):
            mount = frame_spec.bind_shape(entry, roots, profile)
            if entry["sha256"] != hashlib.sha256(self.source_bytes).hexdigest():
                raise frame_spec.SpecHeld("BIND_DIGEST_CHANGED")
            return mount, {}
        self.enterContext(patch.object(frame_spec, "bind_facts", side_effect=fixture_file))

    def planned(self):
        result = operation.plan(self.p, self.rt)
        self.assertEqual(result["status"], "PLANNED", result)
        return result

    def held(self, delta, code):
        self.p["configDelta"] = delta
        result = operation.plan(self.p, self.rt)
        self.assertEqual((result["status"], result["reason"]), ("HELD", code))
        self.assertNotIn("load", self.rt.events)

    def assert_restored(self):
        doc = self.rt.inspect(self.p["container"])
        self.assertEqual(doc["Id"], self.old["Id"])
        self.assertTrue(doc["State"]["Running"])
        self.assertEqual(doc["Config"], self.old["Config"])
        self.assertEqual(doc["HostConfig"], self.old["HostConfig"])
        self.assertEqual(doc["Mounts"], self.old["Mounts"])
        frame.check_live_networks(self.old, doc)
        if fixture.NEW in self.rt.docs:
            failed = self.rt.inspect(self.p["failedName"])
            self.assertEqual(failed["Id"], fixture.NEW)
            self.assertFalse(failed["State"]["Running"])
            self.assertFalse(failed["NetworkSettings"]["Networks"])

    def test_DEP_58L_01_closed_grammar(self):
        for delta, code in [
            ({}, "EMPTY_DELTA"), ({"aliases": {self.net: []}}, "EMPTY_DELTA"),
            ({"ports": []}, "INVALID_DELTA"), ({"removeBinds": []}, "INVALID_DELTA"),
            ({"env": [{**self.change, "name": "OTHER"}]}, "ENV_NAME_DENIED"),
            ({"env": [{**self.change, "before": "enabled"}]}, "EMPTY_DELTA"),
            ({"binds": [{**self.bind, "mode": "rw"}]}, "DELTA_RO_BIND_REQUIRED"),
            ({"binds": [{k: v for k, v in self.bind.items() if k != "sha256"}]}, "DELTA_RO_BIND_REQUIRED"),
            ({"aliases": {"absent": ["fixture"]}}, "INVALID_DELTA_ALIAS"),
            ({"aliases": {self.net: self.p["networks"][self.net]["aliases"]}}, "DELTA_ALIAS_EXISTS"),
        ]:
            with self.subTest(code=code):
                self.held(delta, code)

    def test_DEP_58L_02_compare_and_set_and_duplicates(self):
        self.held({"env": [{**self.change, "before": ""}]}, "DELTA_PRECONDITION_FAILED")
        self.held({"env": [self.change, self.change]}, "AMBIGUOUS_ENV")
        self.rt.docs[fixture.OLD]["Config"]["Env"] += ["KEEP=second"]
        self.held({"env": [self.change]}, "AMBIGUOUS_ENV")

    def test_DEP_58L_03_secret_value_and_file_custody(self):
        self.p["envAllowlist"].append("TOKEN")
        for row in ({"name": "TOKEN", "after": "fixture"},
                    {"name": "FEATURE", "after": "Bearer fixture"}):
            self.held({"env": [{**self.change, **row}]}, "SECRET_ENV_DENIED")
        self.held({"env": [self.delta["env"][-1]]}, "FILE_ENV_REQUIRES_RO_BIND")
        self.install_delta()
        self.held({**self.delta, "binds": [{**self.bind, "target": "/fixture/sub"}]}, "MOUNT_TARGET_OVERLAP")
        self.p["configDelta"] = self.delta
        stamp = self.planned()["planSha256"]
        self.source_bytes += b"!"
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["reason"], "BIND_DIGEST_CHANGED")
        self.assertNotIn("load", self.rt.events)

    def test_DEP_58L_04_same_image_needs_effective_delta(self):
        self.rt.docs[fixture.OLD]["Image"] = self.p["oldImage"] = self.p["ci"]["imageId"]
        self.assertEqual(operation.plan(self.p, self.rt)["reason"], "ALREADY_INSTALLED")
        self.install_delta()
        stamp = self.planned()["planSha256"]
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["status"], "READY")
        self.assertEqual(self.rt.events.count("create"), 1)

    def test_DEP_58L_05_plan_receipt_and_candidate_inspect(self):
        self.install_delta()
        planned = self.planned()
        body, stamp = planned["plan"], planned["planSha256"]
        self.assertEqual(stamp, operation.digest(body))
        self.assertEqual(body["configDeltaSha256"], hashlib.sha256(frame_spec.canonical(self.delta)).hexdigest())
        lines = body["approvalLines"]
        self.assertEqual(len(lines), 5)
        self.assertIn('"enabled"', lines[0])
        self.assertIn("KEEP", lines[1])
        self.assertNotIn("fixture", lines[1])
        self.assertNotIn(self.bind["target"], lines[2])
        self.assertIn(self.bind["sha256"], lines[3])
        ready = operation.apply(self.p, stamp, self.rt)
        self.assertEqual(ready["status"], "READY", ready)
        self.assertEqual(operation.read(self.root / stamp, "receipt.json")["configDeltaSha256"], body["configDeltaSha256"])
        candidate = self.rt.inspect(fixture.NEW)
        self.assertEqual([e for e in candidate["Config"]["Env"] if "=" in e],
                         ["FEATURE=enabled", "CREDENTIAL_FILE=/fixture-config"])
        self.assertEqual(candidate["Mounts"][:-1], self.old["Mounts"])
        self.assertEqual(candidate["Mounts"][-1], {"Source": self.bind["source"], "Destination": self.bind["target"],
                         "Type": "bind", "RW": False, "Propagation": "rprivate", "Mode": "ro"})
        self.assertIn("fixture-alias", candidate["NetworkSettings"]["Networks"][self.net]["Aliases"])
        candidate["Mounts"][-1]["RW"] = True
        with self.assertRaisesRegex(operation.Held, "CONFIGURATION_DELTA"):
            frame.check_body(self.old, candidate, self.p["ci"]["imageId"], self.p["ci"]["imageId"],
                             config_delta=self.delta)

    def test_DEP_58L_06_legacy_create_bytes(self):
        image = self.p["ci"]["imageId"]
        expected = copy.deepcopy(self.old["Config"])
        expected.pop("MacAddress")
        expected["Image"] = image
        expected["HostConfig"] = dict(self.old["HostConfig"], OomKillDisable=False)
        expected["NetworkingConfig"] = {"EndpointsConfig": {
            name: {"IPAMConfig": {"IPv4Address": ep["IPAddress"]}, "Aliases": ep["Aliases"]}
            for name, ep in self.old["NetworkSettings"]["Networks"].items()}}
        self.assertEqual(json.dumps(frame.request(self.old, image)).encode(), json.dumps(expected).encode())

    def interrupted_return(self, stop_before):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(operation, stop_before, side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assert_restored()

    def test_DEP_58L_07_interruption_before_create(self):
        self.interrupted_return("retained")
        self.assertNotIn("create", self.rt.events)

    def test_DEP_58L_08_interruption_after_create(self):
        self.interrupted_return("start_candidate")
        self.assertNotIn("gate:2", self.rt.events)

    def test_DEP_58L_09_interruption_after_start(self):
        self.interrupted_return("finish_apply")
        self.assertNotIn("signal:2", self.rt.events)

    def test_DEP_58L_10_readiness_failure(self):
        self.install_delta()
        self.rt.fault = "readiness"
        result = operation.apply(self.p, self.planned()["planSha256"], self.rt)
        self.assertEqual((result["reason"], result["rollback"]), ("READINESS_NOT_UP", "ROLLED_BACK"))
        self.assert_restored()

    def test_DEP_58L_11_ready_return_checks_receipt_and_restores_once(self):
        import mandate
        self.install_delta()
        stamp = self.planned()["planSha256"]
        req = dict(commit="c"*40, run="1", attempt="1", operation="module-release",
                   module=self.p["module"], phase="rollback", digest=stamp)
        mandate.validate(req, {"commit": req["commit"], "modules": {req["module"]: self.p}})
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["status"], "READY")
        receipt = self.root / stamp / "receipt.json"
        original = receipt.read_bytes()
        for key in ("planSha256", "predecessorCid", "successorFrameSha256", "configDeltaSha256"):
            receipt.write_text(json.dumps({**json.loads(original), key: "0" * 64}))
            self.assertEqual(return_operation.run(self.p, stamp, self.rt)["status"], "HELD", key)
            self.assertNotIn("stop:2", self.rt.events)
        receipt.write_bytes(original)
        self.assertEqual(return_operation.run(self.p, stamp, self.rt)["status"], "ROLLED_BACK")
        self.assert_restored()
        self.assertEqual(return_operation.run(self.p, stamp, self.rt)["status"], "HELD")

    def test_DEP_58L_12_replace_empty_string_and_unset_image_default(self):
        self.install_delta()
        self.change.update(before="", after="replacement")
        self.rt.docs[fixture.OLD]["Config"]["Env"].append("FEATURE=")
        old = self.rt.inspect(fixture.OLD)
        with patch.object(self.rt, "image_defaults", return_value={"Env": ["KEEP=image-default"]}):
            stamp = self.planned()["planSha256"]
            outcome = operation.apply(self.p, stamp, self.rt)
            self.assertEqual(outcome["status"], "READY", outcome)
            new = self.rt.inspect(fixture.NEW)
            self.assertIn("FEATURE=replacement", new["Config"]["Env"])
            self.assertFalse(any(item.startswith("KEEP=") for item in new["Config"]["Env"]))
            new["Config"]["Env"] = ["KEEP=image-default" if item == "KEEP" else item for item in new["Config"]["Env"]]
            with self.assertRaisesRegex(operation.Held, "CONFIGURATION_DELTA"):
                frame.check_body(old, new, new["Image"], new["Image"],
                                 image_defaults=self.rt.image_defaults(new["Image"]), config_delta=self.delta)

    def test_DEP_58L_13_recovery_receipt_bound_to_same_delta(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(operation, "finish_apply", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        result = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual(result["status"], "READY", result)
        self.assertEqual(result["configDeltaSha256"], operation.digest(self.delta))
        self.assertEqual(self.rt.events.count("create"), 1)
        self.assertEqual(return_operation.run(self.p, stamp, self.rt)["status"], "ROLLED_BACK")
        self.assert_restored()
