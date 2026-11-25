"""Isolated regressions for the reviewed module-release configuration delta."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_module_release as fixture
from tools.module_release import frame, frame_spec, operation, recovery, return_operation


class DeltaEngine(fixture.Engine):
    def start(self, cid):
        super().start(cid)
        count = self.events.count("gate:" + cid[0])
        self.docs[cid]["State"].update(Pid=55 + count, StartedAt=f"start-{count}")

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

    def test_DEP_58LB_01_dsn_credentials_never_reach_show_values(self):
        self.p["envAllowlist"].append("DATABASE_URL")
        self.p["showValues"].append("DATABASE_URL")
        for value in ("host=fixture password=synthetic", "jdbc:fixture://db/app?PaSsWoRd=synthetic",
                      "Server=db;UID=fixture;PWD = synthetic", "postgresql://user:synthetic@db/app"):
            for side in ("before", "after"):
                with self.subTest(value=value, side=side):
                    row = {"name": "DATABASE_URL", "before": None, "after": None, side: value}
                    self.p["configDelta"] = {"env": [row]}
                    env = list(self.old["Config"]["Env"])
                    if side == "before":
                        env.append("DATABASE_URL=" + value)
                    with patch.dict(self.rt.docs[fixture.OLD]["Config"], Env=env):
                        result = operation.plan(self.p, self.rt)
                    self.assertEqual(result["status"], "HELD")
                    self.assertEqual(result["reason"], "SECRET_ENV_DENIED")
                    self.assertNotIn("synthetic", json.dumps(result))

    def test_DEP_58LB_02_return_after_engine_start_before_journal(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        root = self.root / stamp
        start = self.rt.start

        def interrupted(cid):
            start(cid)
            raise KeyboardInterrupt

        with patch.object(self.rt, "start", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        self.assertFalse((root / "start-generation.json").exists())
        self.assertEqual(operation.read(root, "start-intent.json"), {"cid": fixture.NEW})
        for changes in ({"RestartCount": 1}, {"Id": "3" * 64}):
            with self.subTest(changes=changes), patch.dict(self.rt.docs[fixture.NEW], changes):
                self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
                self.assertFalse((root / "return-intent.json").exists())
                self.assertNotIn("stop:2", self.rt.events)
        with patch.object(return_operation, "restore", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt, recover=True)
        with patch.dict(self.rt.docs[fixture.NEW]["State"], StartedAt="different-generation"):
            self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
            self.assertNotIn("stop:2", self.rt.events)
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(self.rt.events.count("gate:2"), 1)
        self.assertNotIn("signal:2", self.rt.events)
        self.assert_restored()

    def test_DEP_58LB_03_resumed_start_checks_bind_content(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(operation, "start_candidate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        self.assertTrue(operation.never_started(self.rt.inspect(fixture.NEW)))
        approved = recovery.proposal(self.p, self.rt)
        with patch.object(frame_spec, "bind_facts", side_effect=OSError), self.assertRaisesRegex(
                operation.Held, "BIND_CUSTODY_UNPROVEN"):
            recovery.resume(self.p, self.rt, approved)
        self.source_bytes += b"changed after create"
        with self.assertRaisesRegex(operation.Held, "BIND_DIGEST_CHANGED"):
            recovery.resume(self.p, self.rt, approved)
        self.assertNotIn("gate:2", self.rt.events)
        self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "ROLLED_BACK")
        self.assert_restored()

    def test_DEP_58LB_04_review_displays_authorized_lines_in_both_plans(self):
        import mandate

        self.p["configDelta"] = {"env": self.delta["env"][:2]}
        body = self.planned()["plan"]
        call, req = fixture.ReleaseTest.governed_dispatch(self)
        render = runpy.run_path(str(fixture.ROOT / ".github/scripts/module-release.py"))["module_review"]
        for run in ("1", "2"):
            req.update(run=run, phase="plan")
            req["digest"] = mandate.intent(req)
            public = call(0)
            summary, notice = io.StringIO(), io.StringIO()
            with redirect_stdout(notice):
                render(summary, self.p["module"], "plan", public, "apply", None)
            self.assertIn("Cosa approvi con il job apply", summary.getvalue())
            for line in body["approvalLines"]:
                self.assertIn("    " + line + "\n", summary.getvalue())
            for output in (summary.getvalue(), notice.getvalue(), json.dumps(public)):
                self.assertNotIn("fixture", output)
                self.assertNotIn("configDelta", output)
            if run == "1":
                with patch.object(operation, "finish_apply", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                    operation.apply(self.p, public["digest"], self.rt)
            else:
                self.assertEqual(public["sourcePlan"], operation.digest(body))

    def test_DEP_58LB_05_clean_a2_install_plans_a_delta(self):
        from test_privileged_executor_install import Bootstrap

        bootstrap = Bootstrap()
        self.addCleanup(bootstrap.doCleanups)
        bootstrap.setUp()
        self.p.update(configDelta={"env": [self.change]}, journal=str(bootstrap.path.parent / "journal"))
        config = json.loads(bootstrap.path.read_bytes())
        config["modules"][self.p["module"]] = self.p
        bootstrap.path.write_text(json.dumps(config))
        bootstrap.install_fixture()
        probe = """
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'lib'))
from module_release.operation import plan
profile = json.loads((root / 'profile.json').read_bytes())['modules']['onboarding']
old = json.load(sys.stdin)
class Engine:
    def inspect(self, name, missing=False):
        return old if name in (profile['container'], old['Id']) else None
    def process(self, doc, gated):
        return not gated
    def probe(self, doc):
        return 200, b'{"status":"UP"}'
print(json.dumps(plan(profile, Engine())))
"""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(bootstrap.inst.ROOT)],
                                input=json.dumps(self.old), capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), self.planned())

    def test_DEP_58LD_01_jdbc_store_password_before_and_after(self):
        self.p.update(envAllowlist=["DATABASE_URL"], showValues=["DATABASE_URL"])
        value = "jdbc:sqlserver://fixture;trustStorePassword=synthetic"
        for side in ("before", "after"):
            with self.subTest(side=side):
                row = {"name": "DATABASE_URL", "before": None, "after": None, side: value}
                env = ["DATABASE_URL=" + value] if side == "before" else []
                self.p["configDelta"] = {"env": [row]}
                with patch.dict(self.rt.docs[fixture.OLD]["Config"], Env=env):
                    result = operation.plan(self.p, self.rt)
                self.assertEqual((result["status"], result.get("reason")), ("HELD", "SECRET_ENV_DENIED"))
                self.assertNotIn("synthetic", json.dumps(result))

    def create_gap(self, created):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        create = self.rt.create

        def interrupted(*args):
            if created:
                create(*args)
            raise KeyboardInterrupt

        with patch.object(self.rt, "create", interrupted), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        self.assertTrue((self.root / stamp / "create-intent.json").is_file())
        self.assertFalse((self.root / stamp / "created.json").exists())
        return stamp

    def test_DEP_58LD_02_before_engine_create(self):
        stamp = self.create_gap(False)
        # A second loss after journaling the empty return must also be resumable.
        with patch.object(return_operation, "restore", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt, recover=True)
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertNotIn("create", self.rt.events)
        self.assert_restored()

    def test_DEP_58LD_02_after_engine_create(self):
        stamp = self.create_gap(True)
        root = self.root / stamp
        cfg = self.rt.docs[fixture.NEW]["Config"]
        for change in ({"Labels": self.old["Config"]["Labels"]},
                       {"Labels": {**cfg["Labels"], "ouf.release.plan": "f" * 64}},
                       {"Env": ["FEATURE=foreign"]}):
            with self.subTest(change=change), patch.dict(cfg, change):
                self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
                self.assertFalse((root / "created.json").exists())
                self.assertFalse((root / "return-intent.json").exists())
                self.assertEqual(self.rt.inspect(self.p["container"])["Id"], fixture.NEW)
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(cfg["Labels"].get("ouf.release.plan"), stamp)
        self.assertEqual(self.rt.events.count("create"), 1)
        self.assertNotIn("gate:2", self.rt.events)
        self.assert_restored()

    def test_DEP_58LD_02_lost_create_response(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        create = self.rt.create

        def lost(*args):
            create(*args)
            raise OSError

        with patch.object(self.rt, "create", lost):
            result = operation.apply(self.p, stamp, self.rt)
        self.assertEqual((result["status"], result["rollback"]), ("HELD", "ROLLED_BACK"), result)
        self.assertEqual(self.rt.events.count("create"), 1)
        self.assert_restored()

    def restore_start_gap(self, started):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["status"], "READY")
        self.rt.docs[fixture.OLD]["State"]["FinishedAt"] = "2026-01-01T00:00:00.123456789Z"
        start = self.rt.start

        def interrupted(cid):
            self.assertEqual(cid, fixture.OLD)
            if started:
                start(cid)
            raise KeyboardInterrupt

        with patch.object(self.rt, "start", interrupted), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt)
        self.assertTrue((self.root / stamp / "restore-start.json").is_file())
        self.assertFalse((self.root / stamp / "restore-generation.json").exists())
        return stamp

    def resumed_restore(self, stamp):
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(self.rt.events.count("gate:1"), 1)
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assert_restored()

    def test_DEP_58LD_03_before_restore_start(self):
        self.resumed_restore(self.restore_start_gap(False))

    def test_DEP_58LD_03_after_restore_start(self):
        self.resumed_restore(self.restore_start_gap(True))

    def test_DEP_58LD_03_foreign_restore_generation(self):
        stamp = self.restore_start_gap(True)
        self.rt.docs[fixture.OLD]["RestartCount"] += 1
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result.get("reason"), "RESTORE_GENERATION_UNCONFIRMED")
        self.assertNotIn("signal:1", self.rt.events)

    def test_DEP_58LD_04_ingestion_same_image_probes_original_and_reduced_argv(self):
        from test_module_release_java import fixture as java_fixture

        with java_fixture("ingestion") as (p, engine, _, _):
            p.update(configDelta={"env": [self.change]}, envAllowlist=["FEATURE"])
            engine.docs[fixture.OLD]["Image"] = p["oldImage"] = p["ci"]["imageId"]
            rt = operation.Docker(p)
            # Use the real procfs probe with argv from the simulated running process.
            rt.inspect, rt.probe = engine.inspect, engine.probe
            cmd = p["gate"]["command"]
            reduced = [arg for arg in cmd if arg not in p["candidate"]["removeArgs"]]
            self.assertNotEqual(cmd, reduced)
            read_bytes = Path.read_bytes
            argv = cmd

            def read(path):
                if path.name == "cmdline":
                    return b"\0".join(arg.encode() for arg in argv) + b"\0"
                return read_bytes(path)

            with patch.object(Path, "read_bytes", read), patch.object(fixture.os, "readlink", return_value="/bin/java"):
                plan = operation.plan(p, rt)
                self.assertEqual(plan["status"], "PLANNED", plan)
                stage = operation.apply(p, plan["planSha256"], engine)
                self.assertEqual(stage["status"], "GATED", stage)
                doc = rt.inspect(fixture.NEW)
                self.assertIsNone(operation.ready_status(rt, doc, p["readiness"]))
                argv = reduced
                self.assertEqual(operation.ready_status(rt, doc, p["readiness"]), 200)

    def test_DEP_58LD_05_dedicated_return_before_migration_checks_baseline(self):
        from test_module_release_mcp import Release

        mcp = Release()
        self.addCleanup(mcp.doCleanups)
        mcp.setUp()
        mcp.dedicated()
        p, rt = mcp.p, mcp.rt
        p.update(configDelta={"env": [self.change]}, envAllowlist=["FEATURE"])
        stamp = operation.plan(p, rt)["planSha256"]
        with patch.object(operation, "start_candidate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(p, stamp, rt)
        root = Path(p["journal"]) / stamp
        self.assertEqual(operation.read(root, "created.json"), {"cid": fixture.NEW})
        mcp.db["schema"].append("drift")
        self.assertEqual(return_operation.run(p, stamp, rt, recover=True).get("reason"), "DATABASE_CHANGED")
        self.assertEqual(rt.inspect(p["container"])["Id"], fixture.NEW)
        mcp.db["schema"].pop()
        operation.record(root, "migration-intent.json", {"cid": fixture.NEW})
        self.assertEqual(return_operation.run(p, stamp, rt, recover=True)["status"], "HELD")
        (root / "migration-intent.json").unlink()
        result = return_operation.run(p, stamp, rt, recover=True)
        self.assertEqual((result["status"], result.get("restoredCid")), ("ROLLED_BACK", fixture.OLD), result)
        self.assertNotIn("migrate", rt.events)
        self.assertNotIn("signal:2", rt.events)

    def test_DEP_58LE_01_http_authorization_before_and_after(self):
        from tools.module_release.config_delta import approval_lines

        self.p.update(envAllowlist=["AUTHORIZATION", "HEADER"], showValues=["AUTHORIZATION", "HEADER"])
        for name in self.p["showValues"]:
            for side in ("before", "after"):
                with self.subTest(name=name, side=side):
                    value = "bAsIc Zml4dHVyZTpmaXh0dXJl"
                    row = {"name": name, "before": None, "after": None, side: value}
                    env = [f"{name}={value}"] if side == "before" else []
                    with patch.dict(self.rt.docs[fixture.OLD]["Config"], Env=env):
                        self.p["configDelta"] = {"env": [row]}
                        result = operation.plan(self.p, self.rt)
                    self.assertEqual(result.get("reason"), "SECRET_ENV_DENIED")
                    self.assertEqual(result["status"], "HELD")
                    self.assertNotIn(value, json.dumps(result))
                    with self.assertRaisesRegex(operation.Held, "SECRET_ENV_DENIED"):
                        approval_lines({"env": [row]}, [name])

    def test_DEP_58LE_02_exited_recorded_candidate(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(operation, "finish_apply", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        self.rt.stop(fixture.NEW)
        doc = self.rt.docs[fixture.NEW]
        for ep in doc["NetworkSettings"]["Networks"].values():
            ep.update(NetworkID="", IPAddress="", EndpointID="")
        for field, change in ((doc["State"], {"StartedAt": "foreign"}), (doc, {"RestartCount": 1}),
                              (doc["Config"], {"Env": ["FOREIGN=fixture"]})):
            with self.subTest(change=change), patch.dict(field, change):
                self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
                self.assertFalse((self.root / stamp / "return-intent.json").exists())
        self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "ROLLED_BACK")
        self.assertEqual(self.rt.events.count("stop:2"), 1)
        self.assert_restored()

    def ready_delta(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["status"], "READY")
        return stamp

    def signal_gap(self, delivered):
        stamp = self.ready_delta()
        signal = self.rt.signal

        def interrupted(cid):
            self.assertEqual(cid, fixture.OLD)
            if delivered:
                signal(cid)
            raise KeyboardInterrupt

        with patch.object(self.rt, "signal", interrupted), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt)
        self.assertTrue((self.root / stamp / "restore-signal.json").is_file())
        return stamp

    def test_DEP_58LE_03_before_restore_signal(self):
        stamp = self.signal_gap(False)
        pid = self.rt.inspect(fixture.OLD)["State"]["Pid"]

        def only_new_generation(cid):
            self.assertNotEqual(self.rt.inspect(cid)["State"]["Pid"], pid)
            signal(cid)

        signal = self.rt.signal
        stop = self.rt.stop
        def interrupted_stop(cid):
            stop(cid)
            raise KeyboardInterrupt

        def resume():
            return return_operation.run(self.p, stamp, self.rt, recover=True)

        with patch.object(self.rt, "stop", interrupted_stop), self.assertRaises(KeyboardInterrupt):
            resume()
        rename = Path.rename
        def interrupted_archive(path, target):
            rename(path, target)
            raise KeyboardInterrupt

        # Resume after each individual archived claim, including the final signal.
        for name in ("restore-start.json", "restore-generation.json", "restore-signal.json"):
            with self.subTest(claim=name), patch.object(Path, "rename", interrupted_archive), self.assertRaises(KeyboardInterrupt):
                resume()
            self.assertFalse((self.root / stamp / name).exists())
        with patch.object(self.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            resume()
        with patch.object(self.rt, "signal", only_new_generation):
            result = resume()
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assert_restored()

    def test_DEP_58LE_03_after_restore_signal(self):
        stamp = self.signal_gap(True)
        self.resumed_restore(stamp)

    def test_DEP_58LE_03_restore_signal_io_error(self):
        stamp = self.ready_delta()
        with patch.object(self.rt, "signal", side_effect=OSError):
            result = return_operation.run(self.p, stamp, self.rt)
        self.assertEqual(result.get("reason"), "PREDECESSOR_READINESS_NOT_UP")
        self.assertFalse((self.root / stamp / "return-receipt.json").exists())
        self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "ROLLED_BACK")
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assert_restored()

    def test_DEP_58LE_03_delayed_delivery_during_readiness(self):
        stamp = self.signal_gap(False)
        # Docker accepted the original signal; its handler runs during the wait.
        with patch.object(self.rt, "pause", side_effect=lambda: self.rt.gates.discard(fixture.OLD)), \
             patch.object(self.rt, "signal", side_effect=AssertionError("second signal")):
            result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(self.rt.events.count("gate:1"), 1)
        self.assert_restored()

    def test_DEP_58LE_03_interrupted_automatic_rollback(self):
        self.install_delta()
        self.rt.fault = "readiness"
        stamp = self.planned()["planSha256"]
        signal = self.rt.signal

        def interrupted(cid):
            if cid == fixture.OLD:
                raise KeyboardInterrupt
            signal(cid)

        with patch.object(self.rt, "signal", interrupted), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        def resume():
            return recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))

        with patch.object(operation, "unlock_module", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            resume()
        self.assertEqual(resume()["rollback"], "ROLLED_BACK")
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assert_restored()

    def test_DEP_58LE_04_ready_lock_before_return_intent(self):
        stamp = self.ready_delta()
        record = return_operation.record

        def interrupted(root, name, data):
            if name == "return-intent.json":
                raise KeyboardInterrupt
            record(root, name, data)

        with patch.object(return_operation, "record", interrupted), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt)
        self.assertNotIn("stop:2", self.rt.events)
        lock = self.root / (self.p["module"] + ".lock") / "owner.json"
        owner = lock.read_bytes()
        lock.write_text(json.dumps({"planSha256": "0"*64}))
        self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True).get("reason"),
                         "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        self.assertNotIn("stop:2", self.rt.events)
        lock.write_bytes(owner)
        self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "ROLLED_BACK")
        self.assert_restored()

    def test_DEP_58LE_04_terminal_receipt_before_unlock(self):
        stamp = self.ready_delta()
        lock = self.root / (self.p["module"] + ".lock")
        with patch.object(return_operation, "unlock_module", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(self.p, stamp, self.rt)
        receipt = self.root / stamp / "return-receipt.json"
        original = receipt.read_bytes()
        for key, value in (("status", "HELD"), ("restoredCid", fixture.NEW), ("planSha256", "0"*64)):
            with self.subTest(key=key):
                receipt.write_text(json.dumps({**json.loads(original), key: value}))
                self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
                self.assertTrue(lock.is_dir())
        receipt.write_bytes(original)
        with patch.dict(self.rt.docs[fixture.OLD]["State"], StartedAt="foreign"):
            self.assertEqual(return_operation.run(self.p, stamp, self.rt, recover=True)["status"], "HELD")
            self.assertTrue(lock.is_dir())
        result = return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(result, json.loads(original))
        self.assertEqual(receipt.read_bytes(), original)
        self.assertFalse(lock.exists())
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assert_restored()

    def test_DEP_58LE_05_dedicated_without_delta_requires_release_receipt(self):
        from test_module_release_mcp import Release

        mcp = Release()
        self.addCleanup(mcp.doCleanups)
        mcp.setUp()
        mcp.dedicated()
        stamp = operation.plan(mcp.p, mcp.rt)["planSha256"]
        with patch.object(operation, "start_candidate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(mcp.p, stamp, mcp.rt)
        events = list(mcp.rt.events)
        result = return_operation.run(mcp.p, stamp, mcp.rt, recover=True)
        self.assertEqual(result.get("reason"), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        self.assertEqual(events, mcp.rt.events)
        self.assertFalse((Path(mcp.p["journal"]) / stamp / "return-intent.json").exists())

    def test_DEP_58LE_05_legacy_restore_start_claim(self):
        from test_module_release_mcp import Release

        mcp = Release()
        self.addCleanup(mcp.doCleanups)
        mcp.setUp()
        stamp = operation.plan(mcp.p, mcp.rt)["planSha256"]
        self.assertEqual(operation.apply(mcp.p, stamp, mcp.rt)["status"], "READY")
        with patch.object(mcp.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(mcp.p, stamp, mcp.rt)
        self.assertEqual(operation.read(Path(mcp.p["journal"]) / stamp, "restore-start.json"), {"cid": fixture.OLD})

    def test_DEP_58LE_05_none_without_delta_preserves_rollback_scope(self):
        import mandate

        stamp = self.planned()["planSha256"]
        req = dict(commit="c"*40, run="1", attempt="1", operation="module-release",
                   module=self.p["module"], phase="rollback", digest=stamp)
        with self.assertRaisesRegex(mandate.Held, "MODULE_REQUEST_SCOPE"):
            mandate.validate(req, {"commit": req["commit"], "modules": {req["module"]: self.p}})
        with self.assertRaisesRegex(operation.Held, "INVALID_RETURN_PLAN"):
            return_operation.run(self.p, stamp, self.rt, recover=True)
