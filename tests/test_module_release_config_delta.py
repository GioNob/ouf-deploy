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

    def test_DEP_58L_10_readiness_failure(self):
        self.install_delta()
        self.rt.fault = "readiness"
        result = operation.apply(self.p, self.planned()["planSha256"], self.rt)
        self.assertEqual((result["reason"], result["rollback"]), ("READINESS_NOT_UP", "ROLLED_BACK"))
        self.assert_restored()

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

    def test_DEP_58LF_01_delta_preserves_rollback_scope(self):
        import mandate

        self.install_delta()
        stamp = self.planned()["planSha256"]
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["status"], "READY")
        req = dict(commit="c"*40, run="1", attempt="1", operation="module-release",
                   module=self.p["module"], phase="rollback", digest=stamp)
        with self.assertRaisesRegex(mandate.Held, "MODULE_REQUEST_SCOPE"):
            mandate.validate(req, {"commit": req["commit"], "modules": {req["module"]: self.p}})
        with self.assertRaisesRegex(operation.Held, "INVALID_RETURN_PLAN"):
            return_operation.run(self.p, stamp, self.rt, recover=True)
        self.assertEqual(self.rt.inspect(self.p["container"])["Id"], fixture.NEW)

    def test_DEP_58LF_02_mysql_pwd_denied_before_approval(self):
        from tools.module_release.config_delta import approval_lines

        self.p.update(envAllowlist=["MYSQL_PWD"], showValues=["MYSQL_PWD"])
        value = "synthetic-credential"
        for side in ("before", "after"):
            with self.subTest(side=side):
                change = {"name": "MYSQL_PWD", "before": None, "after": None, side: value}
                delta = {"env": [change]}
                env = ["MYSQL_PWD=" + value] if side == "before" else []
                with patch.dict(self.rt.docs[fixture.OLD]["Config"], Env=env):
                    self.p["configDelta"] = delta
                    result = operation.plan(self.p, self.rt)
                self.assertEqual((result["status"], result["reason"]), ("HELD", "SECRET_ENV_DENIED"))
                self.assertNotIn(value, json.dumps(result))
                self.assertNotIn("plan", result)
                with self.assertRaisesRegex(operation.Held, "^SECRET_ENV_DENIED$"):
                    approval_lines(delta, self.p["showValues"])

    def check_terminal_receipt(self, status):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(operation, "unlock_module", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        lock = self.root / (self.p["module"] + ".lock")
        path = self.root / stamp / "receipt.json"
        original = path.read_bytes()
        receipt = json.loads(original)
        self.assertEqual(receipt["status"], status)
        for changed in ("0" * 64, None):
            with self.subTest(changed=changed):
                altered = dict(receipt, configDeltaSha256=changed)
                if changed is None:
                    del altered["configDeltaSha256"]
                path.write_bytes(json.dumps(altered).encode())
                approved = recovery.proposal(self.p, self.rt)
                with self.assertRaisesRegex(operation.Held, "^RECOVERY_RECEIPT_CHANGED$"):
                    recovery.resume(self.p, self.rt, approved)
                self.assertTrue((lock / "owner.json").is_file())
                self.assertEqual(json.loads(path.read_bytes()), altered)
        path.write_bytes(original)
        self.assertEqual(recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt)), receipt)
        self.assertFalse(lock.exists())
        self.assertEqual(path.read_bytes(), original)

    def test_DEP_58LF_03_ready_receipt_delta_bound_before_unlock(self):
        self.check_terminal_receipt("READY")

    def test_DEP_58LF_04_automatic_rollback_receipt_delta_bound_before_unlock(self):
        self.rt.fault = "readiness"
        self.check_terminal_receipt("HELD")

    def test_DEP_58LF_09_existing_database_return_binds_delta(self):
        from test_module_release_mcp import Release

        mcp = Release()
        self.addCleanup(mcp.doCleanups)
        mcp.setUp()
        p, rt = mcp.p, mcp.rt
        p.update(configDelta={"env": [self.change]}, envAllowlist=["FEATURE"])
        stamp = operation.plan(p, rt)["planSha256"]
        self.assertEqual(operation.apply(p, stamp, rt)["status"], "READY")
        path = mcp.root / stamp / "receipt.json"
        original = path.read_bytes()
        path.write_bytes(json.dumps(dict(json.loads(original), configDeltaSha256="0"*64)).encode())
        self.assertEqual(return_operation.run(p, stamp, rt)["reason"], "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
        self.assertNotIn("stop:2", rt.events)
        path.write_bytes(original)
        result = return_operation.run(p, stamp, rt)
        self.assertEqual((result["status"], result["restoredCid"]), ("ROLLED_BACK", fixture.OLD))
        self.assertEqual(result["configDeltaSha256"], json.loads(original)["configDeltaSha256"])

    def test_DEP_58LG_01_credentials_denied_before_approval(self):
        from tools.module_release.config_delta import approval_lines

        secret = "synthetic-redis-or-spring"
        for name, value in (("REDISCLI_AUTH", secret),
                            ("SPRING_APPLICATION_JSON", json.dumps({"spring": {"datasource": {"password": secret}}})),
                            ("SPRING_APPLICATION_JSON", r'{"spring.datasource.pass\u0077ord":"synthetic-redis-or-spring"}')):
            self.p.update(envAllowlist=[name], showValues=[name])
            for side in ("before", "after"):
                with self.subTest(name=name, side=side, value=value):
                    row = {"name": name, "before": None, "after": None, side: value}
                    self.p["configDelta"] = {"env": [row]}
                    env = [f"{name}={value}"] if side == "before" else []
                    with patch.dict(self.rt.docs[fixture.OLD]["Config"], Env=env):
                        result = operation.plan(self.p, self.rt)
                    self.assertEqual((result["status"], result.get("reason")), ("HELD", "SECRET_ENV_DENIED"))
                    self.assertNotIn(secret, json.dumps(result))
                    with self.assertRaisesRegex(operation.Held, "^SECRET_ENV_DENIED$"):
                        approval_lines(self.p["configDelta"], [name])
        value = '{"spring":{"application":{"name":"fixture"}}}'
        self.p["configDelta"] = {"env": [{"name": "SPRING_APPLICATION_JSON", "before": None, "after": value}]}
        self.assertIn(json.dumps(value), self.planned()["plan"]["approvalLines"][0])

    def interrupt_create(self, *, applied):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        create = self.rt.create

        def interrupt(*args):
            if applied:
                create(*args)
            raise KeyboardInterrupt

        with patch.object(self.rt, "create", interrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(self.p, stamp, self.rt)
        root = self.root / stamp
        self.assertTrue((root / "create-intent.json").is_file())
        self.assertFalse((root / "created.json").exists())
        return root

    def check_create_recovery(self, *, applied):
        root = self.interrupt_create(applied=applied)
        result = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual((result["rollback"], result["restoredCid"]), ("ROLLED_BACK", fixture.OLD))
        self.assertEqual(result.get("successorCid"), fixture.NEW if applied else None)
        self.assertEqual(operation.read(root, "receipt.json"), result)
        self.assertEqual(self.rt.events.count("create"), int(applied))
        self.assertNotIn("gate:2", self.rt.events)
        self.assertFalse((self.root / (self.p["module"] + ".lock")).exists())
        self.assert_restored()

    def test_DEP_58LG_02_interrupted_before_create(self):
        self.check_create_recovery(applied=False)

    def test_DEP_58LG_03_interrupted_after_create(self):
        self.check_create_recovery(applied=True)

    def test_DEP_58LG_04_native_checkout_does_not_require_full_history(self):
        path = fixture.ROOT / ".github/workflows/privileged-executor-native.yml"
        self.assertNotRegex(path.read_text(encoding="utf-8"), r"(?m)^\s*fetch-depth:\s*0\s*$")

    def test_DEP_58LG_05_unverified_candidate_stays_in_place(self):
        root = self.interrupt_create(applied=True)
        labels = self.rt.docs[fixture.NEW]["Config"]["Labels"]
        with patch.dict(labels, {operation.OWNER_LABEL: "0" * 64}):
            with self.assertRaisesRegex(operation.Held, "^CREATE_OWNERSHIP_UNCONFIRMED$"):
                recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertFalse((root / "created.json").exists())
        self.assertEqual(self.rt.inspect(self.p["container"])["State"]["Status"], "created")
        result = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual(result["rollback"], "ROLLED_BACK")
        self.assert_restored()

    def test_DEP_58LG_06_recovery_interrupted_after_restoring_without_candidate(self):
        root = self.interrupt_create(applied=False)
        with patch.object(operation, "record_result", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assert_restored()
        result = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual(operation.read(root, "receipt.json"), result)
        self.assertEqual(result["rollback"], "ROLLED_BACK")
        self.assertNotIn("create", self.rt.events)
        self.assertEqual(self.rt.events.count("gate:1"), 1)
        self.assertEqual(self.rt.events.count("signal:1"), 1)
