"""DEP-58LF: execute both releases against the same MCP archive, profile and Engine."""
import copy
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

import test_module_release as fixture
import test_module_release_mcp as mcp
from test_module_release_config_delta import executor_with_busy_lock
import mandate
from tools.module_release import frame, operation, recovery, return_operation


# Tip of origin/release/d091-t2-deploy at DN-L1-5. Keep the oracle fixed after merge.
REFERENCE = "c8851aba5d6fabb93f84829e39e461bc57094b3e"


class Trace:
    """Capture calls at the Docker adapter boundary, before the Engine changes state."""
    def __init__(self, engine, docker):
        self.engine = engine
        self.docker = docker
        self.calls = []
        self.creates = []

    def create(self, name, body):
        # Exercise this version's Docker.create and Docker.api up to the socket boundary.
        response = Mock(status=201)
        response.read.return_value = json.dumps({"Id": fixture.NEW}).encode()
        with patch.object(HTTPConnection, "request") as send, patch.object(HTTPConnection, "getresponse",
                                                                         return_value=response):
            cid = self.docker.create(name, body)
        method, path, payload, headers = send.call_args.args
        self.creates.append(payload)
        self.calls.append(json.dumps([method, path, headers, payload.hex()]).encode())
        self.engine.create(name, json.loads(payload))
        return cid

    def __getattr__(self, name):
        method = getattr(self.engine, name)
        if not callable(method):
            return method

        def call(*args, **kwargs):
            if name == "load":
                archive, package = args
                offset = archive.tell()
                recorded = [archive.read().hex(), package]
                archive.seek(offset)
            else:
                recorded = args
            self.calls.append(json.dumps([name, recorded, kwargs]).encode())
            return method(*args, **kwargs)
        return call


class NoDeltaParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.enterClassContext(tempfile.TemporaryDirectory())
        try:
            archive = subprocess.check_output(["git", "archive", "--format=zip", REFERENCE, "tools/module_release",
                                               "scripts/ouf-a2-executor", "tools/privileged_executor/mandate.py"],
                                              cwd=fixture.ROOT, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            shallow = subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=fixture.ROOT)
            if shallow.strip() == b"true" and subprocess.run(
                    ["git", "cat-file", "-e", REFERENCE], cwd=fixture.ROOT, stderr=subprocess.DEVNULL).returncode:
                raise unittest.SkipTest(f"Shallow checkout lacks reference release {REFERENCE}") from None
            raise
        cls.reference_root = Path(tmp) / "dep58lf_reference"
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            source.extractall(cls.reference_root)
        cls.enterClassContext(patch.object(sys, "path", [tmp, *sys.path]))
        from dep58lf_reference.tools.module_release import operation, recovery, return_operation
        from dep58lf_reference.tools.privileged_executor import mandate as reference_mandate
        cls.reference_mandate = reference_mandate
        cls.reference = (operation, recovery, return_operation)

    def complete_release(self, modules, case, rt, stamp, interrupted):
        op, rec, ret = modules
        p = case.p
        if interrupted:
            # The candidate exists and its CID is journaled, but start has not run.
            with patch.object(case.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                op.apply(p, stamp, rt)
            approved = rec.proposal(p, rt)
            result = rec.resume(p, rt, approved)
        else:
            result = op.apply(p, stamp, rt)
        if p["migration"]["mode"] == "dedicated":
            self.assertEqual(result["status"], "GATED", result)
            stage = result["migrationSha256"]
            if interrupted:
                migrate = case.rt.migrate

                def lost_migration_response(*args):
                    migrate(*args)
                    raise KeyboardInterrupt

                with patch.object(case.rt, "migrate", lost_migration_response), self.assertRaises(KeyboardInterrupt):
                    op.migrate(p, stamp, stage, rt)
                self.assertEqual(rec.resume(p, rt, rec.proposal(p, rt))["migrationSha256"], stage)
            result = op.migrate(p, stamp, stage, rt, recover=interrupted)
        self.assertEqual(result["status"], "READY", result)

        if interrupted and p["migration"]["mode"] == "none":
            signal = case.rt.signal

            def lost_restore_response(cid):
                signal(cid)
                raise KeyboardInterrupt

            with patch.object(case.rt, "signal", lost_restore_response), self.assertRaises(KeyboardInterrupt):
                ret.run(p, stamp, rt)
            returned = ret.run(p, stamp, rt, recover=True)
        else:
            returned = ret.run(p, stamp, rt)
        root = Path(p["journal"]) / stamp
        self.assertEqual(op.read(root, "return-receipt.json"), returned)
        self.assertEqual(op.read(root, "receipt.json"), result)
        if p["migration"]["mode"] == "dedicated":
            self.assertEqual((returned["status"], returned["reason"]), ("HELD", "DATABASE_CHANGED"))
        else:
            self.assertEqual((returned["status"], returned["restoredCid"]), ("ROLLED_BACK", fixture.OLD))

    def run_release(self, modules, case, interrupted, exercise):
        op, rec, _ = modules
        p = case.p
        journal = Path(p["journal"])
        journal.mkdir()
        try:
            rt = Trace(case.rt, op.Docker(p))
            planned = op.plan(p, rt)
            self.assertEqual(planned["status"], "PLANNED", planned)
            stamp = planned["planSha256"]
            if exercise is None:
                self.complete_release(modules, case, rt, stamp, interrupted)
            else:
                exercise(op, rec, case, rt, stamp)
            self.assertEqual(len(rt.creates), 1)
            return {"CREATE": rt.creates[0], "planSha256": stamp.encode(), "Docker calls": rt.calls,
                    "journal": {f.relative_to(journal): f.read_bytes()
                                for f in journal.rglob("*") if f.is_file()}}
        finally:
            shutil.rmtree(journal)

    def compare(self, mode, interrupted=False, exercise=None):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["journal"] = str(case.root / "journal")
        blob, baseline_db = case.rt.blob, case.db
        self.assertNotIn("configDelta", case.p)
        results = []
        for modules in (self.reference, (operation, recovery, return_operation)):
            case.db = copy.deepcopy(baseline_db)
            case.rt = fixture.Engine(case.p, blob)
            case.rt.database = lambda old: copy.deepcopy(case.db)
            if mode == "dedicated":
                case.dedicated()
            self.assertEqual(case.p["migration"]["mode"], mode)
            results.append(self.run_release(modules, case, interrupted, exercise))
        expected, actual = results
        for key in expected:
            with self.subTest(field=key):
                self.assertEqual(expected[key], actual[key])

    def test_DEP_58LF_05_none(self):
        self.compare("none", interrupted=False)

    def test_DEP_58LJ_04_busy_lock_public_error_matches_release(self):
        profile = json.loads(fixture.PROFILE.with_name("mcp.example.json").read_bytes())
        self.assertNotIn("configDelta", profile)
        reference = executor_with_busy_lock(self.reference_root, self.reference_mandate, profile)
        actual = executor_with_busy_lock(fixture.ROOT, mandate, profile)
        self.assertEqual(reference, ((1, "", "A2_EVIDENCE_UNPROVEN/BlockingIOError@ouf-a2-executor:54\n"), 1, 1))
        self.assertEqual(actual, reference)

    def test_DEP_58LF_06_none_interrupted_apply_and_return(self):
        self.compare("none", interrupted=True)

    def test_DEP_58LF_07_dedicated(self):
        self.compare("dedicated", interrupted=False)

    def test_DEP_58LF_08_dedicated_interrupted_apply_and_migration(self):
        self.compare("dedicated", interrupted=True)

    def test_DEP_58LI_04_created_publication_io_error(self):
        def exercise(op, rec, case, rt, stamp):
            link = op.os.link

            def publish(source, dest):
                if dest.name == "created.json":
                    raise OSError("synthetic publication failure")
                link(source, dest)

            with patch.object(op.os, "link", publish):
                result = op.apply(case.p, stamp, rt)
            self.assertEqual((result["status"], result["rollback"], result["restoredCid"]),
                             ("HELD", "ROLLED_BACK", fixture.OLD))
            self.assertEqual(result["reason"], "RELEASE_IO_OR_INPUT_ERROR/OSError@operation.py:137")
            self.assertEqual(op.read(Path(case.p["journal"]) / stamp, "receipt.json"), result)

        for mode in ("none", "dedicated"):
            with self.subTest(mode=mode):
                self.compare(mode, exercise=exercise)

    def test_DEP_58LI_05_interrupted_start_and_failed_resume(self):
        def exercise(op, rec, case, rt, stamp):
            record = op.record

            def interrupt(root, name, data):
                if name == "start-generation.json":
                    if reason != "START_GENERATION_UNCONFIRMED":
                        record(root, name, data)
                    raise KeyboardInterrupt
                record(root, name, data)

            with patch.object(op, "record", interrupt), self.assertRaises(KeyboardInterrupt):
                op.apply(case.p, stamp, rt)
            if reason == "START_GENERATION_CHANGED":
                case.rt.stop(fixture.NEW)
            if reason == "READINESS_NOT_UP":
                case.rt.fault = "readiness"
            with self.assertRaises(op.Held) as held:
                rec.resume(case.p, rt, rec.proposal(case.p, rt))
            self.assertEqual(str(held.exception), reason)

        for reason in ("START_GENERATION_UNCONFIRMED", "START_GENERATION_CHANGED", "READINESS_NOT_UP"):
            with self.subTest(reason=reason):
                self.compare("none", exercise=exercise)

    def test_DEP_58LI_06_lost_predecessor_start_response(self):
        def exercise(op, rec, case, rt, stamp):
            case.rt.fault = "readiness"
            start = case.rt.start

            def unreliable_start(cid):
                if cid != fixture.OLD or started:
                    start(cid)
                if cid == fixture.OLD:
                    raise OSError("synthetic lost response")

            with patch.object(case.rt, "start", unreliable_start):
                result = op.apply(case.p, stamp, rt)
            self.assertEqual((result["status"], result["reason"], result["rollback"]),
                             ("HELD", "READINESS_NOT_UP", "HELD"))
            self.assertEqual(op.read(Path(case.p["journal"]) / stamp, "receipt.json"), result)
            with self.assertRaisesRegex(op.Held, "^TERMINAL_HELD_REQUIRES_OWNER$"):
                rec.resume(case.p, rt, rec.proposal(case.p, rt))

        for started in (False, True):
            with self.subTest(started=started):
                self.compare("none", exercise=exercise)


class WithoutDelta(unittest.TestCase):
    def test_DEP_58L_06_legacy_create_bytes(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        old = case.rt.inspect(fixture.OLD)
        image = case.p["ci"]["imageId"]
        expected = copy.deepcopy(old["Config"])
        expected.pop("MacAddress")
        expected["Image"] = image
        expected["HostConfig"] = dict(old["HostConfig"], OomKillDisable=False)
        expected["NetworkingConfig"] = {"EndpointsConfig": {
            name: {"IPAMConfig": {"IPv4Address": ep["IPAddress"]}, "Aliases": ep["Aliases"]}
            for name, ep in old["NetworkSettings"]["Networks"].items()}}
        self.assertEqual(json.dumps(frame.request(old, image)).encode(), json.dumps(expected).encode())

    def test_DEP_58LE_05_dedicated_without_delta_requires_release_receipt(self):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.dedicated()
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        with patch.object(operation, "start_candidate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(case.p, stamp, case.rt)
        events = list(case.rt.events)
        result = return_operation.run(case.p, stamp, case.rt, recover=True)
        self.assertEqual(result.get("reason"), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        self.assertEqual(events, case.rt.events)
        self.assertFalse((Path(case.p["journal"]) / stamp / "return-intent.json").exists())

    def test_DEP_58LE_05_legacy_restore_start_claim(self):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        self.assertEqual(operation.apply(case.p, stamp, case.rt)["status"], "READY")
        with patch.object(case.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(case.p, stamp, case.rt)
        self.assertEqual(operation.read(Path(case.p["journal"]) / stamp, "restore-start.json"), {"cid": fixture.OLD})

    def test_DEP_58LE_05_none_without_delta_preserves_rollback_scope(self):
        import mandate

        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["migration"] = {"mode": "none", "rollbackCompatible": True}
        stamp = case.planned()
        req = dict(commit="c"*40, run="1", attempt="1", operation="module-release",
                   module=case.p["module"], phase="rollback", digest=stamp)
        with self.assertRaisesRegex(mandate.Held, "MODULE_REQUEST_SCOPE"):
            mandate.validate(req, {"commit": req["commit"], "modules": {req["module"]: case.p}})
        with self.assertRaisesRegex(operation.Held, "INVALID_RETURN_PLAN"):
            return_operation.run(case.p, stamp, case.rt, recover=True)

    def test_DEP_58LG_04_native_checkout_does_not_require_full_history(self):
        path = fixture.ROOT / ".github/workflows/privileged-executor-native.yml"
        self.assertNotRegex(path.read_text(encoding="utf-8"), r"(?m)^\s*fetch-depth:\s*0\s*$")
