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
from tools.module_release import operation, recovery, return_operation


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
        archive = subprocess.check_output(["git", "archive", "--format=zip", REFERENCE, "tools/module_release"],
                                          cwd=fixture.ROOT)
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            source.extractall(Path(tmp) / "dep58lf_reference")
        cls.enterClassContext(patch.object(sys, "path", [tmp, *sys.path]))
        from dep58lf_reference.tools.module_release import operation, recovery, return_operation
        cls.reference = (operation, recovery, return_operation)

    def run_release(self, modules, case, interrupted):
        op, rec, ret = modules
        p = case.p
        journal = Path(p["journal"])
        journal.mkdir()
        try:
            rt = Trace(case.rt, op.Docker(p))
            planned = op.plan(p, rt)
            self.assertEqual(planned["status"], "PLANNED", planned)
            stamp = planned["planSha256"]
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
            if p["migration"]["mode"] == "dedicated":
                self.assertEqual((returned["status"], returned["reason"]), ("HELD", "DATABASE_CHANGED"))
            else:
                self.assertEqual((returned["status"], returned["restoredCid"]), ("ROLLED_BACK", fixture.OLD))
            self.assertEqual(len(rt.creates), 1)
            root = journal / stamp
            return {"CREATE": rt.creates[0], "planSha256": stamp.encode(), "plan": (root / "plan.json").read_bytes(),
                    "receipt": (root / "receipt.json").read_bytes(), "return": (root / "return-receipt.json").read_bytes(),
                    "Docker calls": rt.calls, "journal": {f.relative_to(journal): f.read_bytes()
                                                          for f in journal.rglob("*.json")}}
        finally:
            shutil.rmtree(journal)

    def compare(self, mode, interrupted):
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
            results.append(self.run_release(modules, case, interrupted))
        expected, actual = results
        for key in expected:
            with self.subTest(field=key):
                self.assertEqual(expected[key], actual[key])

    def test_DEP_58LF_05_none(self):
        self.compare("none", interrupted=False)

    def test_DEP_58LF_06_none_interrupted_apply_and_return(self):
        self.compare("none", interrupted=True)

    def test_DEP_58LF_07_dedicated(self):
        self.compare("dedicated", interrupted=False)

    def test_DEP_58LF_08_dedicated_interrupted_apply_and_migration(self):
        self.compare("dedicated", interrupted=True)
