"""Run both Java module profiles through the shared release and recovery owners."""
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_module_release import Engine, NEW, OLD, PROFILE, artifact
from tools.module_release import flyway, operation, recovery, return_operation, transport
from tools.module_release.contract import Held


MODULES = ("udp", "ingestion")


@contextmanager
def fixture(module):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        p = json.loads(PROFILE.with_name(module + ".example.json").read_bytes())
        p.update(container="fixture", inbox=directory, journal=directory, dockerSocket=str(root/"socket"),
                 nsenter=str(root/"nsenter"), oldImage="sha256:"+"a"*64,
                 networks={"fixture-net": {"ipv4": "192.0.2.10", "aliases": [module]}},
                 readiness=dict(path="/ready", port=8000, acceptStatus=[200], jsonStatus="UP", attempts=2))
        p["gate"]["command"] = ["java", "-jar", "/app/app.jar"]
        p["migration"]["rollbackCompatible"] = True
        pg = "3"*64
        p["migration"]["flyway"].update(postgresCid=pg, socket="/tmp", userEnv="APP_USER",
                                       urlEnv="APP_URL", database=module, schema="schema_" + module)
        p["ci"].update(workflow="ci.yml", pullRequest=2, runId=15, runAttempt=1, artifactId=17,
                       sourceCommit="b"*40, sourceTree="c"*40, imageName=module,
                       manifestSchema="fixture.tested.v1", artifactPrefix=module+"-artifact")
        rt = Engine(p, artifact(p, root))
        rt.docs[OLD]["Config"]["Env"] += ["APP_USER=fixture", "APP_URL=jdbc:postgresql://pg/"+module]
        rt.docs[pg] = dict(Id=pg, Name="/pg", State={"Running": True},
                           NetworkSettings={"Networks": copy.deepcopy(rt.nets)})
        rows = [dict(version=str(i), script=f"V{i}__fixture.sql", type="SQL", checksum=i, success=True)
                for i in (1, 2)]
        history = rows[:1]

        def sql(cmd, *, input, **kwargs):
            assert cmd[-4:] == ["-U", "fixture", "-d", module]
            assert "schema=schema_" + module in cmd
            assert b"READ ONLY" in input and b'FROM :"schema".flyway_schema_history' in input
            return SimpleNamespace(returncode=0, stdout=json.dumps(
                {"databaseOid":"42", "history":history}).encode())

        with patch.object(flyway, "inventory", return_value=rows), patch.object(flyway.subprocess, "run", side_effect=sql):
            yield p, rt, rows, history


class JavaRelease(unittest.TestCase):
    def plan(self, p, rt):
        proposal = operation.plan(p, rt)
        self.assertEqual(proposal["status"], "PLANNED", proposal)
        return proposal["planSha256"]

    def test_interrupted_create_and_signal_then_reviewed_return(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, rt, rows, history):
                stamp = self.plan(p, rt)
                with patch.object(rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                    operation.apply(p, stamp, rt)
                stage = recovery.resume(p, rt, recovery.proposal(p, rt))
                self.assertEqual(stage["status"], "GATED")
                journal = Path(p["journal"]) / stamp
                review = operation.read(journal, "migration-plan.json")["flywayReview"]
                self.assertEqual(review["pending"], rows[1:])
                self.assertTrue(rt.process(rt.inspect(NEW), gated=True))
                signal = rt.signal
                def delivered(cid):
                    signal(cid)
                    history.append(dict(rows[1], checksum=-1))
                    raise KeyboardInterrupt
                with patch.object(rt, "signal", side_effect=delivered), self.assertRaises(KeyboardInterrupt):
                    operation.migrate(p, stamp, stage["migrationSha256"], rt)
                with self.assertRaisesRegex(Held, "FLYWAY_OUTCOME_UNCONFIRMED"):
                    recovery.resume(p, rt, recovery.proposal(p, rt))
                history[-1] = rows[1]
                final = recovery.resume(p, rt, recovery.proposal(p, rt))
                self.assertEqual((final["status"], final["successorCid"], final["readyHttp"]), ("READY", NEW, 200))
                self.assertEqual(rt.events.count("signal:2"), 1)
                history.pop()
                self.assertEqual(return_operation.run(p, stamp, rt)["reason"], "FLYWAY_HISTORY_UNPROVEN")
                self.assertTrue(rt.inspect(NEW)["State"]["Running"])
                history.append(rows[1])
                park = rt.rename
                def interrupted(cid, name):
                    park(cid, name)
                    raise KeyboardInterrupt
                with patch.object(rt, "rename", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                    return_operation.run(p, stamp, rt)
                restored = return_operation.run(p, stamp, rt, recover=True)
                self.assertEqual((restored["restoredCid"], restored["predecessorReadyHttp"]), (OLD, 200))
                self.assertEqual(rt.events.count("create"), 1)

    def test_partial_detach_and_invalid_bindings(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, rt, _, _):
                db = p["migration"]["flyway"]
                db["database"] = "wrong"
                self.assertEqual(operation.plan(p, rt)["reason"], "FLYWAY_DATASOURCE_UNPROVEN")
                db["database"] = module
                stamp = self.plan(p, rt)
                disconnect = rt.disconnect
                def interrupted(cid, net):
                    disconnect(cid, net)
                    raise KeyboardInterrupt
                with patch.object(rt, "disconnect", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                    operation.apply(p, stamp, rt)
                result = recovery.resume(p, rt, recovery.proposal(p, rt))
                self.assertEqual((result["restoredCid"], result["predecessorReadyHttp"]), (OLD, 200))
                self.assertNotIn("create", rt.events)

    def test_reviewed_return_while_gated(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, rt, _, _):
                stamp = self.plan(p, rt)
                stage = operation.apply(p, stamp, rt)
                self.assertEqual(stage["status"], "GATED", stage)
                returned = return_operation.run(p, stamp, rt, recover=True)
                self.assertEqual((returned["restoredCid"], returned["predecessorReadyHttp"]), (OLD, 200))
                self.assertNotIn("signal:2", rt.events)

    def test_reviewed_migration_and_ready_return(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, rt, rows, history):
                stamp = self.plan(p, rt)
                stage = operation.apply(p, stamp, rt)
                signal = rt.signal
                def launch(cid):
                    signal(cid)
                    history.append(rows[1])
                with patch.object(rt, "signal", side_effect=launch):
                    result = operation.migrate(p, stamp, stage["migrationSha256"], rt)
                self.assertEqual((result["status"], result["readyHttp"]), ("READY", 200))
                self.assertFalse(rt.inspect(p["retainedName"])["State"]["Running"])
                self.assertEqual(return_operation.run(p, stamp, rt)["status"], "ROLLED_BACK")

    def test_pinned_transport_verifies_exact_zip_tree_and_attempt(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, _, __, ___):
                ci = p["ci"]
                repo = {"full_name":ci["repository"]}
                run = dict(id=15, event="pull_request", status="completed", conclusion="success", run_attempt=1,
                           repository=repo, head_repository=repo, head_sha="d"*40, path=".github/workflows/ci.yml",
                           pull_requests=[{"number":2, "head":{"sha":ci["sourceCommit"]}}])
                obj = dict(id=17, expired=False, workflow_run={"id":15, "head_sha":"d"*40},
                           name=ci["artifactPrefix"]+"-15", digest="sha256:"+ci["zipSha256"])
                archive = Path(p["inbox"]) / (ci["zipSha256"] + ".zip")
                inbox = archive.parent / "transport"
                inbox.mkdir()
                def api(path, output=None):
                    if output:
                        output.write(archive.read_bytes())
                    elif "/commits/" in path:
                        return dict(sha=path.rsplit("/",1)[1], tree={"sha":ci["sourceTree"]},
                                    parents=[{"sha":ci["sourceCommit"]}])
                    else:
                        return run if path.endswith("/runs/15") else obj
                with patch.object(transport, "github", side_effect=api):
                    receipt = transport.transport(p, 15, 17, inbox)
                    self.assertEqual(receipt["zipSha256"], ci["zipSha256"])
                    self.assertEqual((inbox / archive.name).read_bytes(), archive.read_bytes())
                    ci["runAttempt"] += 1
                    with self.assertRaisesRegex(Held, "TRANSPORT_PIN_CHANGED"):
                        transport.transport(p, 15, 17, inbox)
