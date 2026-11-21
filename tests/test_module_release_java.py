"""Run both Java module profiles through the shared release and recovery owners."""
from contextlib import closing, contextmanager
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

from test_module_release import Engine, NEW, OLD, PROFILE, artifact
from tools.module_release import flyway, operation, recovery, return_operation, transport
from tools.module_release.contract import Held, digest


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
        if module == "udp":
            p["gate"]["command"] = ["java", "-jar", "/app/app.jar", "--ouf.udp.lake.s3.endpoint=fixture"]
        p["migration"]["rollbackCompatible"] = True
        pg = "3"*64
        p["migration"]["flyway"].update(postgresCid=pg, socket="/tmp", userEnv="APP_USER",
                                       urlEnv="APP_URL", database=module, schema="schema_" + module)
        p["ci"].update(workflow="ci.yml", pullRequest=2, runId=15, runAttempt=1, artifactId=17,
                       sourceCommit="b"*40, sourceTree="c"*40, imageName=module,
                       manifestSchema="fixture.tested.v1", artifactPrefix=module+"-artifact")
        rt = Engine(p, artifact(p, root))
        rt.docs[OLD]["Config"]["Env"] += ["APP_USER=fixture", "APP_URL=jdbc:postgresql://pg/"+module]
        if module == "ingestion":
            rt.docs[OLD]["Config"]["Env"] += ["SPRING_CONFIG_ADDITIONAL_LOCATION=file:/fixture/ingestion.yml",
                                              "SPRING_FLYWAY_ENABLED=false"]
        else:
            rt.docs[OLD]["Config"]["Env"].append('SPRING_APPLICATION_JSON={"ouf":{"udp":{"storage":"private-marker"}}}')
        rt.docs[pg] = dict(Id=pg, Name="/pg", State={"Running": True},
                           NetworkSettings={"Networks": copy.deepcopy(rt.nets)})
        rows = [dict(version=str(i), script=f"V{i}__fixture.sql", type="SQL", checksum=i, success=True)
                for i in ((20, 21) if module == "ingestion" else (1, 2))]
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

    def test_json_overrides_fail_closed_in_private(self):
        with fixture("udp") as (p, rt, _, __):
            env = rt.docs[OLD]["Config"]["Env"]
            env.pop()
            for raw in ('{"spring":{"dataSource":{"url":"private-marker"}}}',
                        '{"spring.flyway.url":"private-marker"}', '{"SPRING_FLYWAY_URL":"private-marker"}',
                        '{"spring.config.import":"private-marker"}', '{"APP_URL":"private-marker"}',
                        '{"x":1,"x":2}', '{"x":NaN}', '[]', 'private-marker'):
                with self.subTest():
                    env.append("SPRING_APPLICATION_JSON=" + raw)
                    self.assertEqual(operation.plan(p, rt)["reason"], "FLYWAY_DATASOURCE_UNPROVEN")
                    env.pop()
            env.append('SPRING_APPLICATION_JSON={"spring.application.name":"private-marker"}')
            self.plan(p, rt)
            del p["migration"]["flyway"]["effectiveDatasource"]
            self.assertEqual(operation.plan(p, rt)["reason"], "FLYWAY_DATASOURCE_UNPROVEN")
            self.assertNotIn("stop:1", rt.events)

    def test_candidate_image_env_checked_before_stop_and_on_gated_container(self):
        with fixture("udp") as (p, rt, _, __):
            rt.docs[OLD]["Config"]["Env"].pop()
            image_env = ['SPRING_APPLICATION_JSON={"spring":{"flyway":{"url":"private-marker"}}}']
            stamp = self.plan(p, rt)
            with patch.object(rt, "image_defaults", return_value={"Env": image_env}):
                result = operation.apply(p, stamp, rt)
                self.assertEqual(result["reason"], "FLYWAY_DATASOURCE_UNPROVEN")
                self.assertEqual(result["rollback"], "ROLLED_BACK")
                self.assertNotIn("signal:2", rt.events)
        with fixture("udp") as (p, rt, _, __):
            rt.docs[OLD]["Config"]["Env"].pop()
            artifact(p, Path(p["inbox"]), image_env=image_env)
            self.assertEqual(operation.plan(p, rt)["reason"], "FLYWAY_DATASOURCE_UNPROVEN")
            self.assertNotIn("stop:1", rt.events)

    def test_candidate_env_override_after_image_merge_and_profile_drift(self):
        with fixture("ingestion") as (p, rt, _, __):
            original = rt.docs[OLD]["Config"]["Env"]
            original.remove("SPRING_FLYWAY_ENABLED=false")
            image_env = ["IMAGE_FIRST=fixture", "SPRING_FLYWAY_ENABLED=false", "IMAGE_LAST=fixture"]
            rt.blob = artifact(p, Path(p["inbox"]), image_env=image_env)
            with patch.object(rt, "image_defaults", return_value={"Env": image_env}):
                stamp = self.plan(p, rt)
                stage = operation.apply(p, stamp, rt)
                self.assertEqual(stage["status"], "GATED", stage)
                self.assertTrue(rt.inspect(NEW)["Config"]["Env"][-3:] ==
                                ["IMAGE_FIRST=fixture", "SPRING_FLYWAY_ENABLED=true", "IMAGE_LAST=fixture"])
                self.assertEqual(return_operation.run(p, stamp, rt, recover=True)["restoredCid"], OLD)
                self.assertTrue(rt.inspect(OLD)["Config"]["Env"] == original)
        with fixture("ingestion") as (p, rt, _, __):
            stamp = self.plan(p, rt)
            p["candidate"]["removeArgs"].pop()
            self.assertNotEqual(operation.apply(p, stamp, rt)["status"], "GATED")
            self.assertNotIn("stop:1", rt.events)
            for removed in (["-jar"], ["--misspelled=true"], p["gate"]["command"][-1:] * 2):
                p["candidate"]["removeArgs"] = removed
                self.assertEqual(operation.plan(p, rt)["reason"], "INVALID_CANDIDATE_PROFILE")

    def test_reviewed_migration_and_ready_return(self):
        for module in MODULES:
            with self.subTest(module=module), fixture(module) as (p, rt, rows, history):
                original = rt.inspect(OLD)["Config"]
                proposal = operation.plan(p, rt)
                body = proposal["plan"]
                stamp = proposal["planSha256"]
                self.assertEqual(stamp, digest(body))
                self.assertNotIn("private-marker", json.dumps(body))
                if module == "ingestion":
                    delta = body["candidateReview"]
                    self.assertEqual(delta["removedArgs"], original["Cmd"][3:])
                    self.assertEqual(delta["predecessorCmdSha256"], digest(original["Cmd"]))
                    self.assertEqual(delta["candidateCmdSha256"], digest(original["Cmd"][:3]))
                    self.assertEqual(delta["envOperations"], {"SPRING_FLYWAY_ENABLED": "enable"})
                stage = operation.apply(p, stamp, rt)
                self.assertEqual(stage["status"], "GATED", stage)
                self.assertTrue(rt.inspect(OLD)["Config"] == original)
                if module == "ingestion":
                    cfg = rt.inspect(NEW)["Config"]
                    self.assertEqual(cfg["Cmd"], original["Cmd"][:3])
                    self.assertTrue("SPRING_FLYWAY_ENABLED=true" in cfg["Env"])
                    self.assertFalse("SPRING_FLYWAY_ENABLED=false" in cfg["Env"])
                    review = operation.read(Path(p["journal"]) / stamp, "migration-plan.json")["flywayReview"]
                    self.assertEqual([r["version"] for r in review["pending"]], ["21"])
                signal = rt.signal
                def launch(cid):
                    signal(cid)
                    history.append(rows[1])
                with patch.object(rt, "signal", side_effect=launch):
                    result = operation.migrate(p, stamp, stage["migrationSha256"], rt)
                self.assertEqual((result["status"], result["readyHttp"]), ("READY", 200))
                self.assertFalse(rt.inspect(p["retainedName"])["State"]["Running"])
                self.assertEqual(return_operation.run(p, stamp, rt)["status"], "ROLLED_BACK")
                self.assertTrue(rt.inspect(p["container"])["Config"] == original)

    def test_ingestion_v21_changes_schema_only_after_migrate(self):
        script = Path(__file__).parent / "fixtures/module-release-flyway/V21__add_repeat_key.sql"
        with fixture("ingestion") as (p, rt, rows, history), closing(sqlite3.connect(":memory:")) as db:
            db.execute("ATTACH DATABASE ':memory:' AS release_fixture")
            base = "CREATE TABLE release_fixture.base_row(id integer);"
            db.execute(base)
            jar = Path(p["inbox"]) / "app.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("BOOT-INF/classes/db/migration/V20__base.sql", base)
                archive.write(script, "BOOT-INF/classes/db/migration/" + script.name)
            rows[:] = flyway.java_migrations(jar)
            history[:] = rows[:1]
            stamp = self.plan(p, rt)
            stage = operation.apply(p, stamp, rt)
            self.assertEqual(stage["status"], "GATED", stage)
            columns = "SELECT name FROM pragma_table_info('base_row', 'release_fixture') ORDER BY cid"
            self.assertEqual(db.execute(columns).fetchall(), [("id",)])
            signal = rt.signal

            def start_java(cid):
                signal(cid)
                cfg = rt.inspect(cid)["Config"]
                if cfg["Cmd"] == ["java", "-jar", "/app/app.jar"] and "SPRING_FLYWAY_ENABLED=true" in cfg["Env"]:
                    with zipfile.ZipFile(jar) as archive:
                        db.executescript(archive.read("BOOT-INF/classes/db/migration/" + script.name).decode())
                    history.append(rows[1])

            with patch.object(rt, "signal", side_effect=start_java):
                result = operation.migrate(p, stamp, stage["migrationSha256"], rt)
            self.assertEqual(result["status"], "READY", result)
            self.assertEqual(db.execute(columns).fetchall(), [("id",), ("repeat_key",)])

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
