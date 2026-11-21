"""Semantic database protocol with a packaged JAR and a transaction-capable double."""
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from test_privileged_executor import mandate, pipeline, store
import semantic_database as db
from module_release import flyway


def packaged(scripts):
    jar = io.BytesIO()
    with zipfile.ZipFile(jar, "w") as z:
        for name, raw in scripts.items():
            z.writestr("BOOT-INF/classes/db/migration/" + name, raw)
    return jar


class SQLiteDatabase:
    db = {"database": "fixture", "schema": "test"}

    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE history(row text)")
        self.writes = 0

    def history(self):
        return {"databaseOid": "42", "history": [json.loads(r[0]) for r in self.conn.execute(
            "SELECT row FROM history ORDER BY rowid")] or None}

    def apply_one(self, before, row, raw):
        self.writes += 1
        with self.conn:
            self.conn.execute("BEGIN")
            assert self.history() == before
            try:
                for sql in raw.decode().split(";"):
                    if sql.strip():
                        self.conn.execute(sql)
            except sqlite3.DatabaseError:
                raise mandate.Held("SEMANTIC_DATABASE_MIGRATION_HELD") from None
            self.conn.execute("INSERT INTO history VALUES (?)", (json.dumps(row),))


class SemanticDatabase(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: path))
        self.enterContext(patch.object(store, "sync_dir"))
        self.database = SQLiteDatabase()
        self.addCleanup(self.database.conn.close)
        self.scripts = {"V12__base.sql": b"CREATE TABLE events(id int);",
                        "V13__new_data.sql": b"INSERT INTO events VALUES (13);",
                        "V14__add_name.sql": b"ALTER TABLE events ADD name text;"}
        self.manifest = [{"name": n, "sha256": hashlib.sha256(s).hexdigest()} for n, s in self.scripts.items()]
        self.jar = packaged(self.scripts)
        self.enterContext(patch.object(flyway, "inventory", side_effect=lambda doc, **kw:
                                     flyway.java_migrations(self.jar, **kw)))
        self.rows, self.scripts = db.reviewed({}, self.manifest)
        self.database.apply_one(self.database.history(), self.rows[0], self.scripts["V12__base.sql"])
        self.plan = db.proposal(self.database, self.rows, self.scripts)

    def apply(self, plan=None, run="123"):
        db.apply(self.root, run, self.database, plan or self.plan, self.rows, self.scripts, lambda: None)

    def test_prefix_inventory_and_idempotence(self):
        self.assertEqual(self.plan["applied"], 1)
        self.assertEqual([r["version"] for r in self.rows[1:]], ["13", "14"])
        self.assertEqual(self.rows[1]["checksum"], flyway.flyway_checksum(self.scripts["V13__new_data.sql"]))
        self.apply()
        self.apply()
        self.apply(db.proposal(self.database, self.rows, self.scripts), run="124")
        self.assertEqual(self.database.writes, 3)
        self.assertEqual(self.database.history()["history"], self.rows)

    def test_inventory_and_history_drift(self):
        for manifest in (self.manifest[:-1], [*self.manifest[1:], dict(self.manifest[0], sha256="0"*64)]):
            with self.assertRaisesRegex(mandate.Held, "INVENTORY_DRIFT"):
                db.reviewed({}, manifest)
        for changed in ({"checksum": 0}, {"script": "other.sql"}, {"success": False}, {"version": "0"}):
            with self.subTest(changed=changed), self.assertRaisesRegex(mandate.Held, "NOT_EXACT_PREFIX"):
                db.prefix({"databaseOid": "42", "history": [dict(self.rows[0], **changed)]}, self.rows, "test")

    def test_rollback_mid_script(self):
        raw = b"INSERT INTO events VALUES(13); SELECT * FROM absent;"
        self.scripts["V13__new_data.sql"] = raw
        self.rows[1]["checksum"] = flyway.flyway_checksum(raw)
        before = self.database.history()
        with self.assertRaisesRegex(mandate.Held, "MIGRATION_HELD"):
            self.apply(db.proposal(self.database, self.rows, self.scripts))
        self.assertEqual(self.database.history(), before)
        self.assertEqual(self.database.conn.execute("SELECT * FROM events").fetchall(), [])
        self.assertFalse(list(self.root.rglob("*.receipt")))
        failure, = self.root.rglob("*.failure")
        self.assertEqual(store.read(failure)["status"], "HELD")

    def test_reconcile_committed_row_after_process_loss_in_a_fresh_dispatch(self):
        write = self.database.apply_one
        def crash(*args):
            write(*args)
            raise KeyboardInterrupt
        with patch.object(self.database, "apply_one", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.apply()
        self.assertFalse(list(self.root.rglob("*.receipt")))
        self.apply(db.proposal(self.database, self.rows, self.scripts), run="124")
        self.assertEqual(self.database.writes, 3)
        self.assertEqual(len(list(self.root.rglob("*.receipt"))), 2)

    def test_reject_unclaimed_progress(self):
        self.database.apply_one(self.database.history(), self.rows[1], self.scripts["V13__new_data.sql"])
        with self.assertRaisesRegex(mandate.Held, "UNCLAIMED"):
            self.apply()
        self.assertEqual(self.database.writes, 2)

    def test_reject_nontransactional_sql_before_first_effect(self):
        db.check_script(b"CREATE FUNCTION f() RETURNS void AS $f$ BEGIN RETURN; END $f$ LANGUAGE plpgsql;")
        db.check_script(b"/* outer /* BEGIN */ end */ SELECT 'COMMIT';")
        for sql in (b"SELECT 1; /* x */ COMMIT;", b"BEGIN TRANSACTION;", b"CREATE INDEX CONCURRENTLY i ON t(c);",
                    b"END TRANSACTION;", b"\\quit", b"START TRANSACTION;", b"PREPARE /* x */ TRANSACTION 'a';"):
            with self.subTest(sql=sql), self.assertRaises(mandate.Held):
                db.proposal(self.database, self.rows, {**self.scripts, "V14__add_name.sql": sql})
        self.assertEqual(self.database.writes, 1)

    def test_online_plan_and_apply_use_live_r3_and_check_readiness(self):
        req = dict(phase="plan", operation="semantic-database-migration", commit="b"*40, run="101", attempt="1")
        req["digest"] = mandate.intent(req)
        cfg = dict(originalProfile={"containerName": "semantic"}, queue={}, socket="/fixture")
        op = pipeline.Cutover(cfg, self.root, req)
        profile = {"containerName": "semantic", "image": "image"}
        op.engine = Mock()
        op.engine.inspect.return_value = {"Id": "cid", "Image": "image", "State": {"Pid": 1, "StartedAt": "start"}}
        op.engine.process.return_value = {"cid": "cid", "pid": 1, "startedAt": "start"}
        op.current_version = lambda: 29
        op.authority = lambda: "chain"
        op.supervisor = lambda head: {"semanticIngress": {"profile": profile}}
        op.ready = Mock()
        with patch.object(db, "Database", return_value=self.database), patch.object(
                pipeline, "live_manifest", return_value=self.manifest):
            result = op.database_operation("plan-review")
            self.assertEqual(result["pending"], self.rows[1:])
            self.assertEqual(self.database.writes, 1)
            req.update(phase="apply", digest=result["digest"])
            result = op.database_operation("apply-review")
        self.assertEqual((result["lastVersion"], result["readiness"], result["head"]), ("14", "UP", 29))
        op.engine.inspect.assert_called_with("semantic")
        op.ready.assert_called_once_with("cid", profile, op.engine.process.return_value)
        op.engine.call.assert_not_called()

    def test_candidate_routes_and_migrate_before_sign(self):
        for flag in ("true", "false"):
            mode = db.route({"Env": ["SPRING_FLYWAY_ENABLED=" + flag]})
            self.assertEqual(mode, "spring-flyway" if flag == "true" else "governed-sql")
        cfg = dict(originalProfile={"containerName": "app"}, queue={}, socket="/fixture",
                   semanticDatabase=dict(postgresCid="d"*64, socket="/tmp", user="fixture", database="fixture", schema="test"))
        for run, release in (("201", {}), ("202", {"release": "next"})):
            with self.subTest(run=run):
                req = dict(run=run, attempt="1", commit="b"*40, direction="forward", queue="empty", phase="plan", **release)
                req["digest"] = mandate.intent(req)
                op = pipeline.Cutover(cfg, self.root, req)
                plan = {"profileSha256": mandate.digest(cfg), "intent": mandate.intent(req), "queue": [],
                        "request": {"Env": ["SPRING_FLYWAY_ENABLED=false"]}, "head": 27 if not release else 28,
                        "old": "old", "authority": "chain", "successorImage": {"ci": {"imageId": "image", "zipSha256": "zip"},
                        "migrations": self.manifest, "newMigrations": []}}
                op.initial = lambda: plan
                op.current_version = lambda: plan["head"]
                op.authority = lambda: "chain"
                op.owner = lambda k: run
                op.retained = Mock()
                op.bind_return = Mock()
                op.engine = Mock()
                gen = {"pid": 123, "startedAt": "epoch"}
                op.engine.process.return_value = gen
                op.engine.inspect.return_value = {"Id": "candidate", "Image": "image", "State": {"Pid": 123,
                        "StartedAt": "epoch"}, "Config": plan["request"]}
                op.prepare_stage = lambda p: {"cid": "candidate", "profile": {"image": "image"}, "generation": gen,
                                               "parent": mandate.digest(p), "issue": {"planSha256": "sign"}}
                op.finish = Mock(return_value={"ingress": "VERIFIED", "readiness": "UP", "worker": "on"})
                op.close_forward = Mock()
                with patch.object(db, "Database", return_value=self.database):
                    proposed = op.execute("review")
                    self.assertEqual(proposed["migrationMode"], "governed-sql")
                    req.update(phase="apply", digest=proposed["digest"])
                    staged = op.execute("review")
                    self.assertEqual(staged["migrationCount"], 2 if not release else 0)
                    req.update(phase="sign", digest="sign")
                    with self.assertRaisesRegex(mandate.Held, "MIGRATION_REVIEW_REQUIRED"):
                        op.execute("review")
                    review_path = op.path / "migrate.review"
                    store.save(review_path, {"request": dict(req, phase="migrate", digest=staged["digest"])})
                    with self.assertRaisesRegex(mandate.Held, "MIGRATION_EFFECT_UNPROVEN"):
                        op.execute("review")
                    review_path.unlink()
                    req.update(phase="migrate", digest=staged["digest"])
                    with patch.object(op, "retained", side_effect=mandate.Held("RETAINED_CID_DRIFT")), \
                            self.assertRaisesRegex(mandate.Held, "RETAINED_CID_DRIFT"):
                        op.migration_guard(plan, op.record("stage"))
                    signed = op.execute("review")
                    self.assertEqual(self.database.history()["history"], self.rows)
                    op.finish.assert_not_called()
                    req.update(phase="sign", digest=signed["digest"])
                    with patch.object(self.database, "history", return_value={"databaseOid": "42", "history": []}), \
                            self.assertRaisesRegex(mandate.Held, "MIGRATION_INCOMPLETE"):
                        op.execute("review")
                    op.execute("review")
                    op.finish.assert_called_once()
                    op.retained.assert_called_with(plan)
