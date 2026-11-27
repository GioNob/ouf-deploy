"""DEP-55J-01..05. Protected dispatch with the offline MCP candidate."""
import copy
import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import test_module_release_mcp as fixture
from module_release import operation, retention
from module_release.contract import Held, digest
import mandate
from module_operation import ModuleRelease


BATCH_CONFIG = dict(OUF_ANALYSIS_WORKLOAD="fixture", OUF_ANALYSIS_STATUS_SECONDS="3600",
                    OUF_ANALYSIS_RESERVATION_DAYS="12", OUF_ANALYSIS_ATTEMPT_DAYS="23",
                    OUF_ANALYSIS_SNAPSHOT_DAYS="34", OUF_ANALYSIS_READ_DAYS="45", OUF_ANALYSIS_RETENTION_BATCH="56")


class RetentionFixture(unittest.TestCase):
    def setUp(self):
        f = self.release = fixture.Release()
        self.addCleanup(f.doCleanups)
        f.setUp()
        self.overloads = [dict(arity=n, definition=f"function {n}", schemaItem=f"fixture routine {n}",
                               permitted=True, acl="fixture ACL") for n in (4, 5)]
        self.rows = []
        self.work = []
        self.crash = None
        spec = dict(functionName="purge_analysis_run_history", functionSha256=digest(["function 4", "function 5"]),
                    sqlSha256="a"*64, ownerAclSha256="b"*64, adminRole="admin_fixture",
                    maintenanceRole="maintenance_fixture", maintenanceLogin="worker_fixture",
                    maintenanceUrlEnv="FIXTURE_WORKER_DATABASE_URL",
                    adminPassfile=str(f.root / "admin"), maintenancePassfile=str(f.root / "worker"))
        m = f.p["migration"]
        m["database"]["version"] = 18
        f.db["history"].extend([[i, "1"*64, "UTC"] for i in range(15, 19)])
        m.update(retentionAdmin019=spec, mode="dedicated", command=[f.p["gate"]["command"][0], "migrate"],
                 migrations=[dict(version=19, checksum="e"*64)],
                 targetSchemaSha256=digest(sorted(map(digest, f.db["schema"] + ["ordinary 019"]))))
        pg = m["database"]["postgresCid"]
        old = f.rt.docs[fixture.OLD]
        old["Config"]["Env"].extend(f"{key}={value}" for key, value in self.batch_config().items())
        old["Config"]["Env"].extend(["OUF_ANALYSIS_OTHER=irrelevant", "MCP_MIGRATION_DATABASE_OID=999",
                                     "MCP_MIGRATION_APPLICATION_ROLE=wrong"])
        old["Config"]["Env"].append("MCP_DATABASE_URL=postgresql://app_fixture@pg_fixture/fixture?sslmode=require")
        f.rt.docs[pg] = dict(Id=pg, Name="/pg_fixture", State=dict(Running=True),
                             NetworkSettings=copy.deepcopy(old["NetworkSettings"]))
        # Each privileged SQL read returns only the catalog of the fixture database.
        self.catalog_read = self.enterContext(patch.object(retention.postgres, "database_snapshot",
            side_effect=lambda *a, **kw: dict(application="app_fixture", oid="42", functions=copy.deepcopy(self.rows))))
        self.logs = self.enterContext(patch.object(retention.subprocess, "run", return_value=Mock(returncode=0,
            stdout=json.dumps(dict(status="VERIFIED", sqlSha256=spec["sqlSha256"],
                                   ownerAclSha256=spec["ownerAclSha256"])).encode() + b"\n")))
        def ordinary(cid, command):
            self.assertEqual(command, m["command"])
            f.db["history"].append([19, "e"*64, "UTC"])
            f.db["schema"].append("ordinary 019")
        f.rt.migrate = ordinary
        create, start = f.rt.create, f.rt.start

        def create_worker(name, request):
            if request["Cmd"][0] not in retention.COMMAND.values():
                return create(name, request)
            self.assertEqual(f.db["history"][-1][0], 19)
            self.assertEqual(request["Image"], f.p["ci"]["imageId"])
            cid = ("4" if not self.work else "5")*64
            f.rt.docs[cid] = dict(Id=cid, Name="/" + name, Image=request["Image"], Path=request["Entrypoint"][0],
                                  Args=request["Cmd"], Config={"Env": request["Env"]}, HostConfig=request["HostConfig"],
                                  RestartCount=0, State=dict(Status="created", Running=False, Pid=0,
                                      StartedAt="0001-01-01T00:00:00Z", FinishedAt="0001-01-01T00:00:00Z"))
            self.work.append(request)
            return cid

        def start_worker(cid):
            if cid in (fixture.NEW, fixture.OLD):
                return start(cid)
            doc = f.rt.docs[cid]
            self.assertEqual(doc["State"]["Status"], "created")
            cmd, = doc["Args"]
            if cmd == retention.COMMAND[retention.ADMIN]:
                self.rows[:] = copy.deepcopy(self.overloads)
                f.db["schema"].extend(row["schemaItem"] for row in self.rows)
            doc["State"].update(Status="exited", ExitCode=0, OOMKilled=False, Error="")
            if self.crash == cmd:
                raise KeyboardInterrupt
        f.rt.create, f.rt.start = create_worker, start_worker
        engine_api = f.rt.api
        def retire(method, path, **kwargs):
            if method == "GET":
                return engine_api(method, path, **kwargs)
            self.assertEqual(method, "DELETE")
            cid = path.removeprefix("/containers/").removesuffix("?v=true")
            self.assertEqual(f.rt.docs[cid]["State"]["Status"], "exited")
            del f.rt.docs[cid]
        f.rt.api = retire
        plan = f.planned()
        self.source = plan["digest"]
        self.root = f.root / self.source
        self.expected = dict(planSha256=self.source, **plan["retentionReview"], status="VERIFIED")
        stage = f.call("apply", self.source)
        ready = f.call("migrate", stage["digest"])
        self.assertEqual(ready["status"], "READY")
        self.assertEqual(ready["retentionReview"], plan["retentionReview"])

    def batch_config(self):
        return BATCH_CONFIG

    def call(self, phase, **kwargs):
        return self.release.call(phase, self.source, **kwargs)


class IncompleteConfig(RetentionFixture):
    def batch_config(self):
        return {key: value for key, value in BATCH_CONFIG.items() if key != "OUF_ANALYSIS_SNAPSHOT_DAYS"}

    def test_dep_55j_02_missing_ttl_prevents_batch_creation(self):
        self.call(retention.ADMIN)
        with self.assertRaisesRegex(mandate.Held, "RETENTION_CONFIG_INCOMPLETE"):
            self.call(retention.BATCH)
        self.assertEqual(len(self.work), 1)
        self.assertFalse((self.root / (retention.BATCH + ".worker.json")).exists())


class PrivateWorker(RetentionFixture):
    def batch_config(self):
        self.release.rt.docs[fixture.OLD]["HostConfig"]["LogConfig"] = {
            "Type": "splunk", "Config": {"splunk-token": "fixture"}}
        return super().batch_config()

    def test_DEP_58QL_15_retention_worker_request(self):
        from module_release import public_output
        p = self.release.p
        self.call(retention.ADMIN)
        plan = json.loads((self.root / "plan.json").read_bytes())
        claim = json.loads((self.root / (retention.ADMIN + ".worker.json")).read_bytes())
        with public_output.scope(p):
            public_output.use_plan(plan)
            self.assertEqual(claim["requestSha256"], public_output.fingerprint("retention-request", self.work[0]))


class Retention(RetentionFixture):
    def test_dep_55j_01_owner_and_acl(self):
        """DEP-55J-01 — separate human review, observed function and owner/ACL."""
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            self.call(retention.ADMIN, approved=False)
        self.assertFalse(self.work)
        self.assertEqual(self.call(retention.ADMIN)["retentionReview"], self.expected)
        self.assertEqual(operation.read(self.root, "retention-admin-019.json"), self.expected)
        for field, value in (("permitted", False), ("definition", "changed"), ("acl", "different ACL")):
            with self.subTest(field=field), patch.dict(self.rows[0], {field: value}), self.assertRaisesRegex(
                    mandate.Held, "RETENTION_(FUNCTION_OR_ACL|CATALOG)_DRIFT"):
                self.call(retention.ADMIN, run=str(10 + len(self.release.approvals)))
        self.assertEqual(len(self.work), 1)

    def test_dep_55j_01_overload_drift_before_admin_starts(self):
        four, five = self.overloads
        for rows in ([four], [five], [four, five, dict(five, arity=6)], [four, dict(five, arity=4)],
                     [dict(four, permitted=False), five], [four, dict(five, permitted=False)],
                     [four, dict(five, definition="different argument type")]):
            self.rows[:] = rows
            with self.subTest(rows=rows), self.assertRaisesRegex(mandate.Held, "RETENTION_FUNCTION_OR_ACL_DRIFT"):
                self.call(retention.ADMIN, run=str(10 + len(self.release.approvals)))
            self.assertFalse(self.work)
            self.assertFalse((self.root / retention.RECEIPT).exists())
        spec = self.release.p["migration"]["retentionAdmin019"]
        self.assertCountEqual(retention.verified_routines(spec, [five, four]),
                              [digest(row["schemaItem"]) for row in self.overloads])

    def test_dep_55j_02_maintenance_batch(self):
        """DEP-55J-02 — one exact candidate, distinct SQL identities and mounts."""
        self.call(retention.ADMIN)
        self.assertEqual(self.call(retention.BATCH)["status"], "SUCCEEDED")
        admin, batch = self.work
        self.assertEqual([admin["Cmd"], batch["Cmd"]], [["migrate-analysis-retention-019"], ["analysis-retention-once"]])
        variable, _, value = batch["Env"][0].partition("=")
        self.assertEqual(variable, "FIXTURE_WORKER_DATABASE_URL")
        url = urlsplit(value)
        self.assertEqual(url.username, "worker_fixture")
        self.assertIn("options=-c%20role%3Dmaintenance_fixture", url.query)
        self.assertEqual(parse_qs(url.query)["options"], ["-c role=maintenance_fixture"])
        def environment(request):
            return dict(entry.split("=", 1) for entry in request["Env"])
        admin_env, batch_env = environment(admin), environment(batch)
        self.assertEqual(admin_env, {"MCP_DATABASE_URL": "postgresql://admin_fixture@pg_fixture/fixture?sslmode=require",
                                     "PGPASSFILE": "/run/ouf-retention.pgpass", "MCP_MIGRATION_DATABASE_OID": "42",
                                     "MCP_MIGRATION_APPLICATION_ROLE": "app_fixture"})
        self.assertEqual(batch_env, {"FIXTURE_WORKER_DATABASE_URL": value, "PGPASSFILE": "/run/ouf-retention.pgpass",
                                     **BATCH_CONFIG})
        self.assertEqual(batch["HostConfig"]["Mounts"][0]["Source"], str(self.release.root / "worker"))
        self.assertEqual(batch["HostConfig"]["NetworkMode"], "container:" + fixture.NEW)
        self.assertNotIn("admin_fixture", str(batch))

    def test_dep_55j_03_receipt_required(self):
        """DEP-55J-03 — an ordinary READY release grants no authority for a batch."""
        with self.assertRaises(mandate.Held):
            self.call(retention.BATCH, run="2")
        self.assertFalse(self.work)
        self.call(retention.ADMIN)
        (self.root / "retention-admin-019.json").unlink()
        with self.assertRaisesRegex(mandate.Held, "RETENTION_RECEIPT_DRIFT"):
            self.call(retention.BATCH)
        self.assertEqual(len(self.work), 1)

    def run_batch(self):
        ready = operation.read(self.root, "receipt.json")
        retention.run(self.release.p, self.release.rt, self.source, retention.BATCH, ready)

    def test_dep_55j_04_drift_or_ambiguous_output(self):
        """DEP-55J-04 — check every receipt field, malformed results and live DB drift."""
        good = self.logs.return_value.stdout
        without_status = json.loads(good)
        del without_status["status"]
        for run, bad in enumerate((good + good, json.dumps(without_status).encode(), good.replace(b'VERIFIED', b'HELD'),
                                   good.replace(b'a'*64, b'f'*64)), 10):
            self.logs.return_value.stdout = bad
            with self.assertRaises(mandate.Held):
                self.call(retention.ADMIN, run=str(run))
            self.assertFalse((self.root / "retention-admin-019.json").exists())
        self.logs.return_value.stdout = good
        self.call(retention.ADMIN, run="5")
        file = self.root / "retention-admin-019.json"
        for field in self.expected:
            with self.subTest(field=field):
                file.write_text(json.dumps({**self.expected, field: "different"}))
                with self.assertRaisesRegex(Held, "RETENTION_RECEIPT_DRIFT"):
                    self.run_batch()
        file.write_text(json.dumps(self.expected))
        self.release.db["schema"].append("unreviewed")
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call(retention.BATCH, run="5")
        self.assertEqual(len(self.work), 1)

    def test_dep_55j_04_batch_requires_verified_output(self):
        self.call(retention.ADMIN)
        for bad in (b'{}', b'{"status":"HELD"}', b'{"status":"VERIFIED","status":"VERIFIED"}', b'not JSON'):
            self.logs.return_value.stdout = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(Held, "RETENTION_OUTPUT_UNCONFIRMED"):
                self.run_batch()
            self.assertFalse((self.root / "retention-batch.json").exists())
        self.logs.return_value.stdout = b'{"status":"VERIFIED"}'
        self.run_batch()
        self.assertEqual(len(self.work), 2)

    def test_dep_55j_05_crash_after_commit(self):
        """DEP-55J-05 — fresh approved dispatch reconciles both exited one-shots."""
        self.crash = retention.COMMAND[retention.ADMIN]
        with self.assertRaises(KeyboardInterrupt):
            self.call(retention.ADMIN)
        self.assertFalse((self.root / "retention-admin-019.json").exists())
        self.assertEqual(self.call(retention.ADMIN, run="2")["status"], "VERIFIED")
        self.crash = retention.BATCH
        with self.assertRaises(KeyboardInterrupt):
            self.call(retention.BATCH, run="2")
        self.call(retention.ADMIN, run="3")
        self.assertEqual(self.call(retention.BATCH, run="3")["status"], "SUCCEEDED")
        self.assertEqual(len(self.work), 2)

    def test_dep_55j_05_crash_before_start_resumes_same_worker(self):
        rt = self.release.rt
        for phase, run in ((retention.ADMIN, "2"), (retention.BATCH, "3")):
            with patch.object(rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                self.call(phase, run=run)
            cid = operation.read(self.root, phase + ".start.json")["cid"]
            self.assertTrue(operation.never_started(rt.inspect(cid)))
            if phase == retention.BATCH:
                self.call(retention.ADMIN, run="4")
            with patch.object(rt, "start", wraps=rt.start) as start:
                self.call(phase, run="4" if phase == retention.BATCH else "3")
                start.assert_called_once_with(cid)
        self.assertEqual(len(self.work), 2)

    def test_dep_55j_05_only_never_started_worker_allows_other_phases(self):
        f = self.release
        with patch.object(f.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.call(retention.ADMIN)
        cid = operation.read(self.root, retention.ADMIN + ".start.json")["cid"]
        state = f.rt.docs[cid]["State"]
        for phase, reason in (("apply", "APPROVED_PLAN_DRIFT"), ("migrate", "APPROVED_MIGRATION_DRIFT"),
                              ("rollback", "ROLLBACK_CHECK_REACHED")):
            req = dict(f.req, phase=phase, digest="0"*64)
            handler = ModuleRelease(f.cfg, f.root, req)
            with patch("module_operation.return_operation.run", side_effect=Held("ROLLBACK_CHECK_REACHED")):
                with self.subTest(phase=phase), self.assertRaisesRegex((Held, mandate.Held), reason):
                    handler.execute_phase("review")
                for changed in ({"Status": "running"}, {"StartedAt": "2026-11-24T00:00:00Z"}):
                    with patch.dict(state, changed), self.assertRaisesRegex(mandate.Held, "RETENTION_WORKER_IN_FLIGHT"):
                        handler.execute_phase("review")
