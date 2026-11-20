"""MCP publisher, PostgreSQL contracts and governed release/return on offline fixtures."""
import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from test_module_release import Engine, ROOT, OLD, NEW
from test_mcp_image_swap import bundle
import mandate
import store
from module_release import operation, postgres, return_operation, transport
from module_release.contract import Held, digest, package


class Release(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        p = self.p = json.loads((ROOT / "config/module-release/mcp.example.json").read_bytes())
        p.update(inbox=temp.name, journal=temp.name, dockerSocket=str(self.root / "docker.sock"),
                 nsenter=str(self.root / "nsenter"), oldImage="sha256:" + "a"*64)
        next(iter(p["networks"].values()))["ipv4"] = "192.0.2.2"
        p["readiness"]["attempts"] = 2
        p["migration"]["rollbackCompatible"] = True
        p["migration"]["database"].update(postgresCid="3"*64, socket="/run/postgresql")
        self.archive = self.make_artifact()
        with zipfile.ZipFile(self.archive) as z:
            self.rt = Engine(p, z.read("image.tar.gz"))
        self.db = {"databaseOid": "42", "tables": True, "history": [[i, "1"*64, "UTC"] for i in range(1, 15)],
                   "schema": ["relation", "column"]}
        self.rt.database = lambda old: copy.deepcopy(self.db)
        self.cfg = dict(repositoryId=10, environmentId=20, branch="protected", environment="test",
                        reviewerIds=[30], commit="a"*40, modules={"mcp": p})
        self.req = dict(run="1", attempt="1", commit=self.cfg["commit"], operation="module-release",
                        module="mcp", phase="plan")
        self.req["digest"] = mandate.intent(self.req)
        self.dispatch = runpy.run_path(str(ROOT / "scripts/ouf-a2-executor"))["dispatch"]
        self.enterContext(patch.object(operation, "Docker", return_value=self.rt))
        self.enterContext(patch.object(return_operation, "Docker", return_value=self.rt))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: path))
        self.enterContext(patch.object(store, "sync_dir"))

    def make_artifact(self, broken=False):
        path = self.root / "candidate.zip"
        pins = bundle(path, broken_sums=broken)
        ci = self.p["ci"]
        ci.update({key: pins[key] for key in ("runId", "artifactId", "sourceCommit", "sourceTree",
                                               "publisherCommit", "zipSha256", "imageId")}, runAttempt=1)
        path = path.replace(self.root / (ci["zipSha256"] + ".zip"))
        if not broken:
            ci["transportSha256"] = package(self.p, transport=True)["transportSha256"]
        return path

    def call(self, phase, stamp, *, approved=True, run="1"):
        self.req.update(run=run, phase=phase, digest=stamp)
        cfg = self.cfg
        job = dict(id=int(run), run_attempt=1, event="workflow_dispatch", status="in_progress",
                   path=mandate.module_workflow("mcp"), head_branch=cfg["branch"], head_sha=cfg["commit"],
                   repository={"id": 10}, head_repository={"id": 10})
        user = {"type": "User", "id": 30}
        env = dict(id=20, name="test", protection_rules=[dict(type="required_reviewers",
                   reviewers=[dict(type="User", reviewer=user)])])
        review = dict(state="approved", comment=mandate.challenge(self.req), user=user, environments=[env])
        get = Mock(side_effect=[job, dict(protected=True, commit={"sha": cfg["commit"]}), env,
                                [review] if approved else []])
        return self.dispatch(self.req, cfg, self.root, get)

    def planned(self):
        return self.call("plan", self.req["digest"])

    def dedicated(self):
        m = self.p["migration"]
        m.update(mode="dedicated", command=["/usr/local/bin/ouf-mcp", "migrate"],
                 migrations=[dict(version=15, checksum="f"*64)],
                 targetSchemaSha256=digest(sorted(map(digest, [*self.db["schema"], "new column"]))))
        def migrate(cid, command):
            self.assertIn(cid, self.rt.gates)
            self.assertEqual(command, m["command"])
            self.rt.events.append("migrate")
            self.db["schema"].append("new column")
            self.db["history"].append([15, "f"*64, "UTC"])
        self.rt.migrate = migrate

    def test_reviewed_90_ready_and_reviewed_return(self):
        plan = self.planned()
        self.assertEqual(plan["databaseReview"]["migrations"], [])
        stamp = plan["digest"]
        with self.assertRaisesRegex(mandate.Held, "APPROVED_PLAN_DRIFT"):
            self.call("apply", "1"*64)
        self.assertNotIn("load", self.rt.events)
        self.assertEqual(self.call("apply", stamp)["status"], "READY")
        candidate = self.rt.inspect(self.p["container"])
        self.assertEqual(candidate["Id"], NEW)
        self.assertEqual(candidate["Config"]["Labels"]["ouf.mcp.analysis-source"], self.p["ci"]["sourceCommit"])
        receipt = json.loads((self.root / stamp / "receipt.json").read_bytes())
        self.assertEqual(receipt["readyHttp"], 204)
        self.assertTrue(all(b"KEEP=fixture" not in path.read_bytes()
                            for path in (self.root / stamp).glob("*.json")))
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            self.call("rollback", stamp, approved=False, run="2")
        self.assertNotIn("stop:2", self.rt.events)
        self.assertEqual(self.call("rollback", stamp, run="2")["status"], "ROLLED_BACK")
        self.assertEqual(self.rt.inspect(self.p["container"])["Id"], OLD)
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        with self.assertRaisesRegex(mandate.Held, "RETURN_ALREADY_CONSUMED"):
            self.call("rollback", stamp, run="3")

    def test_migration_requires_exact_review_and_verifies_additions(self):
        self.dedicated()
        plan = self.planned()
        self.assertEqual(plan["databaseReview"]["migrations"], self.p["migration"]["migrations"])
        self.assertEqual(plan["databaseReview"]["migrationsSha256"], digest(self.p["migration"]["migrations"]))
        stage = self.call("apply", plan["digest"])
        self.assertEqual(stage["status"], "GATED")
        with self.assertRaisesRegex(mandate.Held, "APPROVED_MIGRATION_DRIFT"):
            self.call("migrate", "1"*64)
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            self.call("migrate", stage["digest"], approved=False)
        self.assertFalse(any(action.startswith("signal:") or action == "migrate" for action in self.rt.events))
        self.assertEqual(self.call("migrate", stage["digest"])["status"], "READY")
        self.assertLess(self.rt.events.index("migrate"), self.rt.events.index("signal:2"))
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call("rollback", plan["digest"], run="2")
        self.assertNotIn("stop:2", self.rt.events)
        self.assertNotIn("signal:1", self.rt.events)
        self.assertTrue((self.root / "mcp.lock").is_dir())

    def test_confirmed_migration_failure_returns_when_database_unchanged(self):
        self.dedicated()
        self.rt.migrate = Mock(side_effect=Held("MIGRATION_FAILED"))
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        with self.assertRaisesRegex(mandate.Held, "MIGRATION_FAILED"):
            self.call("migrate", stage["digest"])
        receipt = json.loads((self.root / stamp / "receipt.json").read_bytes())
        self.assertEqual((receipt["rollback"], receipt["predecessorReadyHttp"]), ("ROLLED_BACK", 204))
        self.assertNotIn("signal:2", self.rt.events)

    def test_rollback_refuses_restarted_successor_before_stop(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        self.rt.docs[NEW]["State"]["StartedAt"] = "another generation"
        with self.assertRaisesRegex(mandate.Held, "IMMEDIATE_SUCCESSOR_CHANGED"):
            self.call("rollback", stamp, run="2")
        self.assertNotIn("stop:2", self.rt.events)

    def test_wrong_post_schema_holds_at_gate_before_either_signal(self):
        self.dedicated()
        self.p["migration"]["targetSchemaSha256"] = "e"*64
        plan = self.planned()
        stage = self.call("apply", plan["digest"])
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call("migrate", stage["digest"])
        self.assertEqual(self.rt.gates, {NEW})
        self.assertNotIn("stop:2", self.rt.events)

    def test_return_checks_history_and_schema_even_on_failed_readiness(self):
        probe = self.rt.probe
        def failed(doc):
            if doc["Id"] == NEW:
                self.db["history"][0][2] = "changed"
                return 503, b""
            return probe(doc)
        self.rt.probe = failed
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call("apply", self.planned()["digest"])
        self.assertNotIn("stop:2", self.rt.events)
        self.assertEqual(self.rt.inspect(self.p["retainedName"])["Id"], OLD)

    def test_return_fails_before_candidate_stop_on_schema_only_drift(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        self.db["schema"].append("unreviewed change")
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            self.call("rollback", stamp, run="2")
        self.assertNotIn("stop:2", self.rt.events)

    def test_migration_plan_changed(self):
        self.dedicated()
        stamp = self.planned()["digest"]
        self.p["migration"]["migrations"][0]["checksum"] = "a"*64
        self.assertEqual(operation.apply(self.p, stamp, self.rt)["reason"], "PLAN_CHANGED")
        self.assertNotIn("load", self.rt.events)

    def test_other_source_run_cannot_reuse_package_with_valid_hashes(self):
        self.p["ci"]["runId"] += 1
        self.assertEqual(operation.plan(self.p, self.rt)["reason"], "TRANSPORT_PROVENANCE_CHANGED")

    def test_r033_envelope_checksum_and_publisher_commit(self):
        self.p["ci"]["publisherCommit"] = "e"*40
        self.assertEqual(operation.plan(self.p, self.rt)["reason"], "CI_PROVENANCE_CHANGED")
        self.make_artifact(broken=True)
        self.assertEqual(operation.plan(self.p, self.rt)["reason"], "PUBLISHER_CHECKSUMS_CHANGED")
        self.assertEqual(self.rt.events, [])

    def test_transport_checks_acquisition_artifact_repo_pr_trees(self):
        ci = self.p["ci"]
        repo = {"full_name": ci["repository"]}
        obj = dict(id=101, expired=False, workflow_run=dict(id=100, head_sha=ci["sourceCommit"]),
                   name="acquisition-mcp-image-100", digest="sha256:" + ci["zipSha256"])
        run = dict(id=100, status="completed", conclusion="success", event="pull_request",
                   path=".github/workflows/ci.yml", head_sha=ci["sourceCommit"], run_attempt=1,
                   repository=repo, head_repository=repo, pull_requests=[dict(number=90, head={"sha": ci["sourceCommit"], "ref": ci["sourceBranch"]})])
        commit = dict(sha=ci["publisherCommit"], parents=[], tree={"sha": ci["sourceTree"]})
        def github(path, out=None):
            if out:
                out.write(self.archive.read_bytes())
                return
            if "/git/commits/" in path:
                return commit
            return run if path.endswith("runs/100") else obj
        with patch.object(transport, "github", side_effect=github):
            self.assertEqual(transport.transport(self.p, 100, 101, self.root)["publisherImageId"][:7], "sha256:")
            commit["tree"]["sha"] = "e"*40
            with self.assertRaisesRegex(Held, "TESTED_TREE_CHANGED"):
                transport.transport(self.p, 100, 101, self.root)
            obj["name"] = "acquisition-mcp-image-99"
            with self.assertRaisesRegex(Held, "CI_ARTIFACT_CHANGED"):
                transport.transport(self.p, 100, 101, self.root)

    def test_reader_binds_app_dsn_and_uses_read_only_sql(self):
        old = self.rt.inspect(OLD)
        old["Config"]["Env"] = ["MCP_DATABASE_URL=postgresql://reader@pg/app?sslmode=require"]
        net = next(iter(old["NetworkSettings"]["Networks"].values()))
        binding = self.p["migration"]["database"]
        pg = dict(Id=binding["postgresCid"], State={"Running": True}, Name="/pg",
                  NetworkSettings={"Networks": {"db": net}})
        with patch.object(postgres.subprocess, "run", return_value=Mock(returncode=0,
                          stdout=json.dumps(self.db).encode())) as call:
            self.assertEqual(postgres.database_snapshot("socket", binding, old, pg), self.db)
            args, kwargs = call.call_args
            self.assertEqual(args[0][-4:], ["-U", "reader", "-d", "app"])
            self.assertIn(b"REPEATABLE READ READ ONLY", kwargs["input"])
            old["Config"]["Env"][0] += "&host=another-db"
            with self.assertRaisesRegex(Held, "DATABASE_BINDING_CHANGED"):
                postgres.database_snapshot("socket", binding, old, pg)
            pg["Id"] = "4"*64
            with self.assertRaisesRegex(Held, "POSTGRES_CHANGED"):
                postgres.database_snapshot("socket", binding, old, pg)
            self.assertEqual(call.call_count, 1)
