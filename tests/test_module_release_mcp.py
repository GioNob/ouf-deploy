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
from platform_restart import identity


class Release(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        p = self.p = json.loads((ROOT / "tests/fixtures/module-release/mcp.example.json").read_bytes())
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
                        reviewerIds=[30], commit="a"*40, runner="fixture", modules={"mcp": p})
        self.req = dict(run="1", attempt="1", commit=self.cfg["commit"], operation="module-release",
                        module="mcp", phase="plan")
        self.req["digest"] = mandate.intent(self.req)
        self.approvals = {}
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
        review = dict(state="approved", comment="", user=user, environments=[env])
        history = self.approvals.setdefault(run, [])
        if approved:
            history.append(review)
        jobs = {"jobs": [dict(status="in_progress", runner_name="fixture",
                              name=phase + " " + self.req["digest"])]}
        get = Mock(side_effect=[job, jobs, dict(protected=True, commit={"sha": cfg["commit"]}), env, history])
        return self.dispatch(self.req, cfg, self.root, get)

    def planned(self):
        return self.call("plan", self.req["digest"], approved=False)

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

    def recover(self, run="2"):
        request = dict(self.req, run=run, phase="plan")
        plan = self.call("plan", mandate.intent(request), approved=False, run=run)
        return self.call("apply", plan["digest"], run=run)

    def test_crash_after_create_and_after_signal_reuses_one_cid(self):
        stamp = self.planned()["digest"]
        with patch.object(self.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.call("apply", stamp)
        self.assertEqual(self.rt.inspect(NEW)["State"]["Status"], "created")
        signal = self.rt.signal
        def lost_response(cid):
            signal(cid)
            raise KeyboardInterrupt
        with patch.object(self.rt, "signal", side_effect=lost_response), self.assertRaises(KeyboardInterrupt):
            self.recover()
        source = operation.read(self.root / stamp, "plan.json")
        self.assertEqual(self.recover("3"), {"status": "READY", "digest": stamp,
                                             "candidateImageId": source["ci"]["imageId"],
                                             "predecessorImageId": source["oldImage"]})
        self.assertEqual(self.rt.events.count("create"), 1)
        self.assertEqual(self.rt.events.count("signal:2"), 1)
        self.assertEqual(operation.read(self.root / stamp, "receipt.json")["readyHttp"], 204)

    def test_start_without_generation_receipt_holds_same_cid_without_signal(self):
        stamp = self.planned()["digest"]
        start = self.rt.start
        def started(cid):
            start(cid)
            raise KeyboardInterrupt
        with patch.object(self.rt, "start", side_effect=started), self.assertRaises(KeyboardInterrupt):
            self.call("apply", stamp)
        with self.assertRaisesRegex(mandate.Held, "START_GENERATION_UNCONFIRMED.*owner=mcp"):
            self.recover()
        self.assertEqual(self.rt.gates, {NEW})
        self.assertNotIn("signal:2", self.rt.events)

    def test_crash_after_detach_restores_original_predecessor(self):
        stamp = self.planned()["digest"]
        detach = self.rt.disconnect
        def interrupted(cid, network):
            detach(cid, network)
            raise KeyboardInterrupt
        with patch.object(self.rt, "disconnect", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.call("apply", stamp)
        with self.assertRaisesRegex(mandate.Held, "INTERRUPTED_RELEASE_RESTORED"):
            self.recover()
        receipt = operation.read(self.root / stamp, "receipt.json")
        self.assertEqual((receipt["restoredCid"], receipt["predecessorReadyHttp"]), (OLD, 204))
        self.assertNotIn("create", self.rt.events)

    def test_missing_migration_receipt_reconciles_exact_history(self):
        self.dedicated()
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        migrate = self.rt.migrate
        def interrupted(cid, argv):
            migrate(cid, argv)
            raise KeyboardInterrupt
        with patch.object(self.rt, "migrate", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.call("migrate", stage["digest"])
        self.assertFalse((self.root / stamp / "migration-complete.json").exists())
        stage2 = self.recover()
        self.assertEqual(stage2, stage)
        self.assertEqual(self.call("migrate", stage2["digest"], run="2")["status"], "READY")
        self.assertEqual(self.rt.events.count("migrate"), 1)
        self.assertEqual(self.rt.events.count("signal:2"), 1)

    def test_recovery_apply_rechecks_reviewed_live_frames_before_start(self):
        with patch.object(self.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.call("apply", self.planned()["digest"])
        req = dict(self.req, run="2", phase="plan")
        plan = self.call("plan", mandate.intent(req), approved=False, run="2")
        self.rt.docs[NEW]["Config"]["Env"].append("DRIFT=1")
        with self.assertRaisesRegex(mandate.Held, "RECOVERY_PLAN_CHANGED.*owner=mcp"):
            self.call("apply", plan["digest"], run="2")
        self.assertNotIn("gate:2", self.rt.events)
        with self.assertRaisesRegex(mandate.Held, "CONFIGURATION_DELTA.*owner=mcp"):
            self.recover("3")
        self.assertNotIn("gate:2", self.rt.events)

    def test_lost_migration_receipt_with_other_checksum_holds_both_cids(self):
        self.dedicated()
        stamp = self.planned()["digest"]
        stage = self.call("apply", stamp)
        migrate = self.rt.migrate
        def interrupted(cid, argv):
            migrate(cid, argv)
            self.db["history"][-1][1] = "a" * 64
            raise KeyboardInterrupt
        with patch.object(self.rt, "migrate", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.call("migrate", stage["digest"])
        resumed = self.recover()
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED.*owner=mcp"):
            self.call("migrate", resumed["digest"], run="2")
        self.assertEqual(self.rt.events.count("migrate"), 1)
        self.assertEqual(self.rt.gates, {NEW})
        self.assertFalse(self.rt.docs[OLD]["State"]["Running"])

    def test_create_response_without_cid_has_public_residual(self):
        self.rt.fault = "lost_create"
        with self.assertRaisesRegex(mandate.Held, "owner=mcp.*container=created"):
            self.call("apply", self.planned()["digest"])
        held = operation.read(self.root / "1", "apply.held")
        self.assertRegex(held["reason"], r"/OSError@operation\.py:[0-9]+")
        self.assertEqual(held["residual"]["container"]["cid"], NEW)
        self.assertEqual(held["residual"]["retainedName"]["state"], "exited")
        self.assertEqual(self.rt.events.count("create"), 1)

    def test_crash_after_return_signal_observes_original_generation(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        signal = self.rt.signal
        def interrupted(cid):
            signal(cid)
            raise KeyboardInterrupt
        with patch.object(self.rt, "signal", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        self.assertEqual(self.rt.events.count("signal:1"), 1)

    def test_reviewed_90_ready_and_reviewed_return(self):
        plan = self.planned()
        self.assertEqual(plan["databaseReview"]["migrations"], [])
        stamp = plan["digest"]
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
        before = list(self.rt.events)
        self.assertEqual(self.call("rollback", stamp, run="3")["status"], "ROLLED_BACK")
        self.assertEqual(store.read(self.root / "3/rollback.result"), store.read(self.root / "2/rollback.result"))
        self.assertEqual(self.rt.events, before)

    def test_apply_with_wrong_digest_consumes_review_before_effect(self):
        self.planned()
        with self.assertRaisesRegex(mandate.Held, "APPROVED_PLAN_DRIFT"):
            self.call("apply", "1"*64)
        self.assertNotIn("load", self.rt.events)
        with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
            self.call("apply", "1"*64, approved=False)

    def exercise_apply_return(self, statuses, expected_error):
        stamp = self.planned()["digest"]
        self.rt.fault = "handler"  # Candidate never proves its gate.
        normal_probe = self.rt.probe
        responses = iter(statuses)

        def probe(doc):
            status, body = normal_probe(doc)
            if doc["Id"] == OLD and "gate:1" in self.rt.events:
                self.assertNotIn(OLD, self.rt.gates)
                return next(responses), b""
            return status, body

        with patch.object(self.rt, "probe", side_effect=probe), self.assertRaisesRegex(mandate.Held, expected_error):
            self.call("apply", stamp)
        self.assertNotIn("signal:2", self.rt.events)
        self.assertEqual(self.rt.events[self.rt.events.index("gate:1"):],
                         ["gate:1", "signal:1", "probe:1", "probe:1"])
        root = self.root / stamp
        self.assertEqual(json.loads((root / "restore-signal.json").read_bytes())["cid"], OLD)
        return json.loads((root / "receipt.json").read_bytes())

    def test_apply_return_waits_for_predecessor_204(self):
        receipt = self.exercise_apply_return([503, 204], "GATE_NOT_PROVEN")
        self.assertEqual((receipt["rollback"], receipt["restoredCid"], receipt["predecessorReadyHttp"]),
                         ("ROLLED_BACK", OLD, 204))

    def test_apply_return_without_predecessor_readiness_is_held(self):
        receipt = self.exercise_apply_return([503, 200], "PREDECESSOR_READINESS_NOT_UP")
        self.assertEqual((receipt["status"], receipt["reason"], receipt["rollback"], receipt["rollbackReason"]),
                         ("HELD", "GATE_NOT_PROVEN", "HELD", "PREDECESSOR_READINESS_NOT_UP"))
        self.assertNotIn("predecessorReadiness", receipt)
        self.assertNotIn("restoredCid", receipt)
        self.assertTrue((self.root / "mcp.lock").is_dir())

    def test_migrate_with_wrong_digest_holds_at_gate(self):
        self.dedicated()
        self.call("apply", self.planned()["digest"])
        with self.assertRaisesRegex(mandate.Held, "APPROVED_MIGRATION_DRIFT"):
            self.call("migrate", "1"*64)
        self.assertFalse(any(action.startswith("signal:") or action == "migrate" for action in self.rt.events))

    def test_migration_requires_new_review_and_verifies_additions(self):
        self.dedicated()
        plan = self.planned()
        self.assertEqual(plan["databaseReview"]["migrations"], self.p["migration"]["migrations"])
        self.assertEqual(plan["databaseReview"]["migrationsSha256"], digest(self.p["migration"]["migrations"]))
        stage = self.call("apply", plan["digest"])
        self.assertEqual(stage["status"], "GATED")
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
        self.assertEqual(self.rt.events[self.rt.events.index("gate:1"):], ["gate:1", "signal:1", "probe:1"])

    def test_unsigned_return_receipt_with_owned_lock_completes_once(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        with patch.object(return_operation, "unlock_module", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.call("rollback", stamp, run="2")
        root = self.root / stamp
        published = (root / "return-receipt.json").read_bytes()
        with patch.object(self.rt, "probe", return_value=(503, b"")), \
                self.assertRaisesRegex(mandate.Held, "RETURN_READINESS_CHANGED"):
            self.call("rollback", stamp, run="3")
        held = self.root / "3/rollback.held"
        evidence = held.read_bytes()
        self.assertEqual(json.loads(evidence)["reason"], "RETURN_READINESS_CHANGED")
        self.assertFalse((self.root / "3/rollback.result").exists())
        self.assertEqual(store.read(self.root / "mcp.lock/owner.json"), {"planSha256": stamp})
        before = len(self.rt.events)
        self.assertEqual(self.call("rollback", stamp, run="4")["status"], "ROLLED_BACK")
        self.assertEqual(held.read_bytes(), evidence)
        self.assertEqual((root / "return-receipt.json").read_bytes(), published)
        for run in ("2", "3", "4"):
            self.assertEqual(store.read(self.root / run / "rollback.result"), json.loads(published))
        self.assertFalse(list(root.glob("*.ed25519")))
        self.assertFalse((self.root / "mcp.lock").exists())
        self.assertEqual(self.rt.events[before:], ["probe:1"])
        with patch.object(identity, "custody"):
            _, terminal = identity.module_history(self.root, self.root, "mcp")
        self.assertEqual(terminal, root / "return-receipt.json")

    def test_rollback_refuses_restarted_successor_before_stop(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        self.rt.docs[NEW]["State"]["StartedAt"] = "another generation"
        with self.assertRaisesRegex(mandate.Held, "IMMEDIATE_SUCCESSOR_CHANGED"):
            self.call("rollback", stamp, run="2")
        self.assertNotIn("stop:2", self.rt.events)

    def test_replay_without_original_approval_cannot_become_a_recovery(self):
        stamp = self.planned()["digest"]
        self.call("apply", stamp)
        self.call("rollback", stamp, run="2")
        (self.root / "2/rollback.review").unlink()
        before = list(self.rt.events)
        for run in ("3", "4"):
            with self.assertRaisesRegex(mandate.Held, "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE"):
                self.call("rollback", stamp, run=run)
            self.assertTrue(store.read(self.root / run / "rollback.review")["returnAlreadyConsumed"])
            self.assertFalse((self.root / run / "rollback.result").exists())
        self.assertEqual(self.rt.events, before)

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
        # The artifact was built on the publisher's test commit, a child of the reviewed PR head.
        ci["sourceCommit"] = "e"*40
        repo = {"full_name": ci["repository"]}
        obj = dict(id=101, expired=False, workflow_run=dict(id=100, head_sha=ci["publisherCommit"]),
                   created_at="2026-11-20T13:01:00Z",
                   name="acquisition-mcp-image-100", digest="sha256:" + ci["zipSha256"])
        run = dict(id=100, status="completed", conclusion="success", event="pull_request",
                   path=".github/workflows/ci.yml", head_sha=ci["publisherCommit"], run_attempt=2,
                   run_started_at="2026-11-20T13:00:00Z",
                   repository=repo, head_repository=repo, pull_requests=[dict(number=90, head={"sha": ci["sourceCommit"], "ref": ci["sourceBranch"]})])
        commit = dict(sha=ci["publisherCommit"], parents=[{"sha": ci["sourceCommit"]}], tree={"sha": ci["sourceTree"]})
        source = dict(sha=ci["sourceCommit"], tree={"sha": ci["sourceTree"]})
        def github(path, out=None):
            if out:
                out.write(self.archive.read_bytes())
                return
            if "/git/commits/" in path:
                return source if path.endswith(ci["sourceCommit"]) else commit
            return run if path.endswith("runs/100") else obj
        with patch.object(transport, "github", side_effect=github):
            self.assertEqual(transport.transport(self.p, 100, 101, self.root)["publisherImageId"][:7], "sha256:")
            with patch.dict(obj, created_at="2026-11-20T12:59:59Z"), self.assertRaisesRegex(Held, "ARTIFACT_ATTEMPT_CHANGED"):
                transport.transport(self.p, 100, 101, self.root)
            with patch.dict(run["pull_requests"][0]["head"], ref="other"), self.assertRaisesRegex(Held, "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED"):
                transport.transport(self.p, 100, 101, self.root)
            with patch.dict(source["tree"], sha="f"*40), self.assertRaisesRegex(Held, "SOURCE_TREE_CHANGED"):
                transport.transport(self.p, 100, 101, self.root)
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
