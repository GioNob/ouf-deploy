"""Offline protocol replay and opt-in Linux pidfd exercise (no target service)."""
import copy
from contextlib import nullcontext
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path[:0] = [str(ROOT / "tools" / subdir) for subdir in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover")]
import mandate
import pipeline
import queue_inventory as queue
import runbooks
import semantic
import store


def frame():
    cid = "a"*64
    return dict(Id=cid, Name="/app", Image="sha256:"+"b"*64, Path="/bin/sh", Args=[], Mounts=[],
        Config=dict(Image="sha256:"+"b"*64, User="10001:10001", Hostname=cid[:12], Entrypoint=semantic.ENTRY,
                    Cmd=["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"],
                    Env=["OUF_DISCOVERY_WORKER_ENABLED=false", "OUF_SCHEMA_GOV_ENABLED=true", "KEEP=yes"]),
        HostConfig=dict(NetworkMode="fixture", Privileged=False, AutoRemove=False, RestartPolicy={"Name":"no"}),
        NetworkSettings={"Networks": {"fixture": {"NetworkID": "c"*64, "IPAddress": "address",
            "IPAMConfig": {"IPv4Address": "address"}, "Aliases": ["alias"]}}})


class Review(unittest.TestCase):
    def setUp(self):
        self.req = dict(run="123", commit="a"*40, attempt="1", phase="plan", direction="forward", queue="empty")
        self.req["digest"] = mandate.intent(self.req)
        self.cfg = dict(repositoryId=17, environment="private", environmentId=4, reviewerIds=[8],
                        commit=self.req["commit"], branch="protected", runner="local", runnerName="vps")
        self.run = dict(id=123, run_attempt=1, event="workflow_dispatch", status="in_progress",
                        head_sha=self.req["commit"], head_branch="protected", path=mandate.WORKFLOW,
                        repository={"id":17}, head_repository={"id":17})
        self.env = dict(id=4, name="private", protection_rules=[dict(type="required_reviewers",
            reviewers=[dict(type="User", reviewer={"id":8})])])
        self.reviews = [dict(state="approved", comment="", user={"id":8,"type":"User"},
                             environments=[{"id":4,"name":"private"}])]
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: path))
        self.enterContext(patch.object(store, "sync_dir"))
        self.effects = Mock()

    def invoke(self, req):
        jobs = {"jobs": [dict(status="in_progress", runner_name="vps", name=req["phase"] + " " + req["digest"])]}
        docs = [self.run, jobs, {"protected":True,"commit":{"sha":self.req["commit"]}}, self.env, self.reviews]
        get = Mock(side_effect=docs)
        review = mandate.authorize(req, self.cfg, get, self.state)
        if req["phase"] == "plan":
            self.assertEqual([call.args[0] for call in get.call_args_list], [
                "/actions/runs/" + req["run"], "/actions/runs/" + req["run"] + "/attempts/1/jobs?per_page=100",
                "/branches/protected", "/environments/private"])
        self.effects(review)
        return review

    def test_next_confirmation_belongs_to_the_reviewed_intent(self):
        req = dict(self.req, release="next", confirmNoReturn=False)
        req["digest"] = mandate.intent(req)
        self.invoke(req)
        with self.assertRaisesRegex(mandate.Held, "PLAN_INTENT_DRIFT"):
            mandate.validate(dict(req, confirmNoReturn=True), self.cfg)
        with self.assertRaisesRegex(mandate.Held, "RETURN_CONFIRMATION_FIELD"):
            mandate.validate(dict(req, confirmNoReturn="true"), self.cfg)

    def test_database_migration_workflow_and_single_approval(self):
        self.cfg["semanticDatabase"] = {}
        req = {k: v for k, v in self.req.items() if k not in ("direction", "queue")}
        req["operation"] = "semantic-database-migration"
        req["digest"] = mandate.intent(req)
        with self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
            self.invoke(req)
        self.run["path"] = ".github/workflows/semantic-database-migration.yml"
        self.invoke(req)
        req.update(phase="apply", digest="c"*64)
        with patch.object(self, "reviews", []), self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            self.invoke(req)
        self.invoke(req)
        with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
            self.invoke(req)

    def test_blank_comment_and_cumulative_reviewer_set(self):
        apply = dict(self.req, phase="apply")
        first = self.invoke(apply)
        self.assertEqual(first, mandate.digest(dict(mandate=apply, environmentId=4,
                                                    approvalIndex=1, reviewerIds=[8])))
        self.cfg["reviewerIds"].append(7)
        self.env["protection_rules"][0]["reviewers"].append(dict(type="User", reviewer={"id": 7}))
        self.reviews.insert(0, dict(self.reviews[0], user={"type": "User", "id": 7}, comment="Va bene"))
        migrate = dict(self.req, phase="migrate", digest="b" * 64)
        self.assertEqual(self.invoke(migrate), mandate.digest(dict(mandate=migrate, environmentId=4,
                                                               approvalIndex=2, reviewerIds=[7, 8])))

    def test_counts_and_phase_replay(self):
        approved = self.reviews[0]
        self.reviews = []
        self.assertEqual(self.invoke(self.req), mandate.digest({
            "mandate": self.req, "environmentId": 4, "approval": "none"}))
        ledger = self.state / "123" / "approvals"
        self.assertEqual(store.read(ledger), [])
        apply = dict(self.req, phase="apply")
        for count in (0, 2):
            self.reviews = [approved] * count
            with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
                self.invoke(apply)
        self.reviews = [approved]
        self.invoke(apply)
        self.reviews.append(approved)
        with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
            self.invoke(self.req)
        with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
            self.invoke(apply)
        self.assertEqual(store.read(ledger), ["apply"])
        self.assertEqual(self.effects.call_count, 2)

    def test_runs_consume_independently(self):
        self.invoke(dict(self.req, phase="apply"))
        self.run["id"] = 456
        req = dict(self.req, run="456", phase="apply")
        self.invoke(req)
        self.assertEqual(self.effects.call_count, 2)

    def test_failed_publication_prevents_dispatch(self):
        req = dict(self.req, phase="apply")
        with patch.object(store, "save", side_effect=OSError), self.assertRaises(OSError):
            self.invoke(req)
        self.effects.assert_not_called()
        with self.assertRaisesRegex(mandate.Held, "APPROVAL_JOURNAL_MISSING"):
            self.invoke(req)

    def test_directory_fsync_failure_after_publication_prevents_effect_and_reuse(self):
        run_dir = self.state / self.req["run"]

        def sync(path):
            if path == run_dir:
                raise OSError("fixture fsync failure")

        with patch.object(store, "sync_dir", side_effect=sync), self.assertRaises(OSError):
            self.invoke(dict(self.req, phase="apply"))
        with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
            self.invoke(dict(self.req, phase="apply"))
        self.effects.assert_not_called()

    def test_drift_before_dispatch(self):
        for key, value in (("digest", "d"*64), ("commit", "b"*40), ("phase", "unknown"), ("run", "456"),
                           ("attempt", "2"), ("direction", "return"), ("queue", "inventory")):
            with self.subTest(key=key), self.assertRaises(mandate.Held):
                self.invoke({**self.req, key:value})
        self.effects.assert_not_called()

    def test_plan_requires_authorized_run_ref_and_protected_environment(self):
        branch = {"protected": True, "commit": {"sha": self.req["commit"]}}
        jobs = {"jobs": [dict(status="in_progress", runner_name="vps", name="plan " + self.req["digest"])]}
        for update in ({"id": 321}, {"run_attempt": 2}, {"event": "push"}, {"status": "completed"},
                       {"path": "other.yml"}, {"head_sha": "b"*40}, {"head_branch": "other"},
                       {"head_repository": {"id": 42}}):
            with self.subTest(update=update), self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
                mandate.authorize(self.req, self.cfg, Mock(side_effect=[dict(self.run, **update)]), self.state)
        for update in ({"protected": False}, {"commit": {"sha": "b"*40}}):
            with self.subTest(update=update), self.assertRaisesRegex(mandate.Held, "PROTECTED_REF_DRIFT"):
                mandate.authorize(self.req, self.cfg, Mock(side_effect=[self.run, jobs, dict(branch, **update)]), self.state)
        for update in ({"id": 42}, {"name": "other"}, {"protection_rules": []},
                       {"protection_rules": [{"type": "required_reviewers", "reviewers": []}]}):
            with self.subTest(update=update), self.assertRaisesRegex(mandate.Held, "ENVIRONMENT_UNPROTECTED"):
                get = Mock(side_effect=[self.run, jobs, branch, dict(self.env, **update)])
                mandate.authorize(self.req, self.cfg, get, self.state)
        self.assertFalse((self.state / self.req["run"]).exists())

    def test_queued_requires_the_active_calling_job_on_the_profile_runner(self):
        job = dict(status="in_progress", runner_name="vps", name="plan " + self.req["digest"])
        for status in ("queued", "in_progress"):
            self.run["status"] = status
            for rows in ([], [dict(job, status="queued")], [dict(job, runner_name="local")], [dict(job, name="intent")]):
                with self.subTest(status=status, rows=rows), self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
                    mandate.authorize(self.req, self.cfg, Mock(side_effect=[self.run, {"jobs": rows}]), self.state)
        self.assertFalse((self.state / self.req["run"]).exists())
        self.run["status"] = "queued"
        self.invoke(self.req)

    def test_missing_unverifiable_or_other_reviewer(self):
        self.cfg["reviewerIds"].append(9)
        self.env["protection_rules"][0]["reviewers"].append(dict(type="User", reviewer={"id": 10}))
        for row in ([], [{**self.reviews[0], "user":{"type":"User","id":9}}],
                    [{**self.reviews[0], "user":{"type":"User","id":10}}],
                    [{**self.reviews[0], "user":{"type":"Bot","id":8}}],
                    [{**self.reviews[0], "state":"rejected"}],
                    [{**self.reviews[0], "environments":[{"id":5,"name":"private"}]}]):
            self.reviews = row
            with self.assertRaises(mandate.Held):
                self.invoke(dict(self.req, phase="apply"))
        with self.assertRaises(OSError):
            mandate.authorize(self.req, self.cfg, Mock(side_effect=OSError), self.state)
        self.effects.assert_not_called()


class Protocol(unittest.TestCase):
    def test_image_defaults_and_allocated_config_hash(self):
        old = frame()
        old["Config"].update(Labels={"common": "request"}, ExposedPorts={"one": {}},
                             Volumes={"/mount": {}}, Healthcheck={"Retries": 3}, WorkingDir="")
        old["HostConfig"]["Binds"] = ["volume:/mount", "second:/second"]
        profile = dict(image=old["Image"], configurationSha256=semantic.semantic_configuration(old),
                       containerName="app")
        image = dict(Labels={"common": "image", "source": "fixture"}, ExposedPorts={"two": {}},
                     Volumes={"/second": {}}, Env=["KEEP=no", "NEW=yes"], WorkingDir="/work",
                     StopSignal="SIGTERM", Healthcheck={"Retries": 5, "Test": ["NONE"]})
        iid = "sha256:" + "f"*64
        request, target = semantic.prepare(old, profile, iid, image)
        # Independently project the daemon's effective container configuration.
        expected = copy.deepcopy(old)
        expected["Config"].update(Image=iid, Labels={"common": "request", "source": "fixture"},
            Env=["OUF_DISCOVERY_WORKER_ENABLED=true", "OUF_SCHEMA_GOV_ENABLED=true", "KEEP=yes", "NEW=yes"],
            ExposedPorts={"one": {}, "two": {}}, Volumes={"/mount": {}, "/second": {}},
            WorkingDir="/work", StopSignal="SIGTERM", Healthcheck={"Retries": 3, "Test": ["NONE"]})
        self.assertEqual(semantic.configuration(request), {**expected["Config"], "Hostname": ""})
        self.assertEqual(target["configurationSha256"], semantic.semantic_configuration(expected))
        cid = "d"*64
        allocated = semantic.allocated_profile(dict(template=semantic.profile_template(old), request=request,
                                                    old=old["Id"], target=target), cid)
        expected["Id"] = cid
        expected["Config"]["Hostname"] = cid[:12]
        self.assertEqual(allocated["configurationSha256"], semantic.semantic_configuration(expected))
        # Like the real successor image: its own Entrypoint is ignored behind the gate.
        own, _ = semantic.prepare(old, profile, iid, {**image, "Entrypoint": ["java", "-jar", "/app/application.jar"]})
        self.assertEqual(own["Entrypoint"], semantic.ENTRY)
        self.assertEqual(semantic.configuration(own), semantic.configuration(request))
        with self.assertRaisesRegex(mandate.Held, "EXPLICIT_MOUNT_REQUIRED"):
            semantic.prepare(old, profile, iid, {**image, "Volumes": {"/anonymous": {}}})
        defaults = {"User": "user", "Entrypoint": ["gate"], "Cmd": ["app"], "Env": ["ONE=yes"]}
        cfg = {}
        semantic.merge_image(cfg, defaults)
        self.assertEqual(cfg, defaults)
        cfg = {"Entrypoint": ["explicit"], "Cmd": None}
        semantic.merge_image(cfg, defaults)
        self.assertEqual((cfg["Entrypoint"], cfg["Cmd"]), (["explicit"], None))

    def test_public_diagnostic_uses_innermost_executor_frame(self):
        import runpy
        public = runpy.run_path(str(ROOT / "scripts/ouf-a2-executor"))["public_error"]
        with tempfile.TemporaryDirectory() as directory, patch.dict(public.__globals__, ROOT=Path(directory)):
            lib = Path(directory) / "lib"
            inner = compile('raise KeyError("private value")', str(Path(directory) / "external.py"), "exec")
            code = compile('\nexec(inner)', str(lib / "module.py"), "exec")
            try:
                exec(code, {"inner": inner})
            except KeyError as error:
                self.assertEqual(public(error), "A2_EVIDENCE_UNPROVEN/KeyError@module.py:2")
            self.assertEqual(public(mandate.Held("PUBLIC_CODE")), "PUBLIC_CODE")

    def test_only_worker_delta(self):
        old = frame()
        profile = dict(image=old["Image"], configurationSha256=semantic.semantic_configuration(old),
                       containerName="app")
        req, target = semantic.prepare(old, profile)
        expected = copy.deepcopy(old)
        expected["Config"]["Env"][0] = "OUF_DISCOVERY_WORKER_ENABLED=true"
        self.assertEqual(target["configurationSha256"], semantic.semantic_configuration(expected))
        self.assertEqual(req["HostConfig"], old["HostConfig"])
        self.assertEqual(req["Env"], expected["Config"]["Env"])
        for mutate in (lambda r: r["Config"]["Env"].append("EXTRA=1"), lambda r: r["Mounts"].append({"Destination":"/x"}),
                       lambda r: r["NetworkSettings"]["Networks"]["fixture"].update(Aliases=[]),
                       lambda r: r["HostConfig"].update(Privileged=True)):
            bad = copy.deepcopy(old)
            mutate(bad)
            with self.assertRaisesRegex(mandate.Held, "BASELINE_DRIFT"):
                semantic.prepare(bad, profile)

    def test_allocated_alias_is_bound_to_the_create_receipt(self):
        old = frame()
        ep = old["NetworkSettings"]["Networks"]["fixture"]
        ep["Aliases"].append(old["Id"][:12])
        ep["DNSNames"] = [old["Id"][:12], "app", "alias"]
        profile = dict(image=old["Image"], configurationSha256=semantic.semantic_configuration(old), containerName="app")
        request, target = semantic.prepare(old, profile)
        cid = "f"*64
        plan = dict(old=old["Id"], request=request, target=target, template=semantic.profile_template(old))
        result = semantic.allocated_profile(plan, cid)
        actual = copy.deepcopy(old)
        actual["Config"].update(Env=request["Env"], Hostname=cid[:12])
        actual["Id"] = cid
        for field in ("Aliases", "DNSNames"):
            actual["NetworkSettings"]["Networks"]["fixture"][field].append(cid[:12])
        self.assertEqual(result["configurationSha256"], semantic.semantic_configuration(actual))
        actual["NetworkSettings"]["Networks"]["fixture"]["Aliases"].append("other")
        self.assertNotEqual(result["configurationSha256"], semantic.semantic_configuration(actual))

    def test_docker_generated_dns_name_follows_new_cid(self):
        old = frame()
        net = old["NetworkSettings"]["Networks"]["fixture"]
        net["DNSNames"] = ["app", old["Id"][:12]]
        profile = dict(image=old["Image"], configurationSha256=semantic.semantic_configuration(old), containerName="app")
        request, target = semantic.prepare(old, profile)
        cid = "f"*64
        plan = dict(old=old["Id"], request=request, target=target, template=semantic.profile_template(old))
        actual = copy.deepcopy(old)
        actual["Id"] = cid
        actual["Config"].update(Env=request["Env"], Hostname=cid[:12])
        actual["NetworkSettings"]["Networks"]["fixture"]["DNSNames"] = ["app", cid[:12]]
        self.assertEqual(semantic.allocated_profile(plan, cid)["configurationSha256"],
                         semantic.semantic_configuration(actual))

    def test_stop_after_renewal(self):
        observation = dict(configurationSha256="c"*64, authorization={"sequence": 30, "decision": "OPERATE"},
                           candidates={"adapter": {"cid": "d"*64, "epoch": {"epoch": 1}}},
                           supervisor={"epochs": {"adapter": 1}, "semanticEpoch": "e"*64},
                           lease={"state": "LEASE_READY", "leaseAuthorized": True})
        old = dict(planSha256="a"*64, outputDirectory="first", observation=observation,
                   lastObservation=copy.deepcopy(observation))
        fresh = {**old, "planSha256": "b"*64, "outputDirectory": "second"}
        books, record = Mock(), Mock()
        books.call.side_effect = [runbooks.RenewalCollision(), fresh, "stopped"]
        self.assertEqual(runbooks.stop(books, 30, old, record), "stopped")
        self.assertEqual([(name, args) for name, args, _ in books.method_calls], [
            ("wait_renewal", ()), ("call", ("stop", 30, old["planSha256"])),
            ("wait_renewal", ()), ("call", ("stop", 30)), ("wait_renewal", ()),
            ("call", ("stop", 30, fresh["planSha256"]))])
        self.assertEqual([c.kwargs for c in books.wait_renewal.call_args_list],
                         [{"required": False}, {}, {"required": True}])
        record.assert_called_once_with(1, fresh)

        for field in ("observation", "lastObservation"):
            for key, value in (("configurationSha256", "f"*64), ("authorization", {"sequence": 31}),
                               ("candidates", {"adapter": {"cid": "0"*64, "epoch": {"epoch": 1}}}),
                               ("supervisor", {"epochs": {"adapter": 2}, "semanticEpoch": "e"*64}),
                               ("lease", {"state": "LEASE_READY", "leaseAuthorized": 1})):
                with self.subTest(field=field, key=key):
                    books, record = Mock(), Mock()
                    drift = {**fresh, field: {**observation, key: value}}
                    books.call.side_effect = [runbooks.RenewalCollision(), drift]
                    with self.assertRaisesRegex(mandate.Held, "STOP_REQUIRES_NEW_REVIEW"):
                        runbooks.stop(books, 30, old, record)
                    record.assert_not_called()
                    self.assertEqual(books.call.call_count, 2)

        books, record = Mock(), Mock()
        books.call.side_effect = [runbooks.RenewalCollision(), mandate.Held("R3_HEAD_DRIFT")]
        with self.assertRaisesRegex(mandate.Held, "STOP_REQUIRES_NEW_REVIEW"):
            runbooks.stop(books, 30, old, record)
        record.assert_not_called()

        books, record = Mock(), Mock()
        third = {**fresh, "outputDirectory": "third", "planSha256": "c"*64}
        books.call.side_effect = [runbooks.RenewalCollision(), fresh, runbooks.RenewalCollision(),
                                  third, runbooks.RenewalCollision()]
        with self.assertRaisesRegex(mandate.Held, "STOP_RETRY_LIMIT"):
            runbooks.stop(books, 30, old, record)
        self.assertEqual([c.args for c in record.call_args_list], [(1, fresh), (2, third)])
        self.assertEqual(books.wait_renewal.call_count, 5)

    def test_wait_for_new_ready_publication(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        journal = root / "lease"
        def publish(state, authorized):
            pending = root / "pending"
            pending.write_text(json.dumps({"state": state, "leaseAuthorized": authorized}))
            pending.replace(journal)
        publish("LEASE_READY", True)
        updates = iter([("LEASE_UPDATING", True), ("LEASE_READY", False), ("LEASE_READY", True)])
        with patch.object(runbooks, "trusted", side_effect=lambda path, **_: Path(path)), \
             patch.object(runbooks.time, "sleep", side_effect=lambda _: publish(*next(updates))) as wait:
            runbooks.Books({"leaseJournal": journal}, root).wait_renewal()
        self.assertEqual(wait.call_count, 3)
        books = runbooks.Books({"leaseJournal": journal}, root)
        with patch.object(runbooks, "trusted", return_value=journal), \
             patch.object(runbooks, "read", side_effect=lambda path: json.loads(path.read_bytes())), \
             patch.object(runbooks.time, "monotonic", side_effect=[0, 16, 20, 36]):
            books.wait_renewal(required=False)
            with self.assertRaisesRegex(mandate.Held, "RENEWAL_TIMEOUT"):
                books.wait_renewal()

    def test_expired_or_unbounded_kernel_lease(self):
        from ingress import live_members
        # nft -j: whole seconds. 0 = under one second left, 31 > lease, 25000 = milliseconds (wrong unit).
        for ttl in (0, 31, 25000):
            with self.assertRaisesRegex(mandate.Held, "LEASE_EXPIRED"):
                live_members([{"elem":{"val":"member","expires":ttl}}], ["member"], 30, .1)
        with self.assertRaisesRegex(mandate.Held, "LEASE_EXPIRED"):
            live_members([{"elem":{"val":"member","expires":1}}], ["member"], 30, 1.5)
        for ttl in (1, 25, 30):
            live_members([{"elem":{"val":"member","expires":ttl}}], ["member"], 30, .1)

    def test_queue_subset_and_scope(self):
        tenant = {"private-subject": "tenant"}
        pending = ("private-subject","ref","PENDING","ACTIVE",1,3,None,None,None,None)
        rows = queue.inventory([pending],tenant)
        self.assertEqual(set(rows[0]), {"tenant",*queue.FIELDS})
        self.assertNotIn("private-subject", str(rows))
        queue.permit(rows, "inventory", rows)
        for rejected in ([], [{**rows[0], "claimGeneration":4}]):
            with self.assertRaises(mandate.Held):
                queue.permit(rows, "inventory", rejected)
        with self.assertRaises(mandate.Held):
            queue.permit(rows, "empty", rows)
        with self.assertRaises(mandate.Held):
            queue.inventory([pending],{})

    def test_readonly_container_projection(self):
        cfg = dict(container="pg", socket="/run/postgresql", role="reader", database="semantic",
                   subjectTenants={"private-subject": "tenant"})
        reader = queue.Queue(cfg, "/run/docker.sock")
        row = dict.fromkeys(queue.COLUMNS)
        row.update(owner_scope="private-subject", request_id="ref", state="PENDING", attempt_count=1)
        with patch.object(queue.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(row).encode() + b"\n"
            observed, = reader.snapshot()
            self.assertEqual(set(observed), {"tenant", *queue.FIELDS})
            self.assertEqual(observed["tenant"], "tenant")
            args, = run.call_args.args
            self.assertEqual(args, ["/usr/bin/docker", "exec", "-i", "-e",
                "PGOPTIONS=-cdefault_transaction_read_only=on", "pg", "psql", "-X", "-w", "-q",
                "-P", "pager=off", "-v", "ON_ERROR_STOP=1", "-h", "/run/postgresql", "-U",
                "reader", "-d", "semantic", "-A", "-t"])
            sql = run.call_args.kwargs["input"].decode()
            self.assertIn(queue.QUERY, sql)
            self.assertIn("READ ONLY", sql)
            self.assertNotIn("private-subject", str(queue.review_rows([observed])))
            run.return_value.stdout = json.dumps(dict(row, payload="unexpected")).encode()
            with self.assertRaisesRegex(mandate.Held, "PROJECTION"):
                reader.snapshot()

    def test_worker_proof_is_private_and_only_reads(self):
        cfg = dict(container="pg", socket="/pg", role="reader", database="semantic",
                   proof=dict(subject="private-'subject", provider="provider", uri="private-uri",
                              keyHash="a"*64, fingerprint="b"*64), proofWaitSeconds=2)
        reader = queue.Queue(cfg, "/run/docker.sock")
        with patch.object(queue.subprocess, "run") as run:
            run.return_value.stdout = b'"request-1"'
            self.assertEqual(reader.worker(123), {"requestId":"request-1", "state":"SUCCEEDED"})
            self.assertNotIn("private-", str(run.call_args.args))
            sql = run.call_args.kwargs["input"]
            self.assertIn(b"READ ONLY", sql)
            self.assertNotIn(b"private-", sql)
            self.assertIn(b"SELECT to_json(r.request_id)", sql)

    def test_release_rejects_image_pid_and_handler_before_signal(self):
        old = frame()
        old["State"] = {"Pid": 1234, "Running":True, "Paused":False, "Restarting":False}
        engine = semantic.Engine("unused")
        engine.inspect = Mock(return_value=old)
        profile = dict(containerName="app", image=old["Image"], configurationSha256=semantic.semantic_configuration(old))
        generation = dict(pid=1234, startTicks=111, namespaceInode=33, cid=old["Id"], image=old["Image"], startedAt="now")
        old["State"]["StartedAt"] = "now"
        observer = Mock()
        observer.observe.return_value = dict(processKind="UNPROVEN", generation={})
        with patch.object(os, "pidfd_open", create=True, return_value=123), patch.object(os, "close"), \
             patch.object(signal, "pidfd_send_signal", create=True) as send, patch.object(Path, "read_text") as proc, \
             patch.object(semantic, "GatedProcessObservation", return_value=observer):
            for image, pid in (("other",1), (old["Image"],2), (old["Image"],1)):
                proc.return_value = "NSpid:\t1234\t"+str(pid)
                with self.assertRaises(mandate.Held):
                    semantic.signal_once(engine, Mock(), old["Id"], {**profile,"image":image}, generation)
            send.assert_not_called()

    def test_write_ahead_signal_replay(self):
        with tempfile.TemporaryDirectory() as d, patch.object(store, "sync_dir"), \
             patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)), \
             patch.object(os, "pidfd_open", create=True, return_value=123), patch.object(os, "close"), \
             patch.object(signal, "SIGUSR1", create=True, new=10), patch.object(signal, "pidfd_send_signal", create=True) as send:
            log = store.Journal(Path(d))
            gen = {"pid":1100}
            engine = Mock()
            engine.process.return_value = gen
            for _ in range(2):
                self.assertEqual(semantic.signal_once(engine, log, "cid", {}, gen), {"sent":1})
            send.assert_called_once()
            (log.path / "signal.receipt").unlink()
            with self.assertRaisesRegex(mandate.Held, "RECONCILIATION"):
                semantic.signal_once(engine, log, "cid", {}, gen)
            send.assert_called_once()

    def test_return_replay_restores_retained_cid(self):
        with tempfile.TemporaryDirectory() as d, patch.object(store, "sync_dir"), \
             patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)):
            log = store.Journal(Path(d))
            engine = semantic.Engine("unused")
            stopped = dict(Id="old",State={"Running":False},NetworkSettings={"Networks":{}})
            engine.call = Mock()
            engine.inspect = lambda name, absent=False: stopped if name == "old" or (
                name == "semantic" and engine.call.called) else None
            plan = {"old":"old", "source":"new", "endpoints":{"network":{"Aliases":["alias"]}}}
            for _ in range(2):
                outcome = log.effect("reconnect", plan, lambda: engine.reconnect(
                    "old", "semantic", plan["endpoints"], {"network":"id"}))
                self.assertEqual(outcome, "old")
            self.assertEqual(len(engine.call.call_args_list), 2)
            self.assertEqual(engine.call.call_args.args[2], {"Container":"old","EndpointConfig":{"Aliases":["alias"]}})

    def test_head_requires_complete_chain_and_installed_profile(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        chain = root / "authorization"
        chain.mkdir()
        c = object.__new__(pipeline.Cutover)
        c.cfg = {"installRoot": str(root), "runbooks": {f"start-{n}": {} for n in range(27, 32)}}
        for n in range(1, 32):
            for suffix in ("json", "signature.json"):
                (chain / f"{n}.{suffix}").touch()
            if n >= 27:
                self.assertEqual(c.current_version(), n)
        with patch.dict(c.cfg["runbooks"], {"start-30": {}}, clear=True), \
                self.assertRaisesRegex(mandate.Held, "HEAD_RECONCILIATION_REQUIRED"):
            c.current_version()
        (chain / "28.signature.json").unlink()
        with self.assertRaisesRegex(mandate.Held, "HEAD_RECONCILIATION_REQUIRED"):
            c.current_version()

    def test_unauthorized_queue_never_signals(self):
        c = object.__new__(pipeline.Cutover)
        c.forward, c.req, c.root = False, {"direction":"return","run":"123","queue":"inventory"}, Path(".")
        c.owner, c.current_version = Mock(return_value="123"), Mock(return_value=27)
        c.authority = Mock(return_value="chain")
        c.engine, c.books, c.log = Mock(), Mock(), Mock()
        c.log.path = Path(self.enterContext(tempfile.TemporaryDirectory()))
        c.next_release = False
        c.engine.process.return_value = {}
        c.observe, c.closed, c.apply_book = Mock(return_value={}), Mock(), Mock()
        c.supervisor = Mock(return_value={"semanticIngress":{"profile":{}}})
        c.queue = Mock()
        c.queue.snapshot.side_effect = [[], [{"state":"PENDING"}]]
        c.books.call.return_value = {"observation":{"authorization":{"sequence":27}, "configurationSha256":"p"}, "planSha256":"p"}
        plan = dict(head=27,sequence=27,target={},queue=[])
        stage = dict(cid="old",profile={},generation={},epoch={},issue=None)
        with patch.object(pipeline, "verified", return_value=nullcontext(None)), \
             patch.object(pipeline, "signal_once") as send, self.assertRaisesRegex(mandate.Held, "QUEUE_APPROVAL_DRIFT"):
            try:
                c.finish(plan,stage)
            finally:
                send.assert_not_called()

    def test_workflow_intent_matches_protocol(self):
        import yaml
        wf = yaml.safe_load((ROOT / mandate.WORKFLOW).read_text())
        jobs = wf["jobs"]
        self.assertIs(wf[True]["workflow_dispatch"]["inputs"]["worker_proof"]["default"], False)
        self.assertEqual(jobs["proof"]["needs"], "sign")
        self.assertEqual(jobs["proof"]["if"], "${{ !cancelled() && needs.sign.result == 'success' && "
                         "inputs.worker_proof && inputs.direction == 'forward' }}")
        self.assertEqual(jobs["migrate"]["needs"], "apply")
        self.assertEqual(jobs["migrate"]["if"], "needs.apply.outputs.migration == 'true'")
        self.assertEqual(jobs["sign"]["needs"], ["apply", "migrate"])
        for phase in mandate.PHASES:
            job = jobs[phase]
            if phase == "plan":
                self.assertNotIn("environment", job)
            else:
                self.assertEqual(job["environment"], "ouf-vps-privileged")
            script = next(step["run"] for step in job["steps"] if step.get("id") == "call")
            self.assertEqual(script.count("/usr/bin/sudo"), 1)
            self.assertNotIn("checkout", script)
            self.assertNotIn("docker", script)
        env = dict(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="c"*40,
                   DIRECTION="forward", QUEUE="empty", RELEASE="a2", CONFIRM_NO_RETURN="false")
        with tempfile.TemporaryDirectory() as d:
            env.update(GITHUB_STEP_SUMMARY=d+"/summary", GITHUB_OUTPUT=d+"/output")
            code = jobs["intent"]["steps"][0]["run"].split("<<'PY'\n")[1].rsplit("\nPY",1)[0]
            with patch.dict(os.environ,env):
                exec(compile(code,"intent","exec"),{})
            req = dict(run="123",attempt="1",commit="c"*40,direction="forward",queue="empty",phase="plan")
            req["digest"] = mandate.intent(req)
            summary = Path(d, "summary").read_text()
            self.assertNotIn("Approvare", summary)
            self.assertIn(req["digest"], summary)
            with patch.dict(os.environ, {**env, "RELEASE": "next", "CONFIRM_NO_RETURN": "true"}):
                exec(compile(code, "intent", "exec"), {})
            req["release"] = "next"
            self.assertIn(mandate.intent(req), Path(d, "summary").read_text())
            self.assertEqual(jobs["apply"]["needs"], "plan")


class RoundTrip(unittest.TestCase):
    """Run the actual phase machine and disk journal against in-memory host boundaries."""

    def test_27_to_28_to_29(self):
        self.round_trip(signed=True)

    def test_return_on_27_without_signature(self):
        self.round_trip(signed=False)

    def test_optional_proof_after_forward_completion(self):
        self.round_trip(signed=True, prove=True)

    def test_image_and_flyway_review_on_resumed_generation(self):
        self.round_trip(signed=True, migrations=["V13__adoption.sql"])

    def test_image_without_new_migrations(self):
        self.round_trip(signed=True, migrations=[])

    def test_reuse_never_started_successor_then_issue_migrate_sign(self):
        self.round_trip(signed=True, migrations=["V13__adoption.sql"], interrupted=True)

    def test_return_never_started_then_new_forward(self):
        self.round_trip(signed=False, migrations=["V13__adoption.sql"], interrupted=True, restart=True)

    def test_new_forward_retires_only_archived_stopped_failure(self):
        self.round_trip(signed=False, migrations=[], restart=True)

    def test_next_release_after_legacy_completion(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="legacy")

    def test_successive_next_from_29_and_signed_return_to_its_predecessor(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="successive")

    def test_next_release_finishes_partial_pointer_archival(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="archive")

    def test_next_release_resume_after_create(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="created")

    def test_next_release_return_before_issue(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="return")

    def test_next_release_resume_after_detach(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="detached")

    def test_next_release_return_after_stop(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="stopped-return")

    def test_next_release_resume_interrupted_return(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="reconnect")

    def test_next_release_resume_after_signature(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="signed")

    def test_next_release_observe_uncertain_signal(self):
        self.round_trip(signed=True, migrations=["V13.sql"], next_mode="signal")

    def test_post_signature_return_interruptions(self):
        for mode in ("return-before-stop", "return-reconnect", "return-signed", "return-signal", "return-gated", "before-upgrade"):
            with self.subTest(mode=mode):
                self.round_trip(signed=True, migrations=["V13.sql"], next_mode=mode)

    def round_trip(self, signed, prove=False, migrations=None, interrupted=False, restart=False, next_mode=None, exercise=None):
        from contextlib import ExitStack
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root = Path(d)
            patches.enter_context(patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)))
            patches.enter_context(patch.object(pipeline, "trusted", side_effect=lambda p, **_: Path(p)))
            patches.enter_context(patch.object(store, "sync_dir"))
            patches.enter_context(patch.object(pipeline, "verified", side_effect=lambda *args: nullcontext(None)))
            old = frame()
            old["Config"]["Image"] = "fixture:original"
            original = dict(role="semantic", containerName="app", image=old["Image"],
                configurationSha256=semantic.semantic_configuration(old), network="fixture",
                networkId="c"*64, bridge="fixture", direction="semantic-to-southbound",
                ipv4="192.0.2.1", destination="192.0.2.2", protocol="tcp", port=443)
            old_id, new_id = old["Id"], "d"*64
            cfg = dict(originalProfile=original, retainedName="saved", failedName="returned", socket="socket", commit="a"*40,
                       leaseJournal=str(root / "lease"), installRoot=str(root), queue={}, roleTables=["one","two"],
                       roleCids=["first","second"])
            if prove:
                cfg["queue"]["proof"] = {"subject":"fixture"}
            new_image = original["image"]
            if migrations is not None:
                new_image = "sha256:" + "f"*64
                cfg["successorImage"] = {"ci": {"imageId": new_image, "zipSha256": "1"*64}}
            admission = patches.enter_context(patch.object(pipeline, "admit",
                return_value={"ci": {"imageId": new_image, "zipSha256": "1"*64},
                              "migrations": ["V12__baseline.sql", *(migrations or [])], "newMigrations": migrations}))
            head = SimpleNamespace(version=27, profile=original, waiting=False)
            store.save(root / "status", {"state":"ACTIVE"})
            counts = []
            tables = []
            patches.enter_context(patch("semantic_identity_v25.semantic_command",
                                        side_effect=lambda *args: json.dumps({"nftables": tables})))
            def observed(cid, profile, sup):
                self.assertTrue(containers[cid]["State"]["Running"])
                return {"cid":cid, "profile":profile}
            def supervisor(version):
                return {"semanticIngress":{"profile":head.profile,"commands":{"socket":"socket"}, "table":"one"},
                        "coordinator":{"journalPath":str(root / "lease"), "nftBinding":{}}, "statusPath":str(root / "status")}
            def stop_book(books, seq, plan, record):
                counts.append(("stop",seq))
                head.waiting = True
                store.save(root / "lease", {"state": "QUIESCED", "leaseAuthorized": False}, replace=True)
                store.save(root/"status", {"state":"WAITING"}, replace=True)
                return {"lastObservation":plan["observation"]}
            patches.enter_context(patch.object(pipeline, "stop", side_effect=stop_book))
            def signal_gate(engine, log, cid, profile, generation, deadline):
                self.assertFalse(head.waiting)
                process_kinds[cid] = "APPLICATION_RUNNING"
                counts.append(("signal",cid))
            patches.enter_context(patch.object(pipeline, "signal_once", side_effect=signal_gate))
            engine = Mock()
            old["State"] = {"Running": True, "Pid": 42, "Status": "running"}
            containers = {old_id: copy.deepcopy(old)}
            process_kinds = {old_id: "APPLICATION_RUNNING"}
            def inspect(name, absent=False):
                if name in cfg["roleCids"]:
                    return {"Id": name, "State": {"Status": "exited" if head.waiting else "running",
                                                  "Pid": 0 if head.waiting else 42}}
                row = next((r for r in containers.values() if name in (r["Id"], r["Name"][1:])), None)
                self.assertTrue(row or absent)
                return copy.deepcopy(row)
            engine.inspect.side_effect = inspect
            engine.call.return_value = {"Id": new_image, "Config": {
                "Labels": {"org.opencontainers.image.source": "fixture"}, "Env": ["ADDED=yes"]}}
            def create(name, request, image):
                config = copy.deepcopy(semantic.configuration(request))
                config["Hostname"] = new_id[:12]
                if migrations is not None:
                    config.setdefault("Labels", {}).setdefault("org.opencontainers.image.source", "fixture")
                    if "ADDED=yes" not in config["Env"]:
                        config["Env"].append("ADDED=yes")
                containers[new_id] = {**copy.deepcopy(old), "Id": new_id, "Image": image, "Config": config,
                    "State": {"Running": False, "Pid": 0, "Status": "created", "StartedAt": "0001-01-01T00:00:00Z"}}
                return new_id
            def detach(cid, name, networks):
                containers[cid].update(Name="/"+name, NetworkSettings={"Networks": {}},
                    State={"Running": False, "Pid": 0, "Status": "exited"})
                return cid
            def reconnect(cid, name, endpoints, networks):
                self.assertIsNone(inspect(name, True))
                containers[cid].update(Name="/"+name, NetworkSettings=copy.deepcopy(old["NetworkSettings"]))
                return cid
            def remove(cid, name, *, created=False):
                self.assertEqual(containers[cid]["Name"], "/"+name)
                self.assertFalse(containers[cid]["State"]["Running"])
                if created:
                    self.assertTrue(semantic.never_started(containers[cid]["State"]))
                del containers[cid]
                return cid
            gate = semantic.Engine("fixture")
            gate.inspect = inspect
            def start_gate(cid, name, request, image):
                gate.stopped_gate(cid, name, request, image)
                process_kinds[cid] = "GATE_WAITING"
                containers[cid]["State"] = {"Pid": 42, "Running": True, "Status": "running"}
            engine.create.side_effect = create
            engine.detach.side_effect = detach
            engine.reconnect.side_effect = reconnect
            def reconnect_missing(cid, name, endpoints, networks, *, rename, missing):
                self.assertFalse(rename)
                self.assertEqual(set(missing), set(networks))
                self.assertEqual(containers[cid]["Name"], "/" + name)
                containers[cid]["NetworkSettings"] = copy.deepcopy(old["NetworkSettings"])
                return cid
            engine.reconnect_missing.side_effect = reconnect_missing
            engine.remove_stopped.side_effect = remove
            engine.stopped_gate.side_effect = gate.stopped_gate
            engine.start_gate.side_effect = start_gate
            def process(cid, profile, kind):
                mandate.need(containers[cid]["State"]["Running"] and process_kinds[cid] == kind, "PROCESS_KIND_UNPROVEN")
                return {"cid": cid, "pid": 42}
            engine.process.side_effect = process
            import hashlib
            payload_hash = hashlib.sha256(b"payload").hexdigest()
            def make_cutover(run, direction, cid, release_next, confirm=None):
                req = dict(run=run,attempt="1",commit=cfg["commit"],phase="plan",queue="empty",direction=direction)
                if release_next:
                    req["release"] = "next"
                    if confirm is not None:
                        req["confirmNoReturn"] = confirm
                req["digest"] = mandate.intent(req)
                c = pipeline.Cutover(cfg,root,req)
                c.engine, c.books, c.queue = engine, Mock(), Mock(spec=queue.Queue)
                c.current_version = lambda: head.version
                c.authority = lambda: "signed-chain"
                c.observe, c.supervisor = observed, supervisor
                c.ready = Mock()
                def probe_preflight(version, cid):
                    books = c.source_probe(c.books)
                    if release_next:
                        self.assertEqual(books.probe_source, root / {28: "103", 29: "202"}[version])
                    return "preflight"
                c.probe_preflight = probe_preflight
                c.queue.snapshot.return_value = []
                c.queue.worker.return_value = {"state":"SUCCEEDED"}
                stored = {}
                def call(op, version, approved=None):
                    if approved:
                        self.assertEqual(approved, stored[op]["planSha256"])
                        counts.append((op, version))
                        if op=="issue":
                            head.version = version
                            auth = root / "authorization" / f"{version}.json"
                            auth.parent.mkdir(exist_ok=True)
                            auth.write_bytes(b"payload")
                            return {"payloadSha256":payload_hash}
                        if op=="upgrade":
                            stage_dir = root / "202" if (run, version) == ("210", 29) else c.path
                            head.profile = store.read(stage_dir / "stage")["profile"]
                        if op=="start":
                            head.waiting = False
                            store.save(root/"status", {"state":"ACTIVE"}, replace=True)
                        return {"status":"done"}
                    if op in ("stop","start"):
                        obs = {"authorization":{"sequence":head.version, "decision":"OPERATE"},
                               "configurationSha256":"bound",
                               "candidates":{r:{"cid":r} for r in cfg["roleCids"]},
                               "tables":{r:{"tableName":r} for r in cfg["roleTables"]}}
                        value = dict(installRoot=str(root),observation=obs)
                    elif op=="issue":
                        plan = c.record("plan")
                        target = semantic.allocated_profile(plan,cid) if direction=="forward" else plan["original"]
                        value = dict(previousHead={"sequence":version-1,"sha256":"previous"},
                                     payload={"sequence":version,"supersedes":"previous"}, payloadSha256=payload_hash,
                                     compositionInputHashes={"semanticProfile":mandate.digest(target)},privateKeysRead=0)
                    elif op=="upgrade":
                        value = dict(versionBefore=version-1,versionAfter=version,authorization={"sha256":payload_hash},
                                     compositionInputHashes=stored["issue"]["compositionInputHashes"])
                    else:
                        self.assertEqual(op,"probe")
                        value = {"observation":{"semantic":{"containerId":cid}}}
                    stored[op] = {**value,"planSha256":mandate.digest(value)}
                    return stored[op]
                c.books.call.side_effect = call
                return c, stored, call

            def scenario(run, direction, seq, cid, stop_at_gate=False, *, release_next=False, confirm=None):
                c, stored, call = make_cutover(run, direction, cid, release_next, confirm)
                req = c.req
                if interrupted and run == "101":
                    # Capture the old run exactly: no image defaults in its plan or create claim.
                    def legacy_prepare(row, profile, image):
                        return semantic.prepare(row, profile, image["ci"]["imageId"], {})
                    c.prepare_image = legacy_prepare
                if (run, next_mode) in (("203", "signed"), ("211", "return-signed"), ("210", "before-upgrade")):
                    prior = store.read(root / ("210" if run == "211" else "202") / "stage")["issue"]
                    stored["issue"] = prior
                    patches.enter_context(patch.object(pipeline, "Books", return_value=c.books))
                if run == "203" and next_mode == "signal":
                    with patch.dict(process_kinds, {cid: "GATE_WAITING"}), self.assertRaisesRegex(mandate.Held, "PROCESS_KIND_UNPROVEN"):
                        c.initial()
                if run == "200":
                    spec = cfg["nextSuccessorImage"]
                    with patch.dict(spec, predecessorMigrations=[]), self.assertRaisesRegex(mandate.Held, "PREDECESSOR_MIGRATIONS_CHANGED"):
                        c.initial()
                    with patch.dict(spec["ci"], imageId=head.profile["image"]), self.assertRaisesRegex(mandate.Held, "NEXT_RELEASE_BASELINE_DRIFT"):
                        c.initial()
                if run == "301":
                    before = counts.copy()
                    with patch.dict(cfg, runbooks={"stop-30": {}}), \
                            patch.object(c.books, "binding", runbooks.Books(cfg, c.path).binding), \
                            self.assertRaisesRegex(mandate.Held, "RUNBOOK_BINDING_REQUIRED"):
                        c.initial()
                    self.assertEqual(counts, before)
                first = c.execute("review-plan")
                if release_next and direction == "forward":
                    self.assertEqual(first["returnAfterIssue"], "available")
                    self.assertEqual(first["returnSequence"], seq + 1)
                    for op in pipeline.SUCCESS:
                        c.books.binding.assert_any_call(op, seq + 1)
                if run == "200":
                    c.books.binding.side_effect = mandate.Held("RUNBOOK_BINDING_REQUIRED")
                    req.update(phase="apply", digest=first["digest"])
                    with self.assertRaisesRegex(mandate.Held, "RUNBOOK_BINDING_REQUIRED"):
                        c.execute("review-apply")
                    self.assertFalse((root / "forward").exists())
                    return
                req.update(phase="apply",digest="e"*64)
                with self.assertRaisesRegex(mandate.Held, "APPROVED_PLAN_DRIFT"):
                    c.execute("unbound-review")
                self.assertFalse((c.path / "apply.review").exists())
                req["digest"] = first["digest"]
                if migrations is not None and not interrupted and run == "101":
                    with patch.dict(engine.call.return_value["Config"], Env=["ADDED=changed"]), \
                            self.assertRaisesRegex(mandate.Held, "SUCCESSOR_PLAN_DRIFT"):
                        c.prepare_stage(c.record("plan"))
                    self.assertFalse((root / "forward").exists())
                if run == "201" and next_mode in ("detached", "stopped-return"):
                    effect = c.log.effect
                    def interrupt(name, claim, action):
                        if name == ("create" if next_mode == "detached" else "detach"):
                            raise InterruptedError
                        return effect(name, claim, action)
                    c.log.effect = interrupt
                    with self.assertRaises(InterruptedError):
                        c.execute("review-apply")
                    return
                if run == "201" and next_mode == "created":
                    with patch.object(engine, "start_gate", side_effect=mandate.Held("fixture interruption")), self.assertRaises(mandate.Held):
                        c.execute("review-apply")
                    return
                if (run, next_mode) == ("210", "return-before-stop"):
                    with patch.object(c.log, "effect", side_effect=InterruptedError), self.assertRaises(InterruptedError):
                        c.execute("review-apply")
                    self.assertEqual(c.owner("return"), run)
                    self.assertFalse((c.path / "stop.claim").exists())
                    return
                if interrupted and run == "101":
                    with self.assertRaisesRegex(mandate.Held, "STOPPED_GATE_FRAME_DRIFT"):
                        c.execute("review-apply")
                    for effect in ("stop", "detach", "create"):
                        self.assertTrue((c.path / (effect + ".receipt")).is_file())
                    self.assertTrue((c.path / "start-gate.claim").is_file())
                    self.assertFalse((c.path / "start-gate.receipt").exists())
                    cfg["commit"] = "b"*40
                    return
                if "createdFrom" in c.record("plan") and not release_next:
                    self.assertEqual(c.record("plan")["createdFrom"], "101")
                    with patch.dict(containers[new_id]["State"], StartedAt="different"), \
                            self.assertRaisesRegex(mandate.Held, "NEVER_STARTED_REQUIRED"):
                        c.prepare_stage(c.record("plan"))
                    with patch.dict(containers[old_id]["Config"], User="other"), \
                            self.assertRaisesRegex(mandate.Held, "RETAINED_CID_DRIFT"):
                        c.prepare_stage(c.record("plan"))
                    tables.append({"table": {"name": "one"}})
                    with self.assertRaisesRegex(mandate.Held, "ROLE_TABLES_PRESENT"):
                        c.prepare_stage(c.record("plan"))
                    tables.clear()
                    if direction == "forward":
                        with patch.dict(containers[cid]["Config"], Labels={"changed": "yes"}), \
                                self.assertRaisesRegex(mandate.Held, "STOPPED_GATE_FRAME_DRIFT"):
                            c.prepare_stage(c.record("plan"))
                if (next_mode, run) in (("reconnect", "202"), ("return-reconnect", "210")):
                    def disconnected(cid, name, endpoints, networks):
                        containers[cid]["Name"] = "/" + name
                        raise InterruptedError
                    with patch.object(engine, "reconnect", side_effect=disconnected), self.assertRaises(InterruptedError):
                        c.execute("review-apply")
                    return
                second = c.execute("review-apply")
                if migrations and direction == "forward":
                    self.assertEqual(second["migrationsSha256"], mandate.digest(migrations))
                    stage = c.record("stage")
                    signing = stage["issue"]["planSha256"] if stage["issue"] else mandate.digest(stage)
                    req.update(phase="sign", digest=signing)
                    with self.assertRaisesRegex(mandate.Held, "MIGRATION_REVIEW_REQUIRED"):
                        c.execute("review-sign")
                    req.update(phase="migrate", digest=signing)
                    with self.assertRaisesRegex(mandate.Held, "APPROVED_MIGRATION_DRIFT"):
                        c.execute("wrong-review")
                    if next_mode != "signal" or run != "203":
                        self.assertNotIn(("signal", cid), counts)
                    req["digest"] = second["digest"]
                    second = c.execute("review-migrate")
                    self.assertEqual(second["digest"], signing)
                else:
                    self.assertNotIn("migrationCount", second)
                if stop_at_gate or (run, next_mode) == ("210", "return-gated"):
                    return
                req.update(phase="sign",digest="f"*64)
                with self.assertRaisesRegex(mandate.Held, "APPROVED_ISSUANCE_DRIFT"):
                    c.execute("unbound-review")
                self.assertFalse((c.path / "issue.claim").exists())
                req["digest"] = second["digest"]
                if (run == "202" and next_mode in ("signed", "signal", "before-upgrade")) or (run == "210" and next_mode in ("return-signed", "return-signal")):
                    class Interrupted(BaseException):
                        pass
                    stop_before_upgrade = next_mode in ("signed", "return-signed", "before-upgrade")
                    if stop_before_upgrade:
                        def halt(op, version, approved=None):
                            if op == "upgrade":
                                raise Interrupted
                            return call(op, version, approved)
                        c.books.call.side_effect = halt
                    else:
                        def halt(engine, journal, container, profile, generation, deadline):
                            store.save(journal.path / "signal.claim", generation)
                            process_kinds[container] = "APPLICATION_RUNNING"
                            counts.append(("signal", container))
                            raise Interrupted
                    interruption = nullcontext() if stop_before_upgrade else patch.object(pipeline, "signal_once", side_effect=halt)
                    with interruption, self.assertRaises(Interrupted):
                        c.execute("review-sign")
                    return
                if run == "103" and next_mode == "archive":
                    unlink = Path.unlink
                    def cut(path, *args, **kwargs):
                        if path == root / "forward-stage":
                            raise InterruptedError
                        return unlink(path, *args, **kwargs)
                    with patch.object(Path, "unlink", cut), self.assertRaises(InterruptedError):
                        c.execute("review-sign")
                    self.assertTrue((root / "103" / "closed-forward").is_file())
                    self.assertFalse((root / "forward").exists())
                    return
                if run == "103" and next_mode == "legacy":
                    c.close_forward = Mock()  # installed 17u left these pointers live
                done = c.execute("review-sign")
                self.assertEqual((done["ingress"], done["readiness"], done["worker"]),
                                 ("VERIFIED", "UP", "on" if direction == "forward" or release_next else "off"))
                c.queue.worker.assert_not_called()
                with self.assertRaises(FileExistsError):
                    c.execute("review-sign")
                if direction == "forward":
                    req.update(phase="proof", digest=done["digest"])
                    if "proof" in cfg["queue"]:
                        self.assertEqual(c.execute("review-proof")["proof"], "SUCCEEDED")
                        c.queue.worker.assert_called_once_with(c.record("result")["proofSince"])
                    else:
                        with self.assertRaisesRegex(mandate.Held, "WORKER_PROOF_PROFILE_REQUIRED"):
                            c.execute("review-proof")
                        c.queue.worker.assert_not_called()
                self.assertEqual(head.version, seq)
            def configure_next():
                nonlocal new_id, migrations, new_image
                line_c = new_id
                new_id = "e"*64
                previous = admission.return_value["migrations"]
                migrations = ["V14__discovery.sql"]
                new_image = "sha256:" + "9"*64
                cfg["nextSuccessorImage"] = {"ci": {"imageId": new_image, "zipSha256": "9"*64},
                                             "predecessorMigrations": previous}
                admission.return_value = {"ci": cfg["nextSuccessorImage"]["ci"],
                                          "migrations": previous + migrations, "newMigrations": migrations}
                engine.call.return_value["Id"] = new_image
                return line_c, new_id

            if exercise is not None:
                return exercise(SimpleNamespace(root=root, cfg=cfg, head=head, engine=engine, counts=counts,
                    containers=containers, process_kinds=process_kinds, old=old_id, new=new_id,
                    make_cutover=make_cutover, configure_next=configure_next, stop=stop_book))

            scenario("101","forward",28,new_id,stop_at_gate=True)
            if signed:
                scenario("103","forward",28,new_id)
                if next_mode:
                    line_c, new_id = configure_next()
                    scenario("200", "forward", 29, new_id, release_next=True, confirm=True)
                    self.assertEqual(store.read(root / "completed-forward")["run"], "103")
                    scenario("201", "forward", 29, new_id, stop_at_gate=True, release_next=True)
                    self.assertEqual(containers[old_id]["Name"], "/saved")
                    self.assertEqual(containers[line_c]["Name"], "/app" if next_mode == "stopped-return" else "/saved-v28")
                    if next_mode in ("return", "stopped-return", "reconnect"):
                        scenario("202", "return", 28, line_c, release_next=True)
                        if next_mode == "reconnect":
                            scenario("203", "return", 28, line_c, release_next=True)
                        self.assertEqual(containers[line_c]["Name"], "/app")
                        self.assertEqual(head.profile["image"], cfg["successorImage"]["ci"]["imageId"])
                        self.assertEqual(store.read(root / "completed-forward")["run"], "103")
                    else:
                        scenario("202", "forward", 29, new_id, release_next=True)
                        if next_mode == "successive":
                            cid29, image29 = new_id, head.profile["image"]
                            previous = admission.return_value["migrations"]
                            new_id, new_image = "7"*64, "sha256:" + "8"*64
                            migrations = []
                            ci = {"imageId": new_image, "zipSha256": "7"*64}
                            cfg["nextSuccessorImage"] = {"ci": ci, "predecessorMigrations": previous}
                            admission.return_value = {"ci": ci, "migrations": previous, "newMigrations": []}
                            engine.call.return_value["Id"] = new_image
                            scenario("299", "forward", 30, new_id, stop_at_gate=True, release_next=True)
                            scenario("300", "return", 29, cid29, release_next=True)
                            self.assertNotIn(("issue", 30), counts)
                            self.assertEqual(store.read(root / "completed-forward")["run"], "202")
                            abandoned = new_id
                            new_id = "6"*64
                            scenario("301", "forward", 30, new_id, release_next=True)
                            self.assertNotIn(abandoned, containers)
                            forward = store.read(root / "301" / "plan")
                            self.assertEqual((forward["head"], forward["old"], forward["original"]["image"]),
                                             (29, cid29, image29))
                            self.assertEqual(containers[cid29]["Name"], "/saved-v29")
                            self.assertEqual(containers[new_id]["Image"], new_image)
                            scenario("302", "return", 31, cid29, release_next=True)
                            self.assertEqual((head.profile["image"], containers[cid29]["Name"]), (image29, "/app"))
                            self.assertIn("OUF_DISCOVERY_WORKER_ENABLED=true", containers[cid29]["Config"]["Env"])
                            self.assertEqual((containers[old_id]["Name"], containers[line_c]["Name"]),
                                             ("/saved", "/saved-v28"))
                            self.assertEqual(containers[new_id]["State"]["Status"], "exited")
                            for seq in (30, 31):
                                for op in ("issue", "upgrade", "start", "probe"):
                                    self.assertEqual(counts.count((op, seq)), 1)
                            self.assertEqual(store.read(root / "last-closed")["run"], "302")
                            return
                        if next_mode in ("signed", "signal"):
                            scenario("203", "forward", 29, new_id, release_next=True)
                        scenario("210", "return", 30, line_c, release_next=True)
                        if next_mode in ("return-before-stop", "return-signed", "return-reconnect", "return-signal", "return-gated"):
                            scenario("211", "return", 30, line_c, release_next=True)
                        self.assertEqual(head.profile["image"], cfg["successorImage"]["ci"]["imageId"])
                        self.assertEqual(containers[line_c]["Name"], "/app")
                        for op in ("issue", "upgrade", "start", "probe"):
                            self.assertEqual(counts.count((op, 30)), 1)
                        self.assertEqual(counts.count(("issue", 29)), 1)
                        self.assertEqual(counts.count(("signal", new_id)), int(next_mode != "before-upgrade"))
                        self.assertEqual(counts.count(("signal", line_c)), 2)
                        self.assertFalse((root / "forward").exists())
                    self.assertEqual(engine.create.call_count, 1 if next_mode == "stopped-return" else 2)
                    return
                scenario("102","return",29,old_id)
            else:
                scenario("102","return",27,old_id)
            engine.create.assert_called_once()
            self.assertEqual(engine.create.call_args.args[1]["Image"],
                             new_image if migrations is not None else "fixture:original")
            self.assertEqual(engine.create.call_args.args[2], new_image)
            self.assertEqual(engine.start_gate.call_args.args[2]["Image"], "fixture:original")
            self.assertEqual(engine.start_gate.call_args.args[3], original["image"])
            self.assertEqual(admission.call_count, int(migrations is not None))
            self.assertEqual(engine.reconnect.call_args.args[0],old_id)
            expected = [("stop",27),("issue",28),("upgrade",28),("start",28),
                        ("signal",new_id),("probe",28),("stop",28),("issue",29),("upgrade",29),("start",29),
                        ("signal",old_id),("probe",29)] if signed else [
                        ("stop",27),("start",27),("signal",old_id),("probe",27)]
            self.assertEqual(counts, expected)
            archive = store.read(root / "102" / "closed-transaction")
            for key in ("forward", "return", "forward-stage", "return-stage"):
                self.assertFalse((root / key).exists())
                self.assertIn(key, archive["pointers"])
            if interrupted and signed:
                self.assertEqual(archive["pointers"]["forward"]["run"], "103")
                self.assertTrue((root / "103" / "reuse.receipt").exists())
            if restart:
                if interrupted:
                    self.assertTrue((root / "102" / "remove-created.receipt").exists())
                else:
                    check = pipeline.Cutover(cfg, root, {"direction": "forward", "run": "104"})
                    check.engine = engine
                    for bad in ({"Id": "e"*64}, {"State": {"Running": True, "Pid": 42, "Status": "running"}}):
                        with patch.dict(containers[new_id], bad), self.assertRaisesRegex(mandate.Held, "ARCHIVED_CID_DRIFT"):
                            check.archived_failure()
                new_id = "e"*64
                scenario("104", "forward", 28, new_id)
                self.assertEqual(engine.create.call_count, 2)
                self.assertFalse((root / "forward-stage").exists())
                self.assertEqual(store.read(root / "completed-forward")["run"], "104")
                self.assertEqual((root / "104" / "remove-archived.receipt").exists(), not interrupted)


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_A2_NATIVE") == "1", "Linux pidfd opt-in")
class NativeGate(unittest.TestCase):
    def test_one_signal_to_real_waiting_process(self):
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "released"
            child = subprocess.Popen([*semantic.ENTRY, "/usr/bin/touch", str(marker)])
            try:
                proc = Path("/proc",str(child.pid))
                def observe(*_):
                    status = (proc / "status").read_text()
                    caught, = [s.split()[1] for s in status.splitlines() if s.startswith("SigCgt:")]
                    mandate.need(int(caught,16) & (1 << (signal.SIGUSR1-1)), "HANDLER")
                    return {"pid":child.pid}
                pipeline.until(observe, 3, "HANDLER")
                engine = Mock()
                engine.process.side_effect = observe
                semantic.signal_once(engine, store.Journal(Path(d)), "fixture", {}, {"pid":child.pid})
                self.assertEqual(child.wait(timeout=5),0)
                self.assertTrue(marker.is_file())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    unittest.main()
