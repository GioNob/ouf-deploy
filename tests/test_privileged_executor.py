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
        old = dict(planSha256="a"*64, outputDirectory="first", observation={"epoch":1})
        fresh = {**old, "planSha256":"b"*64, "outputDirectory":"second"}
        books, record = Mock(), Mock()
        books.call.side_effect = [runbooks.RenewalCollision(), fresh, "stopped"]
        self.assertEqual(runbooks.stop(books, 27, old, record), "stopped")
        self.assertEqual([c.args for c in books.call.call_args_list],
                         [("stop",27,old["planSha256"]), ("stop",27), ("stop",27,fresh["planSha256"])])
        books.wait_renewal.assert_called_once()
        record.assert_called_once_with(1, fresh)
        books.call.side_effect = [runbooks.RenewalCollision(), {**fresh, "observation":{"epoch":2}}]
        with self.assertRaisesRegex(mandate.Held, "NEW_REVIEW"):
            runbooks.stop(books, 27, old, record)
        books.call.side_effect = [runbooks.RenewalCollision(), fresh]*3
        with self.assertRaisesRegex(mandate.Held, "RETRY_LIMIT"):
            runbooks.stop(books, 27, old, record)

    def test_expired_or_unbounded_kernel_lease(self):
        from ingress import live_members
        for ttl in (0, 50, 40000):
            with self.assertRaisesRegex(mandate.Held, "LEASE_EXPIRED"):
                live_members([{"elem":{"val":"member","expires":ttl}}], ["member"], 30, .1)
        live_members([{"elem":{"val":"member","expires":1000}}], ["member"], 30, .1)

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
            engine.inspect = lambda name, absent=False: stopped if name=="old" else None
            engine.call = Mock()
            plan = {"old":"old", "source":"new", "endpoints":{"network":{"Aliases":["alias"]}}}
            for _ in range(2):
                outcome = log.effect("reconnect", plan, lambda: engine.reconnect(
                    "old", "semantic", plan["endpoints"], {"network":"id"}))
                self.assertEqual(outcome, "old")
            self.assertEqual(len(engine.call.call_args_list), 2)
            self.assertEqual(engine.call.call_args.args[2], {"Container":"old","EndpointConfig":{"Aliases":["alias"]}})

    def test_unauthorized_queue_never_signals(self):
        c = object.__new__(pipeline.Cutover)
        c.forward, c.req, c.root = False, {"direction":"return","run":"123","queue":"inventory"}, Path(".")
        c.owner, c.current_version = Mock(return_value="123"), Mock(return_value=27)
        c.authority = Mock(return_value="chain")
        c.engine, c.books, c.log = Mock(), Mock(), Mock()
        c.engine.process.return_value = {}
        c.observe, c.closed, c.apply_book = Mock(return_value={}), Mock(), Mock()
        c.supervisor = Mock(return_value={"semanticIngress":{"profile":{}}})
        c.queue = Mock()
        c.queue.snapshot.side_effect = [[], [{"state":"PENDING"}]]
        c.books.call.return_value = {"observation":{"authorization":{}, "configurationSha256":"p"}}
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
            script = job["steps"][0]["run"]
            self.assertEqual(script.count("/usr/bin/sudo"), 1)
            self.assertNotIn("checkout", script)
            self.assertNotIn("docker", script)
        env = dict(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="c"*40,
                   DIRECTION="forward", QUEUE="empty")
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

    def round_trip(self, signed, prove=False, migrations=None):
        from contextlib import ExitStack
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root = Path(d)
            patches.enter_context(patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)))
            patches.enter_context(patch.object(store, "sync_dir"))
            patches.enter_context(patch.object(pipeline, "verified", side_effect=lambda *args: nullcontext(None)))
            old = frame()
            old["Config"]["Image"] = "fixture:original"
            original = dict(role="semantic", containerName="app", image=old["Image"],
                configurationSha256=semantic.semantic_configuration(old), network="fixture",
                networkId="c"*64, bridge="fixture", direction="semantic-to-southbound",
                ipv4="192.0.2.1", destination="192.0.2.2", protocol="tcp", port=443)
            old_id, new_id = old["Id"], "d"*64
            cfg = dict(originalProfile=original, retainedName="saved", failedName="returned", socket="socket",
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
            def observed(cid, profile, sup):
                return {"cid":cid, "profile":profile}
            def closed(sup):
                self.assertTrue(head.waiting)
            def supervisor(version):
                return {"semanticIngress":{"profile":head.profile,"commands":{"socket":"socket"}},
                        "coordinator":{"journalPath":str(root / "lease")}, "statusPath":str(root / "status")}
            def stop_book(books, seq, plan, record):
                counts.append(("stop",seq))
                head.waiting = True
                store.save(root/"status", {"state":"WAITING"}, replace=True)
                return {"lastObservation":plan["observation"]}
            patches.enter_context(patch.object(pipeline, "stop", side_effect=stop_book))
            def signal_gate(engine, log, cid, profile, generation, deadline):
                self.assertFalse(head.waiting)
                counts.append(("signal",cid))
            patches.enter_context(patch.object(pipeline, "signal_once", side_effect=signal_gate))
            engine = Mock()
            def inspect(name, absent=False):
                if absent:
                    return None
                if name=="app" or (name==old_id and not engine.detach.called):
                    return old
                self.assertEqual(name, old_id)
                return {**old, "Name":"/saved","NetworkSettings":{"Networks":{}},"State":{"Running":False}}
            engine.inspect.side_effect = inspect
            engine.call.return_value = {"Id": new_image}
            engine.create.return_value = new_id
            engine.reconnect.return_value = old_id
            engine.detach.side_effect = lambda cid, *_: cid
            engine.start_gate.return_value = None
            engine.process.side_effect = lambda cid,*_: {"cid":cid, "pid":42}
            def scenario(run, direction, seq, cid, stop_at_gate=False):
                req = dict(run=run,attempt="1",commit="a"*40,phase="plan",queue="empty",direction=direction)
                req["digest"] = mandate.intent(req)
                c = pipeline.Cutover(cfg,root,req)
                c.engine, c.books, c.queue = engine, Mock(), Mock(spec=queue.Queue)
                c.current_version = lambda: head.version
                c.authority = lambda: "signed-chain"
                c.observe, c.closed, c.supervisor = observed, closed, supervisor
                c.ready = Mock()
                c.probe_preflight = Mock(return_value="preflight")
                c.queue.snapshot.return_value = []
                c.queue.worker.return_value = {"state":"SUCCEEDED"}
                stored = {}
                def call(op, version, approved=None):
                    if approved:
                        self.assertEqual(approved, stored[op]["planSha256"])
                        counts.append((op, version))
                        if op=="issue":
                            head.version = version
                            return {"payloadSha256":"payload"}
                        if op=="upgrade":
                            head.profile = c.record("stage")["profile"]
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
                        target = semantic.allocated_profile(plan,cid) if direction=="forward" else original
                        value = dict(previousHead={"sequence":version-1,"sha256":"previous"},
                                     payload={"sequence":version,"supersedes":"previous"},
                                     compositionInputHashes={"semanticProfile":mandate.digest(target)},privateKeysRead=0)
                    elif op=="upgrade":
                        value = dict(versionBefore=version-1,versionAfter=version,authorization={"sha256":"payload"},
                                     compositionInputHashes=stored["issue"]["compositionInputHashes"])
                    else:
                        self.assertEqual(op,"probe")
                        value = {"observation":{"semantic":{"containerId":cid}}}
                    stored[op] = {**value,"planSha256":mandate.digest(value)}
                    return stored[op]
                c.books.call.side_effect = call
                first = c.execute("review-plan")
                req.update(phase="apply",digest="e"*64)
                with self.assertRaisesRegex(mandate.Held, "APPROVED_PLAN_DRIFT"):
                    c.execute("unbound-review")
                self.assertFalse((c.path / "apply.review").exists())
                req["digest"] = first["digest"]
                second = c.execute("review-apply")
                if migrations and direction == "forward":
                    self.assertEqual(second["migrationsSha256"], mandate.digest(migrations))
                    signing = c.record("stage")["issue"]["planSha256"]
                    req.update(phase="sign", digest=signing)
                    with self.assertRaisesRegex(mandate.Held, "MIGRATION_REVIEW_REQUIRED"):
                        c.execute("review-sign")
                    req.update(phase="migrate", digest=signing)
                    with self.assertRaisesRegex(mandate.Held, "APPROVED_MIGRATION_DRIFT"):
                        c.execute("wrong-review")
                    self.assertNotIn(("signal", cid), counts)
                    req["digest"] = second["digest"]
                    second = c.execute("review-migrate")
                    self.assertEqual(second["digest"], signing)
                else:
                    self.assertNotIn("migrationCount", second)
                if stop_at_gate:
                    return
                req.update(phase="sign",digest="f"*64)
                with self.assertRaisesRegex(mandate.Held, "APPROVED_ISSUANCE_DRIFT"):
                    c.execute("unbound-review")
                self.assertFalse((c.path / "issue.claim").exists())
                req["digest"] = second["digest"]
                done = c.execute("review-sign")
                self.assertEqual((done["ingress"], done["readiness"], done["worker"]),
                                 ("VERIFIED", "UP", "on" if direction == "forward" else "off"))
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
            scenario("101","forward",28,new_id,stop_at_gate=True)
            if signed:
                scenario("103","forward",28,new_id)
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
