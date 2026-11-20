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
        self.req = dict(run="123", commit="a"*40, attempt="1", phase="apply", direction="forward",
                        queue="empty", digest="c"*64)
        self.cfg = dict(repositoryId=17, environment="private", environmentId=4, reviewerIds=[8],
                        commit=self.req["commit"], branch="protected")
        self.run = dict(id=123, run_attempt=1, event="workflow_dispatch", status="in_progress",
                        head_sha=self.req["commit"], head_branch="protected", path=mandate.WORKFLOW,
                        repository={"id":17}, head_repository={"id":17})
        self.env = dict(id=4, name="private", protection_rules=[dict(type="required_reviewers",
            reviewers=[dict(type="User", reviewer={"id":8})])])
        self.reviews = [dict(state="approved", comment=mandate.challenge(self.req), user={"id":8,"type":"User"},
                             environments=[{"id":4,"name":"private"}])]
        self.effects = Mock()

    def invoke(self, req):
        docs = [self.run, {"protected":True,"commit":{"sha":self.req["commit"]}}, self.env, self.reviews]
        review = mandate.authorize(req, self.cfg, Mock(side_effect=docs))
        self.effects(review)

    def test_exact(self):
        self.invoke(self.req)
        self.effects.assert_called_once()

    def test_drift_before_dispatch(self):
        for key, value in (("digest", "d"*64), ("commit", "b"*40), ("phase", "sign"), ("run", "456"),
                           ("attempt", "2"), ("direction", "return"), ("queue", "inventory")):
            with self.subTest(key=key), self.assertRaises(mandate.Held):
                self.invoke({**self.req, key:value})
        self.effects.assert_not_called()

    def test_missing_unverifiable_or_other_reviewer(self):
        for row in ([], [{**self.reviews[0], "user":{"type":"User","id":9}}],
                    [{**self.reviews[0], "state":"rejected"}],
                    [{**self.reviews[0], "environments":[{"id":5,"name":"private"}]}]):
            self.reviews = row
            with self.assertRaises(mandate.Held):
                self.invoke(self.req)
        with self.assertRaises(OSError):
            mandate.authorize(self.req, self.cfg, Mock(side_effect=OSError))
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
        pending = ("private-subject","ref","PENDING","ACTIVE",1,3,None,None,None)
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
        c.queue.snapshot.return_value = nullcontext([{"state":"PENDING"}])
        c.books.call.return_value = {"observation":{"authorization":{}, "configurationSha256":"p"}}
        plan = dict(head=27,sequence=27,target={},queue=[])
        stage = dict(cid="old",profile={},generation={},epoch={},issue=None)
        with patch.object(pipeline, "signal_once") as send, self.assertRaisesRegex(mandate.Held, "QUEUE_APPROVAL_DRIFT"):
            try:
                c.finish(plan,stage)
            finally:
                send.assert_not_called()

    def test_workflow_intent_matches_protocol(self):
        import yaml
        wf = yaml.safe_load((ROOT / mandate.WORKFLOW).read_text())
        jobs = wf["jobs"]
        for phase in mandate.PHASES:
            job = jobs[phase]
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
            self.assertIn(mandate.challenge(req),Path(d,"summary").read_text())


class RoundTrip(unittest.TestCase):
    """Run the actual phase machine and disk journal against in-memory host boundaries."""

    def test_27_to_28_to_29(self):
        self.round_trip(signed=True)

    def test_return_on_27_without_signature(self):
        self.round_trip(signed=False)

    def round_trip(self, signed):
        from contextlib import ExitStack
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root = Path(d)
            patches.enter_context(patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)))
            patches.enter_context(patch.object(store, "sync_dir"))
            patches.enter_context(patch.object(pipeline, "verified", side_effect=lambda *args: nullcontext(None)))
            old = frame()
            original = dict(role="semantic", containerName="app", image=old["Image"],
                configurationSha256=semantic.semantic_configuration(old), network="fixture",
                networkId="c"*64, bridge="fixture", direction="semantic-to-southbound",
                ipv4="192.0.2.1", destination="192.0.2.2", protocol="tcp", port=443)
            old_id, new_id = old["Id"], "d"*64
            cfg = dict(originalProfile=original, retainedName="saved", failedName="returned", socket="socket",
                       leaseJournal=str(root / "lease"), installRoot=str(root), queue={}, roleTables=["one","two"],
                       roleCids=["first","second"])
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
            engine.call.return_value = {"Id": original["image"]}
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
                c.queue.snapshot.side_effect = lambda **kw: nullcontext([])
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
                if stop_at_gate:
                    return
                req.update(phase="sign",digest="f"*64)
                with self.assertRaisesRegex(mandate.Held, "APPROVED_ISSUANCE_DRIFT"):
                    c.execute("unbound-review")
                self.assertFalse((c.path / "issue.claim").exists())
                req["digest"] = second["digest"]
                self.assertEqual(c.execute("review-sign")["ingress"], "VERIFIED")
                with self.assertRaises(FileExistsError):
                    c.execute("review-sign")
                self.assertEqual(head.version, seq)
            scenario("101","forward",28,new_id,stop_at_gate=True)
            if signed:
                scenario("103","forward",28,new_id)
                scenario("102","return",29,old_id)
            else:
                scenario("102","return",27,old_id)
            engine.create.assert_called_once()
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
