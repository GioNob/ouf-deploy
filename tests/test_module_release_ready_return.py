"""DEP-58Q interruption matrix. Engine state crosses process boundaries separately from the journal."""
from concurrent.futures import ProcessPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import test_module_release as fixture
from tools.module_release import frame, frame_spec, operation as op, recovery, return_operation, reviewed


class Crash(BaseException):
    pass


class Engine(fixture.Engine):
    def start(self, cid):
        super().start(cid)
        self.docs[cid]["State"]["StartedAt"] = str(len(self.events))


def interrupted(rt, plan, phase, point, after):
    """Crash on either side of an actual journal publication or Engine method."""
    stamp = op.digest(plan)
    old_cid = fixture.OLD
    with ExitStack() as stack:
        def wrap(owner, method, identify):
            original = getattr(owner, method)

            def invoke(*args, **kwargs):
                hit = point is not None and identify(*args) == point
                if hit and not after:
                    raise Crash()
                value = original(*args, **kwargs)
                if hit and after:
                    raise Crash()
                return value
            stack.enter_context(patch.object(owner, method, invoke))

        def record_point(directory, name, data):
            if directory.name.startswith(".prepare-"):
                return "private-" + name
            if directory.name.startswith("restore-after-"):
                return "recycled-" + name
            return name

        wrap(op, "record", record_point)
        wrap(Path, "unlink", lambda path: "cleanup-" + path.name if "-retired-" in path.parent.name else "unlink")
        wrap(reviewed, "acquire", lambda *args: "publish-lock")
        wrap(reviewed, "unlock", lambda *args: "unlock")
        wrap(reviewed.os, "rename", lambda src, dest: "unpublish-lock" if src.name.endswith(".lock") else "rename-lock")
        for method in ("stop", "disconnect", "rename", "create", "start", "connect", "signal", "probe"):
            def identify(cid, *args, method=method):
                if isinstance(cid, dict):
                    cid = cid["Id"]
                if method == "create":
                    return method
                prefix = "old-" if cid == old_cid else "new-"
                if method in ("disconnect", "connect"):
                    return prefix + method + "-" + args[0][0]
                return prefix + method
            wrap(rt, method, identify)
        try:
            if phase == "apply":
                result = op.apply(rt.p, stamp, rt)
            else:
                result = reviewed.return_run(rt.p, stamp, rt, approved_plan=plan)
        except Crash:
            result = "crash"
    return result, rt


def attest_fixture(binding, directory, *, issue=False):
    signature = directory / "receipt.ed25519"
    value = op.digest(op.read(directory, "receipt.json"))
    if issue and not signature.exists():
        signature.write_text(value)
    if signature.read_text() != value:
        raise AssertionError("fixture receipt signature changed")


def approved_retry(rt, stamp, run, *, interrupt):
    import module_operation
    case = fixture.ReleaseTest()
    case.p, case.rt, case.root = rt.p, rt, Path(rt.p["journal"])
    try:
        dispatch, req = case.governed_dispatch()
        req.update(run=run, digest=stamp, phase="rollback")
        record = module_operation.operation.record
        def publish(directory, name, data):
            if interrupt and name == "return-receipt.json":
                raise Crash()
            record(directory, name, data)
        with patch.object(module_operation.operation, "record", publish), \
             patch.object(module_operation.module_receipt, "attest", attest_fixture):
            try:
                result = dispatch(1)
            except Crash:
                result = "crash"
        return result, rt
    finally:
        case.doCleanups()


class ReadyReturn(unittest.TestCase):
    def case(self, delta=True):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        p = case.p
        p["migration"] = {"mode": "none", "rollbackCompatible": True}
        if delta:
            p.update(configDelta={"env": [{"name": "LISTEN_ADDRESS", "before": None, "after": "[::1]:8080"}]},
                     envAllowlist=["LISTEN_ADDRESS"], showValues=["LISTEN_ADDRESS"])
        else:
            p["readyReturn"] = True
        rt = Engine(p, case.rt.blob)
        plan = op.plan(p, rt)
        self.assertEqual(plan["status"], "PLANNED", plan)
        return rt, plan["plan"]

    def oracle(self, rt, plan, result):
        p = rt.p
        root = Path(p["journal"]) / op.digest(plan)
        self.assertEqual(result["status"], "ROLLED_BACK", result)
        self.assertEqual(rt.inspect(p["container"])["Id"], fixture.OLD)
        self.assertTrue(op.ready(rt, rt.inspect(fixture.OLD), p["readiness"]))
        original = Engine(p, rt.blob).inspect(fixture.OLD)
        doc = rt.inspect(fixture.OLD)
        frame.check_body(original, doc, original["Image"], original["Config"]["Image"])
        frame.check_live_networks(original, doc)
        if fixture.NEW in rt.docs:
            failed = rt.inspect(p["failedName"])
            self.assertEqual((failed["Id"], failed["State"]["Pid"], failed["NetworkSettings"]["Networks"]),
                             (fixture.NEW, 0, {}))
        self.assertFalse(reviewed.lock_path(p).exists())
        self.assertFalse(list(root.parent.glob(".*-retired-" + root.name)))
        self.assertEqual(result, op.read(root, "return-receipt.json"))

    def test_DEP_58Q_02_apply_boundaries_then_interrupted_approved_return(self):
        seed, _ = self.case()
        networks = [ep["NetworkID"][0] for ep in seed.nets.values()]
        points = ["private-plan.json", "private-owner.json", "rename-lock", "publish-lock", "plan.json",
                  "baseline.private.json", "stop-intent.json", "old-stop", *["old-disconnect-" + n for n in networks],
                  "old-rename", "create-intent.json", "create", "created.json", "create-proof.json",
                  "start-intent.json", "new-start", "candidate-epoch.json", "start-generation.json",
                  "release-signal.json", "new-signal", "new-probe", "receipt.json", "unpublish-lock", "unlock"]
        self.matrix(points, applying=True)

    def test_DEP_58Q_03_ready_return_boundaries(self):
        seed, _ = self.case()
        networks = [ep["NetworkID"][0] for ep in seed.nets.values()]
        points = ["publish-lock", "return-intent.json", "new-stop", *["new-disconnect-" + n for n in networks],
                  "new-rename", "old-rename", *["old-connect-" + n for n in networks], "restore-start.json",
                  "old-start", "restore-generation.json", "restore-signal.json", "old-signal", "old-probe",
                  "return-receipt.json", "unpublish-lock", "cleanup-plan.json", "cleanup-owner.json", "unlock"]
        self.matrix(points, applying=False)

    def matrix(self, points, applying):
        # New OS processes for both retries. No module globals, open FDs or executor stack survive.
        with ProcessPoolExecutor(1) as retry, ProcessPoolExecutor(1) as finish:
            for point in points:
                for after in (False, True):
                    with self.subTest(point=point, after=after):
                        rt, plan = self.case()
                        if not applying:
                            ready = op.apply(rt.p, op.digest(plan), rt)
                            self.assertEqual(ready["status"], "READY", ready)
                        phase = "apply" if applying else "return"
                        result, rt = interrupted(rt, plan, phase, point, after)
                        self.assertEqual(result, "crash", result)
                        result, rt = retry.submit(interrupted, rt, plan, "return", "return-receipt.json", False).result()
                        self.assertTrue(result == "crash" or result["status"] == "ROLLED_BACK", result)
                        result, rt = finish.submit(interrupted, rt, plan, "return", None, False).result()
                        self.oracle(rt, plan, result)

    def test_DEP_58Q_04_same_image_and_simple_opt_in(self):
        for delta in (False, True):
            rt, plan = self.case(delta=delta)
            if delta:
                rt.docs[fixture.OLD]["Image"] = rt.p["oldImage"] = rt.p["ci"]["imageId"]
                plan = op.plan(rt.p, rt)["plan"]
            ready = op.apply(rt.p, op.digest(plan), rt)
            self.assertEqual(ready["status"], "READY", ready)
            if delta:
                self.assertIn("LISTEN_ADDRESS=[::1]:8080", rt.inspect(fixture.NEW)["Config"]["Env"])
                self.assertEqual(ready["configDeltaSha256"], plan["configDeltaSha256"])
            self.oracle(rt, plan, return_operation.run(rt.p, op.digest(plan), rt))

    def test_DEP_58Q_05_stopped_candidate_and_lost_restore_start(self):
        with ProcessPoolExecutor(1) as retry, ProcessPoolExecutor(1) as finish:
            for point in ("new-start", "start-generation.json"):
                for started in (False, True):
                    rt, plan = self.case()
                    _, rt = interrupted(rt, plan, "apply", point, True)
                    rt.stop(fixture.NEW)
                    result, rt = retry.submit(interrupted, rt, plan, "return", "old-start", started).result()
                    self.assertEqual(result, "crash", result)
                    result, rt = finish.submit(interrupted, rt, plan, "return", None, False).result()
                    self.oracle(rt, plan, result)
                    self.assertEqual(rt.events.count("gate:" + fixture.OLD[0]), 1)

    def test_DEP_58Q_06_recycle_cut(self):
        with ProcessPoolExecutor(1) as retry, ProcessPoolExecutor(1) as finish:
            for point in ("restore-recycle.json", "old-stop", "recycled-restore-start.json",
                          "recycled-restore-generation.json", "recycled-restore-signal.json", "old-signal"):
                for side in (False, True):
                    with self.subTest(point=point, side=side):
                        rt, plan = self.case()
                        self.assertEqual(op.apply(rt.p, op.digest(plan), rt)["status"], "READY")
                        result, rt = interrupted(rt, plan, "return", "restore-signal.json", True)
                        self.assertEqual(result, "crash", result)
                        result, rt = retry.submit(interrupted, rt, plan, "return", point, side).result()
                        self.assertEqual(result, "crash", result)
                        result, rt = finish.submit(interrupted, rt, plan, "return", None, False).result()
                        self.oracle(rt, plan, result)
                        self.assertEqual(rt.events.count("signal:" + fixture.OLD[0]), 1)

    def test_DEP_58Q_20_delayed_delivery_before_recycle_stop(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        _, rt = interrupted(rt, plan, "return", "restore-signal.json", True)
        _, rt = interrupted(rt, plan, "return", "restore-recycle.json", True)
        rt.signal(fixture.OLD)
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))
        self.assertEqual(rt.events.count("gate:" + fixture.OLD[0]), 1)
        self.assertEqual(rt.events.count("signal:" + fixture.OLD[0]), 1)

    def test_DEP_58Q_07_resume_failure_restores_and_preserves_held(self):
        for started in (False, True):
            rt, plan = self.case()
            _, rt = interrupted(rt, plan, "apply", "start-generation.json", True)
            rt.fault = "readiness"
            start = rt.start
            def lost(cid):
                if started:
                    start(cid)
                raise OSError("lost response")
            with patch.object(rt, "start", lost):
                failed = recovery.resume(rt.p, rt, recovery.proposal(rt.p, rt))
            self.assertEqual((failed["status"], failed["rollback"]), ("HELD", "HELD"))
            root = Path(rt.p["journal"]) / op.digest(plan)
            self.assertEqual(failed, op.read(root, "receipt.json"))
            self.oracle(rt, plan, return_operation.run(rt.p, root.name, rt))
            self.assertEqual(failed, op.read(root, "receipt.json"))

    def test_DEP_58Q_14_drift_before_effect(self):
        for fault in ("cid", "generation", "digest", "bind", "endpoint", "owner", "empty-lock", "stale-plan"):
            with self.subTest(fault=fault):
                rt, plan = self.case()
                stamp = op.digest(plan)
                root = Path(rt.p["journal"]) / stamp
                self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
                if fault in ("cid", "digest"):
                    receipt = op.read(root, "receipt.json")
                    receipt["successorCid" if fault == "cid" else "configDeltaSha256"] = "a" * 64
                    (root / "receipt.json").write_text(json.dumps(receipt))
                elif fault == "bind":
                    rt.docs[fixture.NEW]["Mounts"][0]["Destination"] += "-other"
                elif fault == "endpoint":
                    next(iter(rt.docs[fixture.NEW]["NetworkSettings"]["Networks"].values()))["Aliases"].append("other")
                elif fault == "generation":
                    rt.docs[fixture.NEW]["State"]["StartedAt"] = "other"
                elif fault == "stale-plan":
                    stamp = "a" * 64
                else:
                    lock = reviewed.lock_path(rt.p)
                    lock.mkdir()
                    if fault == "owner":
                        op.record(lock, "owner.json", {"planSha256": "b" * 64})
                before = json.dumps(rt.docs)
                events = list(rt.events)
                result = return_operation.run(rt.p, stamp, rt)
                self.assertEqual(result["status"], "HELD", result)
                self.assertEqual(json.dumps(rt.docs), before)
                self.assertEqual(rt.events, events)

    def test_DEP_58Q_18_pre_stop_replan_and_late_retry(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        _, rt = interrupted(rt, plan, "apply", "baseline.private.json", False)
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))
        new = op.plan(rt.p, rt)
        self.assertNotEqual(new["planSha256"], stamp)
        self.assertEqual(new["status"], "PLANNED", new)
        reviewed.acquire(reviewed.lock_path(rt.p), new["planSha256"], new["plan"])
        before = list(rt.events)
        late = return_operation.run(rt.p, stamp, rt)
        self.assertEqual(late["status"], "HELD")
        self.assertEqual(rt.events, before)
        reviewed.owner(reviewed.lock_path(rt.p), new["planSha256"])

    def test_DEP_58Q_19_first_park_inspect_drift(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        result, rt = interrupted(rt, plan, "return", "return-intent.json", True)
        self.assertEqual(result, "crash")
        original = op.park
        def drift(engine, cid, name, networks, **kwargs):
            rt.docs[cid]["State"]["StartedAt"] = "foreign"
            return original(engine, cid, name, networks, **kwargs)
        events = list(rt.events)
        with patch.object(op, "park", drift):
            held = return_operation.run(rt.p, stamp, rt)
        self.assertEqual(held["status"], "HELD")
        self.assertEqual(rt.events, events)
        self.assertTrue(rt.inspect(fixture.NEW)["State"]["Running"])

    def test_DEP_58Q_15_late_create_after_empty_inspect(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        result, rt = interrupted(rt, plan, "apply", "create", False)
        self.assertEqual(result, "crash")
        result, rt = interrupted(rt, plan, "return", "old-rename", False)
        self.assertEqual(result, "crash")
        root = Path(rt.p["journal"]) / stamp
        old = op.load_predecessor(rt.p, rt, root)
        req = reviewed.request(rt.p, old, None)
        rt.create(rt.p["container"], reviewed.stamp_request(req, root))
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

    def test_DEP_58Q_16_review_and_ready_publication(self):
        import mandate
        import module_operation
        retry = self.enterContext(ProcessPoolExecutor(1))
        finish = self.enterContext(ProcessPoolExecutor(1))
        for cut in ("apply.review", "apply.result", "pointer", "signature"):
            for after in (False, True):
                with self.subTest(cut=cut, after=after):
                    case = fixture.ReleaseTest()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    case.p.update(readyReturn=True, migration={"mode": "none", "rollbackCompatible": True},
                                  receiptSigning={"publicKey": {"path": str(case.root / "pub"), "sha256": "a"*64},
                                                  "privateKey": str(case.root / "key")})
                    call, req = case.governed_dispatch()
                    stamp = call(0)["digest"]
                    plan = op.read(case.root / "1", "plan")["plan"]
                    req.update(phase="apply", digest=stamp)
                    save = module_operation.save
                    def publish(path, data, **kwargs):
                        name = "pointer" if path.name.endswith(".ready") else path.name
                        if name == cut and not after:
                            raise Crash()
                        save(path, data, **kwargs)
                        if name == cut and after:
                            raise Crash()
                    def loss(binding, directory, **kwargs):
                        if cut == "signature" and not after:
                            raise Crash()
                        attest_fixture(binding, directory, **kwargs)
                        if cut == "signature":
                            raise Crash()
                    with patch.object(module_operation.module_receipt, "signing_key"), \
                         patch.object(module_operation.module_receipt, "attest", loss), \
                         patch.object(module_operation, "save", publish), self.assertRaises(Crash):
                        call(1)
                    req.update(phase="rollback", run="2")
                    before = json.dumps(case.rt.docs)
                    with self.assertRaises(mandate.Held):
                        call(0)
                    self.assertEqual(json.dumps(case.rt.docs), before)
                    result, rt = retry.submit(approved_retry, case.rt, stamp, "2", interrupt=True).result()
                    self.assertEqual(result, "crash")
                    result, rt = finish.submit(approved_retry, rt, stamp, "3", interrupt=False).result()
                    self.assertEqual(result["status"], "ROLLED_BACK", result)
                    self.oracle(rt, plan, op.read(case.root / stamp, "return-receipt.json"))

    def test_DEP_58Q_21_ready_published_by_recovery_dispatch(self):
        import mandate
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p.update(readyReturn=True, migration={"mode": "none", "rollbackCompatible": True})
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        with patch.object(case.rt, "signal", side_effect=Crash), self.assertRaises(Crash):
            call(1)
        # The signal reached PID 1 before the worker died; a recovery apply proves readiness.
        case.rt.signal(fixture.NEW)
        req.update(run="2", phase="plan")
        req["digest"] = mandate.intent(req)
        recovery_stamp = call(0)["digest"]
        req.update(phase="apply", digest=recovery_stamp)
        self.assertEqual(call(1)["status"], "READY")
        req.update(run="3", phase="rollback", digest=stamp)
        self.assertEqual(call(1)["status"], "ROLLED_BACK")
        plan = op.read(case.root / stamp, "plan.json")
        self.oracle(case.rt, plan, op.read(case.root / stamp, "return-receipt.json"))


class DeltaEngine(fixture.Engine):
    def create(self, name, request):
        cid = super().create(name, request)
        doc = self.docs[cid]
        for bind in request["HostConfig"].get("Binds") or []:
            source, target, mode = bind.split(":")
            doc["Mounts"].append(dict(Type="bind", Source=source, Destination=target,
                                      Mode=mode, RW=mode != "ro", Propagation="rprivate"))
        return cid


class ConfigDeltaTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        p = self.p = json.loads(fixture.PROFILE.read_bytes())
        p.update(inbox=str(self.root), journal=str(self.root), nsenter=str(self.root / "nsenter"),
                 dockerSocket=str(self.root / "sock"), bindRoots=["/fixture-input"],
                 envAllowlist=["FEATURE", "KEEP", "CREDENTIAL_FILE"], showValues=["FEATURE"])
        p["ci"].update(runId=15, runAttempt=1, artifactId=17)
        p["migration"] = {"mode": "none", "rollbackCompatible": True}
        for i, net in enumerate(p["networks"].values(), 1):
            net["ipv4"] = f"192.0.2.{i}"
        p["readiness"]["attempts"] = 2
        p["oldImage"] = "sha256:" + "a" * 64
        self.rt = DeltaEngine(p, fixture.artifact(p, self.root))
        self.old = self.rt.inspect(fixture.OLD)
        self.net = next(iter(p["networks"]))
        self.change = {"name": "FEATURE", "before": None, "after": "enabled"}
        self.source_bytes = b"synthetic fixture"
        self.bind = {"source": "/fixture-input/config", "target": "/fixture-config",
                     "mode": "ro", "sha256": hashlib.sha256(self.source_bytes).hexdigest()}
        self.delta = {"env": [self.change, {"name": "KEEP", "before": "fixture", "after": None},
                              {"name": "CREDENTIAL_FILE", "before": None, "after": self.bind["target"]}],
                      "aliases": {self.net: ["fixture-alias"]}, "binds": [self.bind]}

    def install_delta(self):
        self.p["configDelta"] = self.delta
        # The Engine and host are synthetic. Exercise the common path/policy grammar
        # and content pin while substituting the POSIX root-owned file reader.
        def fixture_file(entry, roots, *, profile):
            mount = frame_spec.bind_shape(entry, roots, profile)
            if entry["sha256"] != hashlib.sha256(self.source_bytes).hexdigest():
                raise frame_spec.SpecHeld("BIND_DIGEST_CHANGED")
            return mount, {}
        self.enterContext(patch.object(frame_spec, "bind_facts", side_effect=fixture_file))

    def planned(self):
        result = op.plan(self.p, self.rt)
        self.assertEqual(result["status"], "PLANNED", result)
        return result

    def held(self, delta, code):
        self.p["configDelta"] = delta
        result = op.plan(self.p, self.rt)
        self.assertEqual((result["status"], result["reason"]), ("HELD", code))
        self.assertNotIn("load", self.rt.events)

    def assert_restored(self):
        doc = self.rt.inspect(self.p["container"])
        self.assertEqual(doc["Id"], self.old["Id"])
        self.assertTrue(doc["State"]["Running"])
        self.assertEqual(doc["Config"], self.old["Config"])
        self.assertEqual(doc["HostConfig"], self.old["HostConfig"])
        self.assertEqual(doc["Mounts"], self.old["Mounts"])
        frame.check_live_networks(self.old, doc)
        if fixture.NEW in self.rt.docs:
            failed = self.rt.inspect(self.p["failedName"])
            self.assertEqual(failed["Id"], fixture.NEW)
            self.assertFalse(failed["State"]["Running"])
            self.assertFalse(failed["NetworkSettings"]["Networks"])

    def test_DEP_58Q_12_bind_drift_at_gate(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(op, "finish_apply", side_effect=Crash), self.assertRaises(Crash):
            op.apply(self.p, stamp, self.rt)
        self.source_bytes += b"changed"
        failure = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual((failure["reason"], failure["rollback"]), ("BIND_DIGEST_CHANGED", "ROLLED_BACK"))
        self.assertNotIn("signal:" + fixture.NEW[0], self.rt.events)
        self.assert_restored()

    def test_DEP_58Q_13_combined_create(self):
        self.install_delta()
        plan = self.planned()
        stamp = plan["planSha256"]
        result = op.apply(self.p, stamp, self.rt)
        self.assertEqual(result["status"], "READY", result)
        doc = self.rt.inspect(fixture.NEW)
        self.assertIn("FEATURE=enabled", doc["Config"]["Env"])
        self.assertNotIn("KEEP=fixture", doc["Config"]["Env"])
        self.assertIn(self.bind["target"], [m["Destination"] for m in doc["Mounts"]])
        self.assertIn("fixture-alias", doc["NetworkSettings"]["Networks"][self.net]["Aliases"])
        self.assertEqual(return_operation.run(self.p, stamp, self.rt)["status"], "ROLLED_BACK")
        self.assert_restored()
