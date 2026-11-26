"""DEP-58Q interruption matrix. Engine state crosses process boundaries separately from the journal."""
from concurrent.futures import ProcessPoolExecutor
from contextlib import ExitStack
import copy
import hashlib
import json
import os
import shutil
import sys
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
                return name if name == "origin.json" else "recycled-" + name
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
            if phase in ("apply", "stage"):
                result = op.apply(rt.p, stamp, rt, defer_migration=phase == "stage")
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

    def apply_points(self):
        seed, _ = self.case()
        networks = [ep["NetworkID"][0] for ep in seed.nets.values()]
        points = ["private-plan.json", "private-owner.json", "rename-lock", "publish-lock", "plan.json",
                  "baseline.private.json", "stop-intent.json", "old-stop", *["old-disconnect-" + n for n in networks],
                  "old-rename", "create-intent.json", "create", "created.json", "create-proof.json",
                  "start-intent.json", "new-start", "candidate-epoch.json", "start-generation.json",
                  "release-signal.json", "new-signal", "new-probe", "receipt.json", "unpublish-lock", "unlock"]
        return points

    def test_DEP_58Q_02_apply_boundaries_then_interrupted_approved_return(self):
        self.matrix(self.apply_points(), applying=True)

    def return_points(self):
        seed, _ = self.case()
        networks = [ep["NetworkID"][0] for ep in seed.nets.values()]
        points = ["publish-lock", "return-intent.json", "park-epoch.json", "new-stop", *["new-disconnect-" + n for n in networks],
                  "new-rename", "old-rename", *["old-connect-" + n for n in networks], "restore-start.json",
                  "restore-stop-epoch.json", "old-start", "restore-generation.json", "restore-signal.json", "old-signal", "old-probe",
                  "return-receipt.json", "unpublish-lock", "cleanup-plan.json", "cleanup-owner.json", "unlock"]
        return points

    def test_DEP_58Q_03_ready_return_boundaries(self):
        self.matrix(self.return_points(), applying=False)

    def loss_row(self, rt, plan, label, retry=None, ambiguous_exit=False):
        """Replay the same independent Docker and filesystem snapshots for each missing file."""
        parent = Path(rt.p["journal"])
        root = parent / op.digest(plan)
        def journal_entries():
            return [p for p in parent.iterdir() if p.is_dir() and (
                p == root or p == reviewed.lock_path(rt.p) or p.name.startswith((".prepare-", "." + rt.p["module"] + ".lock-")))]
        # Keep the approval ledger as a separate input to each dispatch. Only
        # the release journal (including its published/private locks) loses a file.
        release_entries = {d.name for d in journal_entries()}
        def relevant(path):
            return path.suffix != ".zip" and (retry is not None or path.parts[0] in release_entries)
        dirs, snapshot = [], {}
        for path in parent.rglob("*"):
            rel = path.relative_to(parent)
            if relevant(rel):
                if path.is_dir():
                    dirs.append(rel)
                else:
                    snapshot[rel] = path.read_bytes()
        files = sorted(rel for rel in snapshot if rel.parts[0] in release_entries)

        def reset():
            entries = [p for p in parent.iterdir() if p.suffix != ".zip"] if retry else journal_entries()
            for path in entries:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            for rel in sorted(dirs, key=lambda d: len(d.parts)):
                (parent / rel).mkdir()
            for rel, data in snapshot.items():
                (parent / rel).write_bytes(data)

        row = []
        try:
            for lost in [None, *files]:
                with self.subTest(cut=label, lost=str(lost)):
                    reset()
                    if lost:
                        (parent / lost).unlink()
                    unobserved = ambiguous_exit and not any((root / name).is_file() for name in
                                                            ("candidate-epoch.json", "start-generation.json"))
                    fresh = copy.deepcopy(rt)
                    if retry is None:
                        result = reviewed.return_run(fresh.p, root.name, fresh, approved_plan=plan)
                    else:
                        result = retry(fresh)
                    cell = str(lost).replace(root.name, "run") if lost else "intact"
                    if unobserved:
                        self.assertEqual((result["status"], result["reason"]), ("HELD", "START_GENERATION_UNCONFIRMED"))
                        self.assertEqual(rt.events, fresh.events)
                        cell += "=HELD/START_GENERATION_UNCONFIRMED"
                    else:
                        self.oracle(fresh, plan, result)
                    row.append(cell)
        finally:
            reset()
        print("D-080", label, "(ROLLED_BACK unless indicated)", ", ".join(row), flush=True)
        return len(files) + 1

    def test_DEP_58QG_02_generated_single_loss_matrix(self):
        phases = {"apply": [*self.apply_points(), "return-frame.json"],
                  "return": [*self.return_points(), "restore-dispatch.json"],
                  "recycle": ["restore-recycle.json", "origin.json", "old-stop", "recycled-restore-stop-epoch.json",
                              "recycled-restore-start.json", "old-start", "recycled-restore-generation.json",
                              "recycled-restore-signal.json", "recycled-restore-dispatch.json", "old-signal"],
                  "failed-apply": ["rollback-intent.json", "new-stop", "old-start", "receipt.json"]}
        cells = rows = 0
        with patch.object(os, "fsync"):
            for phase, points in phases.items():
                for point in points:
                    for after in (False, True):
                        rt, plan = self.case()
                        stamp = op.digest(plan)
                        if phase in ("return", "recycle"):
                            self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
                        if phase == "recycle":
                            self.assertEqual(interrupted(rt, plan, "return", "restore-signal.json", True)[0], "crash")
                        if phase == "failed-apply":
                            rt.fault = "readiness"
                        action = "apply" if phase in ("apply", "failed-apply") else "return"
                        result, rt = interrupted(rt, plan, action, point, after)
                        self.assertEqual(result, "crash", (phase, point, after, result))
                        cells += self.loss_row(rt, plan, (phase, point, after))
                        rows += 1
        print(f"D-080 matrix: {rows} interruption boundaries, {cells} cases", flush=True)

    def test_DEP_58QG_02_publication_and_transient_return_cuts(self):
        points = {"apply": ["cleanup-plan.json", "cleanup-owner.json"],
                  "return": ["private-plan.json", "private-owner.json", "rename-lock"],
                  "late-signal": ["recycle-ready.json"], "failed-restore": ["receipt.json"],
                  "dedicated": ["migration-plan.json", "stage.json"],
                  "spring-flyway": ["migration-plan.json", "stage.json"]}
        rows = cells = 0
        for scenario, cuts in points.items():
            for point in cuts:
                for after in (False, True):
                    rt, plan = self.case()
                    phase = "apply"
                    with ExitStack() as stack:
                        if scenario in ("dedicated", "spring-flyway"):
                            phase = "stage"
                            rt.p["migration"]["mode"] = scenario
                            if scenario == "dedicated":
                                rt.p["migration"]["command"] = ["fixture-migrate"]
                            plan = op.plan(rt.p, rt)["plan"]
                        elif scenario == "failed-restore":
                            rt.fault = "readiness"
                            start = rt.start
                            def transient(cid):
                                if cid == fixture.OLD:
                                    raise OSError("fixture")
                                start(cid)
                            stack.enter_context(patch.object(rt, "start", transient))
                        elif scenario in ("return", "late-signal"):
                            phase = "return"
                            self.assertEqual(op.apply(rt.p, op.digest(plan), rt)["status"], "READY")
                            if scenario == "late-signal":
                                for claim in ("restore-signal.json", "restore-recycle.json"):
                                    self.assertEqual(interrupted(rt, plan, phase, claim, True)[0], "crash")
                                rt.signal(fixture.OLD)
                        self.assertEqual(interrupted(rt, plan, phase, point, after)[0], "crash")
                    cells += self.loss_row(rt, plan, (scenario, point, after))
                    rows += 1
        print(f"D-080 publication and recovery: {rows} interruption boundaries, {cells} cases", flush=True)

    def test_DEP_58QG_02_immediate_exit_single_loss_matrix(self):
        cells = 0
        for cut, after in (("new-start", True), ("candidate-epoch.json", False), ("candidate-epoch.json", True),
                           ("start-generation.json", False), ("start-generation.json", True)):
            rt, plan = self.case()
            self.assertEqual(interrupted(rt, plan, "apply", cut, after)[0], "crash")
            rt.stop(fixture.NEW)
            cells += self.loss_row(rt, plan, ("exited", cut, after), ambiguous_exit=True)
        print(f"D-080 exited: 5 interruption boundaries, {cells} cases", flush=True)

    def test_DEP_58QG_02_migration_single_loss_matrix(self):
        cells = rows = 0
        for mode in ("dedicated", "spring-flyway"):
            points = ["migration-review-consumed.json", "release-signal.json", "signal", "receipt.json"]
            if mode == "dedicated":
                points += ["migration-intent.json", "migrate", "migration-complete.json"]
            for point in points:
                for after in (False, True):
                    rt, _ = self.case()
                    rt.p["migration"]["mode"] = mode
                    if mode == "dedicated":
                        rt.p["migration"]["command"] = ["fixture-migrate"]
                    plan = op.plan(rt.p, rt)["plan"]
                    stamp = op.digest(plan)
                    stage = op.apply(rt.p, stamp, rt, defer_migration=True)
                    def cut(name, fn, *args, **kwargs):
                        if name == point and not after:
                            raise Crash()
                        result = fn(*args, **kwargs)
                        if name == point and after:
                            raise Crash()
                        return result
                    record = op.record
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(op, "record", lambda d, n, v: cut(n, record, d, n, v)))
                        for name in ("signal", "migrate"):
                            original = getattr(rt, name)
                            stack.enter_context(patch.object(rt, name,
                                lambda *a, n=name, fn=original: cut(n, fn, *a)))
                        with self.assertRaises(Crash):
                            op.migrate(rt.p, stamp, stage["migrationSha256"], rt)
                    cells += self.loss_row(rt, plan, (mode, point, after))
                    rows += 1
        print(f"D-080 migration: {rows} interruption boundaries, {cells} cases", flush=True)

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

    def test_DEP_58QB_02_unbound_spring_recovery_before_generation(self):
        rt, _ = self.case()
        rt.p["migration"]["mode"] = "spring-flyway"
        plan = op.plan(rt.p, rt)["plan"]
        result, rt = interrupted(rt, plan, "apply", "start-generation.json", False)
        self.assertEqual(result, "crash")
        resumed = recovery.resume(rt.p, rt, recovery.proposal(rt.p, rt))
        self.assertEqual(resumed["rollback"], "ROLLED_BACK", resumed)
        self.oracle(rt, plan, op.read(Path(rt.p["journal"]) / op.digest(plan), "return-receipt.json"))

    def test_DEP_58QB_05_foreign_restart_before_restore_generation(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        result, rt = interrupted(rt, plan, "return", "restore-generation.json", False)
        self.assertEqual(result, "crash")
        rt.stop(fixture.OLD)
        rt.start(fixture.OLD)
        before = list(rt.events)
        denied = return_operation.run(rt.p, stamp, rt)
        self.assertEqual((denied["status"], denied["reason"]), ("HELD", "RESTORE_GENERATION_CHANGED"))
        self.assertEqual(rt.events, before)
        directory = Path(rt.p["journal"]) / stamp
        self.assertFalse((directory / "restore-generation.json").exists())
        self.assertFalse((directory / "return-receipt.json").exists())

    def test_DEP_58QD_04_return_fences_staged_run_and_uncertain_spring(self):
        for mode in ("dedicated", "spring-flyway"):
            for cut in ("return-intent.json", "release-signal.json"):
                with self.subTest(mode=mode, cut=cut):
                    rt, _ = self.case()
                    rt.p["migration"]["mode"] = mode
                    if mode == "dedicated":
                        rt.p["migration"]["command"] = ["fixture-migrate"]
                    plan = op.plan(rt.p, rt)["plan"]
                    stamp = op.digest(plan)
                    stage = op.apply(rt.p, stamp, rt, defer_migration=True)
                    self.assertEqual(stage["status"], "GATED")
                    if cut == "return-intent.json":
                        self.assertEqual(interrupted(rt, plan, "return", cut, True)[0], "crash")
                        events = list(rt.events)
                        with self.assertRaisesRegex(op.Held, "REVIEWED_RETURN_REQUIRED"):
                            op.migrate(rt.p, stamp, stage["migrationSha256"], rt)
                        self.assertEqual(rt.events, events)
                    else:
                        with patch.object(rt, "signal", side_effect=Crash), self.assertRaises(Crash):
                            op.migrate(rt.p, stamp, stage["migrationSha256"], rt)
                    self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

    def test_DEP_58QD_05_unbound_dedicated_returns_across_migration(self):
        for cut in ("start-generation.json", "migration-intent.json", "migration-complete.json"):
            for after in (False, True):
                with self.subTest(cut=cut, after=after):
                    rt, _ = self.case()
                    rt.p["migration"].update(mode="dedicated", command=["fixture-migrate"])
                    plan = op.plan(rt.p, rt)["plan"]
                    stamp = op.digest(plan)
                    if cut == "start-generation.json":
                        self.assertEqual(interrupted(rt, plan, "apply", cut, after)[0], "crash")
                    else:
                        stage = op.apply(rt.p, stamp, rt, defer_migration=True)
                        record = op.record
                        def interrupt(directory, name, data):
                            if name == cut and not after:
                                raise Crash()
                            record(directory, name, data)
                            if name == cut:
                                raise Crash()
                        with patch.object(op, "record", interrupt), self.assertRaises(Crash):
                            op.migrate(rt.p, stamp, stage["migrationSha256"], rt)
                    self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

    def test_DEP_58QD_06_missing_rollback_intent_after_io_failure(self):
        rt, plan = self.case()
        rt.fault = "readiness"
        original = op.record
        def record(root, name, data):
            if name == "rollback-intent.json":
                raise OSError("unavailable")
            original(root, name, data)
        with patch.object(op, "record", record):
            failure = op.apply(rt.p, op.digest(plan), rt)
        self.assertEqual((failure["status"], failure["rollback"]), ("HELD", "HELD"))
        self.oracle(rt, plan, return_operation.run(rt.p, op.digest(plan), rt))

    def test_DEP_58QD_07_digest_owner_survives_interruption_before_apply_review(self):
        import mandate
        import module_operation
        case = self.governed_case()
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        with patch.object(module_operation, "save", side_effect=Crash), self.assertRaises(Crash):
            call(1)
        req.update(phase="plan", run="2")
        req["digest"] = mandate.intent(req)
        self.assertEqual(call(0)["digest"], stamp)
        req.update(phase="apply", digest=stamp)
        events = list(case.rt.events)
        with self.assertRaisesRegex(mandate.Held, "PLAN_ALREADY_CONSUMED"):
            call(1)
        self.assertEqual(events, case.rt.events)
        self.assertEqual(op.read(case.root / "2", "approvals"), [])
        req.update(phase="rollback", run="3")
        self.assertEqual(call(1)["status"], "ROLLED_BACK")
        directory = case.root / stamp
        self.oracle(case.rt, op.read(directory, "plan.json"), op.read(directory, "return-receipt.json"))

    def test_DEP_58QD_08_foreign_restart_before_candidate_epoch(self):
        rt, plan = self.case()
        self.assertEqual(interrupted(rt, plan, "apply", "candidate-epoch.json", False)[0], "crash")
        rt.stop(fixture.NEW)
        rt.start(fixture.NEW)
        events = list(rt.events)
        held = return_operation.run(rt.p, op.digest(plan), rt)
        self.assertEqual((held["status"], held["reason"]), ("HELD", "START_GENERATION_CHANGED"))
        self.assertEqual(rt.events, events)
        self.assertFalse((Path(rt.p["journal"]) / op.digest(plan) / "return-intent.json").exists())

    def test_DEP_58QE_03_generation_at_stop(self):
        for inside_stop in (False, True):
            for already_exited in (False, True):
                with self.subTest(inside_stop=inside_stop, already_exited=already_exited):
                    rt, plan = self.case()
                    stamp = op.digest(plan)
                    self.assertEqual(interrupted(rt, plan, "apply", "candidate-epoch.json", False)[0], "crash")
                    stop, confirm = rt.stop, op.confirm
                    def foreign_restart():
                        stop(fixture.NEW)
                        rt.start(fixture.NEW)
                        if already_exited:
                            stop(fixture.NEW)
                    def at_stop(cid):
                        if inside_stop:
                            foreign_restart()
                        stop(cid)
                    def after_proof(root, name, value):
                        confirm(root, name, value)
                        if not inside_stop and name == "park-epoch.json":
                            foreign_restart()
                    with patch.object(rt, "stop", side_effect=at_stop) as requested, patch.object(op, "confirm", after_proof):
                        held = return_operation.run(rt.p, stamp, rt)
                    self.assertEqual((held["status"], held["reason"]), ("HELD", "START_GENERATION_CHANGED"))
                    self.assertEqual(requested.call_count, int(inside_stop))
                    self.assertFalse(rt.inspect(fixture.OLD)["State"]["Running"])
                    self.assertFalse((Path(rt.p["journal"]) / stamp / "return-receipt.json").exists())

    def test_DEP_58QE_04_ready_create_intent_redundant(self):
        for after_park in (False, True):
            with self.subTest(after_park=after_park):
                rt, plan = self.case()
                stamp = op.digest(plan)
                root = Path(rt.p["journal"]) / stamp
                self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
                if after_park:
                    self.assertEqual(interrupted(rt, plan, "return", "new-rename", True)[0], "crash")
                    (root / "created.json").unlink()
                (root / "create-intent.json").unlink()
                self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))
                (root / "created.json").unlink()
                self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

        rt, plan = self.case()
        stamp = op.digest(plan)
        root = Path(rt.p["journal"]) / stamp
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        (root / "create-intent.json").unlink()
        (root / "created.json").write_text(json.dumps({"cid": fixture.OLD}))
        events = list(rt.events)
        held = return_operation.run(rt.p, stamp, rt)
        self.assertEqual(held["status"], "HELD")
        self.assertEqual(events, rt.events)

    def test_DEP_58QD_09_http_change_and_terminal_retry(self):
        rt, _ = self.case()
        rt.p["readiness"]["acceptStatus"] = [200, 204]
        plan = op.plan(rt.p, rt)["plan"]
        stamp = op.digest(plan)
        ready = op.apply(rt.p, stamp, rt)
        self.assertEqual(ready["readyHttp"], 200)
        with patch.object(rt, "probe", return_value=(204, b'{"status":"UP"}')):
            returned = return_operation.run(rt.p, stamp, rt)
            self.oracle(rt, plan, returned)
            self.assertEqual(returned["predecessorReadyHttp"], 204)
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

    def test_DEP_58QD_10_review_owner_before_run_ledger(self):
        import store
        case = self.governed_case()
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        save = store.save
        def cut(path, value, **kwargs):
            if path.name == "approvals":
                raise Crash()
            save(path, value, **kwargs)
        with patch.object(store, "save", cut), self.assertRaises(Crash):
            call(1)
        self.assertEqual(op.read(case.root / "1", "approvals"), [])
        req.update(run="2", phase="rollback")
        self.assertEqual(call(1)["status"], "ROLLED_BACK")
        self.assertNotIn("stop:" + fixture.OLD[0], case.rt.events)

    def test_DEP_58QD_11_compatible_schema_and_stopped_ready_candidate(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        root = Path(rt.p["journal"]) / stamp
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        rt.stop(fixture.NEW)
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))
        for mode, claim in (("dedicated", "migration-intent.json"), ("spring-flyway", "release-signal.json")):
            with self.subTest(mode=mode):
                profile = {"migration": {"mode": mode, "rollbackCompatible": False}}
                directory = root / mode
                directory.mkdir()
                reviewed.return_compatible(profile, directory)
                op.record(directory, claim, {})
                with self.assertRaisesRegex(op.Held, "MIGRATION_ROLLBACK_BLOCKED"):
                    reviewed.return_compatible(profile, directory)

    def test_DEP_58QD_12_epoch_and_receipt_prove_candidate_without_redundant_intents(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        directory = Path(rt.p["journal"]) / stamp
        for name in ("stop-intent.json", "start-intent.json", "release-signal.json", "start-generation.json"):
            (directory / name).unlink()
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))

    def test_bound_none_refuses_changed_database_before_stop(self):
        import test_module_release_mcp as mcp
        import mandate
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["configDelta"] = {"aliases": {next(iter(case.p["networks"])): ["reviewed-db-client"]}}
        stamp = case.planned()["digest"]
        self.assertEqual(case.call("apply", stamp)["status"], "READY")
        events = list(case.rt.events)
        case.db["schema"].append("unexpected column")
        with self.assertRaisesRegex(mandate.Held, "DATABASE_CHANGED"):
            case.call("rollback", stamp, run="2")
        self.assertEqual(events, case.rt.events)
        self.assertEqual(case.rt.inspect(case.p["container"])["Id"], fixture.NEW)

    def test_signed_ready_before_result_republication_single_loss_matrix(self):
        import module_operation
        import mandate
        cells = 0
        for unlock_error, apply_error in ((Crash, Crash), (OSError, mandate.Held)):
            case = self.governed_case()
            case.p["receiptSigning"] = {"publicKey": {"path": str(case.root / "pub"), "sha256": "a"*64},
                                        "privateKey": str(case.root / "key")}
            call, req = case.governed_dispatch()
            stamp = call(0)["digest"]
            plan = op.read(case.root / "1", "plan")["plan"]
            req.update(phase="apply", digest=stamp)
            with patch.object(module_operation.module_receipt, "signing_key"), \
                 patch.object(module_operation.operation.reviewed, "unlock", side_effect=unlock_error), self.assertRaises(apply_error):
                call(1)
            req.update(run="2", phase="rollback")
            def signed(binding, directory, **kwargs):
                attest_fixture(binding, directory, **kwargs)
                raise Crash()
            with patch.object(module_operation.module_receipt, "attest", signed), self.assertRaises(Crash):
                call(1)
            self.assertTrue((case.root / stamp / "receipt.ed25519").is_file())
            target = case.root / "1" / "apply.result"
            if unlock_error is OSError:
                self.assertEqual(op.read(target.parent, target.name)["status"], "HELD")
            else:
                self.assertFalse(target.exists())
            def governed(fresh):
                result, _ = approved_retry(fresh, stamp, "3", interrupt=False)
                self.assertEqual(result["status"], "ROLLED_BACK", result)
                return op.read(case.root / stamp, "return-receipt.json")
            cells += self.loss_row(case.rt, plan, ("signed-before-republication", unlock_error.__name__), governed)
        print(f"D-080 signed before republication: 2 interruption boundaries, {cells} cases", flush=True)

    def test_DEP_58QD_13_bound_dedicated_keeps_compatible_committed_schema(self):
        import test_module_release_mcp as mcp
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.dedicated()
        net = next(iter(case.p["networks"]))
        case.p["configDelta"] = {"aliases": {net: ["reviewed-db-client"]}}
        stamp = case.planned()["digest"]
        gated = case.call("apply", stamp)
        self.assertEqual(case.call("migrate", gated["digest"])["status"], "READY")
        self.assertEqual(case.call("rollback", stamp, run="2")["status"], "ROLLED_BACK")
        self.assertEqual(case.db["history"][-1][0], 15)
        self.assertEqual(case.rt.inspect(case.p["container"])["Id"], fixture.OLD)

    def test_DEP_58QD_14_return_after_republication_of_ready(self):
        import mandate
        import module_operation
        for mode in ("none", "dedicated"):
            with self.subTest(mode=mode):
                case = self.governed_case()
                if mode == "dedicated":
                    case.p["migration"].update(mode=mode, command=["fixture-migrate"])
                call, req = case.governed_dispatch()
                stamp = call(0)["digest"]
                req.update(phase="apply", digest=stamp)
                count = 1
                if mode == "dedicated":
                    req.update(phase="migrate", digest=call(1)["digest"])
                    count = 2
                with patch.object(module_operation.operation.reviewed, "unlock", side_effect=Crash), self.assertRaises(Crash):
                    call(count)
                req.update(run="2", phase="plan")
                req["digest"] = mandate.intent(req)
                proposal = call(0)
                req.update(phase="apply", digest=proposal["digest"])
                self.assertEqual(call(1)["status"], "READY")
                req.update(run="3", phase="rollback", digest=stamp)
                self.assertEqual(call(1)["status"], "ROLLED_BACK")
                directory = case.root / stamp
                self.oracle(case.rt, op.read(directory, "plan.json"), op.read(directory, "return-receipt.json"))

    def test_DEP_58QD_15_return_after_uncertain_spring_signal(self):
        rt, _ = self.case()
        rt.p["migration"]["mode"] = "spring-flyway"
        plan = op.plan(rt.p, rt)["plan"]
        stamp = op.digest(plan)
        gated = op.apply(rt.p, stamp, rt, defer_migration=True)
        rt.fault = "lost_signal"
        failed = op.migrate(rt.p, stamp, gated["migrationSha256"], rt)
        self.assertEqual(failed["reason"], "FLYWAY_OUTCOME_UNCONFIRMED")
        self.oracle(rt, plan, return_operation.run(rt.p, stamp, rt))
        self.assertEqual(rt.events.count("signal:" + fixture.NEW[0]), 1)

    def test_DEP_58QD_16_consumed_migration_digest_has_one_run(self):
        import mandate
        import module_operation
        case = self.governed_case()
        case.p["migration"].update(mode="dedicated", command=["fixture-migrate"])
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        stage = call(1)["digest"]
        req.update(phase="migrate", digest=stage)
        with patch.object(module_operation, "save", side_effect=Crash), self.assertRaises(Crash):
            call(2)
        req.update(run="2", phase="plan")
        req["digest"] = mandate.intent(req)
        recovery_stamp = call(0)["digest"]
        req.update(phase="apply", digest=recovery_stamp)
        self.assertEqual(call(1)["digest"], stage)
        req.update(phase="migrate", digest=stage)
        with self.assertRaisesRegex(mandate.Held, "PLAN_ALREADY_CONSUMED"):
            call(2)
        self.assertNotIn("migrate", case.rt.events)
        req.update(run="3", phase="rollback", digest=stamp)
        self.assertEqual(call(1)["status"], "ROLLED_BACK")

    def governed_case(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p.update(migration={"mode": "none", "rollbackCompatible": True},
                      configDelta={"env": [dict(name="FEATURE", before=None, after="enabled")]},
                      envAllowlist=["FEATURE"])
        return case

    def test_DEP_58QB_03_ready_with_unlock_io_failure(self):
        import mandate
        import module_operation
        case = self.governed_case()
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        with patch.object(module_operation.operation.reviewed, "unlock", side_effect=OSError), self.assertRaises(mandate.Held):
            call(1)
        receipt = op.read(case.root / stamp, "receipt.json")
        failure = op.read(case.root / "1", "apply.result")
        self.assertEqual((receipt["status"], failure["status"]), ("READY", "HELD"))
        req.update(phase="rollback", run="2")
        self.assertEqual(call(1)["status"], "ROLLED_BACK")
        directory = case.root / stamp
        self.oracle(case.rt, op.read(directory, "plan.json"), op.read(directory, "return-receipt.json"))
        self.assertEqual(op.read(case.root / "1", "apply.result"), receipt)
        self.assertEqual(op.read(case.root / "1", "apply.unlock-failure"), failure)

    def test_DEP_58QB_04_recovery_review_consumed_before_apply_review(self):
        import mandate
        import module_operation
        case = self.governed_case()
        call, req = case.governed_dispatch()
        stamp = call(0)["digest"]
        req.update(phase="apply", digest=stamp)
        with patch.object(case.rt, "signal", side_effect=Crash), self.assertRaises(Crash):
            call(1)
        req.update(phase="plan", run="2")
        req["digest"] = mandate.intent(req)
        recovery_stamp = call(0)["digest"]
        req.update(phase="apply", digest=recovery_stamp)
        with patch.object(module_operation, "save", side_effect=Crash), self.assertRaises(Crash):
            call(1)
        self.assertEqual(op.read(case.root / "2", "approvals"), ["apply"])
        self.assertFalse((case.root / "2/apply.review").exists())
        req.update(phase="rollback", run="3", digest=stamp)
        self.assertEqual(call(1)["status"], "ROLLED_BACK")
        directory = case.root / stamp
        self.oracle(case.rt, op.read(directory, "plan.json"), op.read(directory, "return-receipt.json"))

    def test_DEP_58Q_05_stopped_candidate_and_lost_restore_start(self):
        with ProcessPoolExecutor(1) as retry, ProcessPoolExecutor(1) as finish:
            for point in ("new-start", "start-generation.json"):
                for started in (False, True):
                    rt, plan = self.case()
                    _, rt = interrupted(rt, plan, "apply", point, True)
                    rt.stop(fixture.NEW)
                    result, rt = retry.submit(interrupted, rt, plan, "return", "old-start", started).result()
                    if point == "new-start":
                        # An exit before any epoch was observed is indistinguishable from a foreign stop/start/exit.
                        self.assertEqual((result["status"], result["reason"]), ("HELD", "START_GENERATION_UNCONFIRMED"))
                        continue
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

    def test_DEP_58QG_02_multiple_run_cids_hold_before_stop(self):
        rt, plan = self.case()
        stamp = op.digest(plan)
        self.assertEqual(op.apply(rt.p, stamp, rt)["status"], "READY")
        extra = "c" * 64
        rt.docs[extra] = dict(rt.inspect(fixture.NEW), Name="/unexpected", Id=extra)
        before = rt.events.copy()
        result = return_operation.run(rt.p, stamp, rt)
        self.assertEqual(result["reason"], "IMMEDIATE_SUCCESSOR_CHANGED")
        self.assertEqual(before, rt.events)

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
        cells = 0
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
                    def governed(fresh):
                        response, _ = approved_retry(fresh, stamp, "2", interrupt=False)
                        self.assertEqual(response["status"], "ROLLED_BACK", response)
                        return op.read(case.root / stamp, "return-receipt.json")
                    cells += self.loss_row(case.rt, plan, ("publication", cut, after), governed)
                    result, rt = retry.submit(approved_retry, case.rt, stamp, "2", interrupt=True).result()
                    self.assertEqual(result, "crash")
                    result, rt = finish.submit(approved_retry, rt, stamp, "3", interrupt=False).result()
                    self.assertEqual(result["status"], "ROLLED_BACK", result)
                    self.oracle(rt, plan, op.read(case.root / stamp, "return-receipt.json"))

        print(f"D-080 publication: 8 interruption boundaries, {cells} cases", flush=True)

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
    def verify_mounted_bind(self, doc, bind):
        if hashlib.sha256(self.mounted[doc["Id"], bind["target"]]).hexdigest() != bind["sha256"]:
            raise op.Held("BIND_DIGEST_CHANGED")

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
        self.rt.mounted = {(fixture.NEW, self.bind["target"]): self.source_bytes}
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

    def test_DEP_58QB_07_changed_mount_with_approved_host_replacement(self):
        self.install_delta()
        stamp = self.planned()["planSha256"]
        with patch.object(op, "finish_apply", side_effect=Crash), self.assertRaises(Crash):
            op.apply(self.p, stamp, self.rt)
        self.rt.mounted[fixture.NEW, self.bind["target"]] = b"old mounted inode was modified"
        failure = recovery.resume(self.p, self.rt, recovery.proposal(self.p, self.rt))
        self.assertEqual((failure["reason"], failure["rollback"]), ("BIND_DIGEST_CHANGED", "ROLLED_BACK"))
        self.assertNotIn("signal:" + fixture.NEW[0], self.rt.events)
        self.assertFalse((self.root / stamp / "release-signal.json").exists())
        self.assert_restored()

    @unittest.skipUnless(sys.platform == "linux", "requires procfs process root")
    def test_DEP_58QB_07_proc_root_reads_the_pinned_inode(self):
        source, mounted = self.root / "source", self.root / "mounted"
        source.write_bytes(self.source_bytes)
        os.link(source, mounted)
        bind = dict(self.bind, source=str(source), target=str(mounted))
        doc = {"State": {"Running": True, "Pid": os.getpid()}}
        rt = op.Docker(self.p)
        rt.verify_mounted_bind(doc, bind)
        replacement = self.root / "replacement"
        replacement.write_bytes(self.source_bytes)
        replacement.replace(source)
        mounted.write_bytes(b"changed behind the mount")
        with self.assertRaisesRegex(op.Held, "^BIND_DIGEST_CHANGED$"):
            rt.verify_mounted_bind(doc, bind)

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
