"""R3 lifecycle contracts; optional Linux/root real-wrapper integration."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.semantic_provider_r3 import operate as O
import test_semantic_provider_r3_install as F

NATIVE = os.environ.get("OUF_R3_OPERATE_NATIVE") == "1"
DOCKER_NATIVE = os.environ.get("OUF_R3_RESTART_POLICY_DOCKER_NATIVE") == "1"
if (NATIVE or DOCKER_NATIVE) and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("R3 native gates require Linux root:root; refusing to skip")


def arguments(action="start", output="/var/lib/operate-result", **changes):
    value = dict(action=action, role="adapter" if action == "restart-one" else None,
        install_root="/etc/ouf/r3", wrapper="/usr/local/sbin/ouf-semantic-admitted-v2",
        wrapper_sha256="a"*64, docker="/usr/bin/docker", docker_sha256="b"*64,
        docker_socket="unix:///var/run/docker.sock", systemctl="/usr/bin/systemctl",
        systemctl_sha256="c"*64, nft="/usr/sbin/nft", nft_sha256="d"*64,
        output_directory=output, timeout_seconds=1, plan_sha256=None)
    return SimpleNamespace(**{**value, **changes})


def observation(live=False, policy="no"):
    rows = {}
    for n, role in enumerate(O.ROLES):
        rows[role] = {"cid": str(n+1)*64, "epoch": ({"epoch": 1, "state": "STARTED", "bootId": "boot",
            "failure": None, "live": True} if live else None), "previousEpoch": None,
            "docker": {"Status": "running" if live else "created", "Running": live,
                "Pid": 100+n if live else 0, "StartedAt": "2026-11-15T00:00:00Z", "RestartCount": 0,
                "Runtime": "ouf-semantic-admitted-v2", "RestartPolicy": policy}}
    return {"configurationSha256": "f"*64, "authorization": {"sha256": "e"*64, "sequence": 1, "decision": "OPERATE"},
        "candidates": rows, "supervisor": {"unit": {"ActiveState": "active", "SubState": "running", "NRestarts": 0},
            "state": "ACTIVE" if live else "WAITING", "reason": None if live else "EPOCH_NOT_LIVE",
            "epochs": dict.fromkeys(O.ROLES, 1 if live else None), "activationsLastHour": 1 if live else 0,
            "authorizationSequence": 1}, "lease": {"state": "LEASE_READY" if live else "QUIESCED", "leaseAuthorized": live},
        "tables": {r: {"tableName": "ouf_r3_"+r, "inet": live, "bridge": live} for r in O.ROLES}}


def successful(action, before):
    after = copy.deepcopy(before)
    if action == "start":
        after = observation(True, "unless-stopped")
        for r in O.ROLES:
            old = before["candidates"][r]["epoch"]
            number = old["epoch"] + 1 if old else 1
            after["candidates"][r]["epoch"]["epoch"] = number
            after["supervisor"]["epochs"][r] = number
    elif action == "restart-policy":
        for r in O.ROLES:
            after["candidates"][r]["docker"]["RestartPolicy"] = "unless-stopped"
    elif action == "restart-one":
        row = after["candidates"]["adapter"]
        row["epoch"]["epoch"] += 1
        row["previousEpoch"] = {"epoch": 1, "state": "DELETED"}
        row["docker"]["Pid"] += 10
        row["docker"]["RestartCount"] += 1
        after["supervisor"]["epochs"]["adapter"] = 2
    else:
        for r in O.ROLES:
            row = after["candidates"][r]
            row["epoch"].update(state="DELETED", live=False)
            row["docker"].update(Status="exited", Running=False, Pid=0)
            after["tables"][r].update(inet=False, bridge=False)
        after["supervisor"].update(state="WAITING", reason="EPOCH_NOT_LIVE")
        after["lease"].update(state="QUIESCED", leaseAuthorized=False)
    return after


class PortableTests(unittest.TestCase):
    def test_terminal_history_binds_to_authenticated_original_entry(self):
        from test_semantic_provider_r3_compose import fixture
        initial = O.C.compose(fixture())
        payload = O.A.validate(initial["authorization"])
        cfg = {"operation": {"authorizationRoot": "/install/authorization"}}
        runtime = SimpleNamespace(read=lambda _: initial["authorization"])
        head = {"sequence": 2}
        row = {"state": "DELETED", "authorizationSha256": O.sha(initial["authorization"]),
               "configurationHash": payload["runtimeConfigurationSha256"]}
        O.terminal_binding(runtime, cfg, head, row)
        for change in ({"state": "STARTED"}, {"configurationHash": "0"*64}, {"authorizationSha256": "0"*64}):
            with self.subTest(change=change), self.assertRaisesRegex(O.A.OperationDenied, "R3_EPOCH_AUTHORIZATION_DRIFT"):
                O.terminal_binding(runtime, cfg, head, {**row, **change})

    def test_wrapper_selects_only_root_or_numeric_versions(self):
        from pathlib import PurePosixPath
        root = PurePosixPath("/install")
        for suffix in ("", "/versions/2", "/versions/12"):
            code_root = PurePosixPath(str(root)+suffix)
            self.assertEqual(O.I.wrapper_code_root(root, O.I.wrapper_bytes("/usr/bin/python3", code_root)), code_root)
        for suffix in ("/versions/1", "/versions/02", "/versions/current", "/elsewhere", "/versions/2/extra"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(O.A.OperationDenied, "R3_WRAPPER_DRIFT"):
                O.I.wrapper_code_root(root, O.I.wrapper_bytes("/usr/bin/python3", PurePosixPath(str(root)+suffix)))

    def test_each_precondition_success_and_violation(self):
        for action in O.SUCCESS:
            args = arguments(action)
            good = observation(action not in {"start", "restart-policy"})
            O.preconditions(args, good)
            bad = observation(action in {"start", "restart-policy"})
            with self.subTest(action=action), self.assertRaises(O.A.OperationDenied):
                O.preconditions(args, bad)

    def test_start_terminal_and_individual_denials(self):
        args, before = arguments(), observation()
        for terminal in O.TERMINAL:
            row = before["candidates"]["adapter"]
            row["epoch"] = {"epoch": 3, "state": terminal, "live": False}
            row["docker"]["Status"] = "exited"
            O.preconditions(args, before)
            self.assertTrue(O.reached(args, before, successful("start", before)))
        for area, key, value in (("supervisor", "state", "FAILED"), ("lease", "state", "LEASE_READY"),
                                  ("lease", "leaseAuthorized", True), ("supervisor", "authorizationSequence", 2)):
            bad = observation()
            bad[area][key] = value
            with self.subTest(key=key), self.assertRaises(O.A.OperationDenied):
                O.preconditions(args, bad)
        bad = observation()
        bad["supervisor"]["unit"]["ActiveState"] = "inactive"
        with self.assertRaisesRegex(O.A.OperationDenied, "SUPERVISOR_NOT_WAITING"):
            O.preconditions(args, bad)

    def test_running_requires_exact_live_started_epoch(self):
        for action in ("restart-one",):
            for field, value in (("state", "FAILED"), ("live", False)):
                before = observation(True)
                before["candidates"]["southbound"]["epoch"][field] = value
                with self.assertRaisesRegex(O.A.OperationDenied, "RUNNING_EPOCHS_REQUIRED"):
                    O.preconditions(arguments(action), before)
        before = observation(True)
        before["supervisor"]["epochs"]["adapter"] = 2
        with self.assertRaisesRegex(O.A.OperationDenied, "SUPERVISOR_NOT_ACTIVE"):
            O.preconditions(arguments("restart-one"), before)

    def test_all_readbacks_and_negative_deltas(self):
        for action in O.SUCCESS:
            before = observation(action not in {"start", "restart-policy"})
            if action == "restart-policy":
                before["candidates"]["adapter"]["epoch"] = {"epoch": 1, "state": "DELETED"}
            after = successful(action, before)
            args = arguments(action)
            self.assertTrue(O.reached(args, before, after), action)
            bad = copy.deepcopy(after)
            bad["authorization"]["sequence"] = 2
            self.assertFalse(O.reached(args, before, bad))
            bad = copy.deepcopy(after)
            bad["candidates"]["adapter"]["cid"] = "0"*64
            self.assertFalse(O.reached(args, before, bad))
            bad = copy.deepcopy(after)
            if action == "stop":
                bad["tables"]["southbound"]["bridge"] = True
            elif action == "restart-policy":
                bad["candidates"]["adapter"]["epoch"]["epoch"] += 1
            else:
                bad["supervisor"]["epochs"]["adapter"] += 1
            self.assertFalse(O.reached(args, before, bad))

    def test_restart_one_requires_old_deleted_and_sibling_unchanged(self):
        before = observation(True)
        for kind in ("old", "pid", "epoch", "live", "lease", "tables"):
            bad = successful("restart-one", before)
            if kind == "old": bad["candidates"]["adapter"]["previousEpoch"]["state"] = "FAILED"
            if kind == "pid": bad["candidates"]["southbound"]["docker"]["Pid"] += 1
            if kind == "epoch": bad["candidates"]["southbound"]["epoch"]["epoch"] += 1
            if kind == "live": bad["candidates"]["adapter"]["epoch"]["live"] = False
            if kind == "lease": bad["lease"]["leaseAuthorized"] = False
            if kind == "tables": bad["tables"]["adapter"]["inet"] = False
            self.assertFalse(O.reached(arguments("restart-one"), before, bad), kind)

    def test_restart_policy_proves_no_restart(self):
        before = observation()
        for field in ("Pid", "StartedAt", "RestartCount"):
            after = successful("restart-policy", before)
            after["candidates"]["adapter"]["docker"][field] = "changed" if field == "StartedAt" else 200
            self.assertFalse(O.reached(arguments("restart-policy"), before, after))

    def test_parallel_start_and_stop_and_all_apply_successes(self):
        for action in O.SUCCESS:
            before = observation(action not in {"start", "restart-policy"}, "unless-stopped"
                                 if action in {"stop", "restart-one"} else "no")
            after = successful(action, before)
            barrier = threading.Barrier(2)
            calls = []
            def fake_docker(args, *argv):
                calls.append(argv)
                if argv[0] in {"start", "stop"}:
                    barrier.wait(timeout=3)  # both requests MUST enter before either returns
                return b""
            with tempfile.TemporaryDirectory() as folder:
                args = arguments(action, str(Path(folder)/"result"))
                plan = O.proposal(args, before)
                args.plan_sha256 = plan["planSha256"]
                report = {"status": "HELD", "doNotRerunApply": False, **O.COUNTERS}
                prepared = successful("restart-policy", before)
                observations = [before, prepared, after] if action == "start" else [before, after]
                with patch.object(O, "observe", side_effect=observations), \
                        patch.object(O, "docker", side_effect=fake_docker), \
                        patch.object(O.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                        patch.object(O.I, "write_once"):
                    O.apply(args, plan, report)
                self.assertEqual(report["status"], O.SUCCESS[action])
                self.assertTrue(report["doNotRerunApply"])
                self.assertEqual(report["lastObservation"], after)
                counter = {"start":"dockerStartRequests", "stop":"dockerStopRequests",
                           "restart-policy":"dockerUpdateRequests", "restart-one":"dockerRestartRequests"}[action]
                self.assertEqual(report[counter], 1 if action == "restart-one" else 2)
                self.assertEqual(sum(report[k] for k in O.COUNTERS if k.startswith("docker")), len(calls))
                if action == "start":
                    self.assertEqual(report["dockerUpdateRequests"], 2)
                    self.assertEqual([c[0] for c in calls], ["update", "update", "start", "start"])
                self.assertEqual((report["signaturesIssued"], report["privateKeysRead"]), (0, 0))
                if action != "stop": self.assertFalse(any(c[0] == "stop" for c in calls))

    def test_timeout_preserves_latest_complete_observation_for_each_action(self):
        for action in O.SUCCESS:
            before = observation(action != "start")
            latest = copy.deepcopy(before)
            latest["candidates"]["adapter"]["epoch"] = {
                "epoch": 2, "state": "FAILED", "failure": "ADMISSION_OR_DRIVER_FAILED", "bootId": "boot", "live": False}
            report = {"lastObservation": before}
            with patch.object(O, "observe", return_value=latest), \
                    patch.object(O.time, "monotonic", side_effect=[0, 2]):
                with self.assertRaisesRegex(O.A.OperationDenied, "R3_READBACK_TIMEOUT"):
                    O.poll(arguments(action), before, report)
            self.assertEqual(report["lastObservation"], latest)
        with patch.object(O, "observe", side_effect=O.A.OperationDenied("EPOCH_POINTER_JOURNAL_DRIFT")), \
                patch.object(O.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(O.A.OperationDenied): O.poll(arguments(), before, report)
        self.assertEqual(report["lastObservation"], latest)
        self.assertEqual(report["observationError"]["reason"], "EPOCH_POINTER_JOURNAL_DRIFT")

    def test_start_policy_failure_or_bad_readback_never_starts(self):
        for failure in ("update", "policy", "running", "identity", "observe"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                before = observation()
                latest = successful("restart-policy", before)
                if failure in {"update", "policy"}:
                    latest["candidates"]["southbound"]["docker"]["RestartPolicy"] = "no"
                if failure == "running":
                    latest["candidates"]["adapter"]["docker"].update(Status="running", Running=True, Pid=42)
                if failure == "identity":
                    latest["candidates"]["adapter"]["cid"] = "0"*64
                args = arguments(output=str(Path(folder)/"out"))
                plan = O.proposal(args, before)
                args.plan_sha256 = plan["planSha256"]
                report = {"status": "HELD", **O.COUNTERS}
                def fake_docker(args, *argv):
                    if failure == "update" and argv[-1] == "2"*64:
                        raise O.A.OperationDenied("R3_COMMAND_FAILED")
                readback = O.A.OperationDenied("R3_COMMAND_FAILED") if failure == "observe" else latest
                with patch.object(O, "observe", side_effect=[before, readback]), \
                        patch.object(O, "docker", side_effect=fake_docker) as docker, \
                        patch.object(O.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                        patch.object(O.I, "write_once"):
                    code = "R3_RESTART_POLICY_UPDATE_FAILED" if failure == "update" else "R3_RESTART_POLICY_READBACK_FAILED"
                    with self.assertRaisesRegex(O.A.OperationDenied, code):
                        O.apply(args, plan, report)
                self.assertEqual(report["status"], "HELD")
                self.assertEqual(report["dockerStartRequests"], 0)
                self.assertEqual(report["dockerUpdateRequests"], 2)
                self.assertTrue(all(c.args[1] == "update" for c in docker.call_args_list))
                self.assertTrue(report["doNotRerunApply"])
                if failure != "observe":
                    self.assertEqual(report["lastObservation"], latest)

    def test_already_set_policy_is_verified_without_update(self):
        for action in ("start", "restart-policy"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                before = observation(policy="unless-stopped")
                args = arguments(action, str(Path(folder)/"out"))
                plan = O.proposal(args, before)
                args.plan_sha256 = plan["planSha256"]
                report = {"status": "HELD", **O.COUNTERS}
                reads = [before, before, successful("start", before)] if action == "start" else [before, before]
                with patch.object(O, "observe", side_effect=reads) as observe, \
                        patch.object(O, "docker", return_value=b"") as docker, \
                        patch.object(O.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                        patch.object(O.I, "write_once"):
                    O.apply(args, plan, report)
                self.assertEqual(report["dockerUpdateRequests"], 0)
                self.assertEqual(report["status"], O.SUCCESS[action])
                self.assertEqual(observe.call_count, len(reads))
                self.assertTrue(all(c.args[1] == "start" for c in docker.call_args_list))

    def test_final_start_readback_requires_policy_on_both_roles(self):
        before = observation()
        for role in O.ROLES:
            after = successful("start", before)
            after["candidates"][role]["docker"]["RestartPolicy"] = "no"
            self.assertFalse(O.reached(arguments(), before, after))

    def test_restart_policy_plan_denies_either_running_or_nonidle_role(self):
        for role in O.ROLES:
            for status, live, pid in (("running", True, 42), ("paused", True, 42),
                                      ("created", False, 42), ("dead", False, 0)):
                before = observation()
                before["candidates"][role]["docker"].update(Status=status, Running=live, Pid=pid)
                with patch.object(O, "docker") as docker, self.assertRaisesRegex(
                        O.A.OperationDenied, "R3_RESTART_POLICY_REQUIRES_STOPPED"):
                    O.proposal(arguments("restart-policy"), before)
                docker.assert_not_called()

    def test_stop_and_restart_one_observe_and_readback_accept_unless_stopped(self):
        for action in ("stop", "restart-one"):
            before = observation(True, "unless-stopped")
            O.preconditions(arguments(action), before)
            self.assertTrue(O.reached(arguments(action), before, successful(action, before)))
            for role, row in before["candidates"].items():
                d = row["docker"]
                raw = json.dumps([{"Id": row["cid"], "State": d, "RestartCount": d["RestartCount"],
                    "HostConfig": {"Runtime": d["Runtime"], "RestartPolicy": {"Name": d["RestartPolicy"]}}}])
                self.assertEqual(O.docker_fields(raw, row["cid"])["RestartPolicy"], "unless-stopped")

    def test_failed_start_never_stops_and_retains_failure(self):
        before = observation(policy="unless-stopped")
        latest = successful("start", before)
        latest["candidates"]["adapter"]["epoch"].update(state="FAILED", live=False, failure="ADMISSION_OR_DRIVER_FAILED")
        with tempfile.TemporaryDirectory() as folder:
            args = arguments(output=str(Path(folder)/"out"))
            plan = O.proposal(args, before)
            args.plan_sha256 = plan["planSha256"]
            report = {"doNotRerunApply": False, **O.COUNTERS}
            with patch.object(O, "observe", side_effect=[before, before, latest]), \
                    patch.object(O, "docker", side_effect=subprocess.TimeoutExpired("PRIVATE", 1)) as docker, \
                    patch.object(O.I, "native_switch", return_value=SimpleNamespace(sync=lambda _: None)), \
                    patch.object(O.I, "write_once"), patch.object(O.time, "monotonic", side_effect=[0, 2]):
                with self.assertRaisesRegex(O.A.OperationDenied, "READBACK_TIMEOUT"): O.apply(args, plan, report)
            self.assertEqual(report["dockerStartRequests"], 2)
            self.assertEqual(report["dockerStopRequests"], 0)
            self.assertEqual(len(report["requestErrors"]), 2)
            self.assertEqual(report["lastObservation"], latest)
            self.assertTrue(all(c.args[1] == "start" for c in docker.call_args_list))
            self.assertNotIn("PRIVATE", O.canonical(report).decode())

    def test_digest_or_drift_blocks_before_output_or_docker(self):
        for drift in (False, True):
            before = observation()
            with tempfile.TemporaryDirectory() as folder:
                args = arguments(output=str(Path(folder)/"out"))
                plan = O.proposal(args, before)
                args.plan_sha256 = plan["planSha256"] if drift else "0"*64
                after = copy.deepcopy(before)
                after["supervisor"]["unit"]["NRestarts"] = 1
                with patch.object(O, "observe", return_value=after), patch.object(O, "docker") as docker:
                    with self.assertRaisesRegex(O.A.OperationDenied, "PLAN_DIGEST_CHANGED"):
                        O.apply(args, plan, {})
                docker.assert_not_called()
                self.assertFalse(Path(args.output_directory).exists())

    def test_stop_targets_only_running_role(self):
        before = observation(True)
        before["candidates"]["southbound"]["docker"].update(Status="exited", Running=False, Pid=0)
        args = arguments("stop")
        O.preconditions(args, before)
        self.assertEqual(O.requests(args, before), [("adapter", ["stop", "--time", "30", "1"*64])])

    def test_cli_arguments_and_redaction(self):
        base = ["--plan", "--action", "start"]
        for k, v in vars(arguments()).items():
            if k not in {"action", "role", "timeout_seconds", "plan_sha256"}:
                base += ["--"+k.replace("_", "-"), v]
        self.assertEqual(O.arguments(base).timeout_seconds, 180)
        for extra in (["--timeout-seconds", "601"], ["--timeout-seconds", "0"], ["--role", "adapter"],
                      ["--plan-sha256", "0"*64]):
            with self.assertRaises(O.A.OperationDenied): O.arguments(base+extra)
        restart = base.copy()
        restart[restart.index("start")] = "restart-one"
        with self.assertRaises(O.A.OperationDenied): O.arguments(restart)
        self.assertEqual(O.arguments(restart+["--role", "southbound"]).role, "southbound")
        out = io.StringIO()
        with redirect_stdout(out): self.assertEqual(O.main(["--PRIVATE"]), 1)
        self.assertEqual(json.loads(out.getvalue())["reason"], "INVALID_ARGUMENTS")
        self.assertNotIn("PRIVATE", out.getvalue())

    def test_command_environment_and_hash_checks_even_after_timeout(self):
        for error in (None, subprocess.TimeoutExpired("PRIVATE", 1), OSError(13, "PRIVATE")):
            with patch.object(O.V, "executable_hash", return_value="/binary") as verify, \
                    patch.object(O.subprocess, "run", return_value=SimpleNamespace(returncode=0), side_effect=error) as run:
                if error:
                    with self.assertRaises(type(error)): O.command("/binary", "a"*64, ["inspect"], 7)
                else:
                    self.assertEqual(O.command("/binary", "a"*64, ["inspect"], 7), b"")
                self.assertEqual(verify.call_count, 2)
                self.assertEqual(run.call_args.kwargs["env"], O.I.ENV)
                self.assertEqual(run.call_args.kwargs["timeout"], 7)
                self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_inspect_sanitizes_and_requires_runtime(self):
        row = {"Id": "1"*64, "State": {"Status": "running", "Running": True, "Pid": 42,
            "StartedAt": "2026-11-15T00:00:00Z", "Secret": "PRIVATE"}, "RestartCount": 0,
            "HostConfig": {"Runtime": "ouf-semantic-admitted-v2", "RestartPolicy": {"Name": "no"}},
            "Config": {"Env": ["PRIVATE"]}}
        fields = O.docker_fields(json.dumps([row]).encode(), "1"*64)
        self.assertNotIn("PRIVATE", json.dumps(fields))
        row["HostConfig"]["Runtime"] = "runc"
        with self.assertRaisesRegex(O.A.OperationDenied, "DOCKER_RUNTIME_DRIFT"):
            O.docker_fields(json.dumps([row]).encode(), "1"*64)

    def test_main_saves_held_result_and_readonly_plan(self):
        for apply in (False, True):
            args = arguments()
            args.apply, args.plan = apply, not apply
            out = io.StringIO()
            def failed_apply(args, plan, report):
                report.update(outputCreated=True, doNotRerunApply=True, dockerStartRequests=2)
                raise OSError(5, "PRIVATE")
            with patch.object(O, "arguments", return_value=args), \
                    patch.object(O.sys, "platform", "linux"), \
                    patch.object(O.os, "geteuid", return_value=0, create=True), \
                    patch.object(O.os, "getegid", return_value=0, create=True), \
                    patch.object(O.sys, "flags", SimpleNamespace(isolated=True, dont_write_bytecode=True)), \
                    patch.object(O, "observe", return_value=observation()), \
                    patch.object(O, "apply", side_effect=failed_apply) as mutate, \
                    patch.object(O.I, "write_once") as write, redirect_stdout(out):
                self.assertEqual(O.main([]), int(apply))
            result = json.loads(out.getvalue())
            if apply:
                self.assertEqual(result["status"], "HELD")
                self.assertEqual(result["errno"], 5)
                self.assertTrue(result["doNotRerunApply"])
                self.assertEqual(write.call_args.args[0].name, "result.json")
                self.assertEqual(json.loads(write.call_args.args[1]), result)
            else:
                self.assertEqual(result["status"], "PLAN_READY")
                mutate.assert_not_called()
                write.assert_not_called()
            self.assertNotIn("PRIVATE", out.getvalue())

    def test_observer_uses_installed_readers_and_selects_public_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/"install"
            args = arguments(install_root=str(root), wrapper_sha256=O.sha(b"wrapper"))
            cfg = {"registryRoot":str(root/"registry"), "operation":{"authorizationRoot":str(root/"authorization")},
                "pythonPath":"/python", "candidates":{str(i+1)*64:{"role":r} for i,r in enumerate(O.ROLES)},
                "leaseQuiesce":{"configuration":{"path":"sup", "sha256":"0"*64}}}
            head = {**observation()["authorization"], "authorization":{"roles":{
                r:{"tableName":"ouf_r3_"+r, "private":"PRIVATE"} for r in O.ROLES}}}
            epoch = {"epoch":1,"state":"STARTED","bootId":"boot","failure":None,"generation":{"pid":42},
                "authorizationSha256":head["sha256"],"configurationHash":O.sha(b"cfg"),"private":"PRIVATE"}
            readers = SimpleNamespace(boot_id=lambda:"boot", current=lambda *_:epoch, live=lambda *_:True)
            sup = {"registryRoot":cfg["registryRoot"],"authorizationRoot":cfg["operation"]["authorizationRoot"],
                "statusPath":"status", "coordinator":{"journalPath":"journal"}}
            status = {"schema":"ouf.semantic-provider-lease-supervisor-status.v1", **observation(True)["supervisor"],
                      "private":"PRIVATE"}
            status.pop("unit")
            custody = lambda path, mode: ({"status":O.canonical(status), "journal":O.canonical({
                "state":"LEASE_READY","leaseAuthorized":True,"private":"PRIVATE"})}.get(str(path), b"wrapper"), ())
            runtime = SimpleNamespace(load_configuration=lambda _:(cfg,b"cfg"), verify_files=lambda _:None,
                operation_modules=lambda _:(object(),readers), authorization_head=lambda *_:head,
                bound_bytes=lambda _:O.canonical(sup), read=lambda p:p.read_bytes())
            for cid in cfg["candidates"]:
                folder = root / "registry" / cid / "epochs/1"
                folder.mkdir(parents=True)
                (folder / "broker-denial-prepare.json").write_bytes(O.canonical(dict(
                    schema=O.C.B.DENIAL_SCHEMA, containerId=cid, epoch=1, mode="prepare",
                    reason="PEER_MAC_IP_DRIFT", at=1500, cohort=None)))
                (folder / "broker-denial-cleanup.json").write_bytes(b"PRIVATE")
            inspect = json.dumps([{"Id":"1"*64,"State":{"Status":"running","Running":True,"Pid":42,
                "StartedAt":"2026-11-15T00:00:00Z"},"RestartCount":0,"HostConfig":{
                "Runtime":"ouf-semantic-admitted-v2","RestartPolicy":{"Name":"no"}},"private":"PRIVATE"}]).encode()
            def fake_docker(args, verb, cid, **_):
                return inspect.replace(b'1'*64, cid.encode())
            def fake_command(path, *_):
                if path == args.systemctl: return b"ActiveState=active\nSubState=running\nNRestarts=0\n"
                return json.dumps({"nftables":[{"table":{"family":f,"name":"ouf_r3_"+r}}
                    for r in O.ROLES for f in ("inet","bridge")]}).encode()
            with patch.object(O.I,"native_switch",return_value=SimpleNamespace(custody=custody)), \
                    patch.object(O.V,"absolute",side_effect=Path), patch.object(O.V,"private_directory"), \
                    patch.object(O.I,"output_directory"), patch.object(O.I,"compiled",return_value=runtime) as load, \
                    patch.object(O.I,"wrapper_bytes",return_value=b"wrapper"), \
                    patch.object(O.I,"wrapper_code_root",return_value=root), \
                    patch.object(O,"docker",side_effect=fake_docker), patch.object(O,"command",side_effect=fake_command):
                result = O.observe(args)
                self.assertEqual(result["authorization"], observation()["authorization"])
                self.assertTrue(result["candidates"]["adapter"]["epoch"]["live"])
                self.assertEqual(result["candidates"]["adapter"]["denials"][0], {"invalid":"BROKER_DENIAL_INVALID"})
                self.assertEqual(result["candidates"]["adapter"]["denials"][1]["reason"], "PEER_MAC_IP_DRIFT")
                self.assertNotIn("PRIVATE", O.canonical(result).decode())
                self.assertEqual(load.call_args.args[3], O.sha((O.I.ROOT/O.C.RUNTIME).read_bytes()))
                epoch["authorizationSha256"] = "0"*64
                with self.assertRaisesRegex(O.A.OperationDenied,"EPOCH_AUTHORIZATION_DRIFT"): O.observe(args)
                epoch["authorizationSha256"] = head["sha256"]
                epoch["bootId"] = "other"
                with self.assertRaisesRegex(O.A.OperationDenied,"EPOCH_BOOT_DRIFT"): O.observe(args)

    def test_native_programs_compile_without_execution(self):
        for source in (DOCKER, SYSTEMCTL, QUIESCE):
            compile(F.F.render(source, BASE="/var/lib/fixture"), "<fake-native-command>", "exec")


# This fake Engine invokes the actual installed wrapper for create/start/delete.
# State is per CID to keep the two Engine requests genuinely independent.
DOCKER = r'''
import json,os,pathlib,subprocess,sys,time
base=pathlib.Path(BASE); args=sys.argv[1:]
assert args[:2]==['--host','unix:///fixture/docker.sock']
mode=args[2]; cid=args[-1]; runtime=base/'runtime/owned'
assert len(cid)==64
marker=base/('engine-'+cid+'.json')
entry=json.loads(marker.read_bytes()) if marker.exists() else {'status':'created','restart':'no','count':0,'started':'0001-01-01T00:00:00Z'}
def save():
    marker.write_text(json.dumps(entry)); marker.chmod(0o600)
def wrapper(*argv):
    p=subprocess.run([str(base/'ouf-semantic-admitted-v2'),'--root',str(runtime),*argv,cid],timeout=120)
    if p.returncode: raise SystemExit(p.returncode)
def start():
    wrapper('create','--bundle',str(base/'bundles'/cid))
    wrapper('start')
    entry.update(status='running',started=str(time.time_ns())+'Z'); save()
if mode=='inspect':
    row=json.loads((runtime/(cid+'.json')).read_bytes()) if entry['status']=='running' else None
    print(json.dumps([{'Id':cid,'State':{'Status':entry['status'],'Running':entry['status']=='running',
        'Pid':row['pid'] if row else 0,'StartedAt':entry['started']},'RestartCount':entry['count'],
        'HostConfig':{'Runtime':'ouf-semantic-admitted-v2','RestartPolicy':{'Name':entry['restart']}}}]))
elif mode=='start':
    assert args[2:]==['start',cid]; start()
elif mode=='update':
    assert args[2:]==['update','--restart','unless-stopped',cid]
    assert entry['status'] in ('created','exited')
    entry['restart']='unless-stopped'; save()
elif mode=='restart':
    assert args[2:]==['restart','--time','30',cid]
    wrapper('delete','--force'); entry['count']+=1; start()
elif mode=='stop':
    assert args[2:]==['stop','--time','30',cid]
    wrapper('delete','--force'); entry['status']='exited'; save()
else: raise SystemExit(2)
'''

# Explicit supervisor/lease simulator, like 41b. It does not pretend to test
# systemd, DNS, real lease activation or recovery; runtime/broker/hook are real.
SYSTEMCTL = r'''
import json,os,pathlib,sys
base=pathlib.Path(BASE); args=sys.argv[1:]
assert args==['show','ouf-semantic-lease-supervisor-v2.service','--property=ActiveState','--property=SubState','--property=NRestarts']
install=base/'install'; cfg=json.loads((install/'runtime-configuration.json').read_bytes())
sup=json.loads((install/'supervisor/configuration.json').read_bytes())
epochs={}; alive=True
for cid,item in cfg['candidates'].items():
    pointer=install/'registry'/cid/'current'
    row=None
    if pointer.exists():
        n=json.loads(pointer.read_bytes())['epoch']
        row=json.loads((install/'registry'/cid/'epochs'/str(n)/'adapter.json').read_bytes())
    live=bool(row and row['state']=='STARTED' and pathlib.Path('/proc/'+str(row['generation']['pid'])+'/stat').exists())
    alive=alive and live; epochs[item['role']]=row['epoch'] if live else None
def write(path,row):
    path=pathlib.Path(path); tmp=path.with_name(path.name+'.fixture-tmp')
    tmp.write_text(json.dumps(row,sort_keys=True,separators=(',',':'))); tmp.chmod(0o600); os.replace(tmp,path)
status={'schema':'ouf.semantic-provider-lease-supervisor-status.v1','state':'ACTIVE' if alive else 'WAITING',
    'reason':None if alive else 'EPOCH_NOT_LIVE','epochs':epochs,'activationsLastHour':1 if alive else 0,
    'authorizationSequence':1,'renewals':0,'updatedAt':0}
write(sup['statusPath'],status)
path=sup['coordinator']['journalPath']; row=json.loads(pathlib.Path(path).read_bytes())
row.update(state='LEASE_READY' if alive else 'QUIESCED',leaseAuthorized=alive,startAuthorized=False)
write(path,row)
print('ActiveState=active\nSubState=running\nNRestarts=0')
'''

QUIESCE = r'''
import hashlib,json,os,pathlib,sys
base=pathlib.Path(BASE)
assert len(sys.argv)==6 and sys.argv[1]=='--configuration' and sys.argv[3]=='--configuration-sha256'
assert sys.argv[5]=='--quiesce-only'
raw=pathlib.Path(sys.argv[2]).read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[4]
if (base/'quiesce-fail').exists(): raise SystemExit(1)
cfg=json.loads(raw); path=pathlib.Path(cfg['coordinator']['journalPath'])
row=json.loads(path.read_bytes()); row.update(state='QUIESCED',leaseAuthorized=False,startAuthorized=False)
# Serialize concurrent create/delete quiescence as the real common lock does.
import fcntl
with open(base/'common.lock','r+') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    tmp=path.with_name(path.name+'.fixture-quiesce-tmp')
    tmp.write_text(json.dumps(row,sort_keys=True,separators=(',',':'))); tmp.chmod(0o600); os.replace(tmp,path)
'''


class OperateFixture(F.InstallFixture):
    __unittest_skip__ = False

    def make_inputs(self):
        super().make_inputs()
        self.inputs['sources']['scripts/semantic-provider-lease-supervisor-v2.py'] = F.F.render(QUIESCE, BASE=str(self.root))

    def script(self, name, source, executable=True, **values):
        if name == "nft":
            # The inherited fake nft's read/modify/write needs serialization
            # when two independent stop/rollback requests run concurrently.
            source = ("import fcntl,pathlib\nlock=open(pathlib.Path(BASE)/'fixture-nft.lock','a')\n"
                      "fcntl.flock(lock,fcntl.LOCK_EX)\n" + source)
        return super().script(name, source, executable=executable, **values)

    def operate_args(self, action, mode="--plan", digest=None):
        nft = json.loads((self.install/'supervisor/configuration.json').read_bytes())['coordinator']['nftBinding']
        args = [mode, '--action', action, '--install-root', str(self.install), '--wrapper', str(self.wrapper),
            '--wrapper-sha256', O.sha(self.wrapper.read_bytes()), '--docker', self.docker['path'],
            '--docker-sha256', self.docker['sha256'], '--docker-socket', 'unix:///fixture/docker.sock',
            '--systemctl', self.systemctl['path'], '--systemctl-sha256', self.systemctl['sha256'],
            '--nft', nft['path'], '--nft-sha256', nft['sha256'], '--timeout-seconds', '120',
            '--output-directory', str(self.root/('operate-'+action))]
        if action == 'restart-one': args += ['--role','adapter']
        return args + (['--plan-sha256', digest] if digest else [])

    def operate_cli(self, args):
        result = subprocess.run([str(self.python), '-I', '-B', str(O.I.ROOT/'scripts/operate-semantic-provider-r3.py'),
            *args], capture_output=True, timeout=330)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode()+self.diagnostic())
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def scenario_operate(self):
        self.assertTrue(str(self.root).startswith('/var/lib/'))
        self.installed()
        self.docker = self.script('docker', DOCKER)
        self.systemctl = self.script('systemctl', SYSTEMCTL)
        for action in ('start','restart-one','stop','restart-policy'):
            plan = self.operate_cli(self.operate_args(action))
            self.assertEqual(plan, self.operate_cli(self.operate_args(action)))
            result = self.operate_cli(self.operate_args(action,'--apply',plan['planSha256']))
            self.assertEqual(result['status'], O.SUCCESS[action])
            self.assertTrue(result['doNotRerunApply'])
            self.assertEqual((result['signaturesIssued'],result['privateKeysRead']), (0,0))
            self.assertEqual(json.loads((self.root/('operate-'+action)/'result.json').read_bytes()), result)
            self.assertEqual({p.name:p.read_bytes() for p in self.chain.iterdir()}, self.authority_bytes)
            if action == 'start':
                for role in O.ROLES:
                    self.assertEqual((self.row(role)['state'],self.row(role)['epoch']), ('STARTED',1))
                self.assertEqual(result['lastObservation']['lease']['state'], 'LEASE_READY')
                self.assertEqual(result['lastObservation']['supervisor']['state'], 'ACTIVE')
            if action == 'restart-one':
                self.assertEqual((self.row()['state'],self.row()['epoch']), ('STARTED',2))
                self.assertEqual(json.loads((self.folder(epoch=1)/'adapter.json').read_bytes())['state'], 'DELETED')
                self.assertEqual((self.row('southbound')['state'],self.row('southbound')['epoch']), ('STARTED',1))
            if action in ('start', 'restart-one'):
                for role in O.ROLES:
                    self.assertTrue(result['lastObservation']['tables'][role]['inet'])
                    self.assertTrue(result['lastObservation']['tables'][role]['bridge'])
            if action == 'stop':
                self.assertEqual(result['lastObservation']['lease']['state'], 'QUIESCED')
                self.assertFalse(result['lastObservation']['lease']['leaseAuthorized'])
                for role in O.ROLES:
                    self.assertFalse(result['lastObservation']['tables'][role]['inet'])
                    self.assertFalse(result['lastObservation']['tables'][role]['bridge'])
        for role in O.ROLES: self.assertEqual(self.row(role)['state'], 'DELETED')


@unittest.skipUnless(NATIVE, 'set OUF_R3_OPERATE_NATIVE=1 under Linux root:root')
class NativeTests(unittest.TestCase):
    def test_real_wrapper_start_restart_stop(self):
        for name in ('unshare','mount','umount','ip','openssl'):
            self.assertIsNotNone(shutil.which(name), 'native prerequisite: '+name)
        result = subprocess.run([shutil.which('unshare'),'--mount','--net','--fork',sys.executable,'-I','-B',
            str(Path(__file__).resolve()),'--native-child'], capture_output=True, timeout=700)
        for line in result.stderr.decode('utf-8','replace').splitlines():
            if line.startswith('FIXTURE_EXEC_DIAGNOSTIC='): print(line, file=sys.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())


@unittest.skipUnless(DOCKER_NATIVE, 'set OUF_R3_RESTART_POLICY_DOCKER_NATIVE=1 under Linux root:root')
class DockerRestartPolicyTests(unittest.TestCase):
    def test_stopped_update_bypasses_runtime_but_running_update_is_rejected(self):
        for name in ('docker', 'dockerd', 'runc', 'sleep', 'ldd'):
            self.assertIsNotNone(shutil.which(name), 'native prerequisite: '+name)
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='ouf-r3-policy-', dir='/var/lib')))
        trace = root/'runtime-requests.jsonl'
        wrapper = root/'reject-update'
        wrapper.write_text(
            f'#!{sys.executable}\nimport json,os,sys\n'
            f'fd=os.open({str(trace)!r},os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n'
            'os.write(fd,(json.dumps(sys.argv[1:])+"\\n").encode()); os.close(fd)\n'
            'if "update" in sys.argv[1:]: raise SystemExit(42)\n'
            f'os.execv({shutil.which("runc")!r},[{shutil.which("runc")!r},*sys.argv[1:]])\n')
        wrapper.chmod(0o755)
        config = root/'daemon.json'
        config.write_text('{}')
        socket = 'unix://'+str(root/'docker.sock')
        # No host socket/config, registry, external network, or runner daemon mutation.
        log = self.enterContext((root/'dockerd.log').open('wb'))
        daemon = subprocess.Popen([shutil.which('dockerd'), '--config-file='+str(config),
            '--host='+socket, '--data-root='+str(root/'data'), '--exec-root='+str(root/'exec'),
            '--pidfile='+str(root/'daemon.pid'), '--storage-driver=vfs', '--bridge=none',
            '--iptables=false', '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
            '--add-runtime=r3-reject-update='+str(wrapper)], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        def shutdown():
            daemon.terminate()
            try:
                daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        self.addCleanup(shutdown)
        def engine(*argv, check=True):
            result = subprocess.run([shutil.which('docker'), '--config', str(root/'client'), '--host', socket, *argv],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
            if check:
                self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
            return result
        end = time.monotonic()+45
        while engine('info', check=False).returncode:
            self.assertIsNone(daemon.poll(), (root/'dockerd.log').read_text())
            self.assertLess(time.monotonic(), end, 'private dockerd readiness timeout')
            time.sleep(.1)
        print('R3_RESTART_POLICY_DOCKER_VERSION='+engine('version', '--format', '{{json .}}').stdout.decode())
        sleep = Path(shutil.which('sleep')).resolve()
        linked = subprocess.run([shutil.which('ldd'), str(sleep)], capture_output=True, check=True).stdout.decode()
        libraries = set(re.findall(r'/[^\s()]+', linked))
        self.assertTrue(libraries, 'sleep dynamic libraries required')
        archive = root/'rootfs.tar'
        with tarfile.open(archive, 'w', dereference=True) as tar:
            tar.add(sleep, arcname='sleep')
            for library in sorted(libraries):
                tar.add(library, arcname=library.lstrip('/'))
        engine('import', str(archive), 'r3-policy-local:fixture')
        cid = engine('create', '--runtime=r3-reject-update', '--network=none',
                     'r3-policy-local:fixture', '/sleep', '300').stdout.decode().strip()
        self.addCleanup(lambda: engine('rm', '--force', cid))
        def inspect():
            return json.loads(engine('inspect', cid).stdout)[0]
        def updates():
            return [row for row in map(json.loads, trace.read_text().splitlines()) if 'update' in row] if trace.exists() else []
        def stopped_policy(status):
            row = inspect()
            self.assertEqual((row['State']['Status'], row['State']['Running'], row['State']['Pid']), (status, False, 0))
            count = len(updates())
            engine('update', '--restart', 'unless-stopped', cid)
            self.assertEqual(inspect()['HostConfig']['RestartPolicy']['Name'], 'unless-stopped')
            self.assertEqual(len(updates()), count, 'stopped update must not reach OCI runtime')
        stopped_policy('created')
        engine('start', cid)
        self.assertTrue(inspect()['State']['Running'])
        self.assertTrue(trace.exists(), 'registered runtime must have handled start')
        self.assertEqual(len(updates()), 0)
        # The identical command must still reach the runtime on a running CID.
        result = engine('update', '--restart', 'unless-stopped', cid, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
        self.assertEqual(len(updates()), 1, trace.read_text())
        engine('stop', '--time', '1', cid)
        stopped_policy('exited')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests),
                              loader.loadTestsFromTestCase(DockerRestartPolicyTests)])


if __name__ == '__main__':
    if sys.argv[1:] == ['--native-child']:
        if not NATIVE: raise RuntimeError('disabled native scenario')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([OperateFixture('scenario_operate')]))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()

