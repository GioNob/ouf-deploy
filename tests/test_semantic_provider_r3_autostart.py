"""Portable D-045 contracts: fake operate, local receipts, simulated time."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3 import autostart as A

ROOT = Path(__file__).resolve().parents[1]
BOOT = "11111111-2222-3333-4444-555555555555"


def configuration(output="/etc/ouf/deploy-snapshots"):
    return dict(schema=A.SCHEMA, bindings={name: {"path": "/usr/bin/" + name, "sha256": "a" * 64}
                for name in ("docker", "nft", "systemctl", "wrapper")}, dockerSocket="unix:///var/run/docker.sock",
                installRoot="/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1",
                volatileRestore=dict(result="/var/lib/ouf/d042/result.json", sha256="b" * 64,
                                     source="/etc/ouf/historical/source"), outputRoot=output,
                attempts=3, waitSeconds=[30, 90, 180])


def receipt(cfg, action="start", epochs=(12, 12), name=None, cids=("a" * 64, "b" * 64)):
    folder = Path(cfg["outputRoot"]) / (name or f"semantic-provider-r3-operate-{action}-20261116T120000")
    folder.mkdir(mode=0o700)
    rows = {role: {"cid": cid, "epoch": {"epoch": epoch}}
            for role, cid, epoch in zip(("adapter", "southbound"), cids, epochs)}
    claim = dict(schema=A.OPERATE_SCHEMA, action=action, installRoot=cfg["installRoot"],
                 observation={"candidates": rows})
    claim["planSha256"] = hashlib.sha256(A.canonical(claim)).hexdigest()
    A.write_once(folder / "operate-claim.json", claim)
    A.write_once(folder / "result.json", dict(schema=A.OPERATE_SCHEMA, action=action, status=A.SUCCESS[action],
                 planSha256=claim["planSha256"], lastObservation={"candidates": rows}))
    return folder


class FakeOperate:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            return reply(args)
        return dict(reply)


READY = dict(status="PLAN_READY", planSha256="c" * 64)
STARTED = dict(status=A.SUCCESS["start"], outputCreated=True, doNotRerunApply=True)
HELD = dict(status="HELD", reason="R3_EPOCH_BOOT_DRIFT", doNotRerunApply=False)


class AutostartTests(unittest.TestCase):
    def setUp(self):
        folder = self.enterContext(tempfile.TemporaryDirectory())
        self.cfg = configuration(folder)
        self.enterContext(patch.object(A, "custody"))
        receipt(self.cfg)
        self.waits, self.incidents = [], []

    def run_driver(self, replies):
        self.fake = FakeOperate(replies)
        return A.run(self.cfg, BOOT, operate=self.fake, sleep=self.waits.append, emit=self.incidents.append)

    def test_first_attempt_success_and_exact_apply_digest(self):
        code, report = self.run_driver([READY, STARTED])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], A.SUCCESS["start"])
        self.assertEqual(self.waits, [30])
        plan, apply = self.fake.calls
        self.assertEqual(plan[0], "--plan")
        self.assertEqual(apply[:3], ["--apply", "--plan-sha256", READY["planSha256"]])
        self.assertEqual(plan[1:], apply[3:])
        self.assertTrue(plan[plan.index("--output-directory") + 1].endswith(f"autostart-start-{BOOT}-1"))
        for name in ("docker", "nft", "systemctl", "wrapper"):
            self.assertIn("--" + name + "-sha256", plan)
        for name in ("--volatile-rootfs-result", "--volatile-rootfs-result-sha256", "--volatile-source"):
            self.assertIn(name, plan)
        self.assertEqual(self.incidents, [])

    def test_held_new_plan_new_output_and_success(self):
        code, report = self.run_driver([HELD, READY, STARTED])
        self.assertEqual((code, report["attempt"]), (0, 2))
        self.assertEqual([c[0] for c in self.fake.calls], ["--plan", "--plan", "--apply"])
        self.assertEqual(self.waits, [30, 90])
        self.assertNotEqual(self.fake.calls[0], self.fake.calls[1])
        saved = Path(self.cfg["outputRoot"]) / f"semantic-provider-r3-autostart-start-{BOOT}-1/autostart-attempt.json"
        self.assertEqual(json.loads(saved.read_bytes())["reason"], HELD["reason"])

    def test_three_denials_incident_reasons_and_simulated_clock(self):
        now, ticks = 0, []
        def sleep(delay):
            nonlocal now
            now += delay
            ticks.append(now)
        fake = FakeOperate([HELD, {**HELD, "reason": "R3_START_SUPERVISOR_NOT_WAITING"}, HELD])
        code, report = A.run(self.cfg, BOOT, operate=fake, sleep=sleep, emit=self.incidents.append)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "R3_AUTOSTART_EXHAUSTED")
        self.assertEqual(ticks, [30, 120, 300])
        self.assertEqual([a["reason"] for a in report["attempts"]],
                         [HELD["reason"], "R3_START_SUPERVISOR_NOT_WAITING", HELD["reason"]])
        self.assertEqual(len(fake.calls), 3)
        saved = Path(self.cfg["outputRoot"]) / f"r3-autostart-incident-{BOOT}.json"
        self.assertEqual(json.loads(saved.read_bytes()), report)
        self.assertEqual(self.incidents, [report])
        self.assertEqual(len(list(Path(self.cfg["outputRoot"]).glob("*autostart-start-*"))), 3)

    def test_apply_flags_never_retry(self):
        for flag in ("outputCreated", "doNotRerunApply"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as folder:
                cfg = configuration(folder)
                receipt(cfg)
                fake = FakeOperate([READY, {**HELD, flag: True}])
                code, report = A.run(cfg, BOOT, operate=fake, sleep=lambda _: None, emit=lambda _: None)
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "R3_AUTOSTART_APPLY_NOT_RETRYABLE")
                self.assertEqual(len(fake.calls), 2)

    def test_output_exists_without_flags_never_retry(self):
        def failed(args):
            Path(args[args.index("--output-directory") + 1]).mkdir()
            return HELD
        code, report = self.run_driver([READY, failed])
        self.assertEqual((code, report["status"]), (1, "R3_AUTOSTART_APPLY_NOT_RETRYABLE"))
        self.assertEqual(len(self.fake.calls), 2)

    def test_apply_timeout_or_bad_json_is_uncertain_and_never_retry(self):
        code, report = self.run_driver([READY, subprocess.TimeoutExpired("operate", 900)])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "R3_AUTOSTART_APPLY_NOT_RETRYABLE")
        self.assertEqual(len(self.fake.calls), 2)

    def test_preapply_denial_without_output_may_replan(self):
        code, _ = self.run_driver([READY, HELD, {**READY, "planSha256": "d" * 64}, STARTED])
        self.assertEqual(code, 0)
        self.assertEqual([c[0] for c in self.fake.calls], ["--plan", "--apply", "--plan", "--apply"])
        self.assertEqual(self.fake.calls[-1][2], "d" * 64)

    def test_latest_successful_stop_prevents_any_start(self):
        receipt(self.cfg, "stop")
        code, report = self.run_driver([])
        self.assertEqual((code, report["status"]), (0, "R3_AUTOSTART_NOT_DESIRED"))
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.waits, [])
        self.assertFalse(list(Path(self.cfg["outputRoot"]).glob("r3-autostart-*.json")))

    def test_new_start_after_stop_is_desired_regardless_of_mtime_or_names(self):
        stop = receipt(self.cfg, "stop")
        newer = receipt(self.cfg, "start", (13, 13), "semantic-provider-r3-operate-start-20000101T000000")
        os.utime(newer / "result.json", (1, 1))
        os.utime(stop / "result.json", (2000000000, 2000000000))
        self.assertEqual(A.desired(self.cfg)["action"], "start")

    def test_successful_autostart_receipt_participates_in_order(self):
        receipt(self.cfg, "stop")
        receipt(self.cfg, "start", (13, 13), f"semantic-provider-r3-autostart-start-{BOOT}-1")
        self.assertEqual(A.desired(self.cfg)["epochs"], [13, 13])

    def test_held_and_partial_claim_do_not_change_last_success(self):
        folder = Path(self.cfg["outputRoot"]) / "semantic-provider-r3-operate-stop-9999"
        folder.mkdir()
        A.write_once(folder / "result.json", dict(status="HELD", action="stop"))
        self.assertEqual(A.desired(self.cfg)["action"], "start")
        (folder / "result.json").unlink()
        self.assertEqual(A.desired(self.cfg)["action"], "start")

    def test_unknown_or_incomparable_history_is_held(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(A.Denied, "DESIRED_STATE_UNPROVEN"):
                A.desired(configuration(folder))
        receipt(self.cfg, "stop", (13, 11))
        with self.assertRaisesRegex(A.Denied, "ORDER_AMBIGUOUS"):
            self.run_driver([])

    def test_different_cohort_needs_reconciliation(self):
        receipt(self.cfg, "stop", cids=("c" * 64, "d" * 64))
        with self.assertRaisesRegex(A.Denied, "COHORT_AMBIGUOUS"):
            A.desired(self.cfg)

    def test_claim_digest_or_installation_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            cfg = configuration(folder)
            wrong = {**cfg, "installRoot": "/etc/another-install"}
            receipt(wrong)
            with self.assertRaisesRegex(A.Denied, "DESIRED_STATE_UNPROVEN"):
                A.desired(cfg)
        path = next(Path(self.cfg["outputRoot"]).glob("*/operate-claim.json"))
        claim = json.loads(path.read_bytes())
        claim["planSha256"] = "0" * 64
        path.write_bytes(A.canonical(claim))
        with self.assertRaisesRegex(A.Denied, "CLAIM_INVALID"):
            A.desired(self.cfg)

    def test_stop_during_wait_or_plan_prevents_apply(self):
        def deny_start(args):
            receipt(self.cfg, "stop")
            return READY
        code, report = self.run_driver([deny_start])
        self.assertEqual((code, report["status"]), (0, "R3_AUTOSTART_NOT_DESIRED"))
        self.assertEqual(len(self.fake.calls), 1)

    def test_same_boot_never_gets_another_attempt_budget(self):
        self.run_driver([HELD] * 3)
        with self.assertRaisesRegex(A.Denied, "BOOT_ALREADY_ATTEMPTED"):
            self.run_driver([])
        self.assertEqual(self.fake.calls, [])

    def test_output_collision_preserves_existing_evidence(self):
        folder = Path(self.cfg["outputRoot"]) / f"semantic-provider-r3-autostart-start-{BOOT}-1"
        folder.mkdir()
        (folder / "preserve").write_bytes(b"untouched")
        with self.assertRaisesRegex(A.Denied, "OUTPUT_ALREADY_EXISTS"):
            self.run_driver([])
        self.assertEqual((folder / "preserve").read_bytes(), b"untouched")

    def test_no_network_driver_and_error_priority(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            code, report = self.run_driver([HELD] * 3)
        self.assertEqual(code, 1)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            A.journal(report)
        self.assertTrue(stderr.getvalue().startswith('<3>{'))
        self.assertIn("R3_AUTOSTART_EXHAUSTED", stderr.getvalue())


class ConfigAndDeliveryTests(unittest.TestCase):
    def test_defaults_and_strict_nonsensitive_configuration(self):
        cfg = configuration()
        del cfg["attempts"], cfg["waitSeconds"]
        parsed = A.config(A.canonical(cfg))
        self.assertEqual((parsed["attempts"], parsed["waitSeconds"]), (3, [30, 90, 180]))
        for change in ({"token": "secret"}, {"dockerSocket": "tcp://127.0.0.1:2375"},
                       {"attempts": 4}, {"attempts": 2}, {"waitSeconds": [30, 30, 30]},
                       {"waitSeconds": [30, 90, 9999]}, {"outputRoot": "/etc/../tmp"}):
            with self.subTest(change=change), self.assertRaises(A.Denied):
                A.config(A.canonical({**cfg, **change}))
        with self.assertRaises(A.Denied):
            A.config(b'{"schema":1,"schema":2}')

    def test_invoke_is_local_isolated_bounded_and_has_no_inherited_environment(self):
        def run(args, **kwargs):
            self.assertEqual(args[:3], [sys.executable, "-I", "-B"])
            self.assertEqual(args[3], str(ROOT / "scripts/operate-semantic-provider-r3.py"))
            self.assertEqual(kwargs["env"], A.ENV)
            self.assertEqual(kwargs["timeout"], 900)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            kwargs["stdout"].write(A.canonical(dict(schema=A.OPERATE_SCHEMA, action="start", **HELD)))
            return subprocess.CompletedProcess(args, 1)
        with patch.object(A.subprocess, "run", side_effect=run):
            self.assertEqual(A.invoke(["--plan"])["reason"], HELD["reason"])

    def test_invoke_rejects_bad_output_and_exit_status(self):
        for raw, code in ((b'not json', 1), (A.canonical(dict(schema=A.OPERATE_SCHEMA, action="start", **HELD)), 0)):
            def run(args, **kwargs):
                kwargs["stdout"].write(raw)
                return subprocess.CompletedProcess(args, code)
            with self.subTest(raw=raw), patch.object(A.subprocess, "run", side_effect=run), self.assertRaises(Exception):
                A.invoke(["--apply"])

    def test_unit_dependencies_timeout_and_compatible_hardening(self):
        text = (ROOT / "ops/vps/systemd/ouf-semantic-r3-autostart.service").read_text()
        fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        self.assertEqual(fields["Type"], "oneshot")
        self.assertEqual(fields["Restart"], "no")
        for field in ("After", "Wants"):
            self.assertEqual(set(fields[field].split()),
                             {"docker.service", "network-online.target", "ouf-semantic-lease-supervisor-v2.service"})
        self.assertGreaterEqual(int(fields["TimeoutStartSec"]), 3 * 2 * 900 + 300 + 60)
        self.assertEqual(fields["RestrictAddressFamilies"], "AF_UNIX AF_NETLINK")
        self.assertEqual(fields["StandardError"], "journal")
        self.assertEqual(fields["SyslogLevelPrefix"], "yes")
        self.assertEqual(fields["ExecStart"], "/usr/bin/python3.13 -I -B "
                         "/etc/ouf/semantic-provider-r3-autostart/source/scripts/autostart-semantic-provider-r3.py "
                         "--config /etc/ouf/semantic-provider-r3-autostart/config.json")
        self.assertNotIn("ExecStop=", text)

    def test_installer_offline_manifest_exactly_extends_operate(self):
        text = (ROOT / "ops/vps/r3-autostart-install.sh").read_text()
        operate = (ROOT / "ops/vps/r3-operate.sh").read_text()
        expected = dict(re.findall(r"^  fetch (\S+) ([0-9a-f]{64})$", operate, re.M))
        python = text.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        tree = ast.parse(python)
        values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id in {"MANIFEST", "UNIT_SHA"}}
        manifest = values["MANIFEST"]
        self.assertEqual(set(manifest), set(expected) | {"tools/semantic_provider_r3/autostart.py",
                                                       "scripts/autostart-semantic-provider-r3.py"})
        for path, digest in manifest.items():
            raw = (ROOT / path).read_bytes().replace(b'\r\n', b'\n')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest, path)
            if path in expected:
                self.assertEqual(expected[path], digest)
        unit = (ROOT / "ops/vps/systemd/ouf-semantic-r3-autostart.service").read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(values["UNIT_SHA"], hashlib.sha256(unit).hexdigest())
        self.assertRegex(text, r"(?m)^C=0{40}$")
        self.assertIn("require(REQUESTED == digest", text)
        self.assertIn("(['daemon-reload'], ['enable', UNIT.name])", text)
        self.assertNotRegex(text, r"systemctl[^\n]*(?:\bstart\b|--now)")
        self.assertNotRegex(text, r"\b(?:curl|wget|urllib|requests)\b")

    def test_previous_boot_epoch_guard_is_retained(self):
        operate = (ROOT / "tools/semantic_provider_r3/operate.py").read_text()
        self.assertIn('require(row["bootId"] == boot, "R3_EPOCH_BOOT_DRIFT")', operate)
        driver = (ROOT / "tools/semantic_provider_r3/autostart.py").read_text()
        self.assertNotIn('"ABANDONED"', driver)

    def test_entrypoint_cli(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/autostart-semantic-provider-r3.py"),
                                 "--help"], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"--config", result.stdout)

    def test_custody_refuses_symlink_and_writable_files(self):
        import stat
        from types import SimpleNamespace
        path = Path.cwd() / "fixture.json"
        def lstat(item):
            if item == path:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0, st_nlink=1)
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0, st_nlink=1)
        with patch.object(Path, "lstat", lstat), self.assertRaisesRegex(A.Denied, "CUSTODY_REQUIRED"):
            A.custody(path)


class InstallerTests(unittest.TestCase):
    """Exercise the actual embedded installer with local fixtures and fake commands."""
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        text = (ROOT / "ops/vps/r3-autostart-install.sh").read_text()
        python = text.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        tree = ast.parse(python)
        tree.body = tree.body[:-1]  # omit the CLI try/except; call install explicitly
        self.ns = {}
        with patch.object(sys, "argv", ["installer", "1" * 40, str(ROOT), "plan", ""]):
            exec(compile(tree, "r3-autostart-install", "exec"), self.ns)
        source = self.base / "checkout"
        source.mkdir()
        self.ns.update(SOURCE=source, DEST=self.base / "installed", UNIT=self.base / "autostart.service")
        self.payload = {name: (ROOT / name).read_bytes().replace(b'\r\n', b'\n')
                        for name in [*self.ns["MANIFEST"], self.ns["UNIT_SOURCE"]]}
        for name, raw in self.payload.items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        self.calls, self.version = [], "v1"
        original_bound = self.ns["bound"]
        def bound(path, expected=None):
            if str(path).startswith(str(self.base)):
                return original_bound(path, expected)
            digest = expected or hashlib.sha256(self.version.encode()).hexdigest()
            return {"path": str(path), "sha256": digest}
        def command(args):
            if args[0] == "/usr/bin/git":
                if args[-1] == "HEAD":
                    return ("1" * 40).encode()
                return self.payload[args[-1].split(":", 1)[1]]
            self.calls.append(args)
            return b""
        self.ns.update(custody=lambda *a, **k: None, bound=bound, command=command)
        self.enterContext(patch.object(sys, "platform", "linux"))
        self.enterContext(patch.object(os, "geteuid", return_value=0, create=True))
        self.enterContext(patch.object(os, "getegid", return_value=0, create=True))

    def plan(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.ns["install"]()
        return json.loads(output.getvalue())

    def test_plan_is_readonly_and_apply_installs_only_enables(self):
        plan = self.plan()
        self.assertFalse(self.ns["DEST"].exists())
        self.assertFalse(self.ns["UNIT"].exists())
        self.assertEqual(self.calls, [])
        self.ns.update(MODE="apply", REQUESTED=plan["planSha256"])
        report = self.plan()
        self.assertEqual(report["status"], "R3_AUTOSTART_INSTALLED_ENABLED")
        self.assertFalse(report["providerStarted"])
        self.assertEqual([c[1:] for c in self.calls], [["daemon-reload"], ["enable", "autostart.service"]])
        self.assertEqual(len(report["installedSha256"]), len(self.ns["MANIFEST"]) + 2)
        cfg = A.config((self.ns["DEST"] / "config.json").read_bytes())
        self.assertEqual(cfg["waitSeconds"], [30, 90, 180])
        with self.assertRaisesRegex(RuntimeError, "ALREADY_PRESENT"):
            self.plan()

    def test_apply_rejects_changed_config_or_wrong_digest_before_writes(self):
        plan = self.plan()
        self.ns.update(MODE="apply", REQUESTED=plan["planSha256"])
        self.version = "v2"
        with self.assertRaisesRegex(RuntimeError, "PLAN_CHANGED"):
            self.plan()
        self.assertFalse(self.ns["DEST"].exists())
        self.assertEqual(self.calls, [])

    def test_delivery_drift_denies_before_installation(self):
        target = self.ns["SOURCE"] / "tools/semantic_provider_r3/autostart.py"
        target.write_bytes(target.read_bytes() + b"# drift\n")
        with self.assertRaisesRegex(RuntimeError, "DELIVERY_DRIFT"):
            self.plan()
        self.assertFalse(self.ns["DEST"].exists())


if __name__ == "__main__":
    unittest.main()
