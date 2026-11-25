import contextlib
import copy
import io
import json
import os
import re
import shlex
import shutil
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]

from tools.platform_restart.controller import Controller, http_ready
from tools.module_release import frame as release_frame
from tools.platform_restart.docker import Docker, GATE_INSPECT, pid1_state
from tools.platform_restart import identity, install
from tools.platform_restart.profile import GATE_LOOP, Held, canonical, load_profile, sha


def configuration():
    probes = [{"type": "running", "stableSeconds": 1}, {"type": "healthy"},
              {"type": "tcp", "network": "sample-net", "port": 12345, "timeoutSeconds": 1}]
    return dict(schema="ouf.platform-restart-profile.v1",
                levels=[dict(timeoutSeconds=4, containers=[dict(containerName=f"sample-{i}", readiness=p)])
                        for i, p in enumerate(probes)],
                governedElsewhere=["sample-private-a", "sample-private-b"],
                docker=dict(path="/example/docker", sha256="a" * 64), dockerSocket="/example/socket",
                stopTimeoutSeconds=2, inventoryTimeoutSeconds=30, receipts="/example/receipts", incidents="/example/incidents",
                bootRetryDelaysSeconds=[1, 2])


class Clock:
    def __init__(self):
        self.now = 0
        self.waits = []

    def sleep(self, delay):
        self.waits.append(delay)
        self.now += delay


class Engine:
    def __init__(self, cfg):
        self.rows = {}
        self.changes = []
        names = [m["containerName"] for level in cfg["levels"] for m in level["containers"]]
        for i, name in enumerate(names + cfg["governedElsewhere"] + ["sample-retained"]):
            self.rows[name] = dict(name=name, cid=f"{i + 1:064x}", status="exited", running=False,
                                   restarting=False, startedAt="generation-0", health="healthy",
                                   restartPolicy=dict(name="no", maximumRetryCount=0),
                                   networks={"sample-net": dict(live=None, static=f"192.0.2.{i + 1}")})

    def inventory(self, targets):
        return copy.deepcopy(list(self.rows.values()))

    def inspect(self, cid, deadline):
        return copy.deepcopy(next(row for row in self.rows.values() if row["cid"] == cid))

    def change(self, action, cid, deadline):
        row = next(row for row in self.rows.values() if row["cid"] == cid)
        self.changes.append((action, row["name"]))
        row["running"] = action == "start"
        row["status"] = "running" if row["running"] else "exited"
        row["startedAt"] = str(len(self.changes))
        for ips in row["networks"].values():
            ips["live"] = ips["static"] if row["running"] else None


class PlatformTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.cfg = configuration()
        raw = canonical(self.cfg)
        self.profile_hash = sha(raw)
        self.cfg = load_profile(raw, self.profile_hash)
        for field in ("receipts", "incidents"):
            directory = Path(temp.name) / field
            directory.mkdir()
            self.cfg[field] = str(directory)
        self.clock = Clock()
        self.engine = Engine(self.cfg)
        self.probes = []
        self.controller = Controller(self.cfg, self.profile_hash, self.engine, clock=lambda: self.clock.now,
                                     sleep=self.clock.sleep, tcp=self.tcp)

    def tcp(self, *args):
        self.probes.append(args)
        return True

    def apply(self, action):
        plan = self.controller.run("plan", action)
        self.assertEqual(plan["status"], "PLAN_READY", plan)
        return self.controller.run("apply", action, plan["planSha256"])

    def test_levels_skip_readiness_and_reverse_stop(self):
        self.engine.change("start", self.engine.rows["sample-1"]["cid"], None)
        self.engine.changes.clear()
        start = self.apply("start")
        self.assertEqual(start["status"], "SUCCEEDED", start)
        self.assertEqual(self.engine.changes, [("start", "sample-0"), ("start", "sample-2")])
        self.assertEqual(self.probes[0], ("192.0.2.3", 12345, 1))
        self.assertEqual(self.apply("start")["status"], "SUCCEEDED")
        self.assertEqual(len(self.engine.changes), 2)
        self.engine.changes.clear()
        self.assertEqual(self.apply("stop")["status"], "SUCCEEDED")
        self.assertEqual(self.engine.changes, [("stop", f"sample-{i}") for i in (2, 1, 0)])
        self.assertEqual(self.apply("stop")["status"], "SUCCEEDED")
        self.assertEqual(len(self.engine.changes), 3)
        for path in Path(self.cfg["receipts"]).glob("*.json"):
            self.assertIn("finishedAt", json.loads(path.read_bytes()))
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_missing_ambiguous_and_exclusion(self):
        snapshot = self.engine.inventory(set())
        for rows, reason in [(snapshot[1:], "MISSING_CONTAINER"), (snapshot + snapshot[:1], "AMBIGUOUS_NAME")]:
            with patch.object(self.engine, "inventory", return_value=rows):
                self.assertEqual(self.controller.run("plan", "start")["reason"], reason)
        self.engine.change("start", self.engine.rows["sample-private-a"]["cid"], None)
        self.engine.changes.clear()
        self.assertEqual(self.controller.run("plan", "stop")["reason"], "GOVERNED_CONTAINER_RUNNING")
        self.assertEqual(self.apply("start")["status"], "SUCCEEDED")
        self.assertFalse(any("private" in name for _, name in self.engine.changes))

    def test_same_address_requires_same_network_and_running_owner(self):
        row = self.engine.rows["sample-retained"]
        row["networks"]["sample-net"]["static"] = "192.0.2.1"
        self.assertEqual(self.controller.run("plan", "start")["status"], "PLAN_READY")
        self.engine.change("start", row["cid"], None)
        self.assertEqual(self.controller.run("plan", "start")["reason"], "IPV4_CONFLICT")
        row["networks"]["other"] = row["networks"].pop("sample-net")
        self.assertEqual(self.controller.run("plan", "start")["status"], "PLAN_READY")

    def test_profile_and_binary_bindings(self):
        raw = canonical(configuration())
        with self.assertRaisesRegex(Held, "PROFILE_HASH_CHANGED"):
            load_profile(raw, "0" * 64)
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "docker"
            binary.write_bytes(b"fixture")
            cfg = configuration()
            cfg["docker"]["path"] = str(binary)
            with patch("tools.platform_restart.docker.custody"), patch("subprocess.check_output") as call:
                ctrl = Controller(self.cfg, self.profile_hash, Docker(cfg))
                self.assertEqual(ctrl.run("plan", "start")["reason"], "DOCKER_HASH_CHANGED")
                call.assert_not_called()

    def test_reject_invalid_and_reserved_targets(self):
        for target in ("sample-retained-x", "sample-before-x", "RETIRED-x", "sample-private-b", "sample-2"):
            cfg = configuration()
            cfg["levels"][0]["containers"][0]["containerName"] = target
            raw = canonical(cfg)
            with self.assertRaises(Held):
                load_profile(raw, sha(raw))
        for key, value in [("extra", 0), ("bootRetryDelaysSeconds", [1, 1]), ("stopTimeoutSeconds", True)]:
            cfg = {**configuration(), key: value}
            raw = canonical(cfg)
            with self.assertRaises(Held):
                load_profile(raw, sha(raw))
        raw = raw.replace(b'"schema":', b'"schema":false,"schema":')
        with self.assertRaisesRegex(Held, "DUPLICATE_FIELD"):
            load_profile(raw, sha(raw))

    def test_plan_digest_binds_identity_and_generation(self):
        before = self.controller.run("plan", "start")
        self.assertEqual(before["planSha256"], self.controller.run("plan", "start")["planSha256"])
        self.engine.rows["sample-1"]["cid"] = "f" * 64
        refused = self.controller.run("apply", "start", before["planSha256"])
        self.assertEqual(refused["reason"], "PLAN_CHANGED")
        self.assertEqual(self.engine.changes, [])

    def test_readiness_failure_stops_before_next_level(self):
        self.engine.rows["sample-1"]["health"] = "unhealthy"
        result = self.apply("start")
        self.assertEqual((result["reason"], result["level"], result["container"]),
                         ("READINESS_TIMEOUT", 2, "sample-1"))
        self.assertEqual(self.engine.changes, [("start", "sample-0"), ("start", "sample-1")])
        self.assertTrue(self.engine.rows["sample-0"]["running"])

    def test_stop_requires_observed_exit(self):
        self.apply("start")
        with patch.object(self.engine, "change") as noop:
            self.assertEqual(self.apply("stop")["reason"], "STOP_UNCONFIRMED")
            self.assertEqual(noop.call_count, 1)

    def test_boot_backoff_marker_and_closed_incident(self):
        boot = str(uuid.uuid4())
        self.engine.rows["sample-1"]["health"] = "starting"
        with contextlib.redirect_stderr(io.StringIO()) as journal:
            result = self.controller.run("boot", "start", boot_id=boot)
        self.assertTrue(journal.getvalue().startswith("<3>"))
        self.assertEqual(result["reason"], "READINESS_TIMEOUT")
        self.assertEqual([e["attempt"] for e in result["events"] if "attempt" in e], [1, 2, 3])
        self.assertEqual([d for d in self.clock.waits if d >= 1], [1, 2])
        path, = Path(self.cfg["incidents"]).glob("*.json")
        incident = json.loads(path.read_bytes())
        self.assertEqual(set(incident), {"schema", "code", "at", "level", "container", "reason"})
        self.assertEqual(incident["code"], "PLATFORM_BOOT_START_FAILED")
        self.assertNotIn("192.0.2.", str(incident))
        self.assertEqual(self.controller.run("boot", "start", boot_id=boot)["reason"], "BOOT_ALREADY_ATTEMPTED")
        self.assertEqual(self.engine.changes, [("start", "sample-0"), ("start", "sample-1")])

    def test_boot_recovers_only_failed_level(self):
        self.engine.rows["sample-1"]["health"] = "starting"
        def recover(delay):
            self.clock.sleep(delay)
            if delay == 1:
                self.engine.rows["sample-1"]["health"] = "healthy"
        self.controller.sleep = recover
        result = self.controller.run("boot", "start", boot_id=str(uuid.uuid4()))
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertEqual(self.engine.changes, [("start", f"sample-{i}") for i in range(3)])
        self.assertEqual(list(Path(self.cfg["incidents"]).iterdir()), [])

    def test_same_level_starts_peers_before_waiting(self):
        first, second, last = self.cfg["levels"]
        first["containers"] += second["containers"]
        self.cfg["levels"] = [first, last]
        self.engine.rows["sample-1"]["health"] = "starting"
        self.assertEqual(self.apply("start")["reason"], "READINESS_TIMEOUT")
        self.assertEqual(self.engine.changes, [("start", "sample-0"), ("start", "sample-1")])

    def test_docker_projects_static_ip_when_live_address_is_absent(self):
        cid = "a" * 64
        docker = Docker(configuration())
        output = json.dumps([cid, "/sample", "exited", False, False, "generation", ["no", 0], None])
        output += '\n["sample-net",null,"192.0.2.9"]'
        with patch.object(docker, "command", return_value=output) as call:
            row = docker.inspect(cid)
            self.assertEqual(row["networks"], {"sample-net": dict(live=None, static="192.0.2.9")})
            self.assertEqual(call.call_args.args[:3], ("inspect", "--type", "container"))

    def test_ready_probe_loses_stability_across_generations(self):
        self.engine.change("start", self.engine.rows["sample-0"]["cid"], None)
        row = self.engine.rows["sample-0"]
        probe = self.cfg["levels"][0]["containers"][0]["readiness"]
        stability = {}
        for generation in ("first", "second"):
            row["startedAt"] = generation
            self.assertFalse(self.controller.ready(row, probe, 9, stability))
            self.clock.sleep(1)
        self.assertTrue(self.controller.ready(row, probe, 9, stability))
        row["restarting"] = True
        self.assertFalse(self.controller.ready(row, probe, 9, stability))

    def test_delivery_pin_matches_current_commit(self):
        installer, operator = [(ROOT / "ops/vps" / name).read_text() for name in
                               ("platform-restart-install.sh", "platform-restart.sh")]
        def pin(script):
            return re.search(r"(?m)^C=([0-9a-f]{40})$", script)[1]
        commit = pin(installer)
        self.assertEqual(commit, pin(operator))
        files = shlex.split(re.search(r"(?s)\nfiles=\(([^)]+)\)", installer)[1])
        def blob(revision, path):
            run = subprocess.run(["git", "--no-replace-objects", "rev-parse", "--verify", revision + ":" + path],
                                 cwd=ROOT, capture_output=True, env={**os.environ, "GIT_NO_LAZY_FETCH": "1",
                                                                     "GIT_ALLOW_PROTOCOL": ""})
            return run.stdout.strip() if run.returncode == 0 else None
        mismatched = []
        for path in files:
            expected = blob(commit, path)
            if not expected or expected != blob("HEAD", path):
                mismatched.append(path)
        self.assertEqual(mismatched, [], "Update both launcher pins after review")

    def test_installed_archive_and_enable_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)
            pyz = dest / "platform.pyz"
            pyz.write_bytes(install.archive())
            help_text = subprocess.check_output([sys.executable, "-I", "-B", str(pyz), "--help"], text=True)
            self.assertIn("--plan-sha256", help_text)
            meta = dict(commit="fixture", unit="unit", unitSha256="unit-hash", python="python",
                        pythonSha256="python-hash", checksum="checksum", checksumSha256="checksum-hash",
                        bootBindingsSha256="sums", systemctl="systemctl", sourceSha256=sha(pyz.read_bytes()),
                        receipts=self.cfg["receipts"], profileSha256=self.profile_hash)
            (dest / "installation.json").write_bytes(canonical(meta))
            hashes = {pyz: meta["sourceSha256"], dest / "boot.sha256": "sums", dest / "profile.json": self.profile_hash,
                      "unit": "unit-hash", "python": "python-hash", "checksum": "checksum-hash"}
            args = SimpleNamespace(mode="enable", receipt="apply-" + "0" * 32 + ".json")
            proof = Path(self.cfg["receipts"]) / args.receipt
            with (patch.object(install, "custody"), patch.object(install, "private_dir"),
                  patch.object(install, "checked_unit"), patch.object(install, "filehash", side_effect=hashes.__getitem__),
                  patch.object(install, "systemctl", return_value="enabled") as manager):
                self.controller.source_hash = meta["sourceSha256"]
                report = self.apply("start")
                proof.write_bytes(canonical({**report, "mode": "boot"}))
                with self.assertRaisesRegex(install.Held, "START_RECEIPT_REQUIRED"):
                    install.administer(args, dest, "fixture")
                manager.assert_not_called()
                proof.write_bytes(canonical(report))
                self.assertEqual(install.administer(args, dest, "fixture")["status"], "ENABLED")
                self.assertEqual([call.args[1] for call in manager.call_args_list], ["enable", "is-enabled"])
                args.mode = "disable"
                manager.reset_mock()
                manager.return_value = "disabled"
                self.assertEqual(install.administer(args, dest, "fixture")["status"], "DISABLED")
                self.assertEqual([call.args[1] for call in manager.call_args_list], ["disable", "is-enabled"])

    def test_installer_reobserves_then_only_reloads(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            dest = folder / "installation"
            units = folder / "units"
            units.mkdir()
            profile = folder / "input.json"
            profile.write_bytes(canonical(configuration()))
            args = SimpleNamespace(mode="plan", profile=str(profile), profile_sha256=sha(profile.read_bytes()),
                                   unit_dir=str(units), systemctl="manager", checksum="checksum", plan_sha256=None)
            cfg = copy.deepcopy(self.cfg)
            def digest(path):
                return sha(Path(path).read_bytes()) if Path(path).is_file() else cfg["docker"]["sha256"]
            changes = []
            def manager(binary, action, *options, check=True):
                if action == "show":
                    loaded = "daemon-reload" in changes
                    return {"LoadState": "loaded" if loaded else "not-found", "DropInPaths": "",
                            "NeedDaemonReload": "no", "FragmentPath": str(units / install.UNIT)}[options[1]]
                if action == "is-enabled":
                    return "disabled" if changes else "not-found"
                changes.append(action)
                return ""
            # Native path/custody, interpreter version and service manager are the host boundaries.
            with (patch.object(install, "safe_path", side_effect=Path), patch.object(install, "custody"),
                  patch.object(install, "private_dir"), patch.object(install.sys, "version_info", (3, 13)),
                  patch.object(install, "load_profile", return_value=cfg),
                  patch.object(install, "filehash", side_effect=digest), patch.object(install, "systemctl", manager)):
                plan = install.configure(args, dest, "fixture")
                self.assertFalse(dest.exists())
                self.assertEqual(changes, [])
                args.mode = "apply"
                with self.assertRaisesRegex(install.Held, "INSTALL_PLAN_CHANGED"):
                    install.configure(args, dest, "fixture")
                args.plan_sha256 = plan["planSha256"]
                self.assertEqual(install.configure(args, dest, "fixture")["status"], "INSTALLED")
                self.assertEqual(changes, ["daemon-reload"])
                unit = (units / install.UNIT).read_text()
                self.assertNotIn("@", unit)
                self.assertIn("--profile-sha256 " + args.profile_sha256, unit)
                self.assertEqual((dest / "profile.json").read_bytes(), profile.read_bytes())


def gated_member():
    return dict(containerName="sample-0",
                gate=dict(imageId="sha256:" + "b" * 64,
                          entrypoint=["/example/sh", "-c", GATE_LOOP, "ouf-gated-application"],
                          command=["java", "-jar", "/example/module.jar"]),
                readiness=dict(type="actuator", address="127.0.0.1", port=12345, path="/sample/ready",
                               acceptStatus=[200], jsonStatus="UP", timeoutSeconds=1, budgetSeconds=2))


class GatedEngine(Engine):
    gate_state = Docker.gate_state

    def __init__(self, cfg):
        super().__init__(cfg)
        self.config = copy.deepcopy(cfg["levels"][0]["containers"][0]["gate"])
        self.trace = []
        self.process = "armed"

    def change(self, action, cid, deadline):
        super().change(action, cid, deadline)
        self.trace.append(self.changes[-1])

    def command(self, *args, deadline):
        row = self.rows["sample-0"]
        if args == ("inspect", "--type", "container", "--format", GATE_INSPECT, row["cid"]):
            self.trace.append(("inspect_gate", row["name"]))
            return json.dumps([row["cid"], "/" + row["name"], row["status"], row["startedAt"], 4321,
                               self.config["imageId"], self.config["entrypoint"], self.config["command"]])
        if args != ("kill", "--signal=USR1", row["cid"]):
            raise AssertionError(args)
        self.trace.append(("USR1", row["name"]))
        self.process = "application"


class GatedRestartTests(unittest.TestCase):
    def setUp(self):
        cfg = configuration()
        cfg["levels"][0]["containers"] = [gated_member()]
        raw = canonical(cfg)
        cfg = load_profile(raw, sha(raw))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        for key in ("incidents", "receipts"):
            directory = Path(temp.name) / key
            directory.mkdir()
            cfg[key] = str(directory)
        self.engine = GatedEngine(cfg)
        self.clock = Clock()
        self.ctrl = Controller(cfg, sha(raw), self.engine, clock=lambda: self.clock.now,
                               sleep=self.clock.sleep, tcp=lambda *args: True)
        self.enterContext(patch("tools.platform_restart.docker.pid1_state", side_effect=self.process))
        self.http = self.enterContext(patch("tools.platform_restart.controller.application_ready", side_effect=self.up))

    def process(self, pid, gate):
        self.assertEqual(pid, 4321)
        self.engine.trace.append(("pid1", self.engine.process))
        return self.engine.process

    def up(self, pid, probe, timeout):
        self.engine.trace.append(("GET", probe["path"]))
        return True

    def start(self):
        plan = self.ctrl.run("plan", "start")
        return self.ctrl.run("apply", "start", plan["planSha256"])

    def test_start_verify_signal_java_and_up_before_next_level(self):
        self.assertEqual(self.start()["status"], "SUCCEEDED")
        self.assertEqual(self.engine.trace, [
            ("start", "sample-0"), ("inspect_gate", "sample-0"), ("pid1", "armed"), ("USR1", "sample-0"),
            ("inspect_gate", "sample-0"), ("pid1", "application"), ("GET", "/sample/ready"),
            ("inspect_gate", "sample-0"), ("pid1", "application"), ("start", "sample-1"), ("start", "sample-2")])
        self.assertEqual(self.start()["status"], "SUCCEEDED")
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)

    def native_restart(self, observed, executable):
        member = self.ctrl.members["sample-0"]
        command = ["/usr/local/bin/ouf-mcp", "server"]
        member["gate"]["command"] = self.engine.config["command"] = command
        probe = member["readiness"]
        probe.update(path="/health/ready", acceptStatus=[204])
        del probe["jsonStatus"]

        def cmdline():
            args = observed if self.engine.process == "application" else member["gate"]["entrypoint"] + command
            return b"\0".join(os.fsencode(arg) for arg in args) + b"\0"

        self.http.side_effect = lambda pid, probe, timeout: http_ready(probe)
        with (patch("tools.platform_restart.docker.pid1_state", side_effect=pid1_state),
              patch("pathlib.Path.read_bytes", side_effect=cmdline),
              patch("pathlib.Path.read_text", return_value="NSpid: 4321 1\nSigCgt: 200"),
              patch("pathlib.Path.readlink", return_value=Path(executable)),
              patch("signal.SIGUSR1", 10, create=True), patch("http.client.HTTPConnection") as connect):
            response = connect.return_value.getresponse.return_value
            response.status = 204
            response.read.side_effect = AssertionError("status-only probe read a body")
            result = self.start()
            if result["status"] == "SUCCEEDED":
                connect.return_value.request.assert_called_once_with("GET", "/health/ready")
            return result

    def test_native_mcp_204_advances_next_level(self):
        result = self.native_restart(["/usr/local/bin/ouf-mcp", "server"], "/usr/local/bin/ouf-mcp")
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertTrue(any(e.get("pid1") == "/usr/local/bin/ouf-mcp" and e["outcome"] == "UP"
                            for e in result["events"]))
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertIn(("start", "sample-1"), self.engine.changes)

    def test_post_exec_unexpected_argument_holds_without_second_signal(self):
        result = self.native_restart(["/usr/local/bin/ouf-mcp", "migrate"], "/usr/local/bin/ouf-mcp")
        self.assertEqual(result["reason"], "READINESS_NOT_UP")
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertEqual(self.engine.changes, [("start", "sample-0")])
        self.http.assert_not_called()

    def test_native_wrong_executable_path_holds(self):
        result = self.native_restart(["/usr/local/bin/ouf-mcp", "server"], "/other/ouf-mcp")
        self.assertEqual(result["reason"], "READINESS_NOT_UP")
        self.http.assert_not_called()

    def test_java_204_holds_next_level(self):
        self.http.side_effect = lambda pid, probe, timeout: http_ready(probe)
        with patch("http.client.HTTPConnection") as connect:
            connect.return_value.getresponse.return_value.status = 204
            self.assertEqual(self.start()["reason"], "READINESS_NOT_UP")
        self.assertEqual(self.engine.changes, [("start", "sample-0")])
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)

    def test_profile_requires_explicit_http_codes(self):
        for value in (None, [], [True], ["204"], [99], [600], [200, 200]):
            with self.subTest(value=value):
                cfg = configuration()
                member = gated_member()
                if value is None:
                    del member["readiness"]["acceptStatus"]
                else:
                    member["readiness"]["acceptStatus"] = value
                cfg["levels"][0]["containers"] = [member]
                raw = canonical(cfg)
                with self.assertRaises(Held):
                    load_profile(raw, sha(raw))

    def test_image_entrypoint_or_arguments_mismatch_holds_without_signal(self):
        original = copy.deepcopy(self.engine.config)
        for key, value in [("imageId", "sha256:" + "e" * 64), ("entrypoint", ["/example/sh"]),
                           ("command", ["java", "-jar", "/example/different.jar"])]:
            with self.subTest(key=key):
                self.engine.config = {**original, key: value}
                self.engine.rows["sample-0"].update(status="exited", running=False)
                result = self.start()
                self.assertEqual((result["reason"], result["gateReason"]),
                                 ("GATE_HELD", "IMAGE_MISMATCH" if key == "imageId" else "LAUNCH_CONFIG_MISMATCH"))
        self.assertFalse(any(op == "USR1" for op, _ in self.engine.trace))
        self.assertEqual({name for _, name in self.engine.changes}, {"sample-0"})

    def test_readiness_budget_is_terminal_even_at_boot(self):
        self.http.side_effect = lambda *args: False
        with contextlib.redirect_stderr(io.StringIO()):
            result = self.ctrl.run("boot", "start", boot_id=str(uuid.uuid4()))
        self.assertEqual((result["reason"], result["level"], result["container"]),
                         ("READINESS_NOT_UP", 1, "sample-0"))
        self.assertEqual(self.clock.now, 2)
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertEqual(self.engine.changes, [("start", "sample-0")])

    def test_waits_for_trap_then_for_exec_without_resending(self):
        self.engine.process = "arming"
        send = self.engine.command
        def pending_exec(*args, deadline):
            result = send(*args, deadline=deadline)
            if args[0] == "kill":
                self.engine.process = "armed"
            return result
        def arm(delay):
            self.clock.sleep(delay)
            self.engine.process = "armed"
        self.ctrl.sleep = arm
        with patch.object(self.engine, "command", side_effect=pending_exec):
            self.assertEqual(self.start()["reason"], "READINESS_NOT_UP")
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertEqual(self.engine.trace[:6], [("start", "sample-0"), ("inspect_gate", "sample-0"),
                         ("pid1", "arming"), ("inspect_gate", "sample-0"), ("pid1", "armed"), ("USR1", "sample-0")])
        self.http.assert_not_called()

    def test_two_gates_share_level_but_have_independent_deadlines(self):
        first, second, last = self.ctrl.cfg["levels"]
        peer = second["containers"][0]
        peer.update(gate=self.engine.config, readiness={**gated_member()["readiness"], "budgetSeconds": 1})
        first["containers"].append(peer)
        self.ctrl.cfg["levels"] = [first, last]
        signals = []
        def state(step, gate, deadline):
            row = self.engine.rows[step["containerName"]]
            pid = int(row["cid"], 16) + 100
            return (row["startedAt"], pid), "application" if row["cid"] in signals else "armed"
        def signal(command, option, cid, *, deadline):
            self.assertEqual((command, option), ("kill", "--signal=USR1"))
            signals.append(cid)
        self.http.side_effect = lambda pid, probe, timeout: pid == 101
        with patch.object(self.engine, "gate_state", side_effect=state), patch.object(self.engine, "command", side_effect=signal):
            result = self.start()
        self.assertEqual((result["reason"], result["container"], self.clock.now), ("READINESS_NOT_UP", "sample-1", 1))
        self.assertEqual(signals, [self.engine.rows[n]["cid"] for n in ("sample-0", "sample-1")])
        self.assertEqual(self.engine.changes, [("start", "sample-0"), ("start", "sample-1")])

    def test_interruptions_resume_or_hold_without_repeating_effects(self):
        class Interrupted(BaseException):
            pass

        for mode, action, cuts in (("apply", "start", ("change", "signal", "verified")),
                                   ("boot", "start", ("change", "signal", "verified")),
                                   ("apply", "stop", ("change", "verified"))):
            for cut in cuts:
                with self.subTest(mode=mode, action=action, cut=cut):
                    fixture = GatedRestartTests()
                    try:
                        fixture.setUp()
                        ctrl, engine = fixture.ctrl, fixture.engine
                        if action == "stop":
                            self.assertEqual(fixture.start()["status"], "SUCCEEDED")
                        engine.trace.clear()
                        engine.changes.clear()
                        obj, method = {"change": (engine, "change"), "signal": (engine, "command"),
                                       "verified": (ctrl, "level")}[cut]
                        original = getattr(obj, method)
                        def interrupt(*args, **kwargs):
                            result = original(*args, **kwargs)
                            if cut != "signal" or args[0] == "kill":
                                raise Interrupted
                            return result
                        def invoke(driver, boot):
                            if mode == "boot":
                                return driver.run(mode, action, boot_id=boot)
                            plan = driver.run("plan", action)
                            return driver.run(mode, action, plan["planSha256"])
                        boot = str(uuid.uuid4())
                        with patch.object(obj, method, side_effect=interrupt), self.assertRaises(Interrupted):
                            invoke(ctrl, boot)
                        resumed = Controller(ctrl.cfg, ctrl.profile_hash, engine, clock=ctrl.clock,
                                             sleep=ctrl.sleep, tcp=ctrl.tcp)
                        if mode == "boot":
                            self.assertEqual(invoke(resumed, boot)["reason"], "BOOT_ALREADY_ATTEMPTED")
                        with contextlib.redirect_stderr(io.StringIO()):
                            result = invoke(resumed, str(uuid.uuid4()))
                        if action == "start" and cut == "change":
                            self.assertEqual((result["status"], result["gateReason"], result["container"]),
                                             ("HELD", "GATE_START_NOT_OWNED", "sample-0"))
                            self.assertTrue(result["plan"]["steps"][0]["observation"]["running"])
                        else:
                            self.assertEqual(result["status"], "SUCCEEDED", result)
                            if action == "start":
                                self.assertIn(("GET", "/sample/ready"), engine.trace)
                        self.assertTrue(all(engine.changes.count(change) == 1 for change in engine.changes))
                        self.assertEqual(engine.trace.count(("USR1", "sample-0")),
                                         int(action == "start" and cut != "change"))
                    finally:
                        fixture.doCleanups()

    def test_new_container_stays_with_upgrade_owner(self):
        self.engine.rows["sample-0"]["status"] = "created"
        self.assertEqual(self.start()["gateReason"], "FIRST_START_REQUIRES_UPGRADE_OWNER")
        self.assertEqual(self.engine.trace, [])

    def test_retry_of_same_level_peer_preserves_gate_deadline(self):
        first, second, last = self.ctrl.cfg["levels"]
        first["containers"] += second["containers"]
        self.ctrl.cfg["levels"] = [first, last]
        self.http.side_effect = lambda *args: False
        inspect = self.engine.inspect
        def transient(cid, deadline):
            if cid == self.engine.rows["sample-1"]["cid"] and self.clock.now == 0:
                self.clock.sleep(0.75)
                raise Held("DOCKER_COMMAND_FAILED")
            return inspect(cid, deadline)
        with patch.object(self.engine, "inspect", side_effect=transient), contextlib.redirect_stderr(io.StringIO()):
            result = self.ctrl.run("boot", "start", boot_id=str(uuid.uuid4()))
        self.assertEqual((result["reason"], result["container"], self.clock.now), ("READINESS_NOT_UP", "sample-0", 2))
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertNotIn(("start", "sample-2"), self.engine.changes)

    def test_signal_with_lost_reply_and_unowned_shell_are_never_replayed(self):
        send = self.engine.command
        def lost(*args, deadline):
            if args[0] == "kill":
                self.engine.trace.append(("USR1", "sample-0"))
                raise Held("DOCKER_TIMEOUT")
            return send(*args, deadline=deadline)
        with patch.object(self.engine, "command", side_effect=lost), contextlib.redirect_stderr(io.StringIO()):
            result = self.ctrl.run("boot", "start", boot_id=str(uuid.uuid4()))
        self.assertEqual(result["gateReason"], "SIGNAL_UNCONFIRMED")
        self.assertEqual(self.start()["gateReason"], "GATE_START_NOT_OWNED")
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), 1)
        self.assertEqual(self.engine.changes, [("start", "sample-0")])

    def test_http_up_cannot_cover_a_restarted_pid1(self):
        def replaced(*args):
            self.engine.rows["sample-0"]["startedAt"] = "replacement"
            return True
        self.http.side_effect = replaced
        self.assertEqual(self.start()["gateReason"], "GENERATION_CHANGED")
        self.assertEqual(self.engine.changes, [("start", "sample-0")])

    def test_pid1_exact_argv_executable_and_installed_handler(self):
        gate = gated_member()["gate"]
        def argv(args):
            return b"\0".join(arg.encode() for arg in args) + b"\0"
        with (patch("pathlib.Path.read_bytes") as cmd, patch("pathlib.Path.read_text") as status,
              patch("pathlib.Path.readlink") as exe, patch("signal.SIGUSR1", 10, create=True)):
            cmd.return_value = argv(gate["entrypoint"] + gate["command"])
            status.return_value = "NSpid:\t4321\t1\nSigCgt:\t0\n"
            self.assertEqual(pid1_state(4321, gate), "arming")
            status.return_value = status.return_value.replace("SigCgt:\t0", "SigCgt:\t200")
            self.assertEqual(pid1_state(4321, gate), "armed")
            cmd.return_value = argv(gate["command"])
            exe.return_value = Path("/example/java")
            self.assertEqual(pid1_state(4321, gate), "application")
            exe.return_value = Path("/example/other")
            with self.assertRaisesRegex(Held, "GATE_HELD"):
                pid1_state(4321, gate)
            cmd.return_value = argv(gate["entrypoint"] + gate["command"] + ["unexpected"])
            with self.assertRaisesRegex(Held, "GATE_HELD"):
                pid1_state(4321, gate)

    def test_http_requires_bounded_json_and_top_level_up(self):
        probe = gated_member()["readiness"]
        with patch("http.client.HTTPConnection") as connect:
            connection = connect.return_value
            response = connection.getresponse.return_value
            for status, body, expected in [(200, b'{"status":"UP"}', True), (204, b"", False),
                                           (503, b'{"status":"UP"}', False), (302, b"", False),
                                           (200, b'{"status":"DOWN"}', False), (200, b"UP", False),
                                           (200, b'{"child":{"status":"UP"}}', False),
                                           (200, b'{"status":"UP","status":"DOWN"}', False),
                                           (200, b" " * 65537, False)]:
                response.status = status
                response.read.return_value = body
                self.assertEqual(http_ready(probe), expected)
            connect.assert_called_with(probe["address"], probe["port"], timeout=probe["timeoutSeconds"])
            connection.request.assert_called_with("GET", probe["path"])

    def test_http_accepts_each_declared_code_and_json_value(self):
        probe = dict(gated_member()["readiness"], acceptStatus=[200, 202], jsonStatus="READY")
        with patch("http.client.HTTPConnection") as connect:
            response = connect.return_value.getresponse.return_value
            response.read.return_value = b'{"status":"READY"}'
            for code in probe["acceptStatus"]:
                response.status = code
                self.assertTrue(http_ready(probe))
            response.read.return_value = b'{"status":"UP"}'
            self.assertFalse(http_ready(probe))

    def test_only_fixed_docker_signal_with_one_full_id(self):
        docker = Docker(configuration())
        cid = "c" * 64
        with patch.object(docker, "verify"), patch("subprocess.check_output") as run:
            for args in [("inspect",), ("ps",), ("start", cid), ("stop", cid), ("kill", "--signal=USR1", cid)]:
                docker.command(*args)
            self.assertEqual(run.call_count, 5)
            for args in [(), ("exec", cid), ("restart", cid), ("run",), ("network", "inspect"), ("kill", cid),
                         ("kill", "--signal=TERM", cid), ("kill", "--signal=USR1", "sample"),
                         ("kill", "--signal=USR1", cid, cid), ("kill", "--signal=USR1", cid[:12])]:
                with self.assertRaisesRegex(Held, "COMMAND_DENIED"):
                    docker.command(*args)
            self.assertEqual(run.call_count, 5)

    def test_profile_denies_weaker_probes_or_mutable_image(self):
        for key, field, value in [("gate", "imageId", "sample:latest"), ("gate", "command", []),
                                  ("gate", "entrypoint", ["/example/sh", "-c", "exit", "ouf-gated-application"]),
                                  ("readiness", "type", "healthy"), ("readiness", "budgetSeconds", 5),
                                  ("readiness", "path", "//other"), ("readiness", "address", "192.0.2.1")]:
            cfg = configuration()
            member = gated_member()
            member[key][field] = value
            cfg["levels"][0]["containers"] = [member]
            raw = canonical(cfg)
            with self.assertRaises(Held):
                load_profile(raw, sha(raw))


def store_json(path, value):
    path.write_bytes(canonical(value))


def signing_fixture(root):
    openssl = Path(shutil.which("openssl")).resolve()
    private, public = root / "fixture-key", root / "public.der"
    subprocess.run([openssl, "genpkey", "-algorithm", "Ed25519", "-out", private], check=True)
    subprocess.run([openssl, "pkey", "-in", private, "-pubout", "-outform", "DER", "-out", public], check=True)
    return dict(publicKey=dict(path=str(public), sha256=sha(public.read_bytes())),
                openssl=dict(path=str(openssl), sha256=sha(openssl.read_bytes())))


def sign(path, binding, private):
    subprocess.run([binding["openssl"]["path"], "pkeyutl", "-rawin", "-sign", "-inkey", private,
                    "-in", path, "-out", path.with_suffix(".ed25519")], check=True)


class ReleaseJournal:
    """Private emitter of producer-format terminal fixtures, also used against a real Engine."""
    def __init__(self, root, old, new, socket_path, create_request, *, candidate=None, signing=True, ready=True):
        root.mkdir()
        self.root = root
        self.state = root / "state"
        self.state.mkdir()
        run = self.state / "1"
        run.mkdir()
        journal = root / "journal"
        journal.mkdir()
        (root / "lock").touch()
        self.binding = dict(source="module-release", module="example", executorRoot=str(root), journalRoot=str(journal))
        profile = dict(container=old["Name"][1:], dockerSocket=socket_path, journal=str(journal))
        if candidate:
            profile["candidate"] = candidate
        if signing:
            signer = self.binding["receiptSigning"] = signing_fixture(root)
            profile["receiptSigning"] = dict(publicKey=signer["publicKey"], privateKey=str(root / "fixture-key"))
        store_json(root / "profile.json", {"modules": {"example": profile}})
        plan = dict(module="example", operation="module-release", oldCid=old["Id"], oldImage=old["Image"],
                    oldFrameSha256=identity.snapshot(old), ci=dict(imageId=create_request["Image"]),
                    requestSha256=identity.digest(create_request))
        if candidate:
            plan["candidateReview"] = dict(predecessorCmdSha256=identity.digest(old["Config"]["Cmd"]),
                                           candidateCmdSha256=identity.digest(create_request["Cmd"]))
        self.source = identity.digest(plan)
        self.tx = journal / self.source
        self.tx.mkdir()
        self.old, self.new = old, new
        store_json(self.tx / "create-intent.json", dict(requestSha256=plan["requestSha256"]))
        store_json(self.tx / "created.json", dict(cid=new["Id"]))
        store_json(self.tx / "plan.json", plan)
        store_json(self.tx / "baseline.private.json", {k: old[k] for k in
                   ("Id", "Name", "State", "NetworkSettings", "RestartCount")})
        store_json(run / "approvals", ["apply"])
        store_json(run / "plan", dict(plan=plan, planSha256=self.source))
        store_json(run / "apply.review", self.review("apply", run.name))
        if ready:
            self.publish_ready(new)

    def publish_ready(self, new):
        run = self.state / "1"
        terminal = dict(operation="module-release", readiness="UP", status="READY", planSha256=self.source,
                        successorCid=new["Id"], predecessorCid=self.old["Id"], successorFrameSha256=identity.snapshot(new))
        store_json(self.tx / "receipt.json", terminal)
        store_json(run / "apply.result", terminal)
        store_json(self.state / "module-example.ready", dict(run=run.name, phase="apply", planSha256=self.source))
        if "receiptSigning" in self.binding:
            self.sign("receipt.json")

    def review(self, phase, run):
        return dict(review="c" * 64, request=dict(module="example", operation="module-release", phase=phase,
                                                  run=run, digest=self.source))

    def sign(self, name):
        sign(self.tx / name, self.binding["receiptSigning"], self.root / "fixture-key")

    def returned(self, *, restored=None, signed=False, interrupted=False):
        if interrupted:
            (self.tx / "receipt.json").unlink()
            (self.tx / "receipt.ed25519").unlink(missing_ok=True)
            (self.state / "module-example.ready").unlink()
            store_json(self.state / "1/apply.result", dict(status="GATED", planSha256=self.source))
        run = self.state / "2"
        run.mkdir()
        store_json(run / "approvals", ["rollback"])
        store_json(run / "rollback.review", self.review("rollback", run.name))
        doc = dict(status="ROLLED_BACK", predecessorReadiness="UP", restoredCid=restored or self.old["Id"],
                   planSha256=self.source, predecessorReadyHttp=200)
        store_json(self.tx / "return-intent.json", dict(cid=self.new["Id"], planSha256=self.source))
        store_json(self.tx / "return-receipt.json", doc)
        store_json(run / "rollback.result", doc)
        if signed:
            self.sign("return-receipt.json")


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        base = GatedRestartTests()
        self.addCleanup(base.doCleanups)
        base.setUp()
        self.ctrl, self.engine = base.ctrl, base.engine
        self.engine.cfg = self.ctrl.cfg
        self.member = self.ctrl.members["sample-0"]
        gate = self.member["gate"]
        entry = release_frame.ENTRY
        self.engine.config["entrypoint"] = entry
        old_cmd = gate["command"] + ["--spring.flyway.enabled=false"]
        self.old = dict(Id="a" * 64, Name="/sample-0", Image="sha256:" + "1" * 64, Path=entry[0],
                        Args=entry[1:] + old_cmd, Config=dict(Entrypoint=entry, Cmd=old_cmd),
                        HostConfig={}, Mounts=[], NetworkSettings={"Networks": {}}, RestartCount=0,
                        State=dict(Pid=20, StartedAt="baseline", Running=True))
        defaults = dict(Entrypoint=["/fixture"], Labels={"ouf.fixture": "gate"}, Env=["HTTP_READY=yes"])
        self.engine.image_defaults = lambda image: defaults
        candidate = dict(removeArgs=["--spring.flyway.enabled=false"])
        create_request = release_frame.request(self.old, gate["imageId"], candidate=candidate, image_defaults=defaults)
        config = copy.deepcopy(create_request)
        host = config.pop("HostConfig")
        config.pop("NetworkingConfig")
        release_frame.merge_image(config, defaults)
        self.new = dict(self.old, Id=self.engine.rows["sample-0"]["cid"], Image=config["Image"], Config=config,
                        Path=config["Entrypoint"][0], Args=config["Entrypoint"][1:] + config["Cmd"], HostConfig=host)
        self.live = self.new
        self.journal = ReleaseJournal(Path(self.ctrl.cfg["receipts"]).parent / "executor", self.old, self.new,
                                      self.ctrl.cfg["dockerSocket"], create_request, candidate=candidate)
        self.member["gate"] = dict(identity=self.journal.binding, entrypoint=entry)
        self.enterContext(patch.object(identity, "custody"))
        self.enterContext(patch.object(identity, "release_locks", return_value=contextlib.nullcontext()))
        self.engine.release_frame = lambda cid: copy.deepcopy(self.live if cid == self.live["Id"] else self.old)
        self.engine.release_launch = self.engine.release_frame

    def start(self):
        planned = self.ctrl.run("plan", "start")
        return self.ctrl.run("apply", "start", planned["planSha256"])

    def returned(self, **kwargs):
        self.journal.returned(**kwargs)
        self.live = self.old
        self.engine.rows["sample-0"]["cid"] = self.old["Id"]
        self.engine.config["command"] = self.old["Config"]["Cmd"]
        self.engine.config["imageId"] = self.old["Image"]

    def test_semantic_completed_forward_and_pending_successor(self):
        root, state = self.journal.root, self.journal.state
        self.member["gate"]["identity"] = dict(source="semantic-a2", executorRoot=str(root))
        store_json(root / "profile.json", dict(socket=self.ctrl.cfg["dockerSocket"],
                                               originalProfile=dict(containerName="sample-0")))
        run = state / "10"
        run.mkdir()
        old, live = self.old, self.new
        target = dict(containerName="sample-0", image=live["Image"])
        plan = dict(old=old["Id"], request=live["Config"], head=28, sequence=29, target=target)
        parent = identity.digest(plan)
        pointers = {"forward": dict(run=run.name, plan=parent), "forward-stage": dict(run=run.name)}
        claim = dict(request=identity.digest(plan["request"]), parent=parent)
        result = dict(worker="on", readiness="UP", ingress="VERIFIED", probe="C_PROBE_PASSED")
        archive = dict(pointers=pointers, result=identity.digest(result), head=29)
        for key, value in {"plan": plan, "stage": dict(parent=parent, profile=target, cid=live["Id"]),
                           "create.claim": claim, "create.receipt": dict(planSha256=identity.digest(claim),
                                                                       result=live["Id"]),
                           "result": result, "closed-forward": archive}.items():
            store_json(run / key, value)
        store_json(state / "completed-forward", dict(run=run.name, archive=identity.digest(archive)))
        self.assertEqual(self.start()["status"], "SUCCEEDED")
        signals = self.engine.trace.count(("USR1", "sample-0"))
        pending = state / "11"
        pending.mkdir()
        store_json(pending / "approvals", ["apply"])
        store_json(pending / "plan.review", dict(request=dict(direction="forward", release="next")))
        store_json(pending / "plan", dict(head=29, sequence=30))
        self.assertEqual(self.start()["reason"], "RELEASE_TRANSACTION_OPEN")
        store_json(state / "forward-stage", {"run": pending.name})
        self.assertEqual(self.start()["reason"], "RELEASE_TRANSACTION_OPEN")
        self.assertEqual(self.engine.trace.count(("USR1", "sample-0")), signals)

    def test_new_approval_without_terminal_blocks_prior_return(self):
        self.returned()
        pending = self.journal.state / "3"
        pending.mkdir()
        store_json(pending / "plan.review", self.journal.review("plan", pending.name))
        store_json(pending / "approvals", ["apply"])
        self.assertEqual(self.start()["reason"], "RELEASE_TRANSACTION_OPEN")
        self.assertEqual(self.engine.trace, [])

    def test_dynamic_and_static_profile_contract(self):
        cfg = configuration()
        member = cfg["levels"][0]["containers"][0] = gated_member()
        for gate in (dict(member["gate"]), dict(entrypoint=member["gate"]["entrypoint"],
                     identity=dict(source="module-release", executorRoot="/example/executor",
                                   journalRoot="/example/journal", module="example")),
                     dict(entrypoint=member["gate"]["entrypoint"],
                          identity=dict(source="semantic-a2", executorRoot="/example/executor"))):
            member["gate"] = gate
            raw = canonical(cfg)
            self.assertEqual(load_profile(raw, sha(raw)), cfg)
        member["gate"].update(command=["java"], imageId="sha256:" + "a" * 64)
        raw = canonical(cfg)
        with self.assertRaises(Held):
            load_profile(raw, sha(raw))

    def test_signed_ready_and_candidate_command(self):
        result = self.start()
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertEqual(result["plan"]["steps"][0]["release"]["readySignature"], "verified")

    def test_ready_requires_approved_create_with_image_defaults(self):
        config = self.live["Config"]
        self.assertEqual(config["Entrypoint"], release_frame.ENTRY)
        self.assertEqual(config["Cmd"], self.old["Config"]["Cmd"][:-1])
        self.assertEqual(config["Labels"], {"ouf.fixture": "gate"})
        self.assertEqual(config["Env"], ["HTTP_READY=yes"])
        plan = self.ctrl.run("plan", "start")
        self.assertEqual(plan["status"], "PLAN_READY", plan)

        # The live launch and its command review still match. This change in
        # the release profile would build a different CREATE (including Env).
        path = self.journal.root / "profile.json"
        policy = json.loads(path.read_bytes())
        policy["modules"]["example"]["candidate"]["enableFlyway"] = True
        store_json(path, policy)
        result = self.ctrl.run("apply", "start", plan["planSha256"])
        self.assertEqual((result["status"], result.get("reason")), ("HELD", "MODULE_CREATE_DRIFT"))
        self.assertEqual(self.engine.trace, [])

    def test_ready_rejects_gate_split_across_entrypoint_and_cmd(self):
        self.live = copy.deepcopy(self.new)
        cfg = self.live["Config"]
        entry = cfg["Entrypoint"]
        cfg["Entrypoint"], cfg["Cmd"] = entry[:1], entry[1:] + cfg["Cmd"]
        self.assertEqual([self.live["Path"], *self.live["Args"]], cfg["Entrypoint"] + cfg["Cmd"])
        self.assertEqual(self.start()["reason"], "RELEASE_ENTRYPOINT_MISMATCH")
        self.assertEqual(self.engine.trace, [])

    def test_unsigned_ready_held(self):
        (self.journal.tx / "receipt.ed25519").unlink()
        self.assertEqual(self.start()["reason"], "MODULE_RECEIPT_SIGNATURE_REQUIRED")
        self.assertEqual(self.engine.changes, [])

    def test_signed_return(self):
        self.returned(signed=True)
        result = self.start()
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertEqual(result["plan"]["steps"][0]["release"]["returnSignature"], "verified")

    def test_replay_and_legacy_probe_failure_preserve_terminal_return(self):
        self.returned(signed=True)
        journal = self.journal
        replay = journal.state / "3"
        replay.mkdir()
        store_json(replay / "approvals", ["rollback"])
        review = journal.review("rollback", replay.name)
        for signed in (True, False):
            if not signed:
                (journal.tx / "return-receipt.ed25519").unlink()
            for reason in (None, "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE", "RETURN_READINESS_CHANGED"):
                with self.subTest(signed=signed, reason=reason):
                    if reason is None:
                        (replay / "rollback.result").unlink(missing_ok=True)
                    else:
                        store_json(replay / "rollback.result", dict(status="HELD", planSha256=journal.source,
                                                                    reason=reason))
                    entry = review if reason == "RETURN_READINESS_CHANGED" else dict(review, returnAlreadyConsumed=True)
                    store_json(replay / "rollback.review", entry)
                    _, terminal = identity.module_history(journal.state, journal.tx.parent, "example")
                    self.assertEqual(terminal, journal.tx / "return-receipt.json")
                    plan = self.ctrl.run("plan", "start")
                    self.assertEqual(plan["status"], "PLAN_READY", plan)
                    signature = plan["plan"]["steps"][0]["release"]["returnSignature"]
                    self.assertEqual(signature, "verified" if signed else "absent")
        # A purported completion must still agree with the module's receipt.
        store_json(replay / "rollback.result", dict(status="ROLLED_BACK", planSha256=journal.source))
        self.assertEqual(self.start()["reason"], "MODULE_RETURN_DRIFT")

    def test_replay_marker_cannot_authorize_the_original_return(self):
        self.returned()
        review = self.journal.review("rollback", "2")
        store_json(self.journal.state / "2/rollback.review", dict(review, returnAlreadyConsumed=True))
        self.assertEqual(self.start()["reason"], "MODULE_RETURN_DRIFT")
        self.assertEqual(self.engine.trace, [])

    def test_compensation_with_later_held_uses_signed_receipt_and_baseline(self):
        self.returned(interrupted=True)
        journal = self.journal
        returned = json.loads((journal.tx / "return-receipt.json").read_bytes())
        compensation = dict(returned, status="HELD", rollback="ROLLED_BACK", operation="module-release",
                            predecessorCid=self.old["Id"], successorCid=self.new["Id"])
        (journal.tx / "return-receipt.json").unlink()
        (journal.tx / "return-intent.json").unlink()
        store_json(journal.tx / "rollback-intent.json", {"cid": self.old["Id"]})
        store_json(journal.tx / "receipt.json", compensation)
        store_json(journal.state / "1/apply.result", compensation)
        journal.sign("receipt.json")
        store_json(journal.state / "2/rollback.result", dict(status="HELD", planSha256=journal.source,
                                                             reason="RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE"))
        result = self.start()
        self.assertEqual(result["status"], "SUCCEEDED", result)
        info = result["plan"]["steps"][0]["release"]
        self.assertEqual((info["terminal"], info["returnSignature"], info["cid"]),
                         ("receipt.json", "verified", self.old["Id"]))
        (journal.tx / "receipt.ed25519").unlink()
        self.assertEqual(self.start()["reason"], "MODULE_RECEIPT_SIGNATURE_REQUIRED")

    def test_altered_signed_return_held(self):
        self.returned(signed=True)
        with (self.journal.tx / "return-receipt.json").open("ab") as stream:
            stream.write(b"\n")
        self.assertEqual(self.start()["reason"], "MODULE_RECEIPT_SIGNATURE_INVALID")
        self.assertEqual(self.engine.trace, [])

    def test_unsigned_interrupted_return_starts(self):
        self.returned(interrupted=True)
        result = self.start()
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertEqual(result["plan"]["steps"][0]["release"]["returnSignature"], "absent")
        self.assertIn(("USR1", "sample-0"), self.engine.trace)

    def test_unsigned_return_wrong_restored_cid(self):
        self.returned(restored="e" * 64)
        self.assertEqual(self.start()["reason"], "MODULE_RETURN_DRIFT")
        self.assertEqual(self.engine.trace, [])

    def test_unsigned_return_changed_command(self):
        self.returned()
        self.live = copy.deepcopy(self.old)
        self.live["Config"]["Cmd"].append("different")
        self.assertEqual(self.start()["reason"], "MODULE_BASELINE_DRIFT")
        self.assertEqual(self.engine.trace, [])

    def test_created_with_open_transaction_never_started_or_signalled(self):
        planned = self.ctrl.run("plan", "start")
        self.engine.rows["sample-0"]["status"] = "created"
        (self.journal.tx / "return-intent.json").touch()
        with contextlib.redirect_stderr(io.StringIO()):
            for mode in ("plan", "apply", "boot"):
                result = self.ctrl.run(mode, "start", planned["planSha256"], str(uuid.uuid4()))
                self.assertEqual(result["reason"], "RELEASE_TRANSACTION_OPEN", result)
                info = result["plan"]["steps"][0]["release"]
                self.assertEqual((info["owner"], info["residual"]), ("example", "return-receipt.json"))
                self.assertEqual(result["events"], [])
        self.assertEqual(self.engine.trace, [])

    def test_pending_head_holds_start_and_stop(self):
        store_json(self.journal.state / "module-example.ready", dict(status="PENDING"))
        for action in ("start", "stop"):
            report = self.ctrl.run("plan", action)
            self.assertEqual(report["reason"], "RELEASE_TRANSACTION_OPEN")
            info = next(s["release"] for s in report["plan"]["steps"] if "release" in s)
            self.assertEqual(info["residual"], "module-example.ready")
        self.assertEqual(self.engine.changes, [])

    def test_later_apply_claim_cannot_reuse_terminal_source(self):
        self.returned()
        run = self.journal.state / "3"
        run.mkdir()
        (run / "plan").write_bytes((self.journal.state / "1/plan").read_bytes())
        store_json(run / "approvals", ["apply"])
        store_json(run / "apply.review", self.journal.review("apply", run.name))
        self.assertEqual(self.start()["reason"], "RELEASE_TRANSACTION_OPEN")
        self.assertEqual(self.engine.trace, [])

    def test_open_module_lock_overrides_signed_terminal(self):
        (self.journal.tx.parent / "example.lock").mkdir()
        self.assertEqual(self.start()["reason"], "RELEASE_TRANSACTION_OPEN")
        self.assertEqual(self.engine.trace, [])

    def test_b7_producer_journal_equivalence(self):
        # Exercise the same governed dispatch and B7 reader used by task-24.
        import test_module_release as b7
        producer = b7.ReleaseTest()
        self.addCleanup(producer.doCleanups)
        producer.setUp()
        import module_operation
        import module_receipt
        signer = self.journal.binding["receiptSigning"]
        producer.p["receiptSigning"] = dict(publicKey=signer["publicKey"],
                                             privateKey=str(self.journal.root / "fixture-key"))
        call, req = producer.governed_dispatch()
        self.enterContext(patch.object(module_receipt, "OPENSSL", signer["openssl"]["path"]))
        self.enterContext(patch.object(module_receipt, "trusted", side_effect=lambda p, **_: Path(p)))
        req["digest"] = call(0)["digest"]
        req["phase"] = "apply"
        req["digest"] = call(1)["digest"]
        req["phase"] = "migrate"
        self.assertEqual(call(2)["status"], "READY")
        adapter = module_operation.ModuleRelease({"modules": {"onboarding": producer.p}}, producer.root, req)
        tip = adapter.previous_release()
        plan, path = identity.module_history(producer.root, producer.root, "onboarding")
        record = identity.read(path)
        identity.ready_head(producer.root, "onboarding", path.parent.name, plan, record)
        identity.verify_signature(signer, path, False, {})
        self.assertEqual((tip["planSha256"], tip["successorCid"], tip["imageId"]),
                         (path.parent.name, record["successorCid"], plan["ci"]["imageId"]))
        review_file = producer.root / "1" / "migrate.review"
        review = identity.read(review_file)
        review["request"]["digest"] = "0" * 64
        store_json(review_file, review)
        with self.assertRaisesRegex(Exception, "MODULE_APPROVAL_DRIFT"):
            adapter.previous_release()
        with self.assertRaisesRegex(Held, "MODULE_APPROVAL_DRIFT"):
            identity.ready_head(producer.root, "onboarding", path.parent.name, plan, record)


if __name__ == "__main__":
    unittest.main()
