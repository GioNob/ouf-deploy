import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import uuid

from tools.platform_restart.controller import Controller, http_ready
from tools.platform_restart.docker import Docker, GATE_INSPECT, pid1_state
from tools.platform_restart import install
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


if __name__ == "__main__":
    unittest.main()
