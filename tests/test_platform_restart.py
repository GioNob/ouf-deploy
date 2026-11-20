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

from tools.platform_restart.controller import Controller
from tools.platform_restart.docker import Docker
from tools.platform_restart import install
from tools.platform_restart.profile import Held, canonical, load_profile, sha


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


if __name__ == "__main__":
    unittest.main()
