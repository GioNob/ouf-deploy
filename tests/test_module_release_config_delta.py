"""Fail-closed release profiles and the isolated 58q library."""
from contextlib import ExitStack, chdir, redirect_stderr, redirect_stdout
from functools import partial
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, mock_open, patch

import test_module_release as fixture
from test_module_install import setup_profile
import test_privileged_executor_install as installer_fixture
import module_operation
from tools.module_release import frame_spec, install_contract, install_operation as install, retention
import mandate
import store
from tools.module_release import config_delta, operation, recovery, return_operation, transport
from tools.module_release.contract import Held, validate


def executor_with_busy_lock(root, policy_module, profile, *, denied=False, operation_name="module-release", phase="plan",
                            locked_profile=None, raw_request=None, installation_fd=None):
    """Run the CLI and capture its public output with the operation lock occupied."""
    script = str(root / "scripts/ouf-a2-executor")
    req = dict(operation=operation_name, module="mcp", phase=phase, run="1", attempt="1", commit="a" * 40)
    req["digest"] = policy_module.intent(req)
    cfg = {"commit": req["commit"], "modules": {"mcp": profile}}
    envelope = json.dumps({"request": req, "token": "fixture"}).encode() if raw_request is None else raw_request
    locks = Mock(LOCK_SH=1, LOCK_EX=2, LOCK_NB=4)
    locks.flock.side_effect = [None, BlockingIOError()]
    if installation_fd is not None:
        import fcntl
        locks = Mock(wraps=fcntl, LOCK_SH=fcntl.LOCK_SH, LOCK_EX=fcntl.LOCK_EX, LOCK_NB=fcntl.LOCK_NB)
    fd = 17 if installation_fd is None else installation_fd
    trusted_lock = Mock(open=mock_open())
    out, err = io.StringIO(), io.StringIO()
    flags = SimpleNamespace(**{k: getattr(sys.flags, k) for k in dir(sys.flags) if not k.startswith("_")})
    flags.isolated = 1
    run_path = runpy.run_path
    installed = Path("/opt/ouf-a2")
    read_bytes = Path.read_bytes
    lstat = Path.lstat

    def stat_file(path):
        if path == installed / "profile.json":
            return SimpleNamespace(st_mode=0o100600, st_uid=0)
        return lstat(path)

    def read_file(path):
        return json.dumps(cfg).encode() if path == installed / "profile.json" else read_bytes(path)

    def run_file(path, **kwargs):
        if Path(path) == installed / "lib/module_release/profile_options.py":
            path = root / "tools/module_release/profile_options.py"
        return run_path(str(path), **kwargs)

    with ExitStack() as stack:
        enter = stack.enter_context
        enter(patch.dict(sys.modules, {"fcntl": locks, "mandate": policy_module}))
        enter(patch.object(sys, "argv", [script]))
        enter(patch.object(sys, "flags", flags))
        enter(patch.object(Path, "lstat", stat_file))
        enter(patch.object(Path, "read_bytes", read_file))
        enter(patch.object(runpy, "run_path", run_file))
        enter(patch.object(sys, "path", list(sys.path)))
        enter(patch.object(sys, "dont_write_bytecode", True))
        enter(patch.object(sys, "stdin", Mock(buffer=io.BytesIO(envelope))))
        enter(patch.object(os, "geteuid", return_value=0, create=True))
        enter(patch.object(os, "O_DIRECTORY", 0, create=True))
        open_lock = enter(patch.object(os, "open", return_value=fd))
        enter(patch.object(os, "environ", {}))
        enter(patch.object(os, "chdir"))
        enter(patch.object(os, "umask"))
        locked = cfg if locked_profile is None else {**cfg, "modules": {"mcp": locked_profile}}
        enter(patch.object(store, "read", return_value=locked))
        trusted = enter(patch.object(store, "trusted", return_value=trusted_lock))
        github = enter(patch.object(policy_module, "github_reader"))
        mkdir = enter(patch.object(os, "mkdir"))
        enter(redirect_stdout(out))
        enter(redirect_stderr(err))
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as error:
            status = error.code
            if isinstance(status, str):
                print(status, file=sys.stderr)
                status = 1
        else:
            status = 0
    github.assert_not_called()
    mkdir.assert_not_called()
    if denied:
        trusted.assert_not_called()
        open_lock.assert_not_called()
        locks.flock.assert_not_called()
    else:
        assert locks.flock.call_args_list[0] == call(fd, locks.LOCK_SH | locks.LOCK_NB)
    return (status, out.getvalue(), err.getvalue()), trusted.call_count, sum(
        args[1] == locks.LOCK_EX | locks.LOCK_NB for args, _ in locks.flock.call_args_list)


class DisabledDeltaTest(unittest.TestCase):
    code = "CONFIG_DELTA_NOT_ENABLED"
    marker = "synthetic-58li-private-value"

    def test_DEP_58LI_01_presence_precedes_profile_validation(self):
        for delta in (None, {}, [], "", False, 0, self.marker):
            with self.subTest(delta_type=type(delta).__name__):
                with self.assertRaises(Held) as denied:
                    validate({"configDelta": delta})
                self.assertEqual(str(denied.exception), self.code)

    def test_DEP_58LI_02_plan_and_recovery_do_not_observe_or_publish(self):
        name = "AZURE_STORAGE_CONNECTION_STRING"
        value = "AccountName=fixture;AccountKey=" + self.marker
        changes = [{"env": [{"name": name, "before": None, "after": None, side: value}]}
                   for side in ("before", "after")]
        changes += [{"env": [{"name": "LISTEN_ADDRESS", "before": None, "after": "[::1]:8080"}]},
                    {"binds": [{"source": self.marker, "mode": "ro"}]}]
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        profile = json.loads(fixture.PROFILE.read_bytes())
        profile.update(journal=str(root), envAllowlist=[name, "LISTEN_ADDRESS"], showValues=[name])
        rt = Mock()
        package = self.enterContext(patch.object(operation, "package"))
        for delta in changes:
            profile["configDelta"] = delta
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err), self.assertNoLogs(level="DEBUG"):
                result = operation.plan(profile, rt)
                applied = operation.apply(profile, "a" * 64, rt)
                with self.assertRaises(Held) as denied:
                    recovery.proposal(profile, rt)
            self.assertEqual(result, {"status": "HELD", "reason": self.code, "rollback": "UNVERIFIED"})
            self.assertEqual((applied["status"], applied["reason"]), ("HELD", self.code))
            self.assertNotIn(self.marker, json.dumps(applied))
            self.assertEqual(str(denied.exception), self.code)
            self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
            self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(rt.mock_calls, [])
        package.assert_not_called()

    def test_DEP_58LI_03_executor_denies_before_authorization_journal(self):
        executor = runpy.run_path(str(fixture.ROOT / "scripts/ouf-a2-executor"))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        profile = {"configDelta": self.marker, "journal": str(root), "migration": {"database": {}}, "install": {}}
        cfg = {"modules": {"mcp": profile}, "commit": "a" * 40}
        get = Mock()
        for kind, phases in (("module-release", ("plan", "apply", "migrate", "rollback")),
                             ("module-install", ("plan", "apply", "rollback"))):
            for phase in phases:
                with self.subTest(operation=kind, phase=phase):
                    req = dict(operation=kind, module="mcp", phase=phase, run="1", attempt="1", commit=cfg["commit"])
                    if kind == "module-install":
                        req["schema"] = "ouf.module-install.v1"
                    req["digest"] = mandate.intent(req)
                    out, err = io.StringIO(), io.StringIO()
                    with redirect_stdout(out), redirect_stderr(err), self.assertRaises(mandate.Held) as denied:
                        executor["dispatch"](req, cfg, root, get)
                    self.assertEqual(executor["public_error"](denied.exception), self.code)
                    self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                    self.assertEqual(list(root.iterdir()), [])
        get.assert_not_called()

    def test_DEP_58LJ_01_executor_denies_before_busy_operation_lock(self):
        profile = json.loads(fixture.PROFILE.with_name("mcp.example.json").read_bytes())
        profile["configDelta"] = self.marker
        output, opens, locks = executor_with_busy_lock(fixture.ROOT, mandate, profile, denied=True)
        self.assertEqual(output, (1, "", self.code + "\n"))
        self.assertEqual((opens, locks), (0, 0))

    def test_DEP_58LJ_02_direct_return_denies_before_lock_directory(self):
        profile = json.loads(fixture.PROFILE.with_name("mcp.example.json").read_bytes())
        profile["configDelta"] = self.marker
        rt = Mock()
        with patch.object(os, "mkdir", side_effect=FileExistsError) as mkdir:
            for recover in (False, True):
                with self.subTest(recover=recover), self.assertRaisesRegex(Held, "^" + self.code + "$"):
                    return_operation.run(profile, "a" * 64, rt, recover=recover)
        mkdir.assert_not_called()
        self.assertEqual(rt.mock_calls, [])

    def test_DEP_58LJ_03_transport_denies_before_github_or_mkdir(self):
        profile = json.loads(fixture.PROFILE.with_name("semantic-successor.example.json").read_bytes())
        profile["configDelta"] = self.marker
        with patch.object(transport, "github") as github, patch.object(os, "mkdir") as mkdir:
            with self.assertRaisesRegex(Held, "^" + self.code + "$"):
                transport.transport(profile, 15, 17, fixture.PROFILE.parent)
        github.assert_not_called()
        mkdir.assert_not_called()

    def test_DEP_58LL_01_build_create_denies_before_rendering(self):
        profile = setup_profile(str(fixture.ROOT))
        with patch.object(frame_spec, "create_with_custody") as render:
            for delta in (None, self.marker):
                with self.subTest(delta=delta), self.assertRaises(frame_spec.SpecHeld) as held:
                    frame_spec.build_create(dict(profile, configDelta=delta), {}, "0" * 64)
                self.assertEqual(str(held.exception), self.code)
            render.assert_not_called()

    def test_DEP_58LL_02_transport_dangling_module_is_usage_only(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        profile = root / "profilo.json"
        raw = json.dumps({"configDelta": self.marker}).encode()
        profile.write_bytes(raw)
        out, err = io.StringIO(), io.StringIO()
        locking = Mock()
        with chdir(root), redirect_stdout(out), redirect_stderr(err), ExitStack() as stack:
            github = stack.enter_context(patch.object(transport, "github"))
            mkdir = stack.enter_context(patch.object(os, "mkdir"))
            open_fd = stack.enter_context(patch.object(os, "open"))
            open_file = stack.enter_context(patch.object(Path, "open"))
            stack.enter_context(patch.dict(sys.modules, fcntl=locking))
            with self.assertRaises(SystemExit) as usage:
                transport.main([profile.name, "1", "2", ".", "--module"])
        self.assertEqual(usage.exception.code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("usage:", err.getvalue())
        self.assertIn("argument --module: expected one argument", err.getvalue())
        self.assertNotIn(self.marker, err.getvalue())
        for effect in (github, mkdir, open_fd, open_file, locking):
            self.assertEqual(effect.mock_calls, [])
        self.assertEqual(list(root.iterdir()), [profile])
        self.assertEqual(profile.read_bytes(), raw)

    def test_DEP_58LM_05_transport_retries_unreadable_profile_after_parsing(self):
        argv = ["profile.json", "1", "2", "."]
        for first_read in (OSError("unavailable"), "{"):
            with self.subTest(first_read=first_read), patch.object(Path, "read_text", side_effect=[
                    first_read, json.dumps({"configDelta": self.marker})]), patch.object(transport, "transport") as send:
                with self.assertRaises(SystemExit) as denied:
                    transport.main(argv)
                self.assertEqual(denied.exception.code, self.code)
                send.assert_not_called()

    def test_DEP_58LK_01_all_profile_ingresses_precede_errors_and_effects(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        journal = root / "journal"
        p = json.loads(fixture.PROFILE.with_name("mcp.example.json").read_bytes())
        p.update(configDelta=self.marker, journal=str(journal))
        first = dict(setup_profile(str(journal)), configDelta=self.marker)
        profile_file = root / "transport.json"
        profile_file.write_text(json.dumps(p), encoding="utf-8")
        bootstrap = installer_fixture.Bootstrap()
        self.addCleanup(bootstrap.doCleanups)
        bootstrap.setUp()
        inst = bootstrap.inst
        # Even the invalid sibling and missing executor-level fields must come second.
        cfg = {"modules": {"onboarding": {}, "mcp": p}}
        bootstrap.path.write_text(json.dumps(cfg))
        files = {inst.ROOT / "profile.json": (json.dumps(cfg).encode(), 0o600)}
        inst.ROOT.mkdir()
        (inst.ROOT / "profile.json").write_text(json.dumps(cfg))
        clean = {inst.ROOT / "profile.json": (b'{"modules":{"mcp":{}}}', 0o600)}
        req = {"operation": "module-release", "module": "mcp", "phase": "plan", "digest": ""}
        get, rt = Mock(), Mock()
        stamp = "a" * 64
        executor = runpy.run_path(str(fixture.ROOT / "scripts/ouf-a2-executor"))

        def cli(kind, phase):
            output, _, _ = executor_with_busy_lock(fixture.ROOT, mandate, p, denied=True,
                                                    operation_name=kind, phase=phase)
            self.assertEqual(output, (1, "", self.code + "\n"))

        def installer_cli(mode):
            with patch.object(sys, "argv", ["install-ouf-a2", mode, str(bootstrap.path)]), \
                 patch.object(inst, "sys", SimpleNamespace(flags=SimpleNamespace(isolated=True))), \
                 patch.object(os, "geteuid", return_value=0, create=True), patch.object(os, "umask"):
                inst.main()

        cases = [
            ("contract.validate", partial(validate, p)),
            ("contract.package", partial(operation.package, p)),
            ("install_contract.validate", partial(install_contract.validate, first)),
            ("install_contract.valid_request", partial(install_contract.valid_request, req, cfg, set())),
            ("mandate.validate", partial(mandate.validate, req, cfg)),
            ("mandate.authorize", partial(mandate.authorize, req, cfg, get, journal)),
            ("executor.dispatch", partial(executor["dispatch"], req, cfg, journal, get)),
            ("ModuleRelease", partial(module_operation.ModuleRelease, cfg, journal, req)),
            ("ModuleRelease.peer", partial(module_operation.ModuleRelease, cfg, journal, dict(req, module="onboarding"))),
            ("ModuleInstall", partial(module_operation.ModuleInstall, cfg, journal, req)),
            ("release.plan", partial(operation.plan, p)),
            ("release.observe", partial(operation.observe, p, rt)),
            ("release.apply", partial(operation.apply, p, "")),
            ("release.migrate", partial(operation.migrate, p, "", "")),
            ("release.migrate.recover", partial(operation.migrate, p, stamp, stamp, recover=True)),
            ("release.rollback", partial(operation.rollback, p, rt, {}, journal, {}, ValueError())),
            ("return", partial(return_operation.run, p, "", rt)),
            ("return.recover", partial(return_operation.run, p, stamp, rt, recover=True)),
            ("recovery.residual", partial(recovery.residual, p, rt)),
            ("recovery.proposal", partial(recovery.proposal, p, rt)),
            ("recovery.resume", partial(recovery.resume, p, rt, {})),
            ("install.engine", partial(install.engine, first)),
            ("install.observe", partial(install.observe, first, rt)),
            ("install.plan", partial(install.plan, first)),
            ("install.plan.resume", partial(install.plan, first, resume=stamp)),
            ("install.apply", partial(install.apply, first, "")),
            ("install.rollback", partial(install.rollback, first, stamp)),
            ("transport", partial(transport.transport, p, 15, 17, root)),
            ("transport.cli", partial(transport.main, ["--module", "udp", str(profile_file), "15", "17", str(root)])),
            ("transport.cli.arguments", partial(transport.main, ["--module", "other", str(profile_file),
                                                                "invalid", "invalid", str(root)])),
            ("transport.cli.missing", partial(transport.main, [str(profile_file)])),
            ("installer.invalid-mode", partial(installer_cli, "unknown")),
            ("installer.read_profiles", partial(inst.read_profiles, bootstrap.path)),
            ("installer.checked_profiles", partial(inst.checked_profiles, files[inst.ROOT / "profile.json"][0])),
            ("installer.inspect", partial(inst.inspect, bootstrap.path)),
            ("installer.journals", partial(inst.journals, files[inst.ROOT / "profile.json"][0])),
            ("installer.manifest", partial(inst.manifest, files)),
            ("installer.install", partial(inst.install, files, {})),
            ("installer.manifest.installed", partial(inst.manifest, clean)),
            ("installer.install.installed", partial(inst.install, clean, {})),
        ]
        cases.extend((phase, partial(retention.run, p, rt, "", phase, {})) for phase in retention.COMMAND)
        cases.extend(("installer." + mode, partial(installer_cli, mode)) for mode in ("plan", "apply", "bootstrap"))
        for kind, phases in (("module-release", ("plan", "apply", "migrate", "rollback", *retention.COMMAND)),
                             ("module-install", ("plan", "apply", "rollback"))):
            cases.extend(("executor." + kind + "." + phase, partial(cli, kind, phase)) for phase in phases)

        # Detect attempted reads (including existence checks) as well as writes to the empty journal.
        effects = []
        def monitor(method):
            def checked(path, *args, **kwargs):
                if path.is_relative_to(journal):
                    effects.append((method.__name__, path))
                    self.fail("accessed private journal")
                return method(path, *args, **kwargs)
            return checked

        with ExitStack() as stack:
            enter = stack.enter_context
            for attr in ("stat", "open"):
                enter(patch.object(Path, attr, monitor(getattr(Path, attr))))
            guards = [enter(patch.object(owner, name, side_effect=AssertionError(name)))
                      for owner, name in ((os, "mkdir"), (operation, "Docker"), (module_operation.operation, "Docker"),
                                          (return_operation, "Docker"), (inst.subprocess, "check_output"),
                                          (transport, "github"), (inst, "installation_lock"), (inst, "visudo"),
                                          (store, "begin_plan"), (store, "consume_approval"))]
            for name, invoke in cases:
                with self.subTest(ingress=name):
                    try:
                        result = invoke()
                    except (Held, mandate.Held, SystemExit, ValueError) as exc:
                        self.assertEqual(str(exc), self.code)
                    else:
                        if name.startswith("executor.module-"):
                            self.assertIsNone(result)  # cli() asserted status, stdout, stderr and both locks
                        else:
                            self.assertEqual((result["status"], result["reason"]), ("HELD", self.code))
                            self.assertNotIn(self.marker, json.dumps(result))
                    self.assertEqual(effects, [])
                    for guard in (*guards, rt, get):
                        self.assertEqual(guard.mock_calls, [])
        self.assertFalse(journal.exists())

    def test_DEP_58LK_02_executor_revalidates_profile_under_shared_lock(self):
        output, opens, locks = executor_with_busy_lock(fixture.ROOT, mandate, {}, locked_profile={"configDelta": None})
        self.assertEqual(output, (1, "", self.code + "\n"))
        self.assertEqual((opens, locks), (0, 0))


class LibraryTest(unittest.TestCase):
    def test_approval_rejects_credentials_in_either_preimage_or_replacement(self):
        for name, value in (("DOCKER_AUTH_CONFIG", '{"auths":{"example":{"auth":"fixture"}}}'),
                            ("MYSQL_PWD", "fixture"), ("REDISCLI_AUTH", "fixture"),
                            ("SPRING_APPLICATION_JSON", '{"spring.datasource.password":"fixture"}')):
            for side in ("before", "after"):
                with self.subTest(name=name, side=side):
                    change = {"name": name, "before": None, "after": None, side: value}
                    with self.assertRaisesRegex(Held, "^SECRET_ENV_DENIED$"):
                        config_delta.approval_lines({"env": [change]}, [name])
