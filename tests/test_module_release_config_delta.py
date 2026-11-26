"""Fail-closed release profiles and the isolated 58q library."""
from contextlib import ExitStack, chdir, nullcontext, redirect_stderr, redirect_stdout
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
from unittest.mock import Mock, mock_open, patch

import test_module_release as fixture
from test_module_install import setup_profile
import test_privileged_executor_install as installer_fixture
import module_operation
from tools.module_release import frame_spec, install_contract, install_operation as install, retention
import mandate
import store
from tools.module_release import config_delta, operation, recovery, return_operation, transport
from tools.module_release.contract import Held, validate


def request_for(kind, module, phase="plan"):
    req = dict(operation=kind, module=module, phase=phase, run="1", attempt="1", commit="a" * 40)
    if kind == "module-install":
        req["schema"] = install_contract.SCHEMA
    return dict(req, digest=mandate.intent(req))


def executor_with_busy_lock(root, policy_module, profile, *, operation_name="module-release", phase="plan",
                            raw_request=None, installation_fd=None):
    """Run the CLI and capture its public output with the operation lock occupied."""
    script = str(root / "scripts/ouf-a2-executor")
    name = profile.get("module", "mcp")
    req = request_for(operation_name, name, phase)
    cfg = {"commit": req["commit"], "modules": {name: profile}}
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
    stream = Mock(wraps=io.BytesIO(envelope))

    def locked_read(path):
        locks.flock.assert_called_once_with(fd, locks.LOCK_SH | locks.LOCK_NB)
        stream.read.assert_not_called()
        return cfg

    with ExitStack() as stack:
        enter = stack.enter_context
        enter(patch.dict(sys.modules, {"fcntl": locks, "mandate": policy_module}))
        enter(patch.object(sys, "argv", [script]))
        enter(patch.object(sys, "flags", flags))
        enter(patch.object(sys, "path", list(sys.path)))
        enter(patch.object(sys, "dont_write_bytecode", True))
        enter(patch.object(sys, "stdin", Mock(buffer=stream)))
        enter(patch.object(os, "geteuid", return_value=0, create=True))
        enter(patch.object(os, "O_DIRECTORY", 0, create=True))
        enter(patch.object(os, "open", return_value=fd))
        enter(patch.object(os, "environ", {}))
        enter(patch.object(os, "chdir"))
        enter(patch.object(os, "umask"))
        read = enter(patch.object(store, "read", side_effect=locked_read))
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
    read.assert_called_once_with(Path("/opt/ouf-a2/profile.json"))
    stream.read.assert_called_once_with(8193)
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
                    req = request_for(kind, "mcp", phase)
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
        output, opens, locks = executor_with_busy_lock(fixture.ROOT, mandate, profile)
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

    def test_DEP_58LL_02_transport_argument_errors_do_not_open_profile(self):
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
            for args in ([profile.name, "1", "2", ".", "--module"], [profile.name],
                         ["--module", "other", profile.name, "1", "2", "."], [profile.name, "invalid", "2", "."]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as usage:
                    transport.main(args)
                self.assertEqual(usage.exception.code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("usage:", err.getvalue())
        self.assertIn("argument --module: expected one argument", err.getvalue())
        self.assertNotIn(self.marker, err.getvalue())
        for effect in (github, mkdir, open_fd, open_file, locking):
            self.assertEqual(effect.mock_calls, [])
        self.assertEqual(list(root.iterdir()), [profile])
        self.assertEqual(profile.read_bytes(), raw)

    def test_DEP_58LM_05_transport_preserves_single_read_error(self):
        argv = ["profile.json", "1", "2", "."]
        for first_read in (OSError("unavailable"), "{"):
            with self.subTest(first_read=first_read), patch.object(Path, "read_text", side_effect=[
                    first_read, json.dumps({"configDelta": self.marker})]) as read, \
                    patch.object(transport, "transport") as send:
                with self.assertRaises(SystemExit) as denied:
                    transport.main(argv)
                self.assertEqual(denied.exception.code, "TRANSPORT_IO_OR_INPUT_ERROR")
                read.assert_called_once_with(encoding="utf-8")
                send.assert_not_called()

    def test_DEP_58LK_01_all_profile_ingresses_deny_before_use(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        journal = root / "journal"
        bootstrap = installer_fixture.Bootstrap()
        self.addCleanup(bootstrap.doCleanups)
        bootstrap.setUp()
        inst = bootstrap.inst
        cfg = json.loads(bootstrap.path.read_bytes())
        p = cfg["modules"]["mcp"]
        p.update(configDelta=self.marker, journal=str(journal))
        first = dict(setup_profile(str(journal)), configDelta=self.marker)
        profile_file = root / "transport.json"
        profile_file.write_text(json.dumps(p), encoding="utf-8")
        bootstrap.path.write_text(json.dumps(cfg))
        req = request_for("module-release", "mcp")
        install_req = request_for("module-install", first["module"])
        install_cfg = dict(cfg, modules={first["module"]: first})
        common = {"commit", "run", "attempt", "phase", "digest"}
        get, rt = Mock(), Mock()
        stamp = "a" * 64
        executor = runpy.run_path(str(fixture.ROOT / "scripts/ouf-a2-executor"))

        def cli(kind, phase):
            profile = first if kind == "module-install" else p
            if phase in retention.COMMAND:
                profile = dict(p, migration=dict(p["migration"], retentionAdmin019={}))
            output, _, _ = executor_with_busy_lock(fixture.ROOT, mandate, profile, operation_name=kind, phase=phase)
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
            ("install_contract.valid_request", partial(install_contract.valid_request, install_req, install_cfg, common)),
            ("mandate.validate", partial(mandate.validate, req, cfg)),
            ("mandate.authorize", partial(mandate.authorize, req, cfg, get, journal)),
            ("executor.dispatch", partial(executor["dispatch"], req, cfg, journal, get)),
            ("ModuleRelease", partial(module_operation.ModuleRelease, cfg, journal, req)),
            ("ModuleRelease.peer", partial(module_operation.ModuleRelease, cfg, journal,
                                           request_for("module-release", "onboarding"))),
            ("ModuleInstall", partial(module_operation.ModuleInstall, install_cfg, journal, install_req)),
            ("release.plan", partial(operation.plan, p)),
            ("release.observe", partial(operation.observe, p, rt)),
            ("release.apply", partial(operation.apply, p, stamp)),
            ("release.migrate", partial(operation.migrate, p, stamp, stamp)),
            ("release.migrate.recover", partial(operation.migrate, p, stamp, stamp, recover=True)),
            ("release.rollback", partial(operation.rollback, p, rt, {}, journal, {}, ValueError())),
            ("return", partial(return_operation.run, p, stamp, rt)),
            ("return.recover", partial(return_operation.run, p, stamp, rt, recover=True)),
            ("recovery.residual", partial(recovery.residual, p, rt)),
            ("recovery.proposal", partial(recovery.proposal, p, rt)),
            ("recovery.resume", partial(recovery.resume, p, rt, {})),
            ("install.engine", partial(install.engine, first)),
            ("install.observe", partial(install.observe, first, rt)),
            ("install.plan", partial(install.plan, first)),
            ("install.plan.resume", partial(install.plan, first, resume=stamp)),
            ("install.apply", partial(install.apply, first, stamp)),
            ("install.rollback", partial(install.rollback, first, stamp)),
            ("transport", partial(transport.transport, p, 15, 17, root)),
            ("transport.cli", partial(transport.main, [str(profile_file), "15", "17", str(root)])),
            ("installer.inspect", partial(inst.inspect, bootstrap.path)),
        ]
        cases.extend((phase, partial(retention.run, p, rt, stamp, phase, {})) for phase in retention.COMMAND)
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
                                          (return_operation, "Docker"), (operation, "request"), (install, "summary"),
                                          (frame_spec, "create_with_custody"), (config_delta, "approval_lines"),
                                          (module_operation, "Journal"), (inst.subprocess, "check_output"),
                                          (transport, "github"), (inst, "manifest"), (inst, "install"),
                                          (inst, "installation_lock"),
                                          (store, "begin_plan"), (store, "consume_approval"))]
            for name, invoke in cases:
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(ingress=name), redirect_stdout(out), redirect_stderr(err), self.assertNoLogs(level="DEBUG"):
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
                    self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                    self.assertEqual(effects, [])
                    for guard in (*guards, rt, get):
                        self.assertEqual(guard.mock_calls, [])
        self.assertFalse(journal.exists())

    def test_DEP_58LK_02_installer_usage_does_not_read_profile(self):
        inst = runpy.run_path(str(fixture.ROOT / "scripts/install-ouf-a2.py"))
        with patch.object(sys, "argv", ["install", "unknown", "profile.json"]), \
             patch.object(Path, "read_bytes") as read, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as usage:
            inst["main"]()
        self.assertEqual(usage.exception.code, 2)
        read.assert_not_called()


class InstalledDeltaTest(unittest.TestCase):
    marker = "private-installed-mcp-delta"

    def setUp(self):
        case = self.case = installer_fixture.Bootstrap()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.install_fixture()
        self.installed = case.inst.ROOT / "profile.json"
        self.clean = self.installed.read_bytes()
        policy = json.loads(self.clean)
        self.old_journal = case.inst.ROOT / "lib" / "retired-journal"
        policy["modules"]["mcp"].update(configDelta=self.marker, journal=str(self.old_journal))
        self.installed.write_text(json.dumps(policy))
        self.old_journal.mkdir()
        self.receipt = self.old_journal / "receipt"
        self.receipt.write_bytes(b"retained receipt")
        if not case.native:
            self.enterContext(patch.object(os, "geteuid", return_value=0, create=True))
            self.enterContext(patch.object(case.inst, "sys", SimpleNamespace(
                flags=SimpleNamespace(isolated=True), path=sys.path, modules=sys.modules)))
        if os.name == "nt":
            self.enterContext(patch.object(case.inst, "installation_lock", nullcontext))

    def cli(self, mode, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["install", mode, str(self.case.path), *args]), \
                redirect_stdout(out), redirect_stderr(err):
            self.case.inst.main()
        self.assertNotIn(self.marker, out.getvalue())
        self.assertEqual(err.getvalue(), "")
        return out.getvalue()

    def test_DEP_58LN_03_installer_plans_replacement_and_protects_old_journal(self):
        before = self.installed.read_bytes()
        plan = json.loads(self.cli("plan"))
        row = plan["files"][str(self.installed)]
        self.assertEqual(row["action"], "replace")
        self.assertEqual(row["before"]["sha256"], self.case.inst.sha(before))
        self.assertEqual(row["after"]["sha256"], self.case.inst.sha(self.clean))
        self.assertEqual(self.installed.read_bytes(), before)

        inventory = self.case.inst.ROOT / "managed-files.json"
        names = json.loads(inventory.read_bytes())
        names.append(self.receipt.relative_to(self.case.inst.ROOT).as_posix())
        inventory.write_text(json.dumps(names))
        with self.assertRaisesRegex(ValueError, "^PROTECTED_INSTALL_STATE$"):
            self.cli("plan")

    def test_DEP_58LP_01_installed_delta_is_absent_from_plan_and_receipt(self):
        plan = json.loads(self.cli("plan"))
        self.assertNotIn(self.marker, json.dumps(plan))
        applied = self.cli("apply", "--plan-sha256", plan["planSha256"])
        published, status = applied.rstrip().rsplit("\n", 1)
        self.assertEqual(json.loads(published), plan)
        self.assertEqual(status, "OUF_A2_INSTALLED")
        self.assertEqual(self.installed.read_bytes(), self.clean)
        self.assertEqual(list(self.old_journal.iterdir()), [self.receipt])
        self.assertEqual(self.receipt.read_bytes(), b"retained receipt")


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
