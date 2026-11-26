"""Fail-closed release profiles and the isolated 58q library."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, mock_open, patch

import test_module_release as fixture
import mandate
import store
from tools.module_release import config_delta, operation, recovery, return_operation, transport
from tools.module_release.contract import Held, validate


def executor_with_busy_lock(root, policy_module, profile):
    """Run the CLI and capture its public output with the operation lock occupied."""
    script = str(root / "scripts/ouf-a2-executor")
    req = dict(operation="module-release", module="mcp", phase="plan", run="1", attempt="1", commit="a" * 40)
    req["digest"] = policy_module.intent(req)
    cfg = {"commit": req["commit"], "modules": {"mcp": profile}}
    envelope = json.dumps({"request": req, "token": "fixture"}).encode()
    locks = Mock(LOCK_SH=1, LOCK_EX=2, LOCK_NB=4)
    locks.flock.side_effect = [None, BlockingIOError()]
    trusted_lock = Mock(open=mock_open())
    out, err = io.StringIO(), io.StringIO()
    with ExitStack() as stack:
        enter = stack.enter_context
        enter(patch.dict(sys.modules, {"fcntl": locks, "mandate": policy_module}))
        enter(patch.object(sys, "argv", [script]))
        enter(patch.object(sys, "flags", Mock(wraps=sys.flags, isolated=1)))
        enter(patch.object(sys, "path", list(sys.path)))
        enter(patch.object(sys, "dont_write_bytecode", True))
        enter(patch.object(sys, "stdin", Mock(buffer=io.BytesIO(envelope))))
        enter(patch.object(os, "geteuid", return_value=0, create=True))
        enter(patch.object(os, "O_DIRECTORY", 0, create=True))
        enter(patch.object(os, "open", return_value=17))
        enter(patch.object(os, "environ", {}))
        enter(patch.object(os, "chdir"))
        enter(patch.object(os, "umask"))
        enter(patch.object(store, "read", return_value=cfg))
        trusted = enter(patch.object(store, "trusted", return_value=trusted_lock))
        github = enter(patch.object(policy_module, "github_reader"))
        mkdir = enter(patch.object(os, "mkdir"))
        enter(redirect_stdout(out))
        enter(redirect_stderr(err))
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as error:
            status = error.code
        else:
            status = 0
    github.assert_not_called()
    mkdir.assert_not_called()
    # Both versions acquire the shared installation lock before importing the executor.
    assert locks.flock.call_args_list[0] == call(17, locks.LOCK_SH | locks.LOCK_NB)
    return (status, out.getvalue(), err.getvalue()), trusted.call_count, locks.flock.call_count - 1


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
