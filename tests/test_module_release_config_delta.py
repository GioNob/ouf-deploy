"""Fail-closed release profiles and the isolated 58q library."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_module_release as fixture
import mandate
from tools.module_release import config_delta, operation, recovery
from tools.module_release.contract import Held, validate


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
                    mandate.validate(req, cfg)
                    out, err = io.StringIO(), io.StringIO()
                    with redirect_stdout(out), redirect_stderr(err), self.assertRaises(mandate.Held) as denied:
                        executor["dispatch"](req, cfg, root, get)
                    self.assertEqual(executor["public_error"](denied.exception), self.code)
                    self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                    self.assertEqual(list(root.iterdir()), [])
        get.assert_not_called()


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
