"""Fail-closed release profiles and the isolated 58q library."""
from contextlib import ExitStack, contextmanager, chdir, nullcontext, redirect_stderr, redirect_stdout
from functools import partial
import base64
import hashlib
import secrets
from urllib.parse import quote
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


@contextmanager
def pinned_install(data, *, delta=False, file_env=True):
    import test_module_install as first
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as store:
        p = first.setup_profile(directory)
        key = Path(store) / ".release-hmac.key"
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(32))
        p["fingerprintKeyFile"] = str(key)
        target = "/app/archiveSha256"
        material = Path(store) / "content"
        material.write_bytes(data)
        pin = hashlib.sha256(data).hexdigest()
        p["install"]["binds"].append(dict(mode="ro", source="/srv/fixture/secret", target=target, sha256=pin))
        if file_env:
            p["install"]["env"].append(dict(name="READ_TOKEN_FILE", value=target))
        if delta:
            p["configDelta"] = {"aliases": {"example-net": ["approved"]}}
        rt = first.Engine(p, fixture.artifact(p, Path(directory)))
        def facts(row, *args, **kwargs):
            if row["target"] != target:
                return {}, {"ino": 42}
            observed = hashlib.sha256(material.read_bytes()).hexdigest()
            frame_spec.check(observed == row["sha256"], "BIND_DIGEST_CHANGED")
            return {}, {"ino": 43, "sha256": observed}
        with patch.object(frame_spec, "bind_facts", facts):
            yield p, rt, target, pin


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


class InvalidDeltaTest(unittest.TestCase):
    code = "INVALID_DELTA"
    marker = "synthetic-58li-private-value"

    def test_DEP_58QI_02_installed_profile_rejects_unlisted_argv_before_plan(self):
        import test_module_release_mcp as mcp

        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.dedicated()
        allowed = case.p["migration"]["command"]
        commands = [allowed + tail for tail in (
            ["--url", "postgresql://user:private-fixture@localhost/db"],
            ["postgresql://user:NOT_ALLOWED@localhost/db"],
            ["--password", "private-fixture"], ["host=db password=;private-fixture"],
            ["--bypass-cache"], ["psql", "--password"], ["psql", "-W"], ["psql", "-p5432"],
            ["-placeholders.region=eu"], ["--url-env", "DB_URL"], ["--password-file", "/run/secrets/database"],
        )]
        commands.extend((allowed[::-1], ["other-migrator", "migrate"], [], [allowed]))
        cases = [("mcp", cmd) for cmd in commands] + [("onboarding", allowed)]
        reason = "MIGRATION_COMMAND_NOT_ALLOWED"
        files = set(case.root.rglob("*"))
        for delta in (False, True):
            if delta:
                case.p["configDelta"] = {"aliases": {next(iter(case.p["networks"])): ["reviewed"]}}
            for module, command in cases:
                with self.subTest(delta=delta, module=module, command=command):
                    case.p.update(module=module)
                    case.p["migration"]["command"] = command
                    with self.assertRaisesRegex(Held, "^" + reason + "$"):
                        validate(case.p)
                    self.assertEqual(operation.plan(case.p, case.rt),
                                     {"status": "HELD", "reason": reason, "rollback": "UNVERIFIED"})
                    public, locks, attempts = executor_with_busy_lock(fixture.ROOT, mandate, case.p)
                    self.assertEqual((public, locks, attempts), ((1, "", reason + "\n"), 0, 0))
        self.assertEqual(set(case.root.rglob("*")), files)
        self.assertEqual(case.rt.events, [])

    def assert_inline_denied(self, profile, reason="CONFIG_DELTA_INLINE_SECRET"):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p.update(profile)
        call, _ = case.governed_dispatch()
        files = {p: p.read_bytes() for p in case.root.rglob("*") if p.is_file()}
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            for result in (operation.plan(case.p, case.rt), operation.apply(case.p, "a" * 64, case.rt)):
                self.assertEqual((result["status"], result["reason"]), ("HELD", reason))
            with self.assertRaisesRegex(mandate.Held, f"^{reason}$"):
                call(0)
        self.assertEqual((out.getvalue(), err.getvalue(), case.rt.events), ("", "", []))
        self.assertEqual(files, {p: p.read_bytes() for p in case.root.rglob("*") if p.is_file()})

    def test_DEP_58QG_01_generated_credential_matrix(self):
        self.credential_matrix(("env-before", "env-after", "nested-json", "json-argument", "json-metadata",
                                "label", "label-argv", "alias", "migration"))

    def test_DEP_58QM_05_credential_outputs_for_log_and_install(self):
        self.credential_matrix(("host-log", "install-bind"))

    def install_bind_outputs(self, p, rt, target, pin, streams):
        from test_release_approval import Approval
        from module_release import frame_spec as installed_spec

        case = fixture.ReleaseTest()
        case.p, case.rt, case.root = p, rt, Path(p["journal"])
        p["module"] = "onboarding"
        workflow = ".github/workflows/module-install.yml"
        results = []
        with ExitStack() as stack:
            stack.callback(case.doCleanups)
            stack.enter_context(patch.object(installed_spec, "bind_facts", frame_spec.bind_facts))
            call, req = case.governed_dispatch()
            req.update(operation="module-install", schema=install_contract.SCHEMA)
            req["digest"] = mandate.intent(req)
            for phase, status in (("plan", "PLANNED"), ("apply", "READY"), ("rollback", "ROLLED_BACK")):
                req["phase"] = phase
                if phase == "rollback":
                    req["run"] = "2"
                with redirect_stdout(streams[0]), redirect_stderr(streams[1]):
                    result = call(int(phase != "plan"), workflow)
                    self.assertEqual(result["status"], status, result)
                    with patch.object(sys, "path", list(sys.path)):
                        published = Approval().client("module-install", phase, result, MODULE=p["module"], RESUME_PLAN="")
                results.extend((result, published))
                if phase == "plan":
                    req["digest"] = result["digest"]
                    plan = operation.read(case.root / "1", "plan")["plan"]
                    with operation.public_output.scope(p):
                        expected = operation.public_output.fingerprint(["install.bind", target], pin)
                    self.assertEqual(result["installReview"]["binds"][-1]["hmacSha256"], expected)
                    self.assertEqual(plan["preconditions"]["bindCustody"][-1]["hmacSha256"], expected)
        return results

    def credential_matrix(self, positions):
        def derivatives(secret):
            raw = secret.encode()
            forms = {raw, raw.hex().encode(), quote(secret, safe="").encode(),
                     "".join(f"%{byte:02X}" for byte in raw).encode(), hashlib.sha256(raw).hexdigest().encode(),
                     hashlib.md5(raw, usedforsecurity=False).hexdigest().encode(), operation.digest(secret).encode()}
            forms.update(encode(raw).rstrip(b"=") for encode in (base64.b64encode, base64.urlsafe_b64encode))
            forms.update(raw[i:i+8] for i in range(len(raw)-7))
            return {form.lower() for form in forms}

        corpus = [
            "postgresql://user:{v}@host/db", "-url=jdbc:postgresql://user:{v}@host/db",
            "host=db dbname=ouf password={v}", "host=db sslpassword='{v}'",
            "jdbc:postgresql://db/ouf?password={v}", "jdbc:postgresql://db/ouf?ssl=true&password={v}",
            "jdbc:sqlserver://db;password={v}", "jdbc:sqlserver://db;password={{{v}}}", "--password={v}", "-password={v}", "-p{v}",
            "PGPASSWORD={v}", "--secret={v}", "--token={v}", "FLYWAY_PASSWORD={v}", "-Dflyway.password={v}",
            "jdbc:oracle:thin:user/{v}@db", "--dbname=sslpassword={v}",
            ("--password", "{v}"), ("--secret", "{v}"), ("--token", "{v}"),
            ("sh", "-c", "migrate --password '{v}'"),
        ]
        count = 0
        for syntax in corpus:
            for position in positions:
                # DNS aliases must also be usable as aliases. Other inputs exercise URL escaping
                # and the distinct standard / URL-safe base64 alphabets with the same oracle.
                prefix = "Qk-" if position in ("label", "label-argv", "alias") else "Qk+AB~"
                marker = prefix + secrets.token_urlsafe(28)
                forbidden = derivatives(marker)
                args = [word.format(v=marker) for word in (syntax if isinstance(syntax, tuple) else (syntax,))]
                value = " ".join(args)
                for delta in (False, True):
                    with self.subTest(syntax=syntax, position=position, delta=delta), ExitStack() as stack:
                        streams = [io.StringIO(), io.StringIO(), io.StringIO()]
                        private_hashes = set()
                        if position == "install-bind":
                            p, rt, target, pin = stack.enter_context(pinned_install(value.encode(), delta=delta))
                            root = Path(p["journal"])
                            responses = self.install_bind_outputs(p, rt, target, pin, streams)
                            private_hashes.update((pin.encode(), operation.digest(p).encode(), operation.digest(pin).encode()))
                        else:
                            case = fixture.ReleaseTest()
                            case.setUp()
                            stack.callback(case.doCleanups)
                            p, rt = case.p, case.rt
                            net = next(iter(p["networks"]))
                            fixture.dedicated_profile(p)
                            cmd = p["migration"]["command"]
                            if delta:
                                p["configDelta"] = {"aliases": {net: ["public-candidate"]}}
                            old = rt.docs[fixture.OLD]
                            if position == "host-log":
                                old["HostConfig"]["LogConfig"] = {"Type": "splunk", "Config": {"splunk-token": value}}
                            elif position == "migration":
                                cmd.extend(args)
                            elif position in ("json-argument", "json-metadata"):
                                nested = {"settings": [{"AccountKey": marker, "connection": value}]}
                                if position == "json-argument":
                                    cmd.append("--settings=" + json.dumps(nested))
                                else:
                                    p["migration"]["options"] = nested
                            elif position == "alias":
                                if delta:
                                    p["configDelta"]["aliases"][net] = [value]
                                else:
                                    p["networks"][net]["aliases"].append(value)
                                    old["NetworkSettings"]["Networks"][net]["Aliases"].append(value)
                            elif position in ("label", "label-argv"):
                                old["Config"]["Labels"]["settings"] = value if position == "label" else json.dumps(args)
                                if not delta:
                                    p["networks"][net]["aliases"].append(marker)
                                    old["NetworkSettings"]["Networks"][net]["Aliases"].append(marker)
                                if delta:
                                    p["configDelta"]["aliases"][net] = [marker]
                            else:
                                setting = json.dumps({"settings": [{"argument": value}]}) if position == "nested-json" else value
                                before = setting if position == "env-before" else None
                                after = setting if before is None else "replacement"
                                if before is not None or not delta:
                                    old["Config"]["Env"].append("APP_SETTINGS=" + setting)
                                if delta:
                                    p.update(envAllowlist=["APP_SETTINGS"], showValues=["APP_SETTINGS"])
                                    p["configDelta"]["env"] = [dict(name="APP_SETTINGS", before=before, after=after)]
                            call, req = case.governed_dispatch()
                            responses = []
                            with redirect_stdout(streams[0]), redirect_stderr(streams[1]):
                                plan = operation.plan(p, rt)
                                responses.append(plan)
                                if position in ("migration", "json-argument"):
                                    self.assertEqual(plan["reason"], "MIGRATION_COMMAND_NOT_ALLOWED")
                                if position in ("json-metadata", "label", "label-argv", "host-log"):
                                    self.assertEqual(plan["status"], "PLANNED", plan)
                                if plan["status"] == "PLANNED":
                                    response = call(0)
                                    responses.append(response)
                                    with patch.object(sys, "path", list(sys.path)):
                                        render = runpy.run_path(str(fixture.ROOT / ".github/scripts/module-release.py"))["module_review"]
                                        render(streams[2], p["module"], "plan", response, "apply", None)
                                    req.update(phase="apply", digest=response["digest"])
                                    result = call(1)
                                    responses.append(result)
                                    self.assertEqual(result["status"], "GATED", result)
                                    responses.append(recovery.proposal(p, rt))
                                    render(streams[2], p["module"], "apply", result, "migrate", None)
                                    req.update(phase="migrate", digest=result["digest"])
                                    ready = call(2)
                                    self.assertEqual(ready["status"], "READY", ready)
                                    responses.append(ready)
                                    render(streams[2], p["module"], "migrate", ready, None, None)
                                    req.update(phase="rollback", run="2", digest=response["digest"])
                                    if delta:
                                        returned = call(1)
                                        self.assertEqual(returned["status"], "ROLLED_BACK", returned)
                                        responses.append(returned)
                                    else:
                                        with self.assertRaises(mandate.Held) as denied:
                                            call(1)
                                        responses.append(str(denied.exception))
                                else:
                                    responses.append(operation.apply(p, "a" * 64, rt))
                                    with self.assertRaises(mandate.Held) as denied:
                                        call(0)
                                    responses.append(str(denied.exception))
                            root = case.root
                            if position == "host-log":
                                request = (operation.reviewed.request(p, old, {}) if delta else
                                           operation.request(old, p["ci"]["imageId"], operation.provenance_labels(p)))
                                private_hashes.add(operation.digest(request).encode())
                            for document in (p, old, p.get("configDelta"), old["Config"]["Cmd"]):
                                if marker in json.dumps(document):
                                    private_hashes.add(operation.digest(document).encode())
                        outputs = [json.dumps(responses).encode(), *(s.getvalue().encode() for s in streams)]
                        for path in root.rglob("*.json"):
                            raw = path.read_bytes()
                            if marker.encode() in raw:
                                private_hashes.add(hashlib.sha256(raw).hexdigest().encode())
                                private_hashes.add(hashlib.md5(raw, usedforsecurity=False).hexdigest().encode())
                                private_hashes.add(operation.digest(json.loads(raw)).encode())
                        for path in root.rglob("*"):
                            if path.is_file() and (path.name in {"plan", "plan.json", "stage.json", "receipt.json",
                                    "ready-before-signing.json", "return-receipt.json"} or path.suffix in (".held", ".result")):
                                outputs.append(path.read_bytes())
                        for output in outputs:
                            self.assertFalse(any(needle in output.lower() for needle in forbidden | private_hashes), position)
                        count += 1
        print(f"Credentials: {len(corpus)} syntaxes x {len(positions)} positions x 2 profiles = {count}")

    def test_migration_and_frame_remain_in_executor_custody(self):
        marker = self.marker
        for delta in (False, True):
            with self.subTest(delta=delta):
                case = fixture.ReleaseTest()
                case.setUp()
                self.addCleanup(case.doCleanups)
                net = next(iter(case.p["networks"]))
                old = case.rt.docs[fixture.OLD]
                old["Config"]["Labels"]["dsn"] = f"postgresql://user:{marker}@db/test"
                case.p["networks"][net]["aliases"].append(marker)
                old["NetworkSettings"]["Networks"][net]["Aliases"].append(marker)
                fixture.dedicated_profile(case.p)
                if delta:
                    case.p["configDelta"] = {"aliases": {net: ["public-candidate"]}}
                call, req = case.governed_dispatch()
                plan = call(0)
                req.update(phase="apply", digest=plan["digest"])
                stage = call(1)
                self.assertEqual(stage["status"], "GATED", stage)
                self.assertNotIn(marker, json.dumps([plan, stage]))
                root = case.root / plan["digest"]
                names = ["migration-plan.json", "baseline.private.json"]
                if delta:
                    names.append("return-frame.json")
                for name in names:
                    path = root / name
                    if name == "migration-plan.json":
                        self.assertEqual(json.loads(path.read_bytes())["migration"]["command"], case.p["migration"]["command"])
                    else:
                        self.assertIn(marker.encode(), path.read_bytes())
                    if os.name == "posix":
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(path.stat().st_uid, os.geteuid())
                if os.name == "posix":
                    for directory in (case.root, root):
                        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                        self.assertEqual(directory.stat().st_uid, os.geteuid())

    def test_DEP_58QE_01_migration_and_aliases(self):
        dsn = "postgresql://user:" + self.marker + "@localhost/test"
        self.assert_inline_denied(dict(configDelta={"aliases": {"backend": [dsn]}}))

    def test_private_inputs_recognize_json_argv_and_encoded_passwords(self):
        output = operation.public_output
        for text in ('["--token","ENV_NAME"]', "postgresql://user:ENV%5FNAME@host/db",
                     "host=db password='ENV_NAME'", "jdbc:oracle:thin:user/ENV_NAME@db"):
            self.assertTrue(output.private_config({"Labels": {"value": text}}))

    def test_DEP_58QE_09_bootstrap_rejects_before_manifest(self):
        case = installer_fixture.Bootstrap()
        self.addCleanup(case.doCleanups)
        case.setUp()
        cfg = json.loads(case.path.read_bytes())
        cfg["modules"]["mcp"].update(configDelta={"aliases": {"backend": ["ok"]}}, showValues=["DB_PASSWORD"])
        case.path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError, "^CONFIG_DELTA_INLINE_SECRET$"):
            case.inst.inspect(case.path)
        self.assertFalse(case.inst.ROOT.exists())

    def test_DEP_58QE_02_nested_settings_and_show_values(self):
        for value in (r'{"nested":[{"Account\u004bey":"fixture-only"}]}',
                      '{"SharedAccessSignature":"fixture-only","SharedAccessSignature":null}',
                      json.dumps([json.dumps({"password": "fixture-only"})]),
                      r'{"url":"postgresql:\/\/user:fixture-only@host/db"}'):
            for side in ("before", "after"):
                row = dict(name="APP_SETTINGS", before=None, after=None)
                row[side] = value
                with self.subTest(side=side, encoding=value[:10]):
                    self.assert_inline_denied(dict(envAllowlist=["APP_SETTINGS"], showValues=["APP_SETTINGS"],
                        configDelta={"env": [row], "aliases": {"backend": ["fixture-only"]}}))
        self.assert_inline_denied(dict(configDelta={"aliases": {"backend": ["ok"]}},
                                      envAllowlist=["ACCOUNT_KEY"], showValues=["ACCOUNT_KEY"]))

    def test_DEP_58QB_01_opaque_literals_remain_digests_through_dispatch(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        names = ["SETTING_A", "SETTING_B", "OPAQUE_SETTINGS", "SPRING_FLYWAY_ENABLED"]
        rows = [dict(name=name, before="enabled", after="disabled") for name in names]
        case.rt.docs[fixture.OLD]["Config"]["Env"].extend(name + "=enabled" for name in names)
        case.p.update(migration={"mode": "none", "rollbackCompatible": True},
                      envAllowlist=names, showValues=names, configDelta={"env": rows})
        call, req = case.governed_dispatch()
        summary, out, err = io.StringIO(), io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self.assertNoLogs():
            result = call(0)
            with operation.public_output.scope(case.p, req["run"]):
                expected = config_delta.approval_lines({"env": rows}, names)
            self.assertEqual(result["approvalLines"], expected)
            self.assertEqual(len({line.split()[4] for line in expected}), len(names))
            with patch.object(sys, "path", list(sys.path)):
                render = runpy.run_path(str(fixture.ROOT / ".github/scripts/module-release.py"))["module_review"]
                render(summary, req["module"], "plan", result, "apply", None)
            req.update(phase="apply", digest=result["digest"])
            applied = call(1)
            self.assertEqual(applied["status"], "READY")
            req.update(phase="rollback", run="2")
            returned = call(1)
            self.assertEqual(returned["status"], "ROLLED_BACK")
        outputs = [summary.getvalue(), out.getvalue(), err.getvalue(), json.dumps([result, applied, returned])]
        for output in outputs:
            self.assertNotRegex(output, "enabled|disabled")

    def fingerprint_scope(self, run="1"):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        key = directory / ".release-hmac.key"
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(32))
        return operation.public_output.scope({"journal": str(directory), "fingerprintKeyFile": str(key), "module": "mcp"}, run)

    def test_hmac_depends_on_field_run_and_private_key(self):
        case = fixture.ReleaseTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        output = operation.public_output
        def marks(run):
            with output.scope(case.p, run):
                return [output.fingerprint(["env", field, "after"], "apply") for field in ("SETTING_A", "SETTING_B")]
        original = marks("1")
        self.assertEqual(original, marks("1"))
        self.assertEqual(len(set(original + marks("2"))), 4)
        path = Path(case.p["fingerprintKeyFile"])
        path.write_bytes(os.urandom(32))
        self.assertTrue(set(original).isdisjoint(marks("1")))
        path.unlink()
        with self.assertRaisesRegex(Held, "^FINGERPRINT_KEY_UNAVAILABLE$"):
            marks("1")

    def test_DEP_58QB_01_show_values_with_all_four_public_literals(self):
        self.enterContext(self.fingerprint_scope())
        flag = "SPRING_FLYWAY_ENABLED"
        for before, after in (("true", "false"), ("enabled", "disabled")):
            public = dict(name=flag, before=before, after=after)
            self.assertRegex(config_delta.approval_lines({"env": [public]}, [flag])[0],
                             rf'^ENV {flag} da sha256 [a-f0-9]{{64}} a "{after}"$')
            for name in ("SNMP_COMMUNITY", "DB_DSN", "DB_PASSWORD", "SERVICE_SECRET", "ACCESS_TOKEN",
                         "SIGNING_KEY", "DB_CONNECTION_STRING"):
                with self.subTest(name=name, before=before):
                    private = dict(name=name, before=after, after=before)
                    delta = {"env": [public, private]}
                    with self.assertRaisesRegex(Held, "^CONFIG_DELTA_INLINE_SECRET$"):
                        config_delta.approval_lines(delta, [name, flag])

    def test_DEP_58QG_01_approval_grammar_at_both_boundaries(self):
        row = {"name": "OPAQUE", "before": None, "after": "ENV"}
        with self.fingerprint_scope():
            self.assertTrue(config_delta.approval_lines({"env": [row]}, ["OPAQUE"])[0].startswith("ENV OPAQUE da sha256 "))
        stream = io.StringIO()
        with patch.object(sys, "path", list(sys.path)), redirect_stdout(stream):
            render = runpy.run_path(str(fixture.ROOT / ".github/scripts/module-release.py"))["module_review"]
            forged = {"status": "PLANNED", "digest": "a" * 64, "approvalLines": ["Alias " + self.marker]}
            with self.assertRaisesRegex(SystemExit, "Righe di approvazione"):
                render(stream, "mcp", "plan", forged, "apply", None)
        self.assertEqual(stream.getvalue(), "")

    def test_public_flag_may_coincide_with_inherited_label(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        flag = "SPRING_FLYWAY_ENABLED"
        case.rt.docs[fixture.OLD]["Config"]["Labels"]["AccountKey"] = "enabled"
        case.p.update(envAllowlist=[flag], showValues=[flag], configDelta={"env": [
            dict(name=flag, before=None, after="enabled")]})
        plan = operation.plan(case.p, case.rt)
        self.assertEqual(plan["status"], "PLANNED", plan)
        self.assertTrue(plan["plan"]["approvalLines"][0].endswith(' a "enabled"'))

    def test_inherited_credential_matching_env_name_through_dispatch(self):
        marker = "SETTING_FROM_PROFILE"
        for source in ("label", "env", "dsn", "PGPASSWORD", "jdbc-braces", "migration-dsn", "label-argv", "job", "psql"):
            with self.subTest(source=source):
                case = fixture.ReleaseTest()
                case.setUp()
                self.addCleanup(case.doCleanups)
                config = case.rt.docs[fixture.OLD]["Config"]
                if source == "migration-dsn":
                    case.p["migration"] = dict(mode="dedicated", rollbackCompatible=True,
                                               command=["migrate", f"host=db password={marker}"])
                elif source == "psql":
                    fixture.dedicated_profile(case.p)
                    config["Labels"]["client"] = "psql --password mcp"
                elif source == "label-argv":
                    config["Labels"]["argv"] = json.dumps(["--token", marker])
                elif source == "job":
                    config["Labels"]["AccountKey"] = "apply"
                elif source == "env":
                    config["Env"].append("DB_PASSWORD=" + marker)
                elif source in ("PGPASSWORD", "jdbc-braces"):
                    config["Labels"]["settings"] = ("PGPASSWORD=" + marker if source == "PGPASSWORD" else
                                                    f"jdbc:sqlserver://db;password={{{marker}}};user=test")
                else:
                    config["Labels"]["AccountKey" if source == "label" else "database.url"] = (
                        marker if source == "label" else f"postgresql://user:{marker}@db/test")
                case.p.update(envAllowlist=[marker], configDelta={"env": [
                    dict(name=marker, before=None, after="on")]})
                call, req = case.governed_dispatch()
                summary, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    if source == "migration-dsn":
                        with self.assertRaisesRegex(mandate.Held, "^MIGRATION_COMMAND_NOT_ALLOWED$"):
                            call(0)
                        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
                        continue
                    result = call(0)
                    self.assertEqual(result["status"], "PLANNED")
                    with patch.object(sys, "path", list(sys.path)):
                        render = runpy.run_path(str(fixture.ROOT / ".github/scripts/module-release.py"))["module_review"]
                        render(summary, case.p["module"], "plan", result, "apply", None)
                self.assertIn("ENV " + marker + " da ", summary.getvalue())
                self.assertIn("Job apply ", stdout.getvalue().replace("%0A", "\n"))
                self.assertFalse((case.root / "1" / "plan.held").exists())

    def test_public_cid_in_residual_after_early_artifact_failure(self):
        case = fixture.ReleaseTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        next(case.root.glob("*.zip")).write_bytes(b"changed")
        case.rt.docs[fixture.OLD]["Config"]["Labels"]["AccountKey"] = fixture.OLD
        call, _ = case.governed_dispatch()
        with self.assertRaisesRegex(mandate.Held, "ARTIFACT_DIGEST_CHANGED owner="):
            call(0)
        self.assertEqual(operation.read(case.root / "1", "plan.held")["residual"]["container"]["cid"], fixture.OLD)

    def test_credential_components_and_boundaries(self):
        from tools.module_release.contract import credential_name
        for name in ("PASSWORD", "UserPasswd", "DB.PWD", "client-secret", "myOAuthToken", "x.APIKEY.id",
                     "AccountKeyId", "authorPrivateKeyPath", "Credential", "credentials", "SAS",
                     "SharedAccessSignature", "DB_CONNECTION_STRING", "dsn", "ACCESS_KEY"):
            self.assertTrue(credential_name(name), name)
        for name in ("TOKENIZER", "TOKENIZER_STATUS", "KEYBOARD_LAYOUT", "PASSAGE", "SECRETARY",
                     "MONKEY", "KEY_ID", "ACCESS_KEY_STATUS"):
            self.assertFalse(credential_name(name), name)

    def test_DEP_58QD_01_alias_collisions_cover_substrings_and_overlapping_values(self):
        delta = {"env": [dict(name="SETTING", before="private-value", after="private-value-long")],
                 "aliases": {"backend": ["private-value-long", "prefix-private-value-suffix"]}}
        self.enterContext(self.fingerprint_scope())
        lines = config_delta.approval_lines(delta, ["SETTING"])
        self.assertNotIn("private-value", "".join(lines))
        self.assertNotIn(operation.digest("private-value-long"), lines[-2])
        self.assertNotIn(operation.digest("prefix-private-value-suffix"), lines[-1])

    def test_DEP_58QD_03_secrets_absent_from_every_output(self):
        from random import Random
        rng = Random(58)
        for option in ("password", "client-secret", "access-token"):
            for inline in (True, False):
                with self.subTest(option=option, inline=inline):
                    case = fixture.ReleaseTest()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    secrets = ["private-" + rng.randbytes(12).hex() for _ in range(5)]
                    before, after, arg, migration, nested = secrets
                    net = next(iter(case.p["networks"]))
                    case.p["networks"][net]["aliases"].append("old-" + before)
                    def argv(value):
                        return ["--" + option + "=" + value] if inline else ["--" + option, value]
                    command = ["fixture-migrate", *argv(migration), "prefix-" + before]
                    case.p["gate"]["command"].extend(argv(arg))
                    case.p.update(migration={"mode": "dedicated", "command": command, "rollbackCompatible": True,
                                             "options": {"credentials": {"password": nested}}},
                                  envAllowlist=["SNMP_COMMUNITY", "SETTING"],
                                  configDelta={"env": [dict(name="SNMP_COMMUNITY", before=before, after=after),
                                                       dict(name="SETTING", before=None, after=arg)],
                                               "aliases": {net: [after, "alias-" + arg, "alias-" + migration, nested]}})
                    case.rt = fixture.Engine(case.p, case.rt.blob)
                    case.rt.docs[fixture.OLD]["Config"]["Env"].append("SNMP_COMMUNITY=" + before)
                    call, req = case.governed_dispatch()
                    out, err = io.StringIO(), io.StringIO()
                    initial = {p: p.read_bytes() for p in case.root.rglob("*") if p.is_file()}
                    with redirect_stdout(out), redirect_stderr(err), self.assertNoLogs():
                        reason = "CONFIG_DELTA_INLINE_SECRET"
                        with self.assertRaisesRegex(mandate.Held, f"^{reason}$") as denied:
                            call(0)
                    self.assertEqual(initial, {p: p.read_bytes() for p in case.root.rglob("*") if p.is_file()})
                    for secret in secrets:
                        self.assertNotIn(secret, str(denied.exception) + out.getvalue() + err.getvalue())

    def test_DEP_58LI_01_presence_precedes_profile_validation(self):
        for delta in (None, {}, [], "", False, 0, self.marker):
            with self.subTest(delta_type=type(delta).__name__):
                with self.assertRaises(Held) as denied:
                    validate({"configDelta": delta})
                self.assertEqual(str(denied.exception), "EMPTY_DELTA" if delta == {} else self.code)

    def test_DEP_58Q_01_credentials_never_published(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        name = "AZURE_STORAGE_CONNECTION_STRING"
        case.p.update(envAllowlist=[name], showValues=[name])
        for side in ("before", "after"):
            case.p["configDelta"] = {"env": [{"name": name, "before": None, "after": None,
                                            side: "AccountName=fixture;AccountKey=" + self.marker}]}
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err, self.assertNoLogs():
                plan = operation.plan(case.p, case.rt)
                apply = operation.apply(case.p, "a" * 64, case.rt)
            self.assertEqual((plan["reason"], apply["reason"]), ("CONFIG_DELTA_INLINE_SECRET", "CONFIG_DELTA_INLINE_SECRET"))
            self.assertNotIn(self.marker, json.dumps([plan, apply, out.getvalue(), err.getvalue()]))
            self.assertFalse(list(case.root.rglob("*.json")))

    def test_DEP_58Q_23_governed_credential_outputs(self):
        for side in ("before", "after"):
            with self.subTest(side=side):
                case = fixture.ReleaseTest()
                self.addCleanup(case.doCleanups)
                case.setUp()
                name = "AZURE_STORAGE_CONNECTION_STRING"
                row = {"name": name, "before": None, "after": None, side: "AccountKey=" + self.marker}
                case.p.update(configDelta={"env": [row]}, envAllowlist=[name], showValues=[name])
                call, _ = case.governed_dispatch()
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err), self.assertNoLogs(), \
                     self.assertRaisesRegex(mandate.Held, "CONFIG_DELTA_INLINE_SECRET") as held:
                    call(0)
                self.assertNotIn(self.marker, out.getvalue() + err.getvalue() + str(held.exception))
                for path in case.root.rglob("*"):
                    if path.is_file() and path.suffix != ".zip":
                        self.assertNotIn(self.marker.encode(), path.read_bytes(), path.name)
        # A free-form value cannot be classified by its spelling alone.
        self.enterContext(self.fingerprint_scope())
        opaque = {"env": [{"name": "SETTINGS", "before": None, "after": self.marker}]}
        self.assertNotIn(self.marker, json.dumps(config_delta.approval_lines(opaque, ["SETTINGS"])))

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
        self.assert_ingresses_deny({"configDelta": self.marker}, self.code)

    def assert_ingresses_deny(self, options, reason):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        journal = root / "journal"
        bootstrap = installer_fixture.Bootstrap()
        self.addCleanup(bootstrap.doCleanups)
        bootstrap.setUp()
        inst = bootstrap.inst
        cfg = json.loads(bootstrap.path.read_bytes())
        p = cfg["modules"]["mcp"]
        p.update(options, journal=str(journal))
        first = dict(setup_profile(str(journal)), **options)
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
            self.assertEqual(output, (1, "", reason + "\n"))

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
                                          (module_operation, "Journal"),
                                          (transport, "github"), (inst, "manifest"), (inst, "install"),
                                          (inst, "installation_lock"),
                                          (store, "begin_plan"), (store, "consume_approval"))]
            if reason == "INVALID_DELTA":
                guards.append(enter(patch.object(inst.subprocess, "check_output", side_effect=AssertionError("git"))))
            for name, invoke in cases:
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(ingress=name), redirect_stdout(out), redirect_stderr(err), self.assertNoLogs(level="DEBUG"):
                    try:
                        result = invoke()
                    except (Held, mandate.Held, SystemExit, ValueError) as exc:
                        self.assertEqual(str(exc), reason)
                    else:
                        if name.startswith("executor.module-"):
                            self.assertIsNone(result)  # cli() asserted status, stdout, stderr and both locks
                        else:
                            self.assertEqual((result["status"], result["reason"]), ("HELD", reason))
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
        self.assertNotIn(self.case.inst.sha(before), json.dumps(plan))
        self.assertRegex(row["before"]["hmacSha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(self.case.inst.sha(self.clean), json.dumps(plan))
        self.assertNotEqual(row["after"]["hmacSha256"], row["before"]["hmacSha256"])
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


class FingerprintPerimeter(unittest.TestCase):
    def test_DEP_58QL_01_log_token_request_frame_and_profile(self):
        for delta in (False, True):
            with self.subTest(delta=delta):
                case = fixture.ReleaseTest()
                case.setUp()
                self.addCleanup(case.doCleanups)
                p, old = case.p, case.rt.docs[fixture.OLD]
                old["HostConfig"]["LogConfig"] = {"Type": "splunk", "Config": {"splunk-token": "apply"}}
                if delta:
                    p["configDelta"] = {"aliases": {next(iter(p["networks"])): ["test-alias"]}}
                result = operation.plan(p, case.rt)
                plan = result["plan"]
                request = (operation.reviewed.request(p, old, {}) if delta else
                           operation.request(old, p["ci"]["imageId"], operation.provenance_labels(p)))
                with operation.public_output.scope(p):
                    operation.public_output.use_plan(plan)
                    self.assertEqual(plan["requestSha256"], operation.public_output.fingerprint("request", request))
                    self.assertEqual(plan["oldFrameSha256"], operation.snapshot(old))
                self.assertNotEqual(plan["profileSha256"], operation.digest(p))
                with patch("tools.module_release.frame.frame_binding", side_effect=lambda name, doc, value: operation.digest(value)):
                    self.assertNotEqual(plan["oldFrameSha256"], operation.snapshot(old))
                self.assertNotEqual(plan["requestSha256"], operation.digest(request))
                Path(p["fingerprintKeyFile"]).unlink()
                self.assertEqual(operation.plan(p, case.rt)["reason"], "FINGERPRINT_KEY_UNAVAILABLE")

    def test_DEP_58QL_02_install_review_and_custody(self):
        for file_env in (True, False):
            with self.subTest(file_env=file_env), pinned_install(secrets.token_bytes(32), file_env=file_env) as inputs:
                p, rt, target, pin = inputs
                proposal = install.plan(p, rt)
                plan, stamp = proposal["plan"], proposal["planSha256"]
                shown = plan["review"]["binds"][-1]["hmacSha256"]
                self.assertEqual(plan["preconditions"]["bindCustody"][-1]["hmacSha256"], shown)
                with operation.public_output.scope(p):
                    self.assertEqual(shown, operation.public_output.fingerprint(["install.bind", target], pin))
                ready = install.apply(p, stamp, rt)
                self.assertEqual(ready["status"], "READY", ready)
                self.assertEqual(install.apply(p, stamp, rt), ready)
                self.assertEqual(install.rollback(p, stamp, rt)["status"], "ROLLED_BACK")
                for secret in (pin, p["fingerprintKeyFile"], operation.digest(p)):
                    self.assertNotIn(secret, json.dumps([proposal, ready]))

    def test_DEP_58QL_03_oci_and_archive_pins(self):
        case = fixture.ReleaseTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        blob = fixture.artifact(case.p, case.root, image_env=["PGPASSWORD=fixture"])
        plan = operation.plan(case.p, case.rt)["plan"]
        self.assertEqual(plan["ci"]["imageId"], case.p["ci"]["imageId"])
        self.assertEqual(plan["archiveSha256"], hashlib.sha256(blob).hexdigest())
        self.assertIn("fingerprintRun", plan)

    def test_DEP_58QL_04_manifest_public_and_private_sides(self):
        case = installer_fixture.Bootstrap()
        case.setUp()
        self.addCleanup(case.doCleanups)
        policy = json.loads(case.path.read_bytes())
        del policy["modules"]["vertical-mock"]
        case.path.write_text(json.dumps(policy))
        files = case.inst.inspect(case.path)
        profile = case.inst.ROOT / "profile.json"
        data, mode = files[profile]
        key = Path(policy["fingerprintKeyFile"])
        key.unlink()
        expected = case.inst.fingerprint(data, mode)
        self.assertEqual(case.inst.manifest(files)[str(profile)]["after"], expected)
        case.inst.ROOT.mkdir()
        old = json.loads(data)
        old["modules"]["mcp"]["migration"]["options"] = {"PGPASSWORD": "fixture"}
        profile.write_text(json.dumps(old))
        with self.assertRaisesRegex(ValueError, "^FINGERPRINT_KEY_UNAVAILABLE$"):
            case.inst.manifest(files)
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(32))
        row = case.inst.manifest(files)[str(profile)]
        self.assertIn("hmacSha256", row["before"])
        self.assertEqual(row["after"], expected)
        self.assertNotIn(fixture.sha(profile.read_bytes()), json.dumps(row))

    def test_DEP_58QL_05_clean_delta_requires_no_key(self):
        case = fixture.ReleaseTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        Path(case.p["fingerprintKeyFile"]).unlink()
        case.p.update(configDelta={"env": [dict(name="FEATURE", before=None, after="off")]}, envAllowlist=["FEATURE"])
        proposal = operation.plan(case.p, case.rt)
        self.assertEqual(proposal["status"], "PLANNED", proposal)
        self.assertNotIn("fingerprintRun", proposal["plan"])
        self.assertRegex(proposal["plan"]["approvalLines"][0], "^ENV FEATURE da sha256 ")


    def release_case(self):
        case = fixture.ReleaseTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_DEP_58QL_06_command_review(self):
        case = self.release_case()
        cmd = case.p["gate"]["command"] + ["--client.password=fixture"]
        case.p["gate"]["command"] = cmd
        case.p["candidate"] = {"removeArgs": cmd[-1:]}
        old = case.rt.docs[fixture.OLD]
        old["Config"]["Cmd"], old["Args"] = cmd, fixture.ENTRY[1:] + cmd
        review = operation.plan(case.p, case.rt)["plan"]["candidateReview"]
        with operation.public_output.scope(case.p):
            for name, args in (("predecessorCmdSha256", cmd), ("candidateCmdSha256", cmd[:-1])):
                self.assertEqual(review[name], operation.public_output.fingerprint("command", args))

    def test_DEP_58QL_07_migration_review(self):
        case = self.release_case()
        fixture.dedicated_profile(case.p)
        case.p["migration"]["options"] = {"DB_PASSWORD": "apply"}
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        result = operation.apply(case.p, stamp, case.rt, defer_migration=True)
        stage = operation.read(case.root / stamp, "migration-plan.json")
        with operation.public_output.scope(case.p):
            self.assertEqual(result["migrationSha256"], operation.public_output.fingerprint("migration-plan", stage))
        self.assertNotEqual(result["migrationSha256"], operation.digest(stage))

    def test_DEP_58QL_08_recovery_journal(self):
        case = self.release_case()
        case.rt.docs[fixture.OLD]["Config"]["Env"].append("PGPASSWORD=apply")
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        with patch.object(case.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(case.p, stamp, case.rt)
        # The supported legacy journal contains the full predecessor inspect.
        name = "baseline.private.json"
        old = fixture.Engine(case.p, case.rt.blob).docs[fixture.OLD]
        old["Config"]["Env"].append("PGPASSWORD=apply")
        path = case.root / stamp / name
        path.write_text(json.dumps(old))
        proposal = recovery.proposal(case.p, case.rt)
        baseline = operation.read(case.root / stamp, name)
        with operation.public_output.scope(case.p):
            self.assertEqual(proposal["journal"][name], operation.public_output.fingerprint(["journal", name], baseline))

    def test_DEP_58QL_09_delta_review_and_receipt(self):
        case = self.release_case()
        old = case.rt.docs[fixture.OLD]
        old["Config"]["Labels"]["splunk-token"] = "fixture"
        net = next(iter(case.p["networks"]))
        delta = {"env": [dict(name="FEATURE", before=None, after="off")], "aliases": {net: ["candidate"]}}
        case.p.update(configDelta=delta, envAllowlist=["FEATURE"], migration={"mode": "none", "rollbackCompatible": True})
        proposal = operation.plan(case.p, case.rt)
        plan = proposal["plan"]
        receipt = operation.apply(case.p, proposal["planSha256"], case.rt)
        with operation.public_output.scope(case.p):
            operation.public_output.use_plan(plan)
            self.assertEqual(receipt["configDeltaSha256"], operation.public_output.fingerprint("configDelta", delta))
            self.assertEqual(receipt["successorFrameSha256"], operation.snapshot(case.rt.inspect(fixture.NEW)))
        self.assertTrue(all("hmac-sha256" in line for line in plan["approvalLines"]))

    def test_DEP_58QL_10_manifest_key_file_origin(self):
        case = installer_fixture.Bootstrap()
        case.setUp()
        self.addCleanup(case.doCleanups)
        policy = json.loads(case.path.read_bytes())
        # A managed name that looks like code is also declared as a key source.
        path = case.inst.ROOT / "lib" / "archiveSha256.py"
        policy["gateway"]["keyFile"] = str(path)
        case.path.write_text(json.dumps(policy))
        files = case.inst.inspect(case.path)
        data = secrets.token_bytes(32)
        files[path] = data, 0o600
        spec = case.inst.manifest(files)
        self.assertIn("hmacSha256", spec[str(path)]["after"])
        self.assertNotIn(hashlib.sha256(data).hexdigest(), json.dumps(spec))


    def test_DEP_58QM_03_manifest_tls_client_key(self):
        from tools.module_release.fingerprints import mac
        case = installer_fixture.Bootstrap()
        case.setUp()
        self.addCleanup(case.doCleanups)
        policy = json.loads(case.path.read_bytes())
        module = policy["modules"]["onboarding"]
        path = case.inst.ROOT / "lib" / "client-key"
        module["readiness"]["tls"] = dict(address=next(iter(module["networks"].values()))["ipv4"],
            serverName="fixture.local", caFile=str(path.with_name("ca")), clientCertFile=str(path.with_name("cert")),
            clientKeyFile=str(path))
        case.path.write_text(json.dumps(policy))
        files = case.inst.inspect(case.path)
        path.parent.mkdir(parents=True)
        before, after = secrets.token_bytes(32), secrets.token_bytes(32)
        path.write_bytes(before)
        files[path] = after, 0o600
        manifest = case.inst.manifest(files)
        runs = {name: [profile["ci"][k] for k in ("repository", "runId", "runAttempt")]
                for name, profile in policy["modules"].items()}
        key = Path(policy["fingerprintKeyFile"]).read_bytes()
        for side, data in (("before", before), ("after", after)):
            row = manifest[str(path)][side]
            self.assertEqual(set(row), {"mode", "hmacSha256"})
            self.assertEqual(row["hmacSha256"], mac(key, [policy["commit"], runs], "lib/client-key", data.hex()))
            self.assertNotIn(hashlib.sha256(data).hexdigest(), json.dumps(manifest))

    def test_DEP_58QL_11_installation_key_across_modules(self):
        import test_module_release_mcp as mcp
        onboarding = self.release_case()
        other = mcp.Release()
        other.setUp()
        self.addCleanup(other.doCleanups)
        key = onboarding.p.pop("fingerprintKeyFile")
        Path(other.p.pop("fingerprintKeyFile")).unlink()
        other.cfg["fingerprintKeyFile"] = key
        for case in (onboarding, other):
            case.rt.docs[fixture.OLD]["Config"]["Env"].append("PGPASSWORD=test")
            with operation.public_output.scope(case.p, "1", key_path=key):
                result = operation.plan(case.p, case.rt)
            self.assertEqual(result["status"], "PLANNED", result)
            self.assertNotIn(key, json.dumps(result))
        self.assertEqual(other.planned()["digest"], result["planSha256"])

    def test_DEP_58QL_12_install_request_and_stable_frame(self):
        import test_module_install as first
        case = first.InstallTest()
        case.setUp()
        self.addCleanup(case.doCleanups)
        key = case.root / ".release-hmac.key"
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(32))
        case.p["fingerprintKeyFile"] = str(key)
        case.p["install"]["env"].append({"name": "READ_TOKEN_FILE", "value": "/token"})
        case.p["install"]["binds"].append({"mode": "ro", "target": "/token", "source": "/srv/fixture/ro"})
        plan = install.plan(case.p, case.rt)
        stamp, body = plan["planSha256"], plan["plan"]
        self.assertEqual(install.apply(case.p, stamp, case.rt)["status"], "READY")
        with operation.public_output.scope(case.p):
            operation.public_output.use_plan(body)
            req = install.approved_create(case.p, case.root / stamp, body, case.rt.image_defaults(case.p["ci"]["imageId"]))
            claim = operation.read(case.root / stamp, "install-intent.json")
            self.assertEqual(claim["requestSha256"], operation.public_output.fingerprint("install.request", req))
            req["Labels"][install.LABEL] = install.EMPTY_LABEL
            self.assertEqual(body["requestSha256"], operation.public_output.fingerprint("install.request", req))
            gate = operation.read(case.root / stamp, "gate-run.json")
            proof = install.park_proof(case.rt.inspect(gate["cid"]))
            self.assertEqual(proof["stableFrameSha256"], gate["stableFrameSha256"])

    def test_DEP_58QL_13_bootstrap_key_read_faults(self):
        case = installer_fixture.Bootstrap()
        case.setUp()
        self.addCleanup(case.doCleanups)
        files = case.inst.inspect(case.path)
        profile = case.inst.ROOT / "profile.json"
        case.inst.ROOT.mkdir()
        profile.write_bytes(files[profile][0])
        key = json.loads(profile.read_bytes())["fingerprintKeyFile"]
        real_open = os.open
        for fault in (None, 1, 2):
            count = 0
            def open_key(path, flags, *args, **kwargs):
                nonlocal count
                if path == key:
                    count += 1
                    if count == fault:
                        raise OSError("injected")
                return real_open(path, flags, *args, **kwargs)
            with patch.object(os, "open", open_key):
                if fault:
                    with self.assertRaisesRegex(ValueError, "^FINGERPRINT_KEY_UNAVAILABLE$"):
                        case.inst.manifest(files)
                else:
                    case.inst.manifest(files)
            self.assertEqual(count, fault or 2)
        print("I/O installer manifest: 2 injected key reads")

    def test_DEP_58QL_14_install_key_read_faults(self):
        def replay(fault):
            events = []
            with pinned_install(b"fixture") as (p, rt, _, _):
                real_open = os.open
                def opened(path, flags, *args, **kwargs):
                    if path == p["fingerprintKeyFile"]:
                        events.append(phase)
                        if len(events) == fault:
                            raise OSError("injected")
                    return real_open(path, flags, *args, **kwargs)
                with patch.object(os, "open", opened):
                    for phase in ("plan", "apply", "resume", "replay", "rollback"):
                        if phase == "plan":
                            result = install.plan(p, rt)
                        elif phase == "resume":
                            result = install.plan(p, rt, resume=stamp)
                        elif phase == "rollback":
                            result = install.rollback(p, stamp, rt)
                        else:
                            result = install.apply(p, stamp, rt)
                        if result["status"] == "HELD":
                            return events, result["reason"]
                        stamp = result["planSha256"]
            return events, result["status"]
        trace, status = replay(None)
        self.assertEqual((set(trace), status), ({"plan", "apply", "resume", "replay", "rollback"}, "ROLLED_BACK"))
        for i in range(1, len(trace) + 1):
            self.assertEqual(replay(i), (trace[:i], "FINGERPRINT_KEY_UNAVAILABLE"))
        print(f"I/O first install: {len(trace)} injected key reads")


class LibraryTest(unittest.TestCase):
    def test_approval_rejects_credentials_in_either_preimage_or_replacement(self):
        for name, value in (("DOCKER_AUTH_CONFIG", '{"auths":{"example":{"auth":"fixture"}}}'),
                            ("MYSQL_PWD", "fixture"), ("REDISCLI_AUTH", "fixture"),
                            ("SPRING_APPLICATION_JSON", '{"spring.datasource.password":"fixture"}')):
            for side in ("before", "after"):
                with self.subTest(name=name, side=side):
                    change = {"name": name, "before": None, "after": None, side: value}
                    with self.assertRaisesRegex(Held, "^CONFIG_DELTA_INLINE_SECRET$"):
                        config_delta.approval_lines({"env": [change]}, [name])
