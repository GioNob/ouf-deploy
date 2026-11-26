"""DEP-58LF: execute both releases against the same MCP archive, profile and Engine."""
import ast
import copy
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from http.client import HTTPConnection
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import zipfile

import test_module_release as fixture
import test_module_release_mcp as mcp
import test_privileged_executor_install as installer_fixture
from test_module_release_config_delta import executor_with_busy_lock
import mandate
import module_operation
from tools.module_release import frame, operation, recovery, return_operation


# Tip of origin/release/d091-t2-deploy at DN-L1-5. Keep the oracle fixed after merge.
REFERENCE = "6ae7001aee5a845b774f3a6b9d82174aa202ba45"


def installer_plan(root, profile, fail_read=0):
    # Supply private, root-owned metadata for the temporary profile on unprivileged hosts.
    launcher = dedent("""\
        import errno, os, runpy, sys
        from pathlib import Path

        profile, fail_read = sys.argv[1], int(sys.argv[2])
        original_stat, original_read = Path.stat, Path.read_bytes
        def private_stat(path, *args, **kwargs):
            s = original_stat(path, *args, **kwargs)
            return os.stat_result((s.st_mode & ~0o077, *s[1:4], 0, *s[5:]))

        reads = 0
        def read(path):
            global reads
            reads += 1
            if reads == fail_read:
                raise OSError(errno.EIO, "simulated read failure")
            return original_read(path)

        os.geteuid = lambda: 0
        Path.stat, Path.read_bytes = private_stat, read
        sys.argv = ["scripts/install-ouf-a2.py", "plan", profile]
        runpy.run_path(sys.argv[0], run_name="__main__")
        """)
    return subprocess.run([sys.executable, "-I", "-B", "-c", launcher, str(profile), str(fail_read)],
                          cwd=root, capture_output=True, timeout=15)


class Trace:
    """Capture calls at the Docker adapter boundary, before the Engine changes state."""
    def __init__(self, engine, docker, *, create_id=fixture.NEW):
        self.create_id = create_id
        self.engine = engine
        self.docker = docker
        self.calls = []
        self.creates = []

    def create(self, name, body):
        # Exercise this version's Docker.create and Docker.api up to the socket boundary.
        response = Mock(status=201)
        response.read.return_value = json.dumps({"Id": self.create_id}).encode()
        with patch.object(HTTPConnection, "request") as send, patch.object(HTTPConnection, "getresponse",
                                                                         return_value=response):
            cid = self.docker.create(name, body)
        method, path, payload, headers = send.call_args.args
        self.creates.append(payload)
        self.calls.append(json.dumps([method, path, headers, payload.hex()]).encode())
        self.engine.create(name, json.loads(payload))
        return cid

    def __getattr__(self, name):
        method = getattr(self.engine, name)
        if not callable(method):
            return method

        def call(*args, **kwargs):
            if name == "load":
                archive, package = args
                offset = archive.tell()
                recorded = [archive.read().hex(), package]
                archive.seek(offset)
            else:
                recorded = args
            self.calls.append(json.dumps([name, recorded, kwargs]).encode())
            return method(*args, **kwargs)
        return call


class NoDeltaParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.enterClassContext(tempfile.TemporaryDirectory())
        try:
            archive = subprocess.check_output(["git", "archive", "--format=zip", REFERENCE, "tools/module_release",
                                               "scripts/ouf-a2-executor", "scripts/install-ouf-a2.py",
                                               ".github/scripts/module-release.py", ".github/scripts/release_review.py",
                                               "tools/privileged_executor/mandate.py",
                                               "tools/privileged_executor/module_operation.py"],
                                              cwd=fixture.ROOT, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            if "CI" in os.environ:
                raise
            shallow = subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=fixture.ROOT)
            if shallow.strip() == b"true" and subprocess.run(
                    ["git", "cat-file", "-e", REFERENCE], cwd=fixture.ROOT, stderr=subprocess.DEVNULL).returncode:
                raise unittest.SkipTest(f"Shallow checkout lacks reference release {REFERENCE}") from None
            raise
        cls.reference_root = Path(tmp) / "dep58lf_reference"
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            source.extractall(cls.reference_root)
        cls.enterClassContext(patch.object(sys, "path", [tmp, *sys.path]))
        from dep58lf_reference.tools import module_release as reference_package
        from dep58lf_reference.tools.module_release import contract, operation, recovery, retention, return_operation
        from dep58lf_reference.tools.privileged_executor import mandate as reference_mandate
        # The installed executor uses absolute imports from its private lib directory.
        with patch.dict(sys.modules, {"module_release": reference_package, "module_release.contract": contract,
                                      "module_release.retention": retention, "mandate": reference_mandate}):
            from dep58lf_reference.tools.privileged_executor import module_operation as reference_executor
        cls.reference_executor = reference_executor
        cls.reference_mandate = reference_mandate
        cls.reference = (operation, recovery, return_operation)

    def complete_release(self, modules, case, rt, stamp, interrupted):
        op, rec, ret = modules
        p = case.p
        if interrupted:
            # The candidate exists and its CID is journaled, but start has not run.
            with patch.object(case.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                op.apply(p, stamp, rt)
            approved = rec.proposal(p, rt)
            result = rec.resume(p, rt, approved)
        else:
            result = op.apply(p, stamp, rt)
        if p["migration"]["mode"] == "dedicated":
            self.assertEqual(result["status"], "GATED", result)
            stage = result["migrationSha256"]
            if interrupted:
                migrate = case.rt.migrate

                def lost_migration_response(*args):
                    migrate(*args)
                    raise KeyboardInterrupt

                with patch.object(case.rt, "migrate", lost_migration_response), self.assertRaises(KeyboardInterrupt):
                    op.migrate(p, stamp, stage, rt)
                self.assertEqual(rec.resume(p, rt, rec.proposal(p, rt))["migrationSha256"], stage)
            result = op.migrate(p, stamp, stage, rt, recover=interrupted)
        self.assertEqual(result["status"], "READY", result)

        if interrupted and p["migration"]["mode"] == "none":
            signal = case.rt.signal

            def lost_restore_response(cid):
                signal(cid)
                raise KeyboardInterrupt

            with patch.object(case.rt, "signal", lost_restore_response), self.assertRaises(KeyboardInterrupt):
                ret.run(p, stamp, rt)
            returned = ret.run(p, stamp, rt, recover=True)
        else:
            returned = ret.run(p, stamp, rt)
        root = Path(p["journal"]) / stamp
        self.assertEqual(op.read(root, "return-receipt.json"), returned)
        self.assertEqual(op.read(root, "receipt.json"), result)
        if p["migration"]["mode"] == "dedicated":
            self.assertEqual((returned["status"], returned["reason"]), ("HELD", "DATABASE_CHANGED"))
        else:
            self.assertEqual((returned["status"], returned["restoredCid"]), ("ROLLED_BACK", fixture.OLD))

    def run_release(self, modules, case, interrupted, exercise):
        op, rec, _ = modules
        p = case.p
        journal = Path(p["journal"])
        journal.mkdir()
        try:
            rt = Trace(case.rt, op.Docker(p))
            planned = op.plan(p, rt)
            self.assertEqual(planned["status"], "PLANNED", planned)
            stamp = planned["planSha256"]
            if exercise is None:
                self.complete_release(modules, case, rt, stamp, interrupted)
            else:
                exercise(op, rec, case, rt, stamp)
            self.assertEqual(len(rt.creates), 1)
            return {"plan": json.dumps(planned).encode(), "inspect": json.dumps(case.rt.docs).encode(),
                    "CREATE": rt.creates[0], "planSha256": stamp.encode(), "Docker calls": rt.calls,
                    "journal": {f.relative_to(journal): f.read_bytes()
                                for f in journal.rglob("*") if f.is_file()}}
        finally:
            shutil.rmtree(journal)

    def compare(self, mode, interrupted=False, exercise=None):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["journal"] = str(case.root / "journal")
        blob, baseline_db = case.rt.blob, case.db
        self.assertNotIn("configDelta", case.p)
        results = []
        for modules in (self.reference, (operation, recovery, return_operation)):
            case.db = copy.deepcopy(baseline_db)
            case.rt = fixture.Engine(case.p, blob)
            case.rt.database = lambda old: copy.deepcopy(case.db)
            if mode == "dedicated":
                case.dedicated()
            self.assertEqual(case.p["migration"]["mode"], mode)
            results.append(self.run_release(modules, case, interrupted, exercise))
        expected, actual = results
        for key in expected:
            with self.subTest(field=key):
                self.assertEqual(expected[key], actual[key])

    def test_DEP_58Q_10_legacy_flyway_bytes(self):
        self.compare_legacy_flyway_bytes()

    def compare_legacy_flyway_bytes(self):
        import test_module_release_java as java
        import importlib
        with java.fixture("udp") as (p, initial, rows, history):
            p["journal"] = str(Path(p["inbox"]) / "journal")
            journal = Path(p["journal"])
            results = []
            for op, _, ret in (self.reference, (operation, recovery, return_operation)):
                journal.mkdir()
                rt = Trace(copy.deepcopy(initial), op.Docker(p))
                fw = importlib.import_module(op.__package__ + ".flyway")
                with patch.object(fw, "inventory", return_value=rows):
                    plan = op.plan(p, rt)
                    stage = op.apply(p, plan["planSha256"], rt)
                    send = rt.engine.signal
                    def launch(cid):
                        send(cid)
                        if cid == fixture.NEW:
                            history.append(rows[1])
                    with patch.object(rt.engine, "signal", launch):
                        ready = op.migrate(p, plan["planSha256"], stage["migrationSha256"], rt)
                    returned = ret.run(p, plan["planSha256"], rt)
                self.assertEqual((ready["status"], returned["status"]), ("READY", "ROLLED_BACK"))
                results.append((rt.calls, rt.creates, json.dumps([plan, stage, ready, returned, rt.engine.docs]).encode(),
                                {f.relative_to(journal): f.read_bytes() for f in journal.rglob("*") if f.is_file()}))
                del history[1:]
                shutil.rmtree(journal)
            self.assertEqual(*results)

    def test_DEP_58Q_11_first_install_bytes(self):
        self.compare_first_install_bytes()

    def compare_first_install_bytes(self):
        import importlib
        import test_module_install as first
        with tempfile.TemporaryDirectory() as tmp:
            p = first.setup_profile(tmp)
            blob = fixture.artifact(p, Path(tmp))
            journal = Path(tmp) / "journal"
            p["journal"] = str(journal)
            results = []
            for op in (self.reference[0], operation):
                journal.mkdir()
                install = importlib.import_module(op.__package__ + ".install_operation")
                spec = importlib.import_module(op.__package__ + ".frame_spec")
                engine = first.Engine(p, blob)
                rt = Trace(engine, op.Docker(p), create_id=fixture.OLD)
                with patch.object(spec, "bind_facts", return_value=({}, {"ino": 42})):
                    plan = install.plan(p, rt)
                    ready = install.apply(p, plan["planSha256"], rt)
                    returned = install.rollback(p, plan["planSha256"], rt)
                self.assertEqual(ready["status"], "READY", ready)
                self.assertEqual(returned["status"], "ROLLED_BACK", returned)
                results.append((rt.calls, rt.creates, json.dumps([plan, ready, returned, engine.docs]).encode(),
                                {f.relative_to(journal): f.read_bytes() for f in journal.rglob("*") if f.is_file()}))
                shutil.rmtree(journal)
            self.assertEqual(*results)

    def test_DEP_58Q_17_legacy_none_denial_and_public_annotation(self):
        self.compare_legacy_none_denial_and_public_annotation()

    def compare_legacy_none_denial_and_public_annotation(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["migration"] = {"mode": "none", "rollbackCompatible": True}
        outputs = []
        for modules, source in ((self.reference, self.reference_root), ((operation, recovery, return_operation), fixture.ROOT)):
            op, _, ret = modules
            rt = Trace(copy.deepcopy(case.rt), op.Docker(case.p))
            planned = op.plan(case.p, rt)
            stamp = planned["planSha256"]
            with self.assertRaisesRegex(op.Held, "^INVALID_RETURN_PLAN$") as held:
                ret.run(case.p, stamp, rt)
            public = {"status": planned["status"], "digest": stamp, "candidateImageId": case.p["ci"]["imageId"],
                      "predecessorImageId": case.p["oldImage"]}
            summary, annotation = io.StringIO(), io.StringIO()
            with patch.object(sys, "path", list(sys.path)), patch.dict(sys.modules), redirect_stdout(annotation):
                sys.modules.pop("release_review", None)
                render = runpy.run_path(str(source / ".github/scripts/module-release.py"))["module_review"]
                render(summary, case.p["module"], "plan", public, "apply", None)
            outputs.append((json.dumps(planned).encode(), rt.calls, summary.getvalue().encode(),
                            annotation.getvalue().encode(), str(held.exception).encode()))
        self.assertEqual(*outputs)

    def test_DEP_58Q_22_reference_from_design(self):
        import importlib
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "dep58q_design"
            archive = subprocess.check_output(["git", "archive", "--format=zip", "c8851aba", "tools/module_release",
                                               ".github/scripts/module-release.py", ".github/scripts/release_review.py"],
                                              cwd=fixture.ROOT)
            with zipfile.ZipFile(io.BytesIO(archive)) as files:
                files.extractall(source)
            with patch.object(sys, "path", [directory, *sys.path]):
                self.reference = tuple(importlib.import_module("dep58q_design.tools.module_release." + name)
                                       for name in ("operation", "recovery", "return_operation"))
                self.reference_root = source
                self.compare("none")
                self.compare("none", interrupted=True)
                self.compare("dedicated", interrupted=True)
                self.compare_legacy_flyway_bytes()
                self.compare_first_install_bytes()
                self.compare_legacy_none_denial_and_public_annotation()

    def test_DEP_58LF_05_none(self):
        self.compare("none", interrupted=False)

    def test_DEP_58LJ_04_busy_lock_public_error_matches_release(self):
        profile = json.loads(fixture.PROFILE.with_name("mcp.example.json").read_bytes())
        self.assertNotIn("configDelta", profile)
        reference = executor_with_busy_lock(self.reference_root, self.reference_mandate, profile)
        actual = executor_with_busy_lock(fixture.ROOT, mandate, profile)
        self.assertEqual(reference, ((1, "", "A2_EVIDENCE_UNPROVEN/BlockingIOError@ouf-a2-executor:54\n"), 1, 1))
        self.assertEqual(actual, reference)

    def test_DEP_58LL_03_apply_without_review_request_matches_release(self):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        req = dict(case.req, phase="apply", digest="a" * 64)
        outcomes = []
        for name, executor in (("release", self.reference_executor), ("candidate", module_operation)):
            root = case.root / name
            root.mkdir()
            with patch.object(executor.operation, "Docker", return_value=case.rt):
                owner = executor.ModuleRelease(case.cfg, root, req)
                (owner.path / "plan.review").write_bytes(b'{"review":"fixture"}')
                with self.assertRaises(executor.Held) as held:
                    owner.execute("fixture")
            receipt = (owner.path / "apply.held").read_bytes()
            outcomes.append((str(held.exception), receipt))
        self.assertEqual(json.loads(outcomes[0][1])["reason"],
                         "RELEASE_IO_OR_INPUT_ERROR/KeyError@module_operation.py:186")
        self.assertEqual(outcomes[1], outcomes[0])

    def test_DEP_58LL_04_executor_dispatch_error_matches_release(self):
        outcomes = []
        for root in (self.reference_root, fixture.ROOT):
            with patch.object(sys, "path", list(sys.path)), patch.object(sys, "dont_write_bytecode", True):
                executor = runpy.run_path(str(root / "scripts/ouf-a2-executor"))
            dispatch = executor["dispatch"]
            with patch.dict(dispatch.__globals__, authorize=Mock(), ModuleRelease=Mock(side_effect=OSError)):
                try:
                    dispatch({"operation": "module-release"}, {}, None, None)
                except OSError as error:
                    outcomes.append(executor["public_error"](error))
                else:
                    self.fail("missing dispatch error")
        self.assertEqual(outcomes[0], "A2_EVIDENCE_UNPROVEN/OSError@ouf-a2-executor:33")
        self.assertEqual(outcomes[1], outcomes[0])

    def test_DEP_58LL_05_malformed_profile_retains_release_diagnostic(self):
        expected = self.reference[0].plan(None, runtime=object())
        self.assertEqual(expected["reason"], "RELEASE_IO_OR_INPUT_ERROR/TypeError@contract.py:87")
        self.assertEqual(operation.plan(None, runtime=object()), expected)

    def test_DEP_58LN_01_transport_transient_read_without_token(self):
        path = fixture.PROFILE.with_name("mcp.example.json")
        profile = path.read_text(encoding="utf-8")
        self.assertNotIn("configDelta", json.loads(profile))
        for package in ("dep58lf_reference.tools.module_release", "tools.module_release"):
            with self.subTest(package=package), ExitStack() as stack:
                enter = stack.enter_context
                enter(patch.dict(os.environ))
                os.environ.pop("GH_TOKEN", None)
                enter(patch.object(sys, "argv", ["transport", str(path), "1", "2", "."]))
                read = enter(patch.object(Path, "read_text", side_effect=[OSError("transient"), profile]))
                enter(patch.dict(sys.modules))
                sys.modules.pop(package + ".transport", None)
                with self.assertRaises(SystemExit) as held:
                    runpy.run_module(package + ".transport", run_name="__main__")
                self.assertEqual(held.exception.code, "TRANSPORT_IO_OR_INPUT_ERROR")
                read.assert_called_once_with(encoding="utf-8")

    def test_DEP_58LN_02_transport_help_with_stdin_open(self):
        outputs = []
        for root in (self.reference_root, fixture.ROOT):
            module = "tools.module_release.transport"
            launch = ["-m", module]
            if os.name == "nt":
                # Windows has pipes but no /dev/stdin. Bind that path to the child's real input pipe.
                launch = ["-c", "import pathlib, runpy, sys\n"
                          "open_path = pathlib.Path.open\n"
                          "def open_input(path, *args, **kwargs):\n"
                          "    return sys.stdin if path.as_posix() == '/dev/stdin' else open_path(path, *args, **kwargs)\n"
                          "pathlib.Path.open = open_input\n"
                          f"runpy.run_module({module!r}, run_name='__main__', alter_sys=True)"]
            cmd = [sys.executable, "-B", *launch, "--help", "/dev/stdin"]
            with subprocess.Popen(cmd, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as cli:
                try:
                    # communicate() would send EOF, masking a read before argparse.
                    self.assertEqual(cli.wait(timeout=10), 0)
                except subprocess.TimeoutExpired:
                    cli.kill()
                    cli.communicate()
                    self.fail("transport --help waited for EOF")
                outputs.append(cli.communicate())
        self.assertIn(b"--module", outputs[0][0])
        self.assertEqual(outputs[0][1], b"")
        self.assertEqual(outputs[1], outputs[0])

    def test_DEP_58LM_01_installer_plan_preserves_first_error(self):
        case = installer_fixture.Bootstrap()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.inst.ROOT.mkdir()
        installed = case.inst.ROOT / "profile.json"
        marker = "private-installer-delta"
        delta = json.dumps({"modules": {"mcp": {"configDelta": marker}}}).encode()
        for proposed, current, diagnostic in ((b"{}", b"{", "INSTALL_PROFILE_FIELDS"),
                                              (b"{", delta, "JSONDecodeError")):
            case.path.write_bytes(proposed)
            installed.write_bytes(current)
            for root in (self.reference_root, fixture.ROOT):
                with self.subTest(root=root, diagnostic=diagnostic):
                    main = runpy.run_path(str(root / "scripts/install-ouf-a2.py"))["main"]
                    out, err, effect = io.StringIO(), io.StringIO(), Mock()
                    with ExitStack() as stack:
                        enter = stack.enter_context
                        enter(patch.dict(main.__globals__, ROOT=case.inst.ROOT, safe=case.inst.safe,
                                         sys=SimpleNamespace(flags=SimpleNamespace(isolated=True)),
                                         manifest=effect, installation_lock=effect, install=effect))
                        read = enter(patch.object(Path, "read_bytes", autospec=True, side_effect=Path.read_bytes))
                        enter(patch.object(sys, "argv", ["install", "plan", str(case.path)]))
                        enter(patch.object(os, "geteuid", return_value=0, create=True))
                        enter(patch.object(os, "umask"))
                        enter(redirect_stdout(out))
                        enter(redirect_stderr(err))
                        with self.assertRaises(ValueError) as caught:
                            main()
                    read.assert_called_once_with(case.path)
                    if diagnostic == "JSONDecodeError":
                        self.assertIs(type(caught.exception), json.JSONDecodeError)
                    else:
                        self.assertEqual(str(caught.exception), diagnostic)
                    self.assertNotIn(marker, str(caught.exception))
                    self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                    effect.assert_not_called()
                    case.inst.subprocess.check_output.assert_not_called()
                    self.assertEqual(list(case.inst.ROOT.iterdir()), [installed])
                    self.assertEqual(installed.read_bytes(), current)

    def test_DEP_58LO_01_installer_plan_public_errors_and_read_faults(self):
        profile = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve() / "profile.json"
        for policy, fail_read, error in (
                ({}, 0, b"ValueError: INSTALL_PROFILE_FIELDS"),
                ({}, 1, b"OSError: [Errno 5] simulated read failure"),
                ({}, 2, b"ValueError: INSTALL_PROFILE_FIELDS"),
                (None, 0, b"TypeError:"),
                ({"modules": ["configDelta"]}, 0, b"ValueError: INSTALL_PROFILE_FIELDS"),
                ({"modules": {"mcp": "configDelta"}}, 0, b"ValueError: INSTALL_PROFILE_FIELDS")):
            with self.subTest(policy=policy, fail_read=fail_read):
                profile.write_text(json.dumps(policy), encoding="utf-8")
                expected = installer_plan(self.reference_root, profile, fail_read)
                actual = installer_plan(fixture.ROOT, profile, fail_read)
                self.assertEqual((expected.returncode, expected.stdout), (1, b""))
                self.assertIn(error, expected.stderr.splitlines()[-1])
                self.assertEqual((actual.returncode, actual.stdout, actual.stderr.splitlines()[-1]),
                                 (expected.returncode, expected.stdout, expected.stderr.splitlines()[-1]))

    def test_DEP_58LO_02_installer_plan_denies_delta_without_value(self):
        case = installer_fixture.Bootstrap()
        self.addCleanup(case.doCleanups)
        case.setUp()
        marker = "private-installer-delta"
        policy = json.loads(case.path.read_bytes())
        policy["modules"]["mcp"]["configDelta"] = marker
        case.path.write_text(json.dumps(policy), encoding="utf-8")
        actual = installer_plan(fixture.ROOT, case.path, fail_read=2)
        self.assertEqual((actual.returncode, actual.stdout), (1, b""))
        self.assertEqual(actual.stderr.splitlines()[-1], b"ValueError: INVALID_DELTA")
        self.assertNotIn(marker.encode(), actual.stderr)

    def test_DEP_58LO_03_changed_hunks_preserve_release_lines(self):
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=fixture.ROOT)

        def library_module(source):
            return not any(isinstance(node, ast.If) and
                           any(isinstance(name, ast.Name) and name.id == "__name__" for name in ast.walk(node.test))
                           for node in ast.walk(ast.parse(source)))

        # New files have no release lines. The only CLI tail is the transport wrapper,
        # exercised by DEP_58LN_01 (transient read) and DEP_58LN_02 (--help with stdin open).
        transport_tail = ("tools/module_release/transport.py", 130, 0, 131, 19)
        paths = git("diff", "--no-renames", "--diff-filter=MDT", "--name-only", "-z", REFERENCE,
                    "--", "tools/", "scripts/", ".github/scripts/")
        for path in os.fsdecode(paths).split("\0"):
            if not path:
                continue
            with self.subTest(path=path):
                original = git("show", f"{REFERENCE}:{path}")
                diff = git("diff", "--no-renames", "--no-color", "--no-ext-diff", "--no-textconv",
                           "--unified=0", REFERENCE, "--", path)
                self.assertNotIn(b"Binary files ", diff)
                for hunk in re.finditer(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", diff, re.M):
                    old, removed, new, added = (int(n or 1) for n in hunk.groups())
                    if removed == added or (path, old, removed, new, added) == transport_tail:
                        continue
                    self.assertEqual((removed, old), (0, len(original.splitlines())), hunk[0])
                    self.assertTrue(path.endswith(".py") and library_module(original) and
                                    library_module((fixture.ROOT / path).read_bytes()), hunk[0])

    def test_DEP_58LM_02_executor_preserves_malformed_request_errors(self):
        marker = "private-executor-delta"
        request = b'{"request":{"operation":"module-release","module":"mcp"},"token":"fixture"}'
        for raw, diagnostic in ((request[:-1], "A2_EVIDENCE_UNPROVEN/JSONDecodeError@ouf-a2-executor:49"),
                                (request.ljust(8194), "REQUEST_LIMIT"),
                                (request[:-1].ljust(8193) + b"}", "REQUEST_LIMIT")):
            for profile in ({}, {"configDelta": marker}):
                with self.subTest(length=len(raw), delta=bool(profile)):
                    for root, policy in ((self.reference_root, self.reference_mandate), (fixture.ROOT, mandate)):
                        with ExitStack() as stack:
                            guards = [stack.enter_context(patch.object(owner, name))
                                      for owner, name in ((policy, "validate"), (module_operation, "Journal"),
                                                          (module_operation.operation, "Docker"),
                                                          (module_operation.operation, "request"))]
                            result = executor_with_busy_lock(root, policy, profile, raw_request=raw)
                        for guard in guards:
                            guard.assert_not_called()
                        self.assertEqual(result, ((1, "", diagnostic + "\n"), 0, 0))

    @unittest.skipUnless(sys.platform == "linux", "requires Linux flock")
    def test_DEP_58LM_04_malformed_request_releases_shared_lock_on_exit(self):
        import fcntl
        from multiprocessing import get_context

        directory = self.enterContext(tempfile.TemporaryDirectory())
        probe = os.open(directory, os.O_DIRECTORY)
        self.addCleanup(os.close, probe)

        def reject(root, policy):
            # A fresh open in the child gives the CLI its own file description.
            fd = os.open(directory, os.O_DIRECTORY)
            result = executor_with_busy_lock(root, policy, {"configDelta": "private-lock-delta"},
                                             raw_request=b" " * 8194, installation_fd=fd)
            self.assertEqual(result, ((1, "", "REQUEST_LIMIT\n"), 0, 0))
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # The CLI leaves fd open until process exit.

        for root, policy in ((self.reference_root, self.reference_mandate), (fixture.ROOT, mandate)):
            with self.subTest(root=root):
                child = get_context("fork").Process(target=reject, args=(root, policy))
                child.start()
                child.join(10)
                if child.is_alive():
                    child.kill()
                    child.join()
                self.assertEqual(child.exitcode, 0)
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)

    def test_DEP_58LF_06_none_interrupted_apply_and_return(self):
        self.compare("none", interrupted=True)

    def test_DEP_58LF_07_dedicated(self):
        self.compare("dedicated", interrupted=False)

    def test_DEP_58LF_08_dedicated_interrupted_apply_and_migration(self):
        self.compare("dedicated", interrupted=True)

    def test_DEP_58LI_04_created_publication_io_error(self):
        def exercise(op, rec, case, rt, stamp):
            link = op.os.link

            def publish(source, dest):
                if dest.name == "created.json":
                    raise OSError("synthetic publication failure")
                link(source, dest)

            with patch.object(op.os, "link", publish):
                result = op.apply(case.p, stamp, rt)
            self.assertEqual((result["status"], result["rollback"], result["restoredCid"]),
                             ("HELD", "ROLLED_BACK", fixture.OLD))
            self.assertEqual(result["reason"], "RELEASE_IO_OR_INPUT_ERROR/OSError@operation.py:139")
            self.assertEqual(op.read(Path(case.p["journal"]) / stamp, "receipt.json"), result)

        for mode in ("none", "dedicated"):
            with self.subTest(mode=mode):
                self.compare(mode, exercise=exercise)

    def test_DEP_58LI_05_interrupted_start_and_failed_resume(self):
        def exercise(op, rec, case, rt, stamp):
            record = op.record

            def interrupt(root, name, data):
                if name == "start-generation.json":
                    if reason != "START_GENERATION_UNCONFIRMED":
                        record(root, name, data)
                    raise KeyboardInterrupt
                record(root, name, data)

            with patch.object(op, "record", interrupt), self.assertRaises(KeyboardInterrupt):
                op.apply(case.p, stamp, rt)
            if reason == "START_GENERATION_CHANGED":
                case.rt.stop(fixture.NEW)
            if reason == "READINESS_NOT_UP":
                case.rt.fault = "readiness"
            with self.assertRaises(op.Held) as held:
                rec.resume(case.p, rt, rec.proposal(case.p, rt))
            self.assertEqual(str(held.exception), reason)

        for reason in ("START_GENERATION_UNCONFIRMED", "START_GENERATION_CHANGED", "READINESS_NOT_UP"):
            with self.subTest(reason=reason):
                self.compare("none", exercise=exercise)

    def test_DEP_58LI_06_lost_predecessor_start_response(self):
        def exercise(op, rec, case, rt, stamp):
            case.rt.fault = "readiness"
            start = case.rt.start

            def unreliable_start(cid):
                if cid != fixture.OLD or started:
                    start(cid)
                if cid == fixture.OLD:
                    raise OSError("synthetic lost response")

            with patch.object(case.rt, "start", unreliable_start):
                result = op.apply(case.p, stamp, rt)
            self.assertEqual((result["status"], result["reason"], result["rollback"]),
                             ("HELD", "READINESS_NOT_UP", "HELD"))
            self.assertEqual(op.read(Path(case.p["journal"]) / stamp, "receipt.json"), result)
            with self.assertRaisesRegex(op.Held, "^TERMINAL_HELD_REQUIRES_OWNER$"):
                rec.resume(case.p, rt, rec.proposal(case.p, rt))

        for started in (False, True):
            with self.subTest(started=started):
                self.compare("none", exercise=exercise)


class WithoutDelta(unittest.TestCase):
    def test_DEP_58L_06_legacy_create_bytes(self):
        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        old = case.rt.inspect(fixture.OLD)
        image = case.p["ci"]["imageId"]
        expected = copy.deepcopy(old["Config"])
        expected.pop("MacAddress")
        expected["Image"] = image
        expected["HostConfig"] = dict(old["HostConfig"], OomKillDisable=False)
        expected["NetworkingConfig"] = {"EndpointsConfig": {
            name: {"IPAMConfig": {"IPv4Address": ep["IPAddress"]}, "Aliases": ep["Aliases"]}
            for name, ep in old["NetworkSettings"]["Networks"].items()}}
        self.assertEqual(json.dumps(frame.request(old, image)).encode(), json.dumps(expected).encode())

    def test_DEP_58LE_05_dedicated_without_delta_requires_release_receipt(self):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.dedicated()
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        with patch.object(operation, "start_candidate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            operation.apply(case.p, stamp, case.rt)
        events = list(case.rt.events)
        result = return_operation.run(case.p, stamp, case.rt, recover=True)
        self.assertEqual(result.get("reason"), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        self.assertEqual(events, case.rt.events)
        self.assertFalse((Path(case.p["journal"]) / stamp / "return-intent.json").exists())

    def test_DEP_58LE_05_legacy_restore_start_claim(self):
        case = mcp.Release()
        self.addCleanup(case.doCleanups)
        case.setUp()
        stamp = operation.plan(case.p, case.rt)["planSha256"]
        self.assertEqual(operation.apply(case.p, stamp, case.rt)["status"], "READY")
        with patch.object(case.rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            return_operation.run(case.p, stamp, case.rt)
        self.assertEqual(operation.read(Path(case.p["journal"]) / stamp, "restore-start.json"), {"cid": fixture.OLD})

    def test_DEP_58LE_05_none_without_delta_preserves_rollback_scope(self):
        import mandate

        case = fixture.ReleaseTest()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.p["migration"] = {"mode": "none", "rollbackCompatible": True}
        stamp = case.planned()
        req = dict(commit="c"*40, run="1", attempt="1", operation="module-release",
                   module=case.p["module"], phase="rollback", digest=stamp)
        with self.assertRaisesRegex(mandate.Held, "MODULE_REQUEST_SCOPE"):
            mandate.validate(req, {"commit": req["commit"], "modules": {req["module"]: case.p}})
        with self.assertRaisesRegex(operation.Held, "INVALID_RETURN_PLAN"):
            return_operation.run(case.p, stamp, case.rt, recover=True)

    def test_DEP_58LM_03_native_checkout_includes_reference_history(self):
        path = fixture.ROOT / ".github/workflows/privileged-executor-native.yml"
        self.assertRegex(path.read_text(encoding="utf-8"), r"(?m)^\s*fetch-depth:\s*0\s*$")
