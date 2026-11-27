"""Native root-only issuance, disposable Ed25519 key and real mandate ledger."""
import json
from contextlib import contextmanager, nullcontext, redirect_stdout, redirect_stderr
import io
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import test_semantic_provider_r3_compose as fixtures
from tools.semantic_provider_operation import supersede_gate as gate

ROOT, A, C = fixtures.ROOT, fixtures.A, fixtures.C
issue = fixtures.load("scripts/issue-semantic-provider-operation-authorization.py", "r3_operation_issuer")
operation = fixtures.load("tests/test_semantic_provider_operation.py", "r3_native_operation_fixture")
NATIVE = os.environ.get("OUF_OPERATION_ISSUANCE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_OPERATION_ISSUANCE_NATIVE requires Linux root:root; refusing to skip")


def issuer_command(argv, wrapper=None):
    script = str(ROOT / "scripts/issue-semantic-provider-operation-authorization.py")
    command = [sys.executable, "-I", "-B"]
    if wrapper is not None:
        # Isolate the same CLI and custody checks on the fixture's local wrapper.
        command += ["-c", """
from pathlib import Path
import runpy
import sys
issuer = runpy.run_path(sys.argv[1])
from tools.semantic_provider_operation import supersede_gate
supersede_gate.WRAPPER = Path(sys.argv[2])
raise SystemExit(issuer['main'](sys.argv[3:]))
""", script, str(wrapper)]
    else:
        command.append(script)
    return [*command, *argv]


class PortableTests(unittest.TestCase):
    def test_supersede_composes_next_version_and_denies_stop_or_time_regression(self):
        inputs = fixtures.fixture()
        initial = C.compose(inputs)
        payload = A.validate(initial["authorization"])
        head = {"sequence": 1, "decision": "OPERATE", "sha256": A.sha(initial["authorization"]),
                "authorization": payload}
        result = issue.compose_next(inputs, head, payload["issuedAt"])
        proposed = A.validate(result["authorization"])
        self.assertEqual((proposed["sequence"], proposed["supersedes"]), (2, head["sha256"]))
        self.assertIn("versions/2/runtime-configuration.json", result["documents"])
        with self.assertRaisesRegex(A.OperationDenied, "SUPERSEDE_REQUIRES_OPERATE_HEAD"):
            issue.compose_next(inputs, {**head, "decision": "STOP"}, payload["issuedAt"])
        with self.assertRaisesRegex(A.OperationDenied, "OPERATION_CHAIN_TIME_REGRESSED"):
            issue.compose_next(inputs, head, payload["issuedAt"]-1)

    def test_cli_argument_error_is_public_code_only(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(issue.main(["--unknown", "PRIVATE_SENTINEL"]), 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "INVALID_ARGUMENTS")
        self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        self.assertEqual(errors.getvalue(), "")

    def test_public_errors_never_include_exception_content(self):
        for error in (ValueError("SECRET_SENTINEL"), OSError("/private/key"), RuntimeError("a key value")):
            self.assertEqual(issue.public(error), "INPUT_OR_IO_UNPROVEN")
        self.assertEqual(issue.public(A.OperationDenied("PLAN_DIGEST_MISMATCH")), "PLAN_DIGEST_MISMATCH")

    def test_exact_key_exclusion_happens_before_open(self):
        # Lexical path only on Windows: the exclusion precedes all custody IO.
        with patch.object(issue.AUTH, "Path", fixtures.PurePosixPath):
            reader = issue.Reader(["/private/installer.pem"])
            with patch.object(issue.os, "open", side_effect=AssertionError("must not open")):
                with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN"):
                    reader.read("/private/installer.pem", "1" * 64)

    def test_apply_rechecks_under_cid_then_chain_locks_before_claim(self):
        root = fixtures.PurePosixPath("/installation")
        chain = root / "authorization"
        head = {"sha256": "a" * 64}
        cids = {"b" * 64: {}, "c" * 64: {}}
        snapshot = {"previousHead": head}
        paths = (root.parent / "new-output", chain, None, None)
        locks = []

        @contextmanager
        def cid_locks(install, candidates):
            self.assertEqual((install, candidates), (root, cids))
            locks.append("cids")
            try:
                yield
            finally:
                self.assertEqual(locks.pop(), "cids")

        def chain_lock(stack, path):
            self.assertEqual((locks, path), (["cids"], chain))
            locks.append("chain")
            stack.callback(locks.pop)

        def observe_epochs(install, previous):
            self.assertEqual((install, previous), (root, head))
            if locks:
                self.assertEqual(locks, ["cids", "chain"])
                raise A.OperationDenied(gate.NOT_STOPPED)
            return cids

        args = SimpleNamespace(supersede=True, plan=False, plan_sha256=A.sha(A.canonical(
            {**snapshot, "supersession": cids})))
        progress = issue.progress_initial()
        with patch.object(issue, "destinations", return_value=paths), \
                patch.object(issue, "observe", return_value=(snapshot,) + (None,) * 8), \
                patch.object(issue, "authorization_head", return_value=head), \
                patch.object(issue, "chain_lock", side_effect=chain_lock), \
                patch.object(gate, "operation_locks", side_effect=cid_locks), \
                patch.object(gate, "observe", side_effect=observe_epochs), \
                patch.object(issue, "publish") as publish, \
                self.assertRaisesRegex(A.OperationDenied, gate.NOT_STOPPED):
            issue.execute(args, progress)
        publish.assert_not_called()
        self.assertEqual(locks, [])
        self.assertEqual(progress, issue.progress_initial())

    def test_execute_retries_same_plan_after_start_releases_common_lock(self):
        chain = fixtures.PurePosixPath("/installation/authorization")
        paths = (chain.parent / "unused", chain, None, None)
        plan = {"previousHead": {"sha256": "a" * 64}, "supersession": {}}
        args = SimpleNamespace(supersede=True, plan=False, plan_sha256=A.sha(A.canonical(plan)))
        binding = {"path": "/owner", "sha256": "b" * 64}
        reader = SimpleNamespace(bound=lambda ref: b"owner")
        observation = (plan, None, reader, None, None, None, None, None, {"coordinatorBinding": binding})
        held = []
        busy = True

        @contextmanager
        def lock(name):
            held.append(name)
            try:
                yield
            finally:
                self.assertEqual(held.pop(), name)

        def common(root, previous, owner, ref):
            self.assertEqual((held, root, previous, owner, ref),
                             (["cids", "chain"], chain.parent, plan["previousHead"], b"owner", binding))
            if busy:
                raise BlockingIOError()
            return lock("common")

        def publish(*_):
            self.assertEqual(held, ["cids", "chain", "common"])
            return "issued"

        progress = issue.progress_initial()
        with patch.object(issue, "destinations", return_value=paths), patch.object(issue, "observe", return_value=observation), \
                patch.object(gate, "observe", return_value={}), patch.object(gate, "operation_locks", side_effect=lambda *_: lock("cids")), \
                patch.object(issue, "chain_lock", side_effect=lambda stack, _: stack.enter_context(lock("chain"))), \
                patch.object(issue, "authorization_head", return_value=plan["previousHead"]), \
                patch.object(issue, "publication_lock", side_effect=common), patch.object(issue, "publish", side_effect=publish) as claim:
            with self.assertRaises(BlockingIOError):
                issue.execute(args, progress)
            claim.assert_not_called()
            self.assertEqual((held, progress), ([], issue.progress_initial()))
            busy = False
            self.assertEqual(issue.execute(args, progress), "issued")
            claim.assert_called_once()
        self.assertEqual(held, [])

    def test_gate_checks_both_cids_and_retained_prepared_failures(self):
        composed = C.compose(fixtures.fixture())
        raw = composed["authorization"]
        payload = A.validate(raw)
        head = {"decision": "OPERATE", "sequence": 1, "sha256": A.sha(raw), "authorization": payload}
        cfg = C.document(composed["documents"]["runtime-configuration.json"])
        root = fixtures.PurePosixPath(cfg["registryRoot"]).parent
        adapter, southbound = (payload["roles"][role]["containerId"] for role in ("adapter", "southbound"))
        row = {"epoch": 1, "state": "DELETED", "driverHash": "e" * 64,
            "authorizationSha256": head["sha256"], "configurationHash": payload["runtimeConfigurationSha256"]}
        current = {adapter: row, southbound: {**row, "state": "STARTED"}}
        epochs = SimpleNamespace(TERMINAL={"ABANDONED", "DELETED", "FAILED"},
                                 current=lambda registry, cid: current[cid])
        history = {adapter: [row], southbound: [current[southbound]]}
        receipts = {}
        runtime = SimpleNamespace(private_directory=lambda path: None, read=lambda path: b"",
            epoch_inventory=lambda base, epochs, row: history[base.name],
            cleanup_receipt=lambda folder, row, status: receipts.get(folder.name))
        with patch.object(gate, "installed", return_value=(cfg, runtime, epochs)), \
                patch.object(A, "private_file", return_value=raw):
            with self.assertRaisesRegex(A.OperationDenied, gate.NOT_STOPPED):
                gate.observe(root, head)
            current[southbound] = row
            history[southbound] = [row]
            self.assertEqual(set(gate.observe(root, head)), set(cfg["candidates"]))
            current[adapter] = {**row, "epoch": 2}
            history[adapter] = [{**row, "state": "FAILED"}, current[adapter]]
            with self.assertRaisesRegex(A.OperationDenied, gate.CLEANUP):
                gate.observe(root, head)
            receipts["1"] = {"operation": "delete"}
            self.assertEqual(gate.observe(root, head)[adapter]["1"]["cleanupReceipt"], receipts["1"])


@unittest.skipUnless(NATIVE, "set OUF_OPERATION_ISSUANCE_NATIVE=1 under Linux root:root")
class NativeTests(operation.Fixture):
    __unittest_skip__ = False  # the base's independent native gate does not govern this suite

    def key(self, name, roles):
        return {**super().key(name, roles), "notBefore": int(time.time()) - 3600, "expiresAt": int(time.time()) + 3600}

    def setUp(self):
        super().setUp()
        self.now = int(time.time())
        self.install = self.root / "install"
        self.install.mkdir(mode=0o700)
        self.chain = self.install / "authorization"  # initially absent
        self.output = self.root / "issued"
        self.inputs = fixtures.fixture()
        settings = json.loads(self.inputs["files"]["settings"])
        settings.update(installationRef="inst", entityRef="ent", issuerRef="installer", installRoot=str(self.install),
            issuedAt=self.now, anchorBinding=self.anchor, mandateRoot=str(self.ledger_root), opensslBinding=self.ssl)
        self.owner = self.root / "owner.json"
        self.common_lock = self.root / "common.lock"
        self.write(self.common_lock, b"")
        owner = C.document(self.inputs["files"]["coordinator"])
        owner["commonLockFile"] = str(self.common_lock)
        self.inputs["files"]["coordinator"] = A.canonical(owner)
        self.write(self.owner, self.inputs["files"]["coordinator"])
        settings["coordinatorBinding"] = {"path": str(self.owner), "sha256": A.sha(self.owner.read_bytes())}
        # Bind the real fixture anchor to this public authority profile.
        self.profile = self.root / "authority.json"
        self.write(self.profile, A.canonical({"schema": "ouf.semantic-existing-installation-authority-bindings.v1",
            "authorities": {"installationRef": "inst", "entityRef": "ent", "intentIssuerRef": "installer",
                            "approvalIssuerRef": "installer"},
            "keyBindings": {"installer": {"path": str(self.keys["key-a"]), "sha256": A.sha(self.keys["key-a"].read_bytes())},
                            "attestor": {"path": str(self.keys["key-b"]), "sha256": A.sha(self.keys["key-b"].read_bytes())}},
            "keyRefs": {"installer": "key-a", "attestor": "key-b"},
            "policyBinding": {"path": str(self.root / "unopened-base.json"), "sha256": "c" * 64}}))
        anchor = json.loads(Path(self.anchor["path"]).read_bytes())
        anchor["authorityProfile"] = {"path": str(self.profile), "sha256": A.sha(self.profile.read_bytes())}
        self.write(self.anchor["path"], A.canonical(anchor))
        self.anchor["sha256"] = A.sha(Path(self.anchor["path"]).read_bytes())
        settings["anchorBinding"] = self.anchor
        accepted = json.loads(self.inputs["files"]["acceptance"])
        accepted.update(installationRef="inst", entityRef="ent", trustPolicy=self.anchor)
        self.inputs["files"]["acceptance"] = A.canonical(accepted) + b"\n"
        self.inputs["files"]["settings"] = A.canonical(settings)
        self.settings = settings
        self.mapping = self.root / "inputs.json"
        self.publish_inputs()

    def publish_inputs(self):
        bundle = {"schema": "ouf.semantic-provider-r3-inputs.v1", "files": {}, "sources": {}}
        blobs = self.root / "blobs"
        blobs.mkdir(mode=0o700, exist_ok=True)
        for kind, values in self.inputs.items():
            for i, (name, raw) in enumerate(sorted(values.items())):
                path = blobs / (kind + str(i))
                self.write(path, raw)
                bundle[kind][name] = {"path": str(path), "sha256": A.sha(raw)}
        self.write(self.mapping, A.canonical(bundle))

    def argv(self, mode="--plan", digest=None):
        argv = [mode, "--inputs", str(self.mapping), "--inputs-sha256", A.sha(self.mapping.read_bytes()),
            "--authority-profile", str(self.profile), "--authority-profile-sha256", A.sha(self.profile.read_bytes()),
            "--install-root", str(self.install), "--issued-at", str(self.now),
            "--output-directory", str(self.output), "--table-name", "adapter=ouf_r3_adapter", "southbound=ouf_r3_southbound"]
        for path in self.keys.values():
            argv.extend(["--private-key-path", str(path)])
        if digest is not None:
            argv.extend(["--plan-sha256", digest])
        return argv

    def execute(self, mode="--plan", digest=None, progress=None, *, supersede=False):
        argv = self.argv(mode, digest)
        if supersede:
            argv.append("--supersede")
        wrapper = patch.object(gate, "WRAPPER", self.wrapper) if supersede else nullcontext()
        with wrapper:
            return issue.execute(issue.arguments(argv), progress if progress is not None else
                                 issue.progress_initial(), self.clock)

    def issuer_cli(self, argv, code=0):
        wrapper = self.wrapper if "--supersede" in argv else None
        result = subprocess.run(issuer_command(argv, wrapper), capture_output=True, timeout=40)
        self.assertEqual(result.returncode, code, result.stdout.decode() + result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def installed_first(self):
        _, composed, *_ = issue.observe(issue.arguments(self.argv()), self.clock)
        first = self.issuer_cli(self.argv())
        self.issuer_cli(self.argv("--apply", first["planSha256"]))
        for relative in sorted(composed["layout"]["directories0700"], key=lambda p: p.count("/")):
            (self.install / relative).mkdir(mode=0o700, exist_ok=True)
        for relative, raw in composed["documents"].items():
            self.write(self.install / relative, raw)
        cfg = C.document(composed["documents"]["runtime-configuration.json"])
        self.cids = {binding["role"]: cid for cid, binding in cfg["candidates"].items()}
        self.wrapper = self.root / "installed-wrapper"
        self.write(self.wrapper, gate.I.wrapper_bytes(cfg["pythonPath"], self.install), 0o755)
        self.output = self.root / "superseded"
        self.first_head = self.head()

    def epoch(self, role, state, *, number=1, prepared=False, **changes):
        cid = self.cids[role]
        base = self.install / "registry" / cid
        folder = base / "epochs" / str(number)
        folder.mkdir(mode=0o700, exist_ok=True)
        row = {"schema": self.e.JOURNAL_SCHEMA, "containerId": cid, "epoch": number, "bootId": operation.BOOT,
            "authorizationSha256": self.first_head["sha256"],
            "configurationHash": self.first_head["authorization"]["runtimeConfigurationSha256"],
            "state": state, "runtimeRoot": None, "bundleHash": None,
            "driverHash": "d" * 64 if prepared else None,
            "generation": {"pid": 100, "startTicks": 200} if state == "STARTED" else None,
            "openedAt": self.now, "failure": "TWO_PHASE_BROKER_DENIED" if state == "FAILED" else None}
        raw = A.canonical({**row, **changes})
        self.write(folder / "adapter.json", raw)
        self.write(base / "current", A.canonical({"epoch": number, "journalSha256": A.sha(raw)}))
        return folder

    def assert_held(self, reason, mode="--plan", digest=None):
        held = self.issuer_cli([*self.argv(mode, digest), "--supersede"], code=1)
        self.assertEqual((held["status"], held["reason"]), ("HELD", reason))
        self.assertEqual((held["privateKeysRead"], held["signaturesIssued"], held["signingAttempted"]), (0, 0, False))
        self.assertFalse(held["doNotRerunApply"])
        self.assertFalse(self.output.exists())
        self.assertEqual(self.head(), self.first_head)

    def test_supersede_cli_keeps_previous_pair_and_authenticates_next_head(self):
        self.installed_first()
        retained = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        plan = self.issuer_cli([*self.argv(), "--supersede"])
        self.assertEqual(plan["privateKeysRead"], 0)
        self.assertEqual(plan["payload"]["sequence"], 2)
        self.assertEqual(plan["payload"]["supersedes"], A.sha(retained["1.json"]))
        result = self.issuer_cli([*self.argv("--apply", plan["planSha256"]), "--supersede"])
        self.assertEqual((result["sequence"], result["privateKeysRead"], result["signaturesIssued"]), (2, 1, 1))
        for name, raw in retained.items(): self.assertEqual((self.chain/name).read_bytes(), raw)
        M = issue.load_mandates(self.inputs["sources"][C.MANDATES], A.sha(self.inputs["sources"][C.MANDATES]), C.MANDATES)
        head = issue.authorization_head(issue.arguments([*self.argv(), "--supersede"]), M, self.settings, self.clock)
        self.assertEqual((head["sequence"], head["sha256"]), (2, result["payloadSha256"]))
        self.assertFalse((self.install / "versions").exists())

    def test_started_epoch_denies_plan_and_apply(self):
        self.installed_first()
        plan = self.execute(supersede=True)
        self.epoch("southbound", "STARTED", prepared=True)
        self.assert_held(gate.NOT_STOPPED)
        self.assert_held(gate.NOT_STOPPED, "--apply", plan["planSha256"])

    def test_prepared_failed_history_needs_exact_cleanup_receipt(self):
        self.installed_first()
        failed = self.epoch("adapter", "FAILED", prepared=True)
        self.epoch("adapter", "DELETED", number=2)
        self.epoch("southbound", "DELETED")
        self.assert_held(gate.CLEANUP)
        self.assert_held(gate.CLEANUP, "--apply", "0" * 64)
        receipt = {"schema": "ouf.semantic-docker-runtime-cleanup.v1", "epoch": 2,
            "operation": "delete", "at": self.now, "runcStatusBefore": "absent"}
        self.write(failed / "runtime-cleanup.json", A.canonical(receipt))
        self.assert_held(gate.CLEANUP)
        self.write(failed / "runtime-cleanup.json", A.canonical({**receipt, "epoch": 1}))
        plan = self.execute(supersede=True)
        self.assertEqual(self.execute("--apply", plan["planSha256"], supersede=True)["sequence"], 2)

    def test_deleted_epochs_allow_supersession(self):
        import fcntl

        self.installed_first()
        for role in C.ROLES:
            self.epoch(role, "DELETED", prepared=True)
        plan = self.execute(supersede=True)
        progress = issue.progress_initial()
        retained = {p.name: p.read_bytes() for p in self.chain.iterdir()}
        with issue.boot.lock(self.common_lock), self.assertRaises(BlockingIOError):
            self.execute("--apply", plan["planSha256"], progress, supersede=True)
        self.assertEqual(progress, issue.progress_initial())
        self.assertFalse(self.output.exists())
        self.assertEqual({p.name: p.read_bytes() for p in self.chain.iterdir()}, retained)
        read_head = A.head
        readback = []

        def verify_locks_at_readback(*args, **kwargs):
            head = read_head(*args, **kwargs)
            if head["sequence"] == 2:
                locks = [self.install / "registry" / cid / "operation.lock" for cid in self.cids.values()]
                for path in [*locks, self.chain, self.common_lock]:
                    fd = os.open(path, os.O_RDONLY)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(fd)
                readback.append(head["sha256"])
            return head

        with patch.object(A, "head", side_effect=verify_locks_at_readback):
            result = self.execute("--apply", plan["planSha256"], progress, supersede=True)
        self.assertEqual((result["sequence"], readback), (2, [result["payloadSha256"]]))
        self.assertEqual(json.loads((self.output / "result.json").read_bytes()), result)

    def test_epoch_pointer_and_authorization_bindings_fail_closed(self):
        self.installed_first()
        self.epoch("adapter", "DELETED", authorizationSha256="f" * 64)
        self.assert_held(gate.BINDING)
        self.epoch("adapter", "DELETED", epoch=True)
        self.assert_held(gate.BINDING)
        folder = self.epoch("adapter", "DELETED")
        (folder.parent.parent / "current").unlink()
        self.assert_held(gate.BINDING)

    def test_installed_configuration_drift_denies_supersession(self):
        self.installed_first()
        path = self.install / "runtime-configuration.json"
        self.write(path, path.read_bytes() + b"\n")
        self.assert_held(gate.CONFIGURATION)

    def test_plan_apply_head_and_no_installation_publication(self):
        # Observe the original installer key through the single dedicated reader.
        original = issue.AUTH.public_bytes
        reads = []
        def key_reader(path, limit=65536):
            if Path(path) == self.keys["key-a"]:
                reads.append(path)
            return original(path, limit)
        with patch.object(issue.AUTH, "public_bytes", side_effect=key_reader):
            first = self.execute()
            self.assertEqual(first, self.execute())
            self.assertFalse(self.chain.exists())
            self.assertFalse(self.output.exists())
            self.assertEqual(reads, [])
            result = self.execute("--apply", first["planSha256"])
        # Hash check of the original custody path before and after signing; never a copy.
        self.assertEqual(len(reads), 2)
        self.assertEqual((result["privateKeysRead"], result["signaturesIssued"]), (1, 1))
        self.assertEqual(self.head()["sha256"], first["payloadSha256"])
        self.assertEqual(self.head()["decision"], "OPERATE")
        self.assertEqual(set(os.listdir(self.output)), {"result.json"})
        self.assertEqual(set(os.listdir(self.install)), {"authorization"})
        self.assertEqual(set(os.listdir(self.chain)), {"1.json", "1.signature.json"})
        self.assertFalse((self.chain / "1.signature.json").read_bytes().endswith(b"\n"))
        self.assertEqual((self.chain.stat().st_mode & 0o777), 0o700)
        for p in (self.chain / "1.json", self.chain / "1.signature.json", self.output / "result.json"):
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(A.OperationDenied):
            self.execute("--apply", first["planSha256"])

    def test_cli_plan_apply_and_readback(self):
        def run(args):
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/issue-semantic-provider-operation-authorization.py"),
                *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout.decode())
            self.assertEqual(result.stderr, b"")
            return json.loads(result.stdout)
        plan = run(self.argv())
        result = run(self.argv("--apply", plan["planSha256"]))
        self.assertTrue(result["doNotRerunApply"])
        self.assertEqual(self.head()["sha256"], plan["payloadSha256"])

    def test_native_runtime_load_configuration_without_portability_adapter(self):
        args = issue.arguments(self.argv())
        _, result, *_ = issue.observe(args, self.clock)
        path = self.root / "runtime-configuration.json"
        self.write(path, result["documents"]["runtime-configuration.json"])
        runtime = fixtures.load(C.RUNTIME, "r3_native_runtime_contract")
        value, raw = runtime.load_configuration(path)
        self.assertEqual(raw, result["documents"]["runtime-configuration.json"])
        self.assertEqual(A.sha(raw), json.loads(result["authorization"])["runtimeConfigurationSha256"])

    def test_wrong_digest_and_changed_input_issue_no_signature(self):
        plan = self.execute()
        for digest in ("0" * 64, plan["planSha256"]):
            if digest != "0" * 64:
                self.inputs["sources"][C.OBSERVER] += b"\n"
                self.publish_inputs()
            progress = issue.progress_initial()
            with self.assertRaisesRegex(A.OperationDenied, "PLAN_DIGEST_MISMATCH"), \
                    patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")):
                self.execute("--apply", digest, progress)
            self.assertEqual(progress["signaturesIssued"], 0)
            self.assertFalse(progress["doNotRerunApply"])
            self.assertFalse(self.output.exists())

    def test_inactive_mandate_now_or_at_issuance_never_signs(self):
        plan = self.execute()
        for field, at in (("now", self.now + 7200), ("issued", self.now - 7200)):
            progress = issue.progress_initial()
            args = issue.arguments(self.argv("--apply", plan["planSha256"]))
            if field == "now":
                clock = lambda: at
            else:
                args.issued_at = at
                clock = self.clock
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "ACTIVE_(INSTALLER_)?MANDATE_REQUIRED"), \
                    patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")) as key_read:
                issue.execute(args, progress, clock)
            key_read.assert_not_called()
            self.assertEqual(progress["signaturesIssued"], 0)
            self.assertFalse(progress["doNotRerunApply"])

    def test_nonempty_or_wrong_mode_authorization_root_never_signs(self):
        plan = self.execute()
        self.chain.mkdir(mode=0o700)
        self.write(self.chain / "foreign", b"retained")
        progress = issue.progress_initial()
        with self.assertRaisesRegex(A.OperationDenied, "AUTHORIZATION_ROOT_NOT_EMPTY"), \
                patch.object(issue.AUTH, "public_bytes", side_effect=AssertionError("key read forbidden")):
            self.execute("--apply", plan["planSha256"], progress)
        self.assertEqual(progress["signaturesIssued"], 0)
        (self.chain / "foreign").unlink()
        self.chain.chmod(0o755)
        with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_DIRECTORY_REQUIRED"):
            self.execute()

    def test_existing_empty_authorization_root_accepted(self):
        self.chain.mkdir(mode=0o700)
        plan = self.execute()
        self.execute("--apply", plan["planSha256"])
        self.assertEqual(self.head()["sequence"], 1)

    def test_absent_install_root_created_exclusively(self):
        self.install.rmdir()
        plan = self.execute()
        self.assertFalse(self.install.exists())
        self.execute("--apply", plan["planSha256"])
        self.assertEqual(self.head()["sequence"], 1)
        self.assertEqual(self.install.stat().st_mode & 0o777, 0o700)

    def test_b1b2_domain_signature_rejected_by_head(self):
        plan = self.execute()
        raw = A.canonical(plan["payload"])
        self.chain.mkdir(mode=0o700)
        signature = self.signature(raw, domain=self.m.DOMAIN)
        self.put(1, raw, signature)
        with self.assertRaisesRegex(self.a.OperationDenied, "OPERATION_SIGNATURE_INVALID"):
            self.head()

    def test_bad_domain_during_issuance_is_partial_and_never_published(self):
        plan = self.execute()
        progress = issue.progress_initial()
        # Fault the signer only. Verification retains the real separate domain.
        original_native = issue.native
        def fault(verifier, argv, limit):
            if argv[0] == "pkeyutl":
                path = Path(argv[argv.index("-in") + 1])
                frame = path.read_bytes()
                path.write_bytes(self.m.DOMAIN + frame[len(A.DOMAIN):])
            return original_native(verifier, argv, limit)
        with patch.object(issue, "native", side_effect=fault), \
                self.assertRaisesRegex(A.OperationDenied, "OPERATION_SIGNATURE_INVALID"):
            self.execute("--apply", plan["planSha256"], progress)
        self.assertTrue(progress["doNotRerunApply"])
        self.assertEqual(progress["signaturesIssued"], 1)
        self.assertEqual(os.listdir(self.chain), [])
        self.assertEqual(os.listdir(self.output), [])
        with self.assertRaises(A.OperationDenied):
            self.execute("--apply", plan["planSha256"])

    def test_reader_custody_links_and_no_key_as_input(self):
        path = self.root / "public.json"
        self.write(path, b"{}")
        reader = issue.Reader([str(p) for p in self.keys.values()])
        self.assertEqual(reader.read(str(path), A.sha(b"{}")), b"{}")
        path.chmod(0o666)
        with self.assertRaisesRegex(A.OperationDenied, "INPUT_FILE_CUSTODY_REQUIRED"):
            reader.read(str(path), A.sha(b"{}"))
        path.chmod(0o600)
        link = self.root / "symlink"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            reader.read(str(link), A.sha(b"{}"))
        hard = self.root / "hardlink"
        os.link(path, hard)
        with self.assertRaisesRegex(A.OperationDenied, "INPUT_FILE_CUSTODY_REQUIRED"):
            reader.read(str(hard), A.sha(b"{}"))
        with self.assertRaisesRegex(A.OperationDenied, "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN"), \
                patch.object(issue.os, "open", side_effect=AssertionError("must not open")):
            reader.read(str(self.keys["key-a"]), "1" * 64)


if __name__ == "__main__":
    unittest.main()
