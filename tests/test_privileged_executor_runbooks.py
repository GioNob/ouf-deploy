"""Offline contract between the executor environment and the reviewed shell runbooks."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from string import Template
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools" / name) for name in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover")]
sys.path.insert(0, str(ROOT / "tools"))
import pipeline
import runbooks
import store

BOOKS = ROOT / "ops/vps"
PROFILE = {"C_R3_INPUTS": "/profile/inputs.json", "C_R3_INPUTS_SHA256": "a" * 64,
           "C_INSTALLATION_PROFILE": "/profile/install.json", "C_INSTALLATION_PROFILE_SHA256": "b" * 64}
STAMP = "c" * 64


def assignment(script, name):
    value, = re.findall(r"^\s*" + name + r"=(.+)$", script, re.M)
    return value.strip('"')


class RunbookPaths(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = dict(probe=PROFILE, queue={}, socket="fixture", installRoot=str(self.root),
                           originalProfile={"containerName": "fixture"})
        self.enterContext(patch.object(store, "sync_dir"))
        self.enterContext(patch.object(runbooks, "save"))
        # Windows fixtures use ordinary regular files. Linux also exercises native open flags.
        for flag in ("O_NONBLOCK", "O_NOFOLLOW"):
            if not hasattr(os, flag):
                self.enterContext(patch.object(os, flag, 0, create=True))

    def test_round_trip_state_and_work_paths(self):
        forward, rollback = [pipeline.Cutover(self.config, self.root, {"direction": direction, "run": run})
                             for direction, run in (("forward", "101"), ("return", "102"))]
        outputs = set()
        issued_indexes = {}
        self.enterContext(patch.object(runbooks, "issued_inputs_sha256", side_effect=issued_indexes.__getitem__))
        self.enterContext(patch.object(runbooks, "read", side_effect=lambda path: json.loads(path.read_bytes())))
        (self.root / "authorization").mkdir()
        binding = self.enterContext(patch.object(runbooks.Books, "binding"))
        launch = self.enterContext(patch.object(runbooks.subprocess, "run"))
        next_return = pipeline.Cutover(self.config, self.root, {"direction": "return", "release": "next", "run": "103"})
        for book, op, version in [(forward, "probe", 27), (forward, "stop", 27), (forward, "issue", 28),
                                  (forward, "upgrade", 28), (forward, "start", 28), (forward, "probe", 28),
                                  (rollback, "stop", 28), (rollback, "issue", 29), (rollback, "upgrade", 29),
                                  (rollback, "start", 29), (rollback, "probe", 29),
                                  (next_return, "stop", 29), (next_return, "issue", 30), (next_return, "upgrade", 30),
                                  (next_return, "start", 30), (next_return, "probe", 30)]:
            with self.subTest(op=op, version=version):
                name = {"probe": "c-probe", "stop": "r3-operate", "start": "r3-operate"}.get(op, f"r3-{op}-v{version}")
                binding.return_value = BOOKS / (name + ".sh")
                script = binding.return_value.read_text(encoding="utf-8")
                snapshots = assignment(script, "S")
                self.assertEqual(snapshots, "/etc/ouf/deploy-snapshots")
                auth = {"sequence": version, "decision": "OPERATE"}
                row = dict(planSha256=STAMP, lastObservation={"authorization": auth}, secretsRead=0,
                           observation={"semantic": {"containerId": "fixture"}, "r3": {"authorization": auth}})
                launch.return_value = SimpleNamespace(stdout=json.dumps(dict(row, status="PLAN_READY")).encode(),
                                                      returncode=0)
                preflight = (op, version) == ("probe", 27)
                if preflight:
                    self.assertEqual(book.probe_preflight(version, "fixture"), STAMP)
                else:
                    book.books.call(op, version)
                binding.assert_called_with(op, version)
                env = launch.call_args.kwargs["env"]
                home = Path(env["HOME"])
                self.assertEqual(home, book.path / "probe-preflight" if preflight else book.path)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
                if op == "probe":
                    self.assertEqual(assignment(script, "STATE"), "${C_PROBE_STATE:-/root/.ouf-c-probe-state}")
                    self.assertIn('[[ ! -e $STATE && ! -L $STATE ]]', script)
                    self.assertIn('directory "$(dirname "$STATE")"', script)
                    self.assertIn("umask 077", script)
                    self.assertIn("(set -o noclobber; printf '%s\\n' \"$D\" > \"$STATE\")", script)
                    self.assertIn('read -r D < "$STATE"', script)
                    self.assertIn('mapfile -d \'\' -t args < "$D/arguments"', script)
                    state = Path(env["C_PROBE_STATE"])
                    source = "semantic-provider-c-source"
                    expected = dict(PROFILE)
                    if not preflight:
                        index = f"{snapshots}/semantic-provider-r3-source.{version:08d}/inputs.json"
                        expected.update(C_R3_INPUTS=index, C_R3_INPUTS_SHA256=issued_indexes[index])
                    self.assertEqual({key: env[key] for key in PROFILE}, expected)
                elif op in ("start", "stop"):
                    self.assertEqual(env["AZIONE"], op)
                    self.assertIn('ACTION=$(printf %s "${AZIONE:-}"', script)
                    state = Path(Template(assignment(script, "OPSTATE")).substitute(HOME=home, ACTION=op))
                    self.assertIn('read -r D OUT < "$OPSTATE"', script)
                    source = "semantic-provider-r3-operate-source"
                else:
                    state = Path(Template(assignment(script, "STATE")).substitute(HOME=home))
                    self.assertIn('read -r D ISSUED_AT < "$STATE"', script)
                    self.assertIn('--inputs "$D/inputs.json" --inputs-sha256 "$INPUTS_SHA"', script)
                    source = "semantic-provider-r3-source"
                    output, = re.findall(r'--output-directory "([^"]+)"', script)
                    output = Template(output).substitute(S=snapshots)
                    self.assertNotIn(output, outputs)
                    outputs.add(output)
                self.assertEqual(state.parent, home)
                if op == "upgrade":
                    self.assertTrue(state.is_file())  # consumes the issue plan's exact pointer
                else:
                    self.assertIn(f'mktemp -d "$S/{source}.XXXXXXXX"', script)
                    self.assertFalse(state.exists())
                    if op == "issue":
                        self.assertIn(f'test -e "$INSTALL/authorization/{version}.json"', script)
                        self.assertIn("printf '%s %s\\n' \"$D\" \"$ISSUED_AT\" > \"$STATE\"", script)
                        directory = f"{snapshots}/{source}.{version:08d}"
                        state.write_bytes(f"{directory} {version}\n".encode())
                        issued_indexes[directory + "/inputs.json"] = hashlib.sha256(directory.encode()).hexdigest()
                    else:
                        state.touch()
                if not preflight:
                    launch.return_value.stdout = json.dumps(dict(row, status=runbooks.SUCCESS[op], **auth,
                                                                 signaturesIssued=1)).encode()
                    book.books.call(op, version, STAMP)
                    self.assertEqual(launch.call_args.kwargs["env"], env)
                    if op == "issue":
                        (self.root / "authorization" / f"{version}.json").write_text(
                            json.dumps(dict(auth, issuedAt=version)), encoding="ascii")

    def test_probe_pairs_in_one_home(self):
        books = runbooks.Books(self.config, self.root)
        states = set()
        with patch.object(books, "binding"), patch.object(runbooks.subprocess, "run") as launch:
            for version in range(27, 31):
                row = dict(planSha256=STAMP, observation={"r3": {"authorization": {"sequence": version}}})
                launch.return_value = SimpleNamespace(stdout=json.dumps(dict(row, status="PLAN_READY")).encode(),
                                                      returncode=0)
                books.call("probe", version)
                state = Path(launch.call_args.kwargs["env"]["C_PROBE_STATE"])
                self.assertEqual(state.parent, self.root)
                self.assertNotIn(state, states)
                states.add(state)
                state.touch()
                launch.return_value.stdout = json.dumps(dict(row, status=runbooks.SUCCESS["probe"])).encode()
                books.call("probe", version, STAMP)
                self.assertEqual(Path(launch.call_args.kwargs["env"]["C_PROBE_STATE"]), state)

    def test_timestamp_outputs_recur_if_the_clock_repeats(self):
        for filename, op, clock, repeated in (
                ("c-probe.sh", "probe", "$(date -u +%Y%m%dT%H%M%SZ)", "20261120T100000Z"),
                ("r3-operate.sh", "stop", "$(date +%Y%m%dT%H%M%S)", "20261120T110000"),
                ("r3-operate.sh", "start", "$(date +%Y%m%dT%H%M%S)", "20261120T120000")):
            script = (BOOKS / filename).read_text(encoding="utf-8")
            self.assertIn('--output-directory "$OUT"', script)
            expr = assignment(script, "OUT")
            self.assertIn(clock, expr)
            output = Template(expr.replace(clock, repeated))
            snapshots = assignment(script, "S")
            first = output.substitute(S=snapshots, ACTION=op, HOME="/private/101")
            second = output.substitute(S=snapshots, ACTION=op, HOME="/private/102")
            self.assertEqual(first, second)

    def test_present_invalid_pointer_never_uses_profile(self):
        pointer = self.root / ".ouf-r3-v28-state"
        prefix = b"/etc/ouf/deploy-snapshots/semantic-provider-r3-source.12345678"
        with patch.object(runbooks, "read", return_value={"sequence": 28, "issuedAt": 42}):
            for raw in (b"", prefix + b" 42\n" + b"x" * 512, prefix + b"/../other 42", prefix + b" 41",
                        prefix + b" 123456789012345678901", prefix[:-1] + b"_ 42"):
                pointer.write_bytes(raw)
                with self.subTest(raw=raw[:80]), self.assertRaises(runbooks.Held):
                    runbooks.issued_probe_inputs(self.root, self.root, 28)

    @unittest.skipUnless(sys.platform == "linux", "Linux no-follow and FIFO semantics")
    def test_link_and_fifo_are_not_missing_pointers(self):
        pointer = self.root / ".ouf-r3-v28-state"
        pointer.symlink_to("missing")
        with self.assertRaises(OSError):
            runbooks.issued_probe_inputs(self.root, self.root, 28)
        pointer.unlink()
        os.mkfifo(pointer)
        with self.assertRaises(runbooks.Held):
            runbooks.issued_probe_inputs(self.root, self.root, 28)

    def test_hashes_only_complete_private_index(self):
        raw = b'{"files":{}}\n'
        info = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600,
                               st_nlink=1, st_size=len(raw), st_mtime_ns=1, st_ctime_ns=1)
        path = self.root / "inputs.json"
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        def metadata(p):
            return info if p == path else directory
        with patch.object(Path, "lstat", autospec=True, side_effect=metadata), patch.object(os, "open", return_value=3), \
             patch.object(os, "close"), patch.object(os, "fstat", return_value=info), \
             patch.object(os, "read", return_value=raw):
            self.assertEqual(runbooks.issued_inputs_sha256(path), hashlib.sha256(raw).hexdigest())
            for drift in (dict(st_mode=stat.S_IFREG | 0o644), dict(st_uid=1), dict(st_nlink=2),
                          dict(st_size=131073), dict(st_size=len(raw) + 1)):
                with patch.dict(info.__dict__, drift), self.assertRaises(runbooks.Held):
                    runbooks.issued_inputs_sha256(path)
            with patch.dict(directory.__dict__, st_mode=stat.S_IFDIR | 0o777), self.assertRaises(runbooks.Held):
                runbooks.issued_inputs_sha256(path)
