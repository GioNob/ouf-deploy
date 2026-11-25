"""Task 63d-b. Quiesced v12 owner fixture, real operate gates, simulated host."""
from contextlib import contextmanager, redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
import test_semantic_provider_r3_operate as F
import test_semantic_provider_r3_v12 as V12
import test_runtime_v52_epochs as E

O = F.O


class PreviousBoot(unittest.TestCase):
    def setUp(self):
        gate = V12.StartGate()
        args, owner, journal, tables, runtime = self.enterContext(gate.observation_fixture())
        self.args, self.owner, self.journal, self.tables, self.runtime = args, owner, journal, tables, runtime
        self.cfg, raw = runtime.load_configuration(None)
        self.head = runtime.authorization_head()
        self.epochs = runtime.operation_modules(None)[1]
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        args.output_directory = str(self.base / "claim")
        self.cfg["runtimeStateRoot"] = str(self.base / "state")
        self.head["authorization"]["runtimeConfigurationSha256"] = O.sha(raw)
        self.head["sha256"] = O.sha(O.canonical(self.head["authorization"]))
        self.records = {cid: dict(containerId=cid, epoch=1, state="STARTED", bootId="earlier",
            failure=None, generation=dict(pid=42, startTicks=123), runtimeRoot=str(self.base / "state" / "child"),
            configurationHash=O.sha(raw), authorizationSha256=self.head["sha256"]) for cid in self.cfg["candidates"]}
        self.row = next(iter(self.records.values()))
        self.epochs.current = lambda registry, cid: self.records[cid]
        self.epochs.live = lambda row, boot: row["bootId"] == boot
        self.locks = []
        @contextmanager
        def lock(name):
            self.locks.append(name)
            try:
                yield
            finally:
                self.assertEqual(self.locks.pop(), name)
        self.enterContext(patch.object(O.I, "operation_locks", side_effect=lambda *_: lock("cid")))
        self.enterContext(patch.object(O.V, "guard_lock", return_value={}))
        self.enterContext(patch.object(O.I, "guard", side_effect=lambda *_: lock("lease")))
        runc = E.PortableContracts().runtime()

        def inactive(cfg, cid, verb, root, argv):
            self.assertEqual(self.locks, ["cid", "lease"])
            self.assertEqual(argv, ["--root", self.records[cid]["runtimeRoot"], "state", cid])
            with patch.object(runc.subprocess, "run", side_effect=self.state_probe):
                return runc.inactive({"runtimePath": "/fixture/runc"}, cid, verb, root, argv)
        self.runtime.inactive = inactive
        self.rc, self.stderr = 1, b"container does not exist"

    def state_probe(self, argv, **kwargs):
        if "stdout" in kwargs:
            kwargs["stderr"].write(self.stderr)
        return E.subprocess.CompletedProcess(argv, self.rc)

    def plan(self):
        return O.proposal(self.args, O.observe(self.args))

    def read_started_cohort(self):
        # Simulate the runtime's publications and Docker inspect. Observe must
        # fetch the immediately preceding journal and verify its authority.
        files = {Path(self.cfg["operation"]["authorizationRoot"]) / (str(n) + ".json"):
                 O.canonical(self.head["authorization"]) if n == self.head["sequence"] else b"earlier"
                 for n in range(1, self.head["sequence"] + 1)}
        self.runtime.read = files.__getitem__
        def journal(raw, cid, number):
            row = O.decode(raw)
            self.assertEqual((row["containerId"], row["epoch"]), (cid, number))
            return row
        self.epochs.validate_journal = journal
        for cid, old in self.records.items():
            path = Path(self.cfg["registryRoot"]) / cid / "epochs/1/adapter.json"
            files[path] = O.canonical({**old, "state": "ABANDONED"})
            self.records[cid] = {**old, "bootId": "boot", "epoch": 2}
        frame = O.docker_fields
        with patch.object(O, "docker_fields", side_effect=lambda *a: {
                **frame(*a), "Status": "running", "Running": True, "Pid": 42}):
            return O.observe(self.args)

    def test_plan_and_abandoned_started_readback(self):
        self.args.plan, self.args.apply = True, False
        out = io.StringIO()
        with patch.object(O, "arguments", return_value=self.args), patch.object(O.sys, "platform", "linux"), \
                patch.object(O.os, "geteuid", return_value=0, create=True), \
                patch.object(O.os, "getegid", return_value=0, create=True), patch.object(O.os, "umask"), \
                patch.object(O.sys, "flags", F.SimpleNamespace(isolated=True, dont_write_bytecode=True)), redirect_stdout(out):
            self.assertEqual(O.main([]), 0, out.getvalue())
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["status"], "PLAN_READY")
        plan = self.plan()
        self.assertEqual(receipt["planSha256"], plan["planSha256"])
        before = plan["observation"]
        pending = before["epochsToAbandon"]
        self.assertEqual(set(pending), set(O.ROLES))
        self.assertEqual(plan, self.plan())
        with patch.object(self.epochs, "boot_id", return_value="later-boot"):
            self.assertNotEqual(self.plan()["planSha256"], plan["planSha256"])
        O.VR.idle(before)
        after = F.successful("start", before)
        after.update(configurationSha256=before["configurationSha256"], authorization=before["authorization"])
        after["supervisor"]["authorizationSequence"] = self.head["sequence"]
        after["candidates"] = self.read_started_cohort()["candidates"]
        for role in O.ROLES:
            for field, bad in (("epoch", 3), ("state", "DELETED"), ("abandonedJournalSha256", "0"*64)):
                different = copy.deepcopy(after)
                different["candidates"][role]["previousEpoch"][field] = bad
                self.assertFalse(O.reached(self.args, before, different))
        report = {"status": "HELD", **O.COUNTERS}
        self.args.plan_sha256 = plan["planSha256"]
        effects = []
        with patch.object(O, "observe", side_effect=[before, before, after]), patch.object(O.VR, "apply"), \
                patch.object(O.I.native_switch(), "sync", create=True), patch.object(O.I, "write_once"), \
                patch.object(O, "docker", side_effect=lambda args, verb, cid: effects.append((verb, cid))):
            O.apply(self.args, plan, report)
        self.assertEqual(report["status"], O.SUCCESS["start"])
        self.assertCountEqual(effects, [("start", cid) for cid in self.records])

    def test_epoch_proof_denials(self):
        for field, bad, code in (("containerId", "0"*64, "COHORT"), ("configurationHash", "0"*64, "CONFIGURATION"),
                                 ("authorizationSha256", "0"*64, "AUTHORIZATION"), ("runtimeRoot", None, "RUNTIME_ROOT"),
                                 ("runtimeRoot", str(self.base), "RUNTIME_ROOT")):
            with self.subTest(field=field, bad=bad), patch.dict(self.row, {field: bad}), \
                    self.assertRaisesRegex(RuntimeError, "R3_PREVIOUS_BOOT_EPOCH_"+code):
                self.plan()
        with patch.dict(self.head, decision="REVOKE"), self.assertRaisesRegex(RuntimeError, "EPOCH_AUTHORIZATION"):
            self.plan()
        with patch.dict(self.head["authorization"]["roles"]["adapter"], containerId="0"*64), \
                self.assertRaisesRegex(RuntimeError, "EPOCH_COHORT"):
            self.plan()
        with patch.dict(self.row, bootId="boot"), self.assertRaisesRegex(RuntimeError, "CANDIDATES_NOT_IDLE"):
            self.plan()
        for self.rc, self.stderr in ((0, b""), (1, b"permission denied"), (2, b"container does not exist")):
            with self.subTest(rc=self.rc), self.assertRaisesRegex(RuntimeError, "EPOCH_RUNC"):
                self.plan()

    def test_docker_lease_and_ingress_denials(self):
        frame = O.docker_fields
        for delta in (dict(Running=True), dict(Status="running"), dict(Pid=42)):
            with self.subTest(delta=delta), patch.object(O, "docker_fields",
                    side_effect=lambda *a: {**frame(*a), **delta}), self.assertRaisesRegex(RuntimeError, "EPOCH_DOCKER"):
                self.plan()
        with patch.dict(self.journal, leaseAuthorized=True), self.assertRaisesRegex(RuntimeError, "EPOCH_LEASE"):
            self.plan()
        with patch.dict(self.journal, state="BLOCKED"), self.assertRaisesRegex(RuntimeError, "KERNEL_JOURNAL_BLOCKED"):
            self.plan()
        command = O.command
        def nft(path, digest, argv, timeout):
            raw = command(path, digest, argv, timeout)
            if argv[:3] != ["-j", "list", "table"]:
                return raw
            data = O.decode(raw)
            for item in data["nftables"]:
                if "set" in item:
                    item["set"]["elem"] = [{"elem": {"val": "192.0.2.1", "expires": ttl}}]
                    if drift:
                        item["set"]["handle"] += 1
            return O.canonical(data)
        for drift, ttl in ((False, 30), (False, 0), (True, 0)):
            with patch.object(O, "command", side_effect=nft), self.assertRaisesRegex(
                    RuntimeError, "KERNEL_STRUCTURE_DRIFT" if drift else "EPOCH_INGRESS"):
                self.plan()
        self.tables.add(("inet", self.head["authorization"]["roles"]["adapter"]["tableName"]))
        with self.assertRaisesRegex(RuntimeError, "EPOCH_INGRESS"):
            self.plan()

    def test_interruption_after_claim_or_after_starts(self):
        for after_start in (False, True):
            self.args.output_directory = str(self.base / str(after_start))
            plan = self.plan()
            before = plan["observation"]
            self.args.plan_sha256 = plan["planSha256"]
            report = {"status": "HELD", **O.COUNTERS}
            claim = Path(self.args.output_directory) / "operate-claim.json"
            def save(path, raw, _):
                path.write_bytes(raw)
            docker = Mock()
            with patch.object(O, "observe", return_value=before), patch.object(O.I, "write_once", side_effect=save), \
                    patch.object(O.I.native_switch(), "sync", create=True), patch.object(O, "docker", docker), \
                    patch.object(O.VR, "apply", side_effect=None if after_start else InterruptedError()), \
                    patch.object(O, "poll", side_effect=InterruptedError()), self.assertRaises(InterruptedError):
                O.apply(self.args, plan, report)
            self.assertEqual(json.loads(claim.read_bytes()), plan)
            self.assertTrue(report["doNotRerunApply"])
            self.assertEqual(docker.call_count, 2 if after_start else 0)
            self.assertTrue(all(row["state"] == "STARTED" for row in self.records.values()))
            self.args.output_directory += "-new"
            if after_start:
                current = self.read_started_cohort()
                for row in current["candidates"].values():
                    self.assertEqual((row["epoch"]["epoch"], row["previousEpoch"]["state"]), (2, "ABANDONED"))
                with self.assertRaisesRegex(RuntimeError, "CANDIDATES_NOT_IDLE"):
                    O.proposal(self.args, current)
            else:
                self.assertEqual(self.plan()["observation"], before)


if __name__ == "__main__":
    unittest.main()
