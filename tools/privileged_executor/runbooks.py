"""Invoke only the reviewed runbook for a protocol role, with a private HOME."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from mandate import Held, hex64, need
from store import bound, read, save, trusted

SUCCESS = {"stop": "SEMANTIC_PROVIDER_R3_STOPPED", "start": "SEMANTIC_PROVIDER_R3_STARTED",
           "issue": "SEMANTIC_PROVIDER_OPERATION_AUTHORIZATION_ISSUED",
           "upgrade": "SEMANTIC_PROVIDER_R3_UPGRADED_WAITING", "probe": "C_PROBE_PASSED"}


def issued_probe_inputs(home, install_root, version):
    """Mirror the C probe's issuance pointer when supplying explicit inputs."""
    pointer = home / f".ouf-r3-v{version}-state"
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        fd = os.open(pointer, flags)
    except FileNotFoundError:
        return {}
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 512, "C_R3_ISSUANCE_UNPROVEN")
        raw = os.read(fd, 513)
        need(len(raw) == info.st_size, "C_R3_ISSUANCE_UNPROVEN")
    finally:
        os.close(fd)
    match = re.fullmatch(rb"(/etc/ouf/deploy-snapshots/semantic-provider-r3-source\.[A-Za-z0-9]{8}) ([0-9]{1,20})\n?", raw)
    need(match, "C_R3_ISSUANCE_UNPROVEN")
    head = read(Path(install_root) / "authorization" / f"{version}.json")
    need(head["sequence"] == version and head["issuedAt"] == int(match[2]), "C_R3_ISSUANCE_UNPROVEN")
    path = match[1].decode("ascii") + "/inputs.json"
    return {"C_R3_INPUTS": path, "C_R3_INPUTS_SHA256": issued_inputs_sha256(path)}


def issued_inputs_sha256(path):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o022, "C_R3_INPUTS_UNPROVEN")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
             and 0 < info.st_size <= 131072, "C_R3_INPUTS_UNPROVEN")
        raw = os.read(fd, 131073)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        need(len(raw) == info.st_size and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()),
             "C_R3_INPUTS_UNPROVEN")
    finally:
        os.close(fd)
    return hashlib.sha256(raw).hexdigest()


class Books:
    def __init__(self, cfg, home):
        self.cfg, self.home = cfg, home
        self.probe_source = None

    def binding(self, op, version):
        need(op in SUCCESS and version in (27, 28, 29), "UNKNOWN_OPERATION")
        binding = self.cfg["runbooks"][f"{op}-{version}"]
        path = bound(binding)
        pin = binding["sourceCommit"]
        need(re.fullmatch("[0-9a-f]{40}", pin) and pin != "0"*40
             and re.findall(rb"^C=([0-9a-f]{40})$", path.read_bytes(), re.M) == [pin.encode()],
             "RUNBOOK_COMMIT_DRIFT")
        return path

    def call(self, op, version, approved=None):
        path = self.binding(op, version)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.home), "LC_ALL": "C"}
        if op in ("start", "stop"):
            env["AZIONE"] = op
        if op == "probe":
            for key in ("C_R3_INPUTS", "C_R3_INPUTS_SHA256", "C_INSTALLATION_PROFILE",
                        "C_INSTALLATION_PROFILE_SHA256"):
                env[key] = self.cfg["probe"][key]
            inputs = issued_probe_inputs(self.probe_source or self.home, self.cfg["installRoot"], version)
            need(self.probe_source is None or inputs, "C_R3_ISSUANCE_UNPROVEN")
            env.update(inputs)
            env["C_PROBE_STATE"] = str(self.home / f".ouf-c-probe-v{version}-state")
        need(approved is None or hex64(approved), "RUNBOOK_DIGEST")
        argv = ["apply", approved] if approved else ["plan"]
        result = subprocess.run(["/bin/bash", str(path), *argv], cwd=self.home, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=1200)
        # Legacy wrappers write delivery diagnostics before their final canonical JSON line.
        try:
            row = json.loads(result.stdout.splitlines()[-1])
        except (ValueError, IndexError):
            row = {}
        evidence = {"operation": op, "version": version, "mode": argv[0], "approved": approved,
                    "returncode": result.returncode, "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
                    "result": row}
        save(self.home / ("book-" + uuid.uuid4().hex), evidence)
        if (op == "stop" and approved and result.returncode == 1 and row.get("status") == "HELD"
                and row.get("reason") == "R3_PLAN_DIGEST_CHANGED" and row.get("doNotRerunApply") is False
                and not row.get("outputCreated") and row["dockerStopRequests"] == 0):
            raise RenewalCollision()
        if (op == "issue" and approved and result.returncode == 1 and row.get("status") == "HELD"
                and row.get("reason") == "PLAN_DIGEST_MISMATCH" and row.get("phase") == "PREFLIGHT"
                and row.get("doNotRerunApply") is False and row.get("signingAttempted") is False
                and row.get("privateKeysRead") == row.get("signaturesIssued") == 0 and row.get("writtenFiles") == []):
            save(self.home / "issue-no-effect", {"plan": approved, "result": row})
            raise Held("ISSUANCE_REQUIRES_NEW_REVIEW")
        need(result.returncode == 0 and row.get("status") == (SUCCESS[op] if approved else "PLAN_READY")
             and hex64(row["planSha256"]) and (not approved or row["planSha256"] == approved),
             "RUNBOOK_HELD")
        if op in ("stop", "start"):
            obs = row["lastObservation"]
            need(obs["authorization"]["sequence"] == version and obs["authorization"]["decision"] == "OPERATE",
                 "R3_HEAD_DRIFT")
        if op == "probe" and approved is None:
            need(row["observation"]["r3"]["authorization"]["sequence"] == version, "R3_HEAD_DRIFT")
        if op == "issue" and approved:
            need(row["sequence"] == version and row["signaturesIssued"] == 1
                 and row["decision"] == "OPERATE", "SIGNATURE_READBACK")
        return row

    def renewal(self):
        path = trusted(self.cfg["leaseJournal"], private=True)
        stat = path.stat()
        lease = read(path)
        need(lease["state"] == "LEASE_READY" and lease["leaseAuthorized"] is True, "LEASE_NOT_READY")
        return (stat.st_ino, stat.st_mtime_ns)

    def wait_renewal(self, previous):
        until = time.monotonic() + 15
        while time.monotonic() < until:
            try:
                if self.renewal() != previous:
                    return
            except Exception:
                pass
            time.sleep(.1)
        need(False, "RENEWAL_TIMEOUT")


class RenewalCollision(Exception):
    pass


def stop(books, version, approved, record):
    # A retry changes the wrapper's unique evidence directory. Its entire operation
    # and observation must equal the approved ones, including lease and peer epochs.
    def scope(row):
        return {k: v for k, v in row.items() if k not in ("outputDirectory", "planSha256")}
    current = approved
    for attempt in range(3):
        before = books.renewal()
        try:
            return books.call("stop", version, current["planSha256"])
        except RenewalCollision:
            need(attempt < 2, "STOP_RETRY_LIMIT")
            books.wait_renewal(before)
            current = books.call("stop", version)
            need(scope(current) == scope(approved), "STOP_REQUIRES_NEW_REVIEW")
            record(attempt + 1, current)
