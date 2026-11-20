"""Private files in a root-owned tree. Journal publication survives process loss."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

from mandate import Held, canonical, need


def trusted(path, *, private=False):
    p = Path(path)
    need(p.is_absolute() and p.resolve(strict=True) == p, "ROOT_PATH_REQUIRED")
    for part in (*reversed(p.parents), p):
        info = part.lstat()
        need(info.st_uid == 0 and not info.st_mode & 0o022, "ROOT_CUSTODY_REQUIRED")
    need(p.is_file() and (not private or not info.st_mode & 0o077), "FILE_CUSTODY_REQUIRED")
    return p


def bound(binding):
    path = trusted(binding["path"])
    need(hashlib.sha256(path.read_bytes()).hexdigest() == binding["sha256"], "BOUND_FILE_DRIFT")
    return path


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value, *, replace=False):
    raw = canonical(value)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            tmp.unlink()
            raise
    try:
        if replace:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
        sync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def read(path):
    return json.loads(trusted(path, private=True).read_bytes())


def begin_plan(directory):
    """Reserve a fresh run under the entrypoint lock without consuming a review."""
    need(not directory.exists(), "PHASE_ALREADY_AUTHORIZED")
    Journal(directory)
    save(directory / "approvals", [])


def consume_approval(directory, phase, index):
    """Called under the entrypoint lock, before dispatching any phase effect."""
    ledger = directory / "approvals"
    existing = directory.exists()
    phases = []
    if existing:
        need(ledger.is_file(), "APPROVAL_JOURNAL_MISSING")
        phases = read(ledger)
        need(isinstance(phases, list) and all(isinstance(item, str) for item in phases)
             and len(set(phases)) == len(phases), "APPROVAL_JOURNAL_INVALID")
    need(phase not in phases, "PHASE_ALREADY_AUTHORIZED")
    need(index == len(phases) + 1, "EXACT_HUMAN_REVIEW_REQUIRED")
    if not existing:
        Journal(directory)
    save(ledger, [*phases, phase], replace=existing)


class Journal:
    def __init__(self, directory):
        self.path = directory
        directory.mkdir(mode=0o700, exist_ok=True)
        sync_dir(directory.parent)

    def effect(self, name, plan, action):
        from mandate import digest
        stamp = digest(plan)
        claim = self.path / (name + ".claim")
        receipt = self.path / (name + ".receipt")
        if receipt.exists():
            row = read(receipt)
            need(read(claim) == plan and row["planSha256"] == stamp, "RECEIPT_PLAN_DRIFT")
            return row["result"]
        need(not claim.exists(), "EFFECT_OUTCOME_REQUIRES_RECONCILIATION")
        save(claim, plan)
        try:
            result = action()
        except Exception as error:
            save(self.path / (name + ".failure"), {"planSha256": stamp,
                 "reason": str(error) if isinstance(error, Held) else "EFFECT_OUTCOME_UNPROVEN"})
            raise
        save(receipt, {"planSha256": stamp, "result": result})
        return result
