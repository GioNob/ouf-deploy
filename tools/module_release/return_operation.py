"""Reviewed return to the retained predecessor of a READY or interrupted release."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import snapshot
from .recovery import verify_stop_claim
from .operation import (Docker, checked_generation, load_predecessor, read as journal_read, ready, reason,
                        record, restore, retained, unlock_module, verify_database, verify_flyway_return,
                        verify_never_started)


def completed_return(profile, rt, root, stamp):
    """Verify the immutable receipt, its journals and the restored service without effects."""
    receipt = journal_read(root, "return-receipt.json")
    require(receipt.get("status") == "ROLLED_BACK", "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    require(receipt.get("planSha256") == stamp, "RETURN_RECEIPT_DRIFT")
    plan = journal_read(root, "plan.json")
    require(digest(plan) == stamp and plan["profileSha256"] == digest(profile), "RETURN_PLAN_CHANGED")
    old = load_predecessor(profile, rt, root)
    require(snapshot(old) == plan["oldFrameSha256"] and old["Id"] == plan["oldCid"], "RETURN_BASELINE_CHANGED")
    successor = None
    if (root / "created.json").exists():
        successor = journal_read(root, "created.json")["cid"]
        require(matches(SHA, successor) and successor != old["Id"] and
                journal_read(root, "create-intent.json") == {"requestSha256": plan["requestSha256"]},
                "RECOVERY_CREATE_CHANGED")
    else:
        require(not (root / "create-intent.json").exists(), "CREATE_OWNERSHIP_UNCONFIRMED")
    if (root / "receipt.json").exists():
        forward = journal_read(root, "receipt.json")
        require(forward.get("status") == "READY" and forward.get("planSha256") == stamp
                and successor and forward.get("successorCid") == successor, "RETURN_RECEIPT_DRIFT")
    require(journal_read(root, "return-intent.json") == {"cid": successor, "planSha256": stamp},
            "RETURN_INTENT_CHANGED")
    require(receipt.get("predecessorReadiness") == "UP" and
            receipt.get("predecessorReadyHttp") in profile["readiness"]["acceptStatus"], "RETURN_RECEIPT_DRIFT")
    doc = rt.inspect(profile["container"])
    require(doc["Id"] == receipt["restoredCid"] == plan["oldCid"] and doc["State"]["Running"]
            and ready(rt, doc, profile["readiness"]), "RETURN_READINESS_CHANGED")
    if (root / "restore-start.json").is_file():
        require(journal_read(root, "restore-generation.json") == {"generation": snapshot(doc)},
                "TERMINAL_GENERATION_CHANGED")
    else:
        require(snapshot(doc) == plan["oldFrameSha256"], "TERMINAL_GENERATION_CHANGED")
    failed = rt.inspect(profile["failedName"], missing=True)
    if successor:
        require(failed and failed["Id"] == successor and not failed["State"]["Running"] and
                not failed["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")
    else:
        require(failed is None, "CUSTODY_NAME_OCCUPIED")
    verify_database(profile, rt, old, root)
    verify_flyway_return(profile, rt, old, root)
    return receipt


def interrupted_successor(profile, rt, old, plan, root):
    """Identify the owned candidate before starting a reviewed return from an open release."""
    if not (root / "created.json").exists():
        require(not (root / "create-intent.json").exists(), "CREATE_OWNERSHIP_UNCONFIRMED")
        return None
    cid = journal_read(root, "created.json")["cid"]
    require(matches(SHA, cid) and cid != old["Id"] and journal_read(root, "create-intent.json") ==
            {"requestSha256": plan["requestSha256"]}, "RECOVERY_CREATE_CHANGED")
    retained(profile, rt, old)
    new = rt.inspect(profile["container"])
    require(new["Id"] == cid, "IMMEDIATE_SUCCESSOR_CHANGED")
    if new["State"]["Status"] == "created":
        verify_never_started(profile, rt, old, new, root)
    else:
        generation, _ = checked_generation(profile, rt, old, cid)
        require(journal_read(root, "start-generation.json") == {"cid": cid, "generation": generation},
                "START_GENERATION_UNCONFIRMED")
    return cid


def run(profile, stamp, runtime=None, *, recover=False, seal=None):
    require(matches(SHA, stamp) and ("database" in profile["migration"] or "flyway" in profile["migration"]),
            "INVALID_RETURN_PLAN")
    parent = Path(profile["journal"])
    root = parent / stamp
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return json.loads((root / name).read_bytes())

    result = {"planSha256": stamp, "status": "HELD"}
    resuming = interrupted = False
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        owned = recover and (lock / "owner.json").is_file() and journal_read(lock, "owner.json") == {"planSha256": stamp}
        if owned and (root / "return-intent.json").is_file() and (root / "return-receipt.json").is_file():
            receipt = completed_return(profile, runtime or Docker(profile), root, stamp)
            if seal:
                seal(root, "return-receipt")
            unlock_module(lock)
            return receipt
        resuming = (root / "return-intent.json").is_file()
        interrupted = "flyway" in profile["migration"] and not (root / "receipt.json").exists()
        if not (owned and (resuming or interrupted) and not (root / "return-receipt.json").exists()):
            return dict(result, reason="OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    unlock = not (resuming or interrupted)
    try:
        plan = read("plan.json")
        require(digest(plan) == stamp and plan["profileSha256"] == digest(profile), "RETURN_PLAN_CHANGED")
        rt = runtime or Docker(profile)
        old = load_predecessor(profile, rt, root)
        require(snapshot(old) == plan["oldFrameSha256"] and old["Id"] == plan["oldCid"], "RETURN_BASELINE_CHANGED")
        if interrupted:
            verify_stop_claim(rt, old, plan, root)
            if resuming:
                require(not (root / "create-intent.json").exists() or (root / "created.json").is_file(),
                        "CREATE_OWNERSHIP_UNCONFIRMED")
                cid = read("created.json")["cid"] if (root / "created.json").exists() else None
                if cid and rt.inspect(cid)["State"]["Running"]:
                    require(read("start-generation.json") == {"cid": cid, "generation": snapshot(rt.inspect(cid))},
                            "START_GENERATION_CHANGED")
            else:
                cid = interrupted_successor(profile, rt, old, plan, root)
        else:
            receipt = read("receipt.json")
            require(receipt["status"] == "READY" and receipt["planSha256"] == stamp
                    and receipt["predecessorCid"] == old["Id"]
                    and (resuming or not (root / "return-intent.json").exists()), "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
            cid = receipt["successorCid"]
        if "database" in profile["migration"]:
            require(digest(read("database.private.json")) == plan["databaseSha256"], "RETURN_BASELINE_CHANGED")
        claim = {"cid": cid, "planSha256": stamp}
        verify_flyway_return(profile, rt, old, root)
        if resuming:
            require(read("return-intent.json") == claim, "RETURN_INTENT_CHANGED")
            new = rt.inspect(cid) if cid else None
            if new and new["State"]["Running"] and not interrupted:
                require(snapshot(new) == receipt["successorFrameSha256"], "IMMEDIATE_SUCCESSOR_CHANGED")
        else:
            if not interrupted:
                retained(profile, rt, old)
                new = rt.inspect(profile["container"])
                require(new["Id"] == cid and snapshot(new) == receipt["successorFrameSha256"],
                        "IMMEDIATE_SUCCESSOR_CHANGED")
                unlock = False
                record(lock, "owner.json", {"planSha256": stamp})
            record(root, "return-intent.json", claim)
        try:
            status = restore(profile, rt, old, cid, root)
            result.update(status="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP", predecessorReadyHttp=status)
        except Exception as exc:
            result["reason"] = reason(exc)
        record(root, "return-receipt.json", result)
        if seal and result["status"] == "ROLLED_BACK":
            # Signed under the module lock: a lost process leaves the lock to completed_return.
            seal(root, "return-receipt")
        unlock = result["status"] == "ROLLED_BACK"
    except Exception as exc:
        if seal and result["status"] == "ROLLED_BACK":
            raise
        result["reason"] = reason(exc)
    finally:
        if unlock:
            unlock_module(lock)
    return result
