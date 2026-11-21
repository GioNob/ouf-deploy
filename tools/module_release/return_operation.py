"""Reviewed return from a READY receipt to its immediate predecessor."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import snapshot
from .operation import Docker, load_predecessor, reason, record, restore, retained, unlock_module


def run(profile, stamp, runtime=None, *, recover=False):
    require(matches(SHA, stamp) and "database" in profile["migration"], "INVALID_RETURN_PLAN")
    parent = Path(profile["journal"])
    root = parent / stamp
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return json.loads((root / name).read_bytes())

    result = {"planSha256": stamp, "status": "HELD"}
    resuming = False
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        if not (recover and (lock / "owner.json").is_file() and json.loads((lock / "owner.json").read_bytes())
                == {"planSha256": stamp} and (root / "return-intent.json").is_file()
                and not (root / "return-receipt.json").exists()):
            return dict(result, reason="OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        resuming = True
    unlock = not resuming
    try:
        plan = read("plan.json")
        require(digest(plan) == stamp and plan["profileSha256"] == digest(profile), "RETURN_PLAN_CHANGED")
        receipt = read("receipt.json")
        require(receipt["status"] == "READY" and receipt["planSha256"] == stamp
                and (resuming or not (root / "return-intent.json").exists()), "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
        rt = runtime or Docker(profile)
        old = load_predecessor(profile, rt, root)
        require(snapshot(old) == plan["oldFrameSha256"] and old["Id"] == receipt["predecessorCid"]
                and digest(read("database.private.json")) == plan["databaseSha256"], "RETURN_BASELINE_CHANGED")
        cid = receipt["successorCid"]
        claim = {"cid": cid, "planSha256": stamp}
        if resuming:
            require(read("return-intent.json") == claim, "RETURN_INTENT_CHANGED")
            new = rt.inspect(cid)
            if new["State"]["Running"]:
                require(snapshot(new) == receipt["successorFrameSha256"], "IMMEDIATE_SUCCESSOR_CHANGED")
        else:
            retained(profile, rt, old)
            new = rt.inspect(profile["container"])
            require(new["Id"] == cid and snapshot(new) == receipt["successorFrameSha256"],
                    "IMMEDIATE_SUCCESSOR_CHANGED")
            unlock = False
            record(lock, "owner.json", {"planSha256": stamp})
            record(root, "return-intent.json", claim)
        try:
            status = restore(profile, rt, old, new["Id"], root)
            result.update(status="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP", predecessorReadyHttp=status)
        except Exception as exc:
            result["reason"] = reason(exc)
        record(root, "return-receipt.json", result)
        unlock = result["status"] == "ROLLED_BACK"
    except Exception as exc:
        result["reason"] = reason(exc)
    finally:
        if unlock:
            unlock_module(lock)
    return result
