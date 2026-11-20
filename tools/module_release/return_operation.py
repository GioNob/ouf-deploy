"""Reviewed return from a READY receipt to its immediate predecessor."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import snapshot
from .operation import Docker, load_predecessor, reason, record, restore, retained


def run(profile, stamp, runtime=None):
    require(matches(SHA, stamp) and "database" in profile["migration"], "INVALID_RETURN_PLAN")
    parent = Path(profile["journal"])
    root = parent / stamp
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return json.loads((root / name).read_bytes())

    result = {"planSha256": stamp, "status": "HELD"}
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        return dict(result, reason="OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    unlock = True
    try:
        plan = read("plan.json")
        require(digest(plan) == stamp and plan["profileSha256"] == digest(profile), "RETURN_PLAN_CHANGED")
        receipt = read("receipt.json")
        require(receipt["status"] == "READY" and receipt["planSha256"] == stamp
                and not (root / "return-intent.json").exists(), "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
        rt = runtime or Docker(profile)
        old = load_predecessor(profile, rt, root)
        require(snapshot(old) == plan["oldFrameSha256"] and old["Id"] == receipt["predecessorCid"]
                and digest(read("database.private.json")) == plan["databaseSha256"], "RETURN_BASELINE_CHANGED")
        retained(profile, rt, old)
        new = rt.inspect(profile["container"])
        require(new["Id"] == receipt["successorCid"] and snapshot(new) == receipt["successorFrameSha256"],
                "IMMEDIATE_SUCCESSOR_CHANGED")
        unlock = False
        record(root, "return-intent.json", {"cid": new["Id"], "planSha256": stamp})
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
            lock.rmdir()
    return result
