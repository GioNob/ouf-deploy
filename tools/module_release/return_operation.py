"""Reviewed return to the retained predecessor of a READY or interrupted release."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import snapshot
from .recovery import verify_stop_claim
from .operation import (Docker, checked_generation, load_predecessor, read as journal_read, reason,
                        record, restore, retained, unlock_module, verify_flyway_return, verify_never_started)


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


def run(profile, stamp, runtime=None, *, recover=False):
    require(matches(SHA, stamp) and {"database", "flyway"}.intersection(profile["migration"]),
            "INVALID_RETURN_PLAN")
    parent = Path(profile["journal"])
    root = parent / stamp
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return journal_read(root, name)

    result = {"planSha256": stamp, "status": "HELD"}
    resuming = interrupted = False
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        resuming = (root / "return-intent.json").is_file()
        interrupted = "flyway" in profile["migration"] and not (root / "receipt.json").exists()
        if not (recover and (lock / "owner.json").is_file() and json.loads((lock / "owner.json").read_bytes())
                == {"planSha256": stamp} and (resuming or interrupted) and not (root / "return-receipt.json").exists()):
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
        unlock = result["status"] == "ROLLED_BACK"
    except Exception as exc:
        result["reason"] = reason(exc)
    finally:
        if unlock:
            unlock_module(lock)
    return result


from .contract import validate_profile_options

_run = run


def run(profile, stamp, runtime=None, *, recover=False):
    validate_profile_options(profile)
    from . import reviewed
    if reviewed.enabled(profile):
        return reviewed.return_run(profile, stamp, runtime)
    return _run(profile, stamp, runtime, recover=recover)


from .public_output import release_output
run = release_output(run)
