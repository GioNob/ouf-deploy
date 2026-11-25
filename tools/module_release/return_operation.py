"""Reviewed return to the retained predecessor of a READY or interrupted release."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import snapshot
from .recovery import verify_stop_claim
from .operation import (Docker, checked_generation, load_predecessor, read as journal_read, reason,
                        reconcile_create, record, restore, retained, unlock_module, verify_database,
                        verify_flyway_return, verify_never_started, waiting_gate)


def interrupted_successor(profile, rt, old, plan, root):
    """Identify the owned candidate before starting a reviewed return from an open release."""
    if not (root / "created.json").exists():
        cid = reconcile_create(profile, rt, old, plan, root) if (root / "create-intent.json").exists() else None
        return {"cid": cid}
    cid = journal_read(root, "created.json")["cid"]
    require(matches(SHA, cid) and cid != old["Id"] and journal_read(root, "create-intent.json") ==
            {"requestSha256": plan["requestSha256"]},
            "RECOVERY_CREATE_CHANGED")
    retained(profile, rt, old)
    new = rt.inspect(profile["container"])
    require(new["Id"] == cid, "IMMEDIATE_SUCCESSOR_CHANGED")
    if new["State"]["Status"] == "created":
        verify_never_started(profile, rt, old, new, root)
    elif (root / "start-generation.json").exists():
        generation, _ = checked_generation(profile, rt, old, cid)
        require(journal_read(root, "start-generation.json") == {"cid": cid, "generation": generation},
                "START_GENERATION_UNCONFIRMED")
    else:
        require((root / "start-intent.json").is_file() and journal_read(root, "start-intent.json") == {"cid": cid}
                and not any((root / name).exists() for name in ("migration-plan.json", "release-signal.json")),
                "START_GENERATION_UNCONFIRMED")
        generation, checked = waiting_gate(profile, rt, old, cid)
        doc = checked()
        state = doc["State"]
        zero = "0001-01-01T00:00:00Z"
        require(doc["RestartCount"] == 0 and state["Status"] == "running" and state["StartedAt"] not in ("", None, zero)
                and state.get("FinishedAt") == zero,
                "START_GENERATION_UNCONFIRMED")
        # Pin this observation to the return only. Forward recovery still needs its own start receipt.
        return {"cid": cid, "generation": generation}
    return {"cid": cid}


def run(profile, stamp, runtime=None, *, recover=False):
    migration = profile["migration"]
    require(matches(SHA, stamp) and ("database" in migration or "flyway" in migration or migration["mode"] == "none"),
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
        resuming = (root / "return-intent.json").is_file()
        interrupted = not (root / "receipt.json").exists()
        if not (recover and (lock / "owner.json").is_file() and json.loads((lock / "owner.json").read_bytes())
                == {"planSha256": stamp} and (resuming or interrupted) and not (root / "return-receipt.json").exists()):
            return dict(result, reason="OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    unlock = not (resuming or interrupted)
    try:
        plan = read("plan.json")
        require(digest(plan) == stamp and plan["profileSha256"] == digest(profile), "RETURN_PLAN_CHANGED")
        if "configDeltaSha256" in plan:
            result["configDeltaSha256"] = plan["configDeltaSha256"]
        rt = runtime or Docker(profile)
        old = load_predecessor(profile, rt, root)
        require(snapshot(old) == plan["oldFrameSha256"] and old["Id"] == plan["oldCid"], "RETURN_BASELINE_CHANGED")
        claim = {"planSha256": stamp}
        if interrupted:
            verify_stop_claim(rt, old, plan, root)
            if migration["mode"] == "dedicated":
                require("database" in migration and not any((root / name).exists() for name in
                        ("migration-intent.json", "migration-complete.json", "release-signal.json")),
                        "MIGRATION_OUTCOME_UNCONFIRMED")
                verify_database(profile, rt, old, root)
            if resuming:
                cid = read("created.json")["cid"] if (root / "created.json").exists() else None
                saved = read("return-intent.json")
                if "generation" in saved:
                    require(cid and matches(SHA, saved["generation"]), "RETURN_INTENT_CHANGED")
                    claim["generation"] = saved["generation"]
            else:
                claim.update(interrupted_successor(profile, rt, old, plan, root))
                cid = claim["cid"]
        else:
            receipt = read("receipt.json")
            require(receipt["status"] == "READY" and receipt["planSha256"] == stamp
                    and receipt.get("configDeltaSha256") == plan.get("configDeltaSha256")
                    and receipt["predecessorCid"] == old["Id"]
                    and (resuming or not (root / "return-intent.json").exists()), "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
            cid = receipt["successorCid"]
        if "database" in profile["migration"]:
            require(digest(read("database.private.json")) == plan["databaseSha256"], "RETURN_BASELINE_CHANGED")
        claim["cid"] = cid
        verify_flyway_return(profile, rt, old, root)
        if resuming:
            require(read("return-intent.json") == claim, "RETURN_INTENT_CHANGED")
            new = rt.inspect(cid) if cid and not interrupted else None
            if new and new["State"]["Running"]:
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
        if interrupted and cid:
            new = rt.inspect(cid)
            if new["State"]["Running"]:
                proof = ({"cid": cid, "generation": claim["generation"]} if "generation" in claim
                         else read("start-generation.json"))
                require(new["Id"] == cid and proof == {"cid": cid, "generation": snapshot(new)},
                        "START_GENERATION_CHANGED")
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
