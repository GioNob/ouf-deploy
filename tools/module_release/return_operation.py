"""Reviewed return to the retained predecessor of a READY or interrupted release."""
import json
from pathlib import Path

from .contract import SHA, digest, matches, require
from .frame import check_created_networks, epoch, snapshot
from .recovery import verify_stop_claim
from .operation import (Docker, checked_generation, load_predecessor, read as journal_read, ready, reason,
                        reconcile_create, record, restore, retained, unlock_module, verify_database,
                        verify_flyway_return, verify_never_started, waiting_gate)


def verify_exited(profile, old, doc, root, *, parking=False):
    from .config_delta import expected_after
    from .install_operation import park_proof, same_stopped_run

    require((root / "gate-run.json").is_file(), "START_GENERATION_UNCONFIRMED")
    proof = journal_read(root, "gate-run.json")
    require(doc["State"]["Status"] == "exited" and same_stopped_run(doc, park_proof(doc), proof)
            and journal_read(root, "start-intent.json") == {"cid": doc["Id"]},
            "START_GENERATION_CHANGED")
    if (root / "start-generation.json").is_file():
        require(journal_read(root, "start-generation.json") == {"cid": doc["Id"], "generation": proof["frameSha256"]},
                "START_GENERATION_CHANGED")
    projected = expected_after(old, profile["configDelta"])
    expected = projected["NetworkSettings"]["Networks"]
    remaining = doc["NetworkSettings"]["Networks"]
    if parking:
        require(remaining.keys() <= expected.keys(), "UNEXPECTED_NETWORK")
        projected["NetworkSettings"]["Networks"] = {k: expected[k] for k in remaining}
    check_created_networks(projected, doc)
    require(all(ep.get("IPAddress", "") in ("", expected[k]["IPAddress"]) for k, ep in remaining.items()),
            "ENDPOINT_DELTA")


def verify_return_receipt(profile, rt, old, cid, root, plan):
    terminal = journal_read(root, "return-receipt.json")
    require(terminal.get("status") == "ROLLED_BACK" and terminal.get("restoredCid") == old["Id"]
            and terminal.get("planSha256") == root.name and terminal.get("configDeltaSha256") == plan["configDeltaSha256"]
            and terminal.get("predecessorReadiness") == "UP"
            and terminal.get("predecessorReadyHttp") in profile["readiness"]["acceptStatus"],
            "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
    doc = rt.inspect(profile["container"])
    require(doc["Id"] == old["Id"] and ready(rt, doc, profile["readiness"]), "TERMINAL_READINESS_CHANGED")
    if (root / "restore-start.json").exists():
        require(journal_read(root, "restore-generation.json") == {"generation": snapshot(doc)} and
                journal_read(root, "restore-signal.json") == {"cid": old["Id"], "epoch": epoch(doc)},
                "TERMINAL_GENERATION_CHANGED")
    else:
        require(snapshot(doc) == plan["oldFrameSha256"], "TERMINAL_GENERATION_CHANGED")
    if cid:
        failed = rt.inspect(profile["failedName"])
        require(failed["Id"] == cid and not failed["State"]["Running"] and failed["State"]["Pid"] == 0
                and not failed["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")
    verify_database(profile, rt, old, root)
    return terminal


def interrupted_successor(profile, rt, old, plan, root):
    """Identify the owned candidate before starting a reviewed return from an open release."""
    if not (root / "created.json").exists():
        cid = None
        if (root / "create-intent.json").exists():
            require("configDelta" in profile, "CREATE_OWNERSHIP_UNCONFIRMED")
            cid = reconcile_create(profile, rt, old, plan, root)
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
    elif "configDelta" in profile and new["State"]["Status"] == "exited":
        verify_exited(profile, old, new, root)
    elif "configDelta" not in profile or (root / "start-generation.json").exists():
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
    delta = "configDelta" in profile
    require(matches(SHA, stamp) and ("database" in migration or "flyway" in migration or delta and migration["mode"] == "none"),
            "INVALID_RETURN_PLAN")
    parent = Path(profile["journal"])
    root = parent / stamp
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return json.loads((root / name).read_bytes())

    result = {"planSha256": stamp, "status": "HELD"}
    resuming = interrupted = existing_lock = False
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        existing_lock = True
        resuming = (root / "return-intent.json").is_file()
        has_receipt = (root / "receipt.json").exists()
        interrupted = (delta or "flyway" in migration) and not has_receipt
        recoverable = resuming or interrupted or (delta and has_receipt)
        if (root / "return-receipt.json").exists():
            recoverable = delta and resuming
        if not (recover and (lock / "owner.json").is_file() and json.loads((lock / "owner.json").read_bytes())
                == {"planSha256": stamp} and recoverable):
            return dict(result, reason="OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    unlock = not existing_lock
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
            if delta and migration["mode"] == "dedicated":
                require("database" in migration and not any((root / name).exists() for name in
                        ("migration-intent.json", "migration-complete.json", "release-signal.json")),
                        "MIGRATION_OUTCOME_UNCONFIRMED")
                verify_database(profile, rt, old, root)
            if resuming:
                require(delta or not (root / "create-intent.json").exists() or (root / "created.json").is_file(),
                        "CREATE_OWNERSHIP_UNCONFIRMED")
                cid = read("created.json")["cid"] if (root / "created.json").exists() else None
                if delta:
                    saved = read("return-intent.json")
                    if "generation" in saved:
                        require(cid and matches(SHA, saved["generation"]), "RETURN_INTENT_CHANGED")
                        claim["generation"] = saved["generation"]
                elif cid and rt.inspect(cid)["State"]["Running"]:
                    require(read("start-generation.json") == {"cid": cid, "generation": snapshot(rt.inspect(cid))},
                            "START_GENERATION_CHANGED")
            else:
                claim.update(interrupted_successor(profile, rt, old, plan, root))
                cid = claim["cid"]
        else:
            receipt = read("receipt.json")
            require(receipt["status"] == "READY" and receipt["planSha256"] == stamp
                    and (not delta or receipt["configDeltaSha256"] == plan["configDeltaSha256"])
                    and receipt["predecessorCid"] == old["Id"]
                    and (resuming or not (root / "return-intent.json").exists()), "RETURN_ALREADY_CONSUMED_OR_UNAVAILABLE")
            cid = receipt["successorCid"]
        if "database" in profile["migration"]:
            require(digest(read("database.private.json")) == plan["databaseSha256"], "RETURN_BASELINE_CHANGED")
        claim["cid"] = cid
        verify_flyway_return(profile, rt, old, root)
        if resuming:
            require(read("return-intent.json") == claim, "RETURN_INTENT_CHANGED")
            if delta and (root / "return-receipt.json").exists():
                terminal = verify_return_receipt(profile, rt, old, cid, root, plan)
                unlock = True
                return terminal
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
                if not existing_lock:
                    record(lock, "owner.json", {"planSha256": stamp})
            record(root, "return-intent.json", claim)
        if delta and interrupted and cid:
            new = rt.inspect(cid)
            if new["State"]["Running"]:
                proof = ({"cid": cid, "generation": claim["generation"]} if "generation" in claim
                         else read("start-generation.json"))
                require(new["Id"] == cid and proof == {"cid": cid, "generation": snapshot(new)},
                        "START_GENERATION_CHANGED")
            elif new["State"]["Status"] == "exited" and (root / "gate-run.json").exists():
                verify_exited(profile, old, new, root, parking=True)
        try:
            status = restore(profile, rt, old, cid, root)
            result.update(status="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP", predecessorReadyHttp=status)
        except Exception as exc:
            result["reason"] = reason(exc)
            if delta and result["reason"] == "PREDECESSOR_READINESS_NOT_UP" and (root / "restore-signal.json").is_file():
                # A fresh reviewed return can observe delivery or retire the still-gated run.
                return result
        record(root, "return-receipt.json", result)
        unlock = result["status"] == "ROLLED_BACK"
    except Exception as exc:
        result["reason"] = reason(exc)
    finally:
        if unlock:
            unlock_module(lock)
    return result
