"""Fresh reviewed dispatch for an interrupted release under the host executor lock."""
from pathlib import Path

from . import operation as op
from .contract import SHA, Held, digest, matches, require, validate
from .frame import check_body, check_live_networks, epoch, snapshot


def residual(p, rt):
    state = {}
    for role in ("container", "retainedName", "failedName"):
        try:
            doc = rt.inspect(p[role], missing=True)
            state[role] = ({"cid": doc["Id"], "state": doc["State"]["Status"],
                            "networks": len(doc["NetworkSettings"]["Networks"])} if doc else "absent")
        except Exception:
            state[role] = "unobserved"
    return state


def proposal(p, rt):
    validate(p)
    parent = Path(p["journal"])
    lock = parent / (p["module"] + ".lock")
    require((lock / "owner.json").is_file(), "LOCK_OWNER_UNPROVEN")
    stamp = op.read(lock, "owner.json")["planSha256"]
    require(matches(SHA, stamp), "LOCK_OWNER_UNPROVEN")
    root = parent / stamp
    require((root / "plan.json").is_file(), "RECOVERY_PLAN_UNPUBLISHED")
    body = op.read(root, "plan.json")
    require(digest(body) == stamp and body["profileSha256"] == digest(p), "RECOVERY_PROFILE_CHANGED")
    require(not (root / "return-intent.json").exists(), "REVIEWED_RETURN_REQUIRED")
    require((root / "baseline.private.json").is_file(), "RECOVERY_BASELINE_UNPUBLISHED")
    if "database" in p["migration"]:
        require((root / "database.private.json").is_file(), "DATABASE_BASELINE_UNPUBLISHED")
    old = op.load_predecessor(p, rt, root)
    require(old["Id"] == body["oldCid"] and snapshot(old) == body["oldFrameSha256"], "RECOVERY_BASELINE_CHANGED")
    frames = {}
    for role in ("container", "retainedName", "failedName"):
        doc = rt.inspect(p[role], missing=True)
        frames[role] = snapshot(doc) if doc else None
    journal = {f.name: digest(op.read(root, f.name)) for f in root.glob("*.json")}
    proposal = {"operation": "module-recovery", "sourcePlan": stamp, "profileSha256": digest(p),
                "journal": journal, "frames": frames}
    if "candidateReview" in body:
        proposal["candidateReview"] = body["candidateReview"]
    return proposal


def verify_stop_claim(rt, old, body, root):
    if (root / "stop-intent.json").exists():
        require(op.read(root, "stop-intent.json") == {"cid": old["Id"]}, "STOP_CLAIM_CHANGED")
    else:
        # Before our stop claim even an exact CID might have been stopped by another owner.
        require(snapshot(rt.inspect(old["Id"])) == body["oldFrameSha256"] and
                not (root / "create-intent.json").exists(), "PRE_STOP_DRIFT")


def verify_compensation_custody(p, rt, receipt):
    failed = rt.inspect(p["failedName"], missing=True)
    require(not failed or failed["Id"] == receipt.get("successorCid"), "FAILED_NAME_OCCUPIED")
    if "successorCid" in receipt:
        require(failed and not failed["State"]["Running"] and
                not failed["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")


def resume(p, rt, approved, *, seal=None):
    """The executor has compared the approved recovery plan under its exclusive lock."""
    observed = proposal(p, rt)
    parent = Path(p["journal"])
    root = parent / observed["sourcePlan"]
    has_receipt = "receipt.json" in observed["journal"]
    receipt = op.read(root, "receipt.json") if has_receipt else None
    if observed != approved:
        if receipt and receipt.get("rollback") == "ROLLED_BACK":
            # Diagnose an occupant that arrived between the recovery review and apply.
            verify_compensation_custody(p, rt, receipt)
        raise Held("RECOVERY_PLAN_CHANGED")
    lock = parent / (p["module"] + ".lock")
    body = op.read(root, "plan.json")
    old = op.load_predecessor(p, rt, root)
    result = {"operation": "module-release", "status": "HELD", "planSha256": root.name,
              "predecessorCid": old["Id"]}
    # A completed receipt is immutable. Re-attest before releasing a leftover lock.
    if has_receipt:
        require(op.terminal_receipt(receipt),
                "TERMINAL_HELD_REQUIRES_OWNER")
        forward = receipt["status"] == "READY"
        if seal:
            successor = op.read(root, "created.json")["cid"] if (root / "created.json").is_file() else None
            require(receipt.get("operation") == "module-release" and receipt.get("planSha256") == root.name
                    and receipt.get("predecessorCid") == old["Id"] and receipt.get("successorCid") == successor,
                    "MODULE_RECEIPT_DRIFT")
            if forward:
                require(successor and receipt.get("readiness") == "UP" and
                        receipt.get("readyHttp") in p["readiness"]["acceptStatus"], "MODULE_RECEIPT_DRIFT")
            else:
                require(receipt.get("restoredCid") == old["Id"] and receipt.get("predecessorReadiness") == "UP"
                        and receipt.get("predecessorReadyHttp") in p["readiness"]["acceptStatus"],
                        "MODULE_RECEIPT_DRIFT")
        doc = rt.inspect(p["container"])
        cid = receipt["successorCid"] if forward else old["Id"]
        require(doc["Id"] == cid and op.ready(rt, doc, p["readiness"]), "TERMINAL_READINESS_CHANGED")
        if forward:
            require(snapshot(doc) == receipt["successorFrameSha256"], "TERMINAL_GENERATION_CHANGED")
            op.retained(p, rt, old)
        else:
            check_body(old, doc, old["Image"], old["Config"]["Image"])
            check_live_networks(old, doc)
            if (root / "restore-signal.json").exists():
                require(op.read(root, "restore-signal.json") == {"cid": cid, "epoch": epoch(doc)},
                        "TERMINAL_GENERATION_CHANGED")
            else:
                require(snapshot(doc) == body["oldFrameSha256"], "TERMINAL_GENERATION_CHANGED")
            verify_compensation_custody(p, rt, receipt)
        op.verify_database(p, rt, old, root, migrated=forward)
        op.verify_flyway_return(p, rt, old, root)
        if seal:
            # Completes a signature lost between the receipt and the lock release; never re-signs.
            seal(root, "receipt")
        op.unlock_module(lock)
        return receipt
    verify_stop_claim(rt, old, body, root)
    created = (root / "created.json").exists()
    if created:
        cid = op.read(root, "created.json")["cid"]
        require(matches(SHA, cid) and cid != old["Id"] and
                op.read(root, "create-intent.json") == {"requestSha256": body["requestSha256"]},
                "RECOVERY_CREATE_CHANGED")
        result["successorCid"] = cid
    if not created or (root / "rollback-intent.json").exists():
        require(not (root / "create-intent.json").exists() or created, "CREATE_OWNERSHIP_UNCONFIRMED")
        if (root / "migration-intent.json").exists():
            require((root / "migration-complete.json").exists(), "MIGRATION_OUTCOME_UNCONFIRMED")
        op.confirm(root, "rollback-intent.json", {"cid": old["Id"]})
        status = op.restore(p, rt, old, result.get("successorCid"), root)
        result.update(reason="INTERRUPTED_RELEASE_RESTORED", rollback="ROLLED_BACK", restoredCid=old["Id"],
                      predecessorReadyHttp=status, predecessorReadiness="UP")
    else:
        op.retained(p, rt, old)
        require(rt.inspect(p["failedName"], missing=True) is None, "CUSTODY_NAME_OCCUPIED")
        doc = rt.inspect(cid)
        require(doc["Id"] == cid and doc["Name"] == old["Name"], "SERVICE_IDENTITY_CHANGED")
        if doc["State"]["Status"] == "created":
            op.verify_never_started(p, rt, old, doc, root)
            op.start_candidate(p, rt, old, cid, root)
        require(op.read(root, "start-intent.json") == {"cid": cid} and
                (root / "start-generation.json").exists(), "START_GENERATION_UNCONFIRMED")
        require(op.read(root, "start-generation.json") == {"cid": cid, "generation": snapshot(rt.inspect(cid))},
                "START_GENERATION_CHANGED")
        if (root / "migration-plan.json").exists():
            stage = op.read(root, "migration-plan.json")
            check = op.checked_generation if (root / "release-signal.json").exists() else op.waiting_gate
            generation, checked = check(p, rt, old, cid)
            expected = {"cid": cid, "generation": generation, "planSha256": root.name,
                              "profileSha256": digest(p), "predecessorFrame": body["oldFrameSha256"],
                              "migration": p["migration"]}
            if "flyway" in p["migration"]:
                proof = (op.read(root, "flyway-plan.json") if (root / "release-signal.json").exists()
                         else op.flyway.checkpoint(rt, checked()))
                require(all(proof[k] == v for k, v in body["flywayBaseline"].items()), "FLYWAY_BASELINE_CHANGED")
                expected["flywayReview"] = proof
            require(stage == expected, "MIGRATION_PLAN_CHANGED")
            if (root / "release-signal.json").exists():
                require(op.read(root, "migration-review-consumed.json") == {"digest": digest(stage)},
                        "MIGRATION_REVIEW_UNPROVEN")
                proof = op.release(p, rt, old, cid, root, expected_generation=generation)
                op.retained(p, rt, old)
                result.update(status="READY", readiness="UP", **proof)
            else:
                result.update(status="GATED", migrationSha256=digest(stage))
        else:
            op.finish_apply(p, rt, body, old, cid, root, result, defer_migration=True)
        if result["status"] == "GATED":
            op.confirm(root, "stage.json", result)
            return result
    op.record(root, "receipt.json", result)
    if seal and op.terminal_receipt(result):
        seal(root, "receipt")
    op.unlock_module(lock)
    return result
