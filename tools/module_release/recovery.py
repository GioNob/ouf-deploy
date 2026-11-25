"""Fresh reviewed dispatch for an interrupted release under the host executor lock."""
from pathlib import Path

from . import operation as op
from .contract import SHA, digest, matches, require, validate
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
    body = op.read(root, "plan.json")
    require(digest(body) == stamp and body["profileSha256"] == digest(p), "RECOVERY_PROFILE_CHANGED")
    require(not (root / "return-intent.json").exists(), "REVIEWED_RETURN_REQUIRED")
    old = op.load_predecessor(p, rt, root)
    require(old["Id"] == body["oldCid"] and snapshot(old) == body["oldFrameSha256"], "RECOVERY_BASELINE_CHANGED")
    frames = {}
    for role in ("container", "retainedName", "failedName"):
        doc = rt.inspect(p[role], missing=True)
        frames[role] = snapshot(doc) if doc else None
    journal = {f.name: digest(op.read(root, f.name)) for f in root.glob("*.json")}
    proposal = {"operation": "module-recovery", "sourcePlan": stamp, "profileSha256": digest(p),
                "journal": journal, "frames": frames}
    if "configDelta" in p:
        from .config_delta import approval_lines
        # Older journals may predate current checks on values shown to the reviewer.
        lines = approval_lines(p["configDelta"], p.get("showValues", []))
        require(lines == body["approvalLines"], "RECOVERY_PROFILE_CHANGED")
        proposal["approvalLines"] = lines
    if "candidateReview" in body:
        proposal["candidateReview"] = body["candidateReview"]
    if "mcp-retention-admin-019" in body:
        proposal["mcp-retention-admin-019"] = body["mcp-retention-admin-019"]
    return proposal


def verify_stop_claim(rt, old, body, root):
    if (root / "stop-intent.json").exists():
        require(op.read(root, "stop-intent.json") == {"cid": old["Id"]}, "STOP_CLAIM_CHANGED")
    else:
        # Before our stop claim even an exact CID might have been stopped by another owner.
        require(snapshot(rt.inspect(old["Id"])) == body["oldFrameSha256"] and
                not (root / "create-intent.json").exists(), "PRE_STOP_DRIFT")


def resume(p, rt, approved):
    """The executor has compared the approved recovery plan under its exclusive lock."""
    require(proposal(p, rt) == approved, "RECOVERY_PLAN_CHANGED")
    parent = Path(p["journal"])
    root = parent / approved["sourcePlan"]
    lock = parent / (p["module"] + ".lock")
    body = op.read(root, "plan.json")
    old = op.load_predecessor(p, rt, root)
    result = {"operation": "module-release", "status": "HELD", "planSha256": root.name,
              "predecessorCid": old["Id"]}
    # A completed receipt is immutable. Re-attest before releasing a leftover lock.
    if (root / "receipt.json").exists():
        receipt = op.read(root, "receipt.json")
        require(receipt.get("status") == "READY" or receipt.get("rollback") == "ROLLED_BACK",
                "TERMINAL_HELD_REQUIRES_OWNER")
        forward = receipt["status"] == "READY"
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
            if "successorCid" in receipt:
                failed = rt.inspect(receipt["successorCid"])
                require(failed["Name"] == "/" + p["failedName"] and not failed["State"]["Running"] and
                        not failed["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")
        op.verify_database(p, rt, old, root, migrated=forward)
        op.verify_flyway_return(p, rt, old, root)
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
    op.unlock_module(lock)
    return result
