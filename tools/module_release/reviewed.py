"""Opt-in release and return journal. All callers hold the installation flock."""
import os
from pathlib import Path
import signal as signals
import tempfile

from . import operation as op
from . import frame
from .docker import Docker
from .config_delta import approval_lines, delta_digest, expected_after, validate_delta
from .contract import SHA, digest, matches, require
from .profile_options import reviewed as enabled

OWNER_LABEL = "ouf.release.plan"


def projected(p, old):
    return expected_after(old, p["configDelta"]) if "configDelta" in p else old


def request(p, old, defaults):
    labels = frame.provenance_labels(p)
    require(OWNER_LABEL not in labels, "INVALID_PROVENANCE_LABELS")
    labels[OWNER_LABEL] = "0" * 64
    if "configDelta" in p:
        delta = validate_delta(p["configDelta"], p, p["module"], predecessor_mounts=old["Mounts"])
        require(not (p.get("candidate", {}).get("enableFlyway") and
                     any(row["name"] == "SPRING_FLYWAY_ENABLED" for row in delta.get("env", []))), "AMBIGUOUS_ENV")
    after = projected(p, old)
    if "persistentPathEnv" in p:
        op.check_persistent_paths(p, after)
    if "flyway" in p["migration"]:
        jar = op.PurePosixPath("/app", op.jar_name(p["gate"]["command"]))
        require(not any(jar.is_relative_to(m["Destination"]) for m in after["Mounts"]), "FLYWAY_JAR_SHADOWED")
    req = frame.request(after, p["ci"]["imageId"], labels, candidate=p.get("candidate"), image_defaults=defaults)
    removed = [r["name"] for r in p.get("configDelta", {}).get("env", []) if r["after"] is None]
    if removed:
        req["Env"] = [e for e in req["Env"] if e.partition("=")[0] not in removed] + removed
    return req


def stamp_request(req, root):
    req["Labels"][OWNER_LABEL] = root.name
    return req


def bind_plan(p, body, old):
    body["createPlanLabel"] = OWNER_LABEL
    if "configDelta" in p:
        body.update(configDeltaSha256=delta_digest(p["configDelta"]),
                    approvalLines=approval_lines(p["configDelta"], p.get("showValues", ())))
    # Re-planning after an interruption before stop may observe exactly the same generation.
    directory = Path(p["journal"])
    while (directory / digest(body) / "return-receipt.json").is_file():
        body["previousReturn"] = digest(body)
    return body, old


def lock_path(p):
    return Path(p["journal"]) / (p["module"] + ".lock")


def acquire(lock, stamp, plan):
    require(not lock.exists(), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    private = Path(tempfile.mkdtemp(prefix=".prepare-", dir=lock.parent))
    op.record(private, "plan.json", plan)
    op.record(private, "owner.json", {"planSha256": stamp})
    os.rename(private, lock)
    op.sync_dir(lock.parent)


def owner(lock, stamp):
    require((lock / "owner.json").is_file() and op.read(lock, "owner.json") == {"planSha256": stamp}
            and digest(op.read(lock, "plan.json")) == stamp, "LOCK_OWNER_UNPROVEN")


def cleanup(lock, stamp):
    directory = lock.with_name("." + lock.name + "-retired-" + stamp)
    if directory.exists():
        require(directory.is_dir() and {f.name for f in directory.iterdir()} <= {"owner.json", "plan.json"},
                "LOCK_CLEANUP_CHANGED")
        if (directory / "plan.json").exists():
            require(digest(op.read(directory, "plan.json")) == stamp, "LOCK_CLEANUP_CHANGED")
        if (directory / "owner.json").exists():
            require(op.read(directory, "owner.json") == {"planSha256": stamp}, "LOCK_CLEANUP_CHANGED")
        (directory / "plan.json").unlink(missing_ok=True)
        (directory / "owner.json").unlink(missing_ok=True)
        directory.rmdir()
        op.sync_dir(lock.parent)
    return directory


def unlock(lock, stamp):
    owner(lock, stamp)
    retired = cleanup(lock, stamp)
    os.rename(lock, retired)
    op.sync_dir(lock.parent)
    cleanup(lock, stamp)


def apply(p, stamp, runtime, previous, defer):
    result = {"operation": "module-release", "status": "HELD", "planSha256": stamp}
    try:
        require(matches(SHA, stamp), "PLAN_DIGEST_REQUIRED")
        lock = lock_path(p)
        require(not lock.exists(), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        rt = runtime or op.Docker(p)
        body, old = op.observe(p, rt, previous)
        require(digest(body) == stamp, "PLAN_CHANGED")
        root = lock.parent / stamp
        require(not root.exists(), "PLAN_ALREADY_CONSUMED")
        acquire(lock, stamp, body)
        root.mkdir(mode=0o700)
        op.sync_dir(root.parent)
        if "configDeltaSha256" in body:
            result["configDeltaSha256"] = body["configDeltaSha256"]
        try:
            op.execute(p, rt, body, old, root, result, defer)
        except Exception as exc:
            result["reason"] = op.reason(exc)
        publish_result(rt, root, result)
        if result["status"] == "READY" or result.get("rollback") == "ROLLED_BACK":
            unlock(lock, stamp)
    except Exception as exc:
        result.update(status="HELD", reason=op.reason(exc))
    return result


def network_baseline(p, old, restoring):
    return old if restoring else projected(p, old)


def labels(p):
    labels = frame.provenance_labels(p)
    if enabled(p):
        labels[OWNER_LABEL] = op.read(lock_path(p), "owner.json")["planSha256"]
    return labels


def removals(p):
    return {row["name"] for row in p.get("configDelta", {}).get("env", ()) if row["after"] is None}


def defaults(p, image_defaults, restoring):
    removed = set() if restoring else removals(p)
    if removed:
        return dict(image_defaults, Env=[v for v in image_defaults.get("Env", ()) if v.partition("=")[0] not in removed])
    return image_defaults


def body_args(p, old, doc, image, config_image, restoring):
    if not restoring and "configDelta" in p:
        old = projected(p, old)
        removed = removals(p)
        if removed:
            values = doc["Config"].get("Env") or []
            require(len({v.partition("=")[0] for v in values}) == len(values), "AMBIGUOUS_ENV")
            doc = dict(doc, Config=dict(doc["Config"], Env=[v for v in values if v not in removed]))
    return old, doc, image, config_image


def created(p, old, doc, root):
    frame.check_created_networks(projected(p, old), doc)
    if enabled(p):
        require(op.never_started(doc), "NEVER_STARTED_UNPROVEN")
        op.confirm(root, "create-proof.json", {"cid": doc["Id"], "stableFrameSha256": stable(doc)})


def stable(doc):
    host = dict(doc["HostConfig"])
    # Docker normalizes explicit false (CREATE) back to null on first start.
    if host.get("OomKillDisable") is False:
        host["OomKillDisable"] = None
    return digest([doc["Id"], doc["Image"], frame.configuration(doc), host, doc["Mounts"], doc["Path"], doc["Args"]])


def confirm_create(p, rt, old, doc, root):
    require(op.never_started(doc) and matches(SHA, doc["Id"]) and doc["Id"] != old["Id"]
            and doc["Name"] == old["Name"], "CREATED_IDENTITY_CHANGED")
    image = p["ci"]["imageId"]
    frame.check_body(*body_args(p, old, doc, image, image, False), created=True, labels=labels(p),
                     image_defaults=defaults(p, rt.image_defaults(image), False), candidate=p.get("candidate"))
    created(p, old, doc, root)


def endpoints(old, doc, *, candidate=False):
    before = old["NetworkSettings"]["Networks"]
    attached = doc["NetworkSettings"]["Networks"]
    require(attached.keys() <= before.keys(), "RESTORE_NETWORK_SET_CHANGED")
    for name, ep in attached.items():
        original = before[name]
        want = frame.endpoint(original)
        ipam = ep.get("IPAMConfig")
        require(ep.get("NetworkID") in ("", original["NetworkID"])
                and (ipam == want["IPAMConfig"] or not candidate and ipam == original.get("IPAMConfig"))
                and ep.get("IPAddress", "") in ("", original["IPAddress"])
                and ep.get("GlobalIPv6Address", "") in ("", original.get("GlobalIPv6Address", ""))
                and set(ep.get("Aliases") or ()) in (set(want["Aliases"]), set(want["Aliases"]) | {doc["Id"][:12]})
                and all(ep.get(k) == original.get(k) for k in ("Links", "GwPriority", "DriverOpts")), "ENDPOINT_DELTA")
    return attached


def attachments(p, old, doc, root):
    require(doc["RestartCount"] == old["RestartCount"], "RESTORE_GENERATION_CHANGED")
    if doc["State"]["Running"] and not (root / "restore-start.json").exists():
        require(frame.snapshot(old) == frame.snapshot(doc), "OLD_SERVICE_CHANGED")
    return endpoints(old, doc)


def candidate_generation(root, cid, doc):
    binding = {"cid": cid, "epoch": frame.epoch(doc), "generation": frame.snapshot(doc)}
    op.confirm(root, "candidate-epoch.json", binding)
    return binding["generation"]


def park_guard(p, rt, old, root, cid):
    if not enabled(p):
        return None

    def verify(doc):
        require(doc["Id"] == cid and doc["Name"] in (old["Name"], "/" + p["failedName"])
                and op.read(root, "create-proof.json") == {"cid": cid, "stableFrameSha256": stable(doc)}
                and doc["RestartCount"] == 0 and (doc["Config"].get("Labels") or {}).get(OWNER_LABEL) == root.name,
                "RESTORE_SUCCESSOR_CHANGED")
        state = doc["State"]
        require(not (root / "start-generation.json").exists() or (root / "candidate-epoch.json").is_file(),
                "START_GENERATION_UNCONFIRMED")
        if (root / "candidate-epoch.json").exists():
            binding = op.read(root, "candidate-epoch.json")
            observed = frame.epoch(doc)
            require(binding["cid"] == cid and binding["epoch"][:2] == observed[:2]
                    and binding["epoch"][3] == observed[3] and (not state["Running"] or
                    binding["epoch"] == observed and binding["generation"] == frame.snapshot(doc)), "START_GENERATION_CHANGED")
            if (root / "start-generation.json").exists():
                require(op.read(root, "start-generation.json") == {"cid": cid, "generation": binding["generation"]},
                        "START_GENERATION_CHANGED")
        if state["Running"]:
            require(op.read(root, "start-intent.json") == {"cid": cid}, "START_GENERATION_UNCONFIRMED")
            _, checked = op.checked_generation(p, rt, old, cid)
            current = checked()
            if not rt.process(current, gated=True):
                require((root / "release-signal.json").is_file() and
                        op.read(root, "release-signal.json") == {"cid": cid, "epoch": frame.epoch(current)}
                        and rt.process(checked(), gated=False), "GATE_CHANGED")
        else:
            require(state["Pid"] == 0 and (op.never_started(doc) or state["Status"] == "exited" and
                    op.read(root, "start-intent.json") == {"cid": cid}), "STOP_UNCONFIRMED")
            endpoints(projected(p, old), doc, candidate=True)
        if (root / "park-epoch.json").exists():
            require(op.read(root, "park-epoch.json") == {"cid": cid, "startedAt": state["StartedAt"]},
                    "START_GENERATION_CHANGED")
        return doc
    return verify


def parking(p, rt, old, root, cid):
    guard = park_guard(p, rt, old, root, cid)
    if guard is None:
        return None

    def verify(doc):
        guard(doc)
        op.confirm(root, "park-epoch.json", {"cid": cid, "startedAt": doc["State"]["StartedAt"]})
        return doc
    return verify


def reconcile_candidate(p, rt, old, root, plan):
    if not (root / "create-intent.json").exists():
        require(not (root / "created.json").exists(), "RECOVERY_CREATE_CHANGED")
        return None
    require(op.read(root, "create-intent.json") == {"requestSha256": plan["requestSha256"]}, "RECOVERY_CREATE_CHANGED")
    if (root / "created.json").exists():
        cid = op.read(root, "created.json")["cid"]
        require(matches(SHA, cid) and cid != old["Id"], "CREATE_ID_UNCONFIRMED")
        doc = rt.inspect(cid)
    else:
        doc = rt.inspect(p["container"], missing=True)
        if doc is None or doc["Id"] == old["Id"]:
            require(not any((root / name).exists() for name in ("create-proof.json", "start-intent.json",
                                                                 "start-generation.json")), "CREATE_OWNERSHIP_UNCONFIRMED")
            return None
        cid = doc["Id"]
    if not any((root / name).exists() for name in ("rollback-intent.json", "return-intent.json")):
        op.retained(p, rt, old)
        require(rt.inspect(p["container"])["Id"] == cid and
                set(doc["NetworkSettings"]["Networks"]) == set(p["networks"]), "IMMEDIATE_SUCCESSOR_CHANGED")
    if not (root / "create-proof.json").is_file():
        op.retained(p, rt, old)
        confirm_create(p, rt, old, doc, root)
    park_guard(p, rt, old, root, cid)(doc)
    op.confirm(root, "created.json", {"cid": cid})
    return cid


def check_binds(p, rt=None, doc=None):
    from .frame_spec import validate_bind
    for bind in p.get("configDelta", {}).get("binds", ()):
        validate_bind(bind, p)
        if doc is not None:
            rt.verify_mounted_bind(doc, bind)


def release_gate(check, p, rt, old, cid, restoring):
    generation, checked = check(p, rt, old, cid, restoring)
    if not restoring and p.get("configDelta", {}).get("binds"):
        check_binds(p, rt, checked())
    return generation, checked


def claim_signal(p, rt, checked, root, name, claim):
    op.record(root, name, claim)
    if p["configDelta"].get("binds"):
        check_binds(p, rt, checked())


def signal(rt, checked):
    if not isinstance(rt, Docker):
        rt.signal(checked()["Id"])
        return
    # Pin the task before the final CID, epoch, argv and installed-handler checks.
    doc = checked()
    fd = os.pidfd_open(doc["State"]["Pid"])
    try:
        require(rt.process(checked(), gated=True), "GATE_CHANGED")
        signals.pidfd_send_signal(fd, signals.SIGUSR1)
    finally:
        os.close(fd)


def restore_start(p, rt, old, root, *, allow_recycle=True):
    cid = old["Id"]
    cycle = root
    before = old["State"]["StartedAt"]
    # Each recycle is an immutable edge from a proven generation to its successor.
    seen = set()
    while (cycle / "restore-recycle.json").is_file():
        require(cycle not in seen, "RESTORE_GENERATION_CHANGED")
        seen.add(cycle)
        claim = op.read(cycle, "restore-recycle.json")
        generation = op.read(cycle, "restore-generation.json")
        require(claim == generation and claim["epoch"][0] == cid and claim["epoch"][1] != before
                and op.read(cycle, "restore-start.json") == {"cid": cid, "startedAt": before}
                and op.read(cycle, "restore-signal.json") == {"cid": cid, "epoch": claim["epoch"]},
                "RESTORE_GENERATION_CHANGED")
        doc = rt.inspect(cid)
        if doc["State"]["StartedAt"] == claim["epoch"][1] and doc["State"]["Running"]:
            require(frame.snapshot(doc) == claim["generation"], "RESTORE_GENERATION_CHANGED")
            if not rt.process(doc, gated=True):
                for _ in range(p["readiness"]["attempts"]):
                    status = op.ready_status(rt, doc, p["readiness"])
                    if status:
                        op.verify_database(p, rt, old, root)
                        op.verify_flyway_return(p, rt, old, root)
                        op.confirm(cycle, "recycle-ready.json", claim)
                        return status
                    rt.pause()
                raise op.Held("PREDECESSOR_READINESS_NOT_UP")
            require(not (cycle / "recycle-ready.json").exists(), "RESTORE_GENERATION_CHANGED")
            rt.stop(cid)
        before = claim["epoch"][1]
        cycle = root / ("restore-after-" + digest(claim))
        cycle.mkdir(mode=0o700, exist_ok=True)
        op.sync_dir(root)
    doc = rt.inspect(cid)
    if not doc["State"]["Running"]:
        frame.check_body(old, doc, old["Image"], old["Config"]["Image"])
        require(doc["Id"] == cid and doc["Name"] == old["Name"] and doc["RestartCount"] == old["RestartCount"],
                "RESTORE_IDENTITY_CHANGED")
        require(doc["State"]["Pid"] == 0 and doc["State"]["StartedAt"] == before and
                not (cycle / "restore-generation.json").exists(), "RESTORE_GENERATION_CHANGED")
        require(set(endpoints(old, doc)) == set(old["NetworkSettings"]["Networks"]), "NETWORK_SET_CHANGED")
        op.confirm(cycle, "restore-stop-epoch.json", stop_epoch(doc))
        op.confirm(cycle, "restore-start.json", {"cid": cid, "startedAt": before})
        rt.start(cid)
    require(op.read(cycle, "restore-start.json") == {"cid": cid, "startedAt": before}, "RESTORE_GENERATION_CHANGED")
    generation, checked = op.checked_generation(p, rt, old, cid, restoring=True)
    doc = checked()
    proof = {"epoch": frame.epoch(doc), "generation": generation}
    require(proof["epoch"][1] != before and doc["RestartCount"] == old["RestartCount"], "RESTORE_GENERATION_CHANGED")
    if (cycle / "restore-stop-epoch.json").exists():
        require(op.read(cycle, "restore-stop-epoch.json") == stop_epoch(doc), "RESTORE_GENERATION_CHANGED")
    else:
        # Older journals can still prove an already recorded live generation.
        require((cycle / "restore-generation.json").is_file(), "RESTORE_GENERATION_UNCONFIRMED")
    op.confirm(cycle, "restore-generation.json", proof)
    signal_claim = {"cid": cid, "epoch": proof["epoch"]}
    if (cycle / "restore-signal.json").exists():
        op.confirm(cycle, "restore-signal.json", signal_claim)
    else:
        gate, _ = op.waiting_gate(p, rt, old, cid, restoring=True)
        require(gate == generation and rt.process(checked(), gated=True), "GATE_CHANGED")
        op.record(cycle, "restore-signal.json", signal_claim)
        signal(rt, checked)
    for _ in range(p["readiness"]["attempts"]):
        status = op.ready_status(rt, checked(), p["readiness"])
        if status:
            op.verify_database(p, rt, old, root)
            op.verify_flyway_return(p, rt, old, root)
            return status
        rt.pause()
    require(rt.process(checked(), gated=True), "PREDECESSOR_READINESS_NOT_UP")
    op.confirm(cycle, "restore-recycle.json", proof)
    # Retry from the durable edge under a fresh review if the replacement gate fails too.
    require(allow_recycle, "PREDECESSOR_READINESS_NOT_UP")
    return restore_start(p, rt, old, root, allow_recycle=False)


def stop_epoch(doc):
    finished = doc["State"].get("FinishedAt")
    require(isinstance(finished, str) and finished and finished != "0001-01-01T00:00:00Z",
            "RESTORE_GENERATION_UNCONFIRMED")
    return {"cid": doc["Id"], "finishedAt": finished}


def restored(p, rt, old, cid, root, plan):
    doc = rt.inspect(p["container"])
    require(doc["Id"] == old["Id"] and doc["State"]["Running"], "RESTORE_IDENTITY_CHANGED")
    _, checked = op.checked_generation(p, rt, old, old["Id"], restoring=True)
    if (root / "restore-start.json").exists():
        cycle = root
        seen = set()
        while (cycle / "restore-recycle.json").is_file():
            require(cycle not in seen, "RESTORE_GENERATION_CHANGED")
            seen.add(cycle)
            proof = op.read(cycle, "restore-generation.json")
            require(op.read(cycle, "restore-recycle.json") == proof, "RESTORE_GENERATION_CHANGED")
            if (cycle / "recycle-ready.json").exists():
                require(op.read(cycle, "recycle-ready.json") == proof, "RESTORE_GENERATION_CHANGED")
                break
            cycle = root / ("restore-after-" + digest(proof))
        require(op.read(cycle, "restore-generation.json") == {"epoch": frame.epoch(doc), "generation": frame.snapshot(doc)}
                and op.read(cycle, "restore-signal.json") == {"cid": old["Id"], "epoch": frame.epoch(doc)},
                "RESTORE_GENERATION_CHANGED")
    else:
        require(frame.snapshot(doc) == plan["oldFrameSha256"], "OLD_SERVICE_CHANGED")
    if cid:
        parked = park_guard(p, rt, old, root, cid)(rt.inspect(cid))
        require(op.read(root, "park-epoch.json") == {"cid": cid, "startedAt": parked["State"]["StartedAt"]}
                and parked["Name"] == "/" + p["failedName"] and not parked["State"]["Running"]
                and not parked["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")
    status = op.ready_status(rt, checked(), p["readiness"])
    require(status, "PREDECESSOR_READINESS_NOT_UP")
    return {"status": "ROLLED_BACK", "planSha256": root.name, "restoredCid": old["Id"],
            "predecessorReadiness": "UP", "predecessorReadyHttp": status,
            **({"configDeltaSha256": plan["configDeltaSha256"]} if "configDelta" in p else {})}


def confirm_return(root, cid, stamp):
    intent = {"cid": cid, "planSha256": stamp}
    if cid and (root / "return-intent.json").is_file() and op.read(root, "return-intent.json") == dict(intent, cid=None):
        require((root / "create-intent.json").is_file(), "RETURN_INTENT_CHANGED")
        op.confirm(root, "late-create.json", intent)
    else:
        op.confirm(root, "return-intent.json", intent)


def return_run(p, stamp, runtime, *, publication=None, approved_plan=None):
    from .profile_options import reviewed_return_allowed
    migration = p["migration"]
    has_binding = bool({"database", "flyway"}.intersection(migration))
    require(matches(SHA, stamp) and (has_binding or reviewed_return_allowed(p)), "INVALID_RETURN_PLAN")
    lock = lock_path(p)
    root = lock.parent / stamp
    result = {"planSha256": stamp, "status": "HELD"}
    try:
        require(p["migration"]["rollbackCompatible"] is True, "MIGRATION_ROLLBACK_BLOCKED")
        if migration["mode"] == "spring-flyway" and not has_binding:
            require(not (root / "release-signal.json").exists(), "FLYWAY_OUTCOME_UNCONFIRMED")
        if lock.exists():
            owner(lock, stamp)
        if (root / "plan.json").exists():
            plan = op.read(root, "plan.json")
        elif lock.exists():
            plan = op.read(lock, "plan.json")
        else:
            plan = approved_plan
        require(plan and digest(plan) == stamp and plan["module"] == p["module"] and
                plan["profileSha256"] == digest(p) and plan["createPlanLabel"] == OWNER_LABEL, "RETURN_PLAN_CHANGED")
        if "configDelta" in p:
            require(plan.get("configDeltaSha256") == delta_digest(p["configDelta"]), "RETURN_PLAN_CHANGED")
        rt = runtime or op.Docker(p)
        old = (op.load_predecessor(p, rt, root) if (root / "baseline.private.json").exists()
               else rt.inspect(plan["oldCid"]))
        require(old["Id"] == plan["oldCid"] and frame.snapshot(old) == plan["oldFrameSha256"], "RETURN_BASELINE_CHANGED")
        pre_stop = not (root / "stop-intent.json").exists()
        if pre_stop:
            require(not (root / "create-intent.json").exists() and
                    frame.snapshot(rt.inspect(p["container"])) == frame.snapshot(old) and
                    op.ready(rt, old, p["readiness"]), "PRE_STOP_DRIFT")
        else:
            require(op.read(root, "stop-intent.json") == {"cid": old["Id"]}, "STOP_CLAIM_CHANGED")
            op.verify_database(p, rt, old, root)
            op.verify_flyway_return(p, rt, old, root)
        receipt = op.read(root, "receipt.json") if (root / "receipt.json").exists() else None
        returning = (root / "return-intent.json").exists()
        if receipt:
            require(receipt.get("operation") == "module-release" and receipt.get("planSha256") == stamp and receipt.get("predecessorCid") == old["Id"] and
                    receipt.get("configDeltaSha256") == plan.get("configDeltaSha256"), "RETURN_RECEIPT_CHANGED")
        if receipt and receipt["status"] == "READY":
            require(not pre_stop and receipt.get("readiness") == "UP" and receipt.get("readyHttp") in p["readiness"]["acceptStatus"], "RETURN_RECEIPT_CHANGED")
            cid = receipt["successorCid"]
            rt.candidate_cid = cid
            require(op.read(root, "created.json") == {"cid": cid} and
                    op.read(root, "start-generation.json") == {"cid": cid, "generation": receipt["successorFrameSha256"]},
                    "IMMEDIATE_SUCCESSOR_CHANGED")
            if not returning:
                op.retained(p, rt, old)
                doc = rt.inspect(p["container"])
                require(doc["Id"] == cid and frame.snapshot(doc) == receipt["successorFrameSha256"]
                        and doc["Config"]["Labels"].get(OWNER_LABEL) == stamp
                        and op.read(root, "create-proof.json") == {"cid": cid, "stableFrameSha256": stable(doc)}
                        and op.read(root, "release-signal.json") == {"cid": cid, "epoch": frame.epoch(doc)}
                        and receipt["readyHttp"] == op.ready_status(rt, doc, p["readiness"]), "IMMEDIATE_SUCCESSOR_CHANGED")
                check_binds(p, rt, doc)
            if publication:
                publication(plan, receipt, returning)
            if "receiptSigning" in p:
                import module_receipt
                module_receipt.attest(p["receiptSigning"], root)
        else:
            if receipt:
                require(receipt.get("status") == "HELD" and bool(receipt.get("reason"))
                        and not (root / "receipt.ed25519").exists() and (pre_stop or
                        receipt.get("rollback") in ("HELD", "ROLLED_BACK") and
                        op.read(root, "rollback-intent.json") == {"cid": old["Id"]}), "RETURN_RECEIPT_CHANGED")
            require(pre_stop or lock.exists() or receipt and receipt.get("rollback") == "ROLLED_BACK",
                    "LOCK_OWNER_UNPROVEN")
            require(not (root / "migration-intent.json").exists() or (root / "migration-complete.json").exists(),
                    "MIGRATION_OUTCOME_UNCONFIRMED")
        if (root / "return-receipt.json").exists():
            claim = op.read(root, "return-intent.json")
            cid = op.read(root, "created.json")["cid"] if (root / "created.json").exists() else None
            final_claim = {"cid": cid, "planSha256": stamp}
            require(claim == final_claim or cid and claim == dict(final_claim, cid=None) and
                    op.read(root, "late-create.json") == final_claim, "RETURN_INTENT_CHANGED")
            final = restored(p, rt, old, cid, root, plan)
            require(final == op.read(root, "return-receipt.json"), "RETURN_RECEIPT_CHANGED")
            if lock.exists():
                unlock(lock, stamp)
            else:
                cleanup(lock, stamp)
            return final
        if not lock.exists():
            require(not returning, "LOCK_OWNER_UNPROVEN")
            acquire(lock, stamp, plan)
        root.mkdir(mode=0o700, exist_ok=True)
        op.sync_dir(root.parent)
        op.confirm(root, "plan.json", plan)
        cid = reconcile_candidate(p, rt, old, root, plan)
        if receipt and receipt["status"] == "READY":
            require(receipt["successorCid"] == cid, "IMMEDIATE_SUCCESSOR_CHANGED")
        if (root / "rollback-intent.json").exists():
            require(op.read(root, "rollback-intent.json") == {"cid": old["Id"]}, "RETURN_INTENT_CHANGED")
        confirm_return(root, cid, stamp)
        if not pre_stop:
            op.restore(p, rt, old, cid, root)
        final = restored(p, rt, old, cid, root, plan)
        op.confirm(root, "return-receipt.json", final)
        unlock(lock, stamp)
        return final
    except Exception as exc:
        result["reason"] = op.reason(exc)
        return result


def rollback(p, rt, old, root, result, exc):
    result.update(status="HELD", reason=op.reason(exc), rollback="HELD")
    try:
        require(not op.reason(exc).startswith("FLYWAY_OUTCOME_UNCONFIRMED"), "FLYWAY_OUTCOME_UNCONFIRMED")
        plan = op.read(root, "plan.json")
        require(digest(plan) == root.name, "RETURN_PLAN_CHANGED")
        require(not (root / "migration-intent.json").exists() or (root / "migration-complete.json").is_file(),
                "MIGRATION_OUTCOME_UNCONFIRMED")
        op.confirm(root, "rollback-intent.json", {"cid": old["Id"]})
        cid = reconcile_candidate(p, rt, old, root, plan)
        if cid:
            result["successorCid"] = cid
        status = op.restore(p, rt, old, cid, root)
        result.update(rollback="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP", predecessorReadyHttp=status)
    except Exception as failure:
        result["rollbackReason"] = op.reason(failure)


def before_start(p, root, cid):
    check_binds(p)
    require(op.read(root, "create-proof.json")["cid"] == cid, "CREATE_ID_UNCONFIRMED")
    op.confirm(root, "start-intent.json", {"cid": cid})


def started(rt, root, cid, generation):
    require(candidate_generation(root, cid, rt.inspect(cid)) == generation, "START_GENERATION_CHANGED")
    op.record(root, "start-generation.json", {"cid": cid, "generation": generation})


def resume(p, rt, stamp):
    root = Path(p["journal"]) / stamp
    owner(lock_path(p), stamp)
    plan = op.read(root, "plan.json")
    old = op.load_predecessor(p, rt, root)
    receipt = op.read(root, "receipt.json") if (root / "receipt.json").exists() else {}
    require(frame.snapshot(old) == plan["oldFrameSha256"] and old["Id"] == plan["oldCid"], "RETURN_BASELINE_CHANGED")
    from .recovery import verify_stop_claim
    verify_stop_claim(rt, old, plan, root)
    cid = reconcile_candidate(p, rt, old, root, plan)
    if receipt.get("status") == "READY":
        require(receipt.get("successorCid") == cid and receipt["predecessorCid"] == old["Id"] and
                receipt["planSha256"] == stamp and receipt.get("configDeltaSha256") == plan.get("configDeltaSha256")
                and receipt["successorFrameSha256"] == frame.snapshot(rt.inspect(cid)), "RECOVERY_RECEIPT_CHANGED")
        op.retained(p, rt, old)
        require(op.ready(rt, rt.inspect(cid), p["readiness"]), "TERMINAL_READINESS_CHANGED")
        if "receiptSigning" in p and (root / "receipt.ed25519").exists():
            import module_receipt
            module_receipt.attest(p["receiptSigning"], root)
        unlock(lock_path(p), stamp)
        return receipt
    result = {"operation": "module-release", "planSha256": stamp, "status": "HELD", "predecessorCid": old["Id"]}
    if "configDelta" in p:
        result["configDeltaSha256"] = plan["configDeltaSha256"]
    if cid:
        result["successorCid"] = cid
    if (not receipt and cid and (root / "migration-plan.json").is_file()
            and not (root / "rollback-intent.json").exists()):
        stage = op.read(root, "migration-plan.json")
        require(stage["cid"] == cid and stage["generation"] == frame.snapshot(rt.inspect(cid)) and
                stage["planSha256"] == stamp and stage["profileSha256"] == digest(p), "MIGRATION_PLAN_CHANGED")
        result.update(status="GATED", migrationSha256=digest(stage))
        op.confirm(root, "stage.json", result)
        return result
    if (not receipt and cid and (root / "start-generation.json").is_file() and rt.inspect(cid)["State"]["Running"]
            and not (root / "rollback-intent.json").exists()):
        op.retained(p, rt, old)
        try:
            op.finish_apply(p, rt, plan, old, cid, root, result, True)
        except Exception as exc:
            rollback(p, rt, old, root, result, exc)
        publish_result(rt, root, result)
        if result["status"] == "READY" or result.get("rollback") == "ROLLED_BACK":
            unlock(lock_path(p), stamp)
        return result
    final = return_run(p, stamp, rt)
    require(final["status"] == "ROLLED_BACK", final.get("reason", "RESTORE_FAILED"))
    return dict(result, rollback="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP",
                predecessorReadyHttp=final["predecessorReadyHttp"], reason="INTERRUPTED_RELEASE_RESTORED")


def first_inspect(rt, cid, restoring):
    if not restoring:
        rt.candidate_cid = cid
    return rt.inspect(cid)


def predecessor_guard(old):
    def verify(doc):
        require(doc["Id"] == old["Id"] and doc["Name"] == old["Name"] and stable(old) == stable(doc)
                and doc["State"]["StartedAt"] == old["State"]["StartedAt"]
                and doc["RestartCount"] == old["RestartCount"], "PRE_STOP_DRIFT")
        if doc["State"]["Running"]:
            require(frame.snapshot(doc) == frame.snapshot(old), "PRE_STOP_DRIFT")
        else:
            endpoints(old, doc)
        return doc
    return verify


def recovery_review(p, root, body, proposal):
    if "configDelta" in p:
        delta = p["configDelta"]
        shown = p.get("showValues", ())
        require(delta_digest(delta) == body["configDeltaSha256"], "RECOVERY_PROFILE_CHANGED")
        lines = approval_lines(delta, shown)
        if lines != body["approvalLines"]:
            # A 58q-b plan could display the Flyway flag in a mixed delta.
            # Verify that exact historical rendering only against the authenticated source plan.
            previous = lines.copy()
            for i, row in enumerate(delta.get("env", ())):
                if row["name"] == "SPRING_FLYWAY_ENABLED":
                    previous[i] = approval_lines({"env": [row]}, shown)[0]
            require(previous == body["approvalLines"], "RECOVERY_PROFILE_CHANGED")
        proposal["approvalLines"] = lines
    for claim in root.glob("restore-after-*/*.json"):
        proposal["journal"][claim.relative_to(root).as_posix()] = digest(op.read(claim.parent, claim.name))
    return proposal


def reconnect_and_start(p, rt, old, root, attached):
    networks = old["NetworkSettings"]["Networks"]
    primary = old["HostConfig"].get("NetworkMode")
    for name in sorted(networks, key=lambda n: n != primary):
        if name not in attached:
            ep = networks[name]
            rt.connect(old["Id"], ep["NetworkID"], frame.endpoint(ep))
    return restore_start(p, rt, old, root)


def publish_result(rt, root, result):
    if result["status"] == "READY" and hasattr(rt, "release_run"):
        result["releaseRun"] = rt.release_run
    op.confirm(root, "stage.json" if result["status"] == "GATED" else "receipt.json", result)
