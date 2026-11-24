"""Typed module-release entry points. Caller authenticates phase and owns the installation lock."""

import json
import os
from pathlib import Path, PurePosixPath
import tempfile

from . import flyway, postgres
from .contract import (CI_COORDINATES, INGESTION_STARTUP_FLAGS, MCP_CI_COORDINATES, Held, SHA, diagnostic,
                       digest, jar_name, matches, package, require, validate)
from .docker import Docker
from .frame import (baseline, check_body, check_created_networks, check_live_networks, endpoint, epoch, merge_image,
                    provenance_labels, request, snapshot)


def reason(exc):
    return str(exc) if isinstance(exc, Held) else diagnostic("RELEASE_IO_OR_INPUT_ERROR", exc)


def ready_status(rt, doc, contract):
    if not rt.process(doc, gated=False):
        return None
    status, body = rt.probe(doc)
    if status not in contract["acceptStatus"]:
        return None
    if "jsonStatus" in contract:
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            return None
        if not isinstance(value, dict) or value.get("status") != contract["jsonStatus"]:
            return None
    after = rt.inspect(doc["Id"])
    return status if snapshot(after) == snapshot(doc) and rt.process(after, gated=False) else None


def ready(rt, doc, contract):
    return bool(ready_status(rt, doc, contract))


def observe(p, rt, previous_release=None):
    validate(p)
    require(p["migration"]["rollbackCompatible"], "MIGRATION_ROLLBACK_BLOCKED")
    binding = p["migration"].get("flyway", {})
    defaults = {} if "candidate" in p or "effectiveDatasource" in binding else None
    artifact = package(p, image_defaults=defaults)
    old = rt.inspect(p["container"])
    previous = None
    if old["Image"] != p["oldImage"] and previous_release is not None:
        previous = previous_release()
        require(old["Id"] == previous["successorCid"] and snapshot(old) == previous["successorFrameSha256"],
                "PREDECESSOR_CHANGED")
    baseline(p, old, predecessor_image=previous["imageId"] if previous else None)
    require(old["Image"] != p["ci"]["imageId"], "ALREADY_INSTALLED")
    require(all(rt.inspect(p[k], missing=True) is None for k in ("retainedName", "failedName")),
            "CUSTODY_NAME_OCCUPIED")
    require(ready(rt, old, p["readiness"]), "PREDECESSOR_NOT_READY")
    coordinates = MCP_CI_COORDINATES if p["ci"].get("publisherFormat") == "acquisition-mcp" else CI_COORDINATES
    create_request = request(old, p["ci"]["imageId"], provenance_labels(p),
                             candidate=p.get("candidate"), image_defaults=defaults)
    if "effectiveDatasource" in binding:
        prospective = {key: create_request.get(key) for key in ("Entrypoint", "Cmd", "Env")}
        merge_image(prospective, defaults)
        flyway.datasource(binding, prospective, predecessor=False)
        if p["module"] == "ingestion":
            require("--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY" not in prospective["Cmd"],
                    "CANDIDATE_VALIDATE_ONLY")
    body = {
        "operation": "module-release", "module": p["module"], "profileSha256": digest(p),
        "oldCid": old["Id"], "oldFrameSha256": snapshot(old), "requestSha256": digest(create_request),
        "oldImage": old["Image"], "ci": {k: p["ci"][k] for k in coordinates}, **artifact,
        "migrationMode": p["migration"]["mode"], "rollback": "AVAILABLE",
    }
    if previous:
        body["predecessorPlanSha256"] = previous["planSha256"]
    if "candidate" in p:
        removed = p["candidate"].get("removeArgs", [])
        body["candidateReview"] = {
            "predecessorCmdSha256": digest(old["Config"]["Cmd"]), "candidateCmdSha256": digest(create_request["Cmd"]),
            "removedArgs": [arg if arg in INGESTION_STARTUP_FLAGS else arg.partition("=")[0] + "=<redacted>"
                            for arg in old["Config"]["Cmd"] if arg in removed],
            "envOperations": {"SPRING_FLYWAY_ENABLED": "enable"} if p["candidate"].get("enableFlyway") else {},
        }
    if "database" in p["migration"]:
        migration = p["migration"]
        state = postgres.observe(rt, old)
        require(len(state["history"]) == migration["database"]["version"], "DATABASE_CHANGED")
        body.update(rollback="IF_DATABASE_UNCHANGED", databaseSha256=digest(state), schemaSha256=digest(state["schema"]),
                    migrations=migration["migrations"], migrationsSha256=digest(migration["migrations"]))
        if migration["migrations"]:
            body["targetSchemaSha256"] = migration["targetSchemaSha256"]
        if "retentionAdmin019" in migration:
            from . import retention
            reference, _ = retention.catalog(rt, old)
            body[retention.ADMIN] = retention.binding(p, reference)
    if "artifactPrefix" in p["ci"]:
        body["ci"]["artifactPrefix"] = p["ci"]["artifactPrefix"]
    if "flyway" in p["migration"]:
        jar = PurePosixPath("/app", jar_name(p["gate"]["command"]))
        require(not any(jar.is_relative_to(m["Destination"]) for m in old["Mounts"]), "FLYWAY_JAR_SHADOWED")
        body["flywayBaseline"] = flyway.baseline(flyway.observe(rt, old, predecessor=True))
    return body, old


def plan(profile: dict, runtime=None, *, previous_release=None) -> dict:
    """Read-only; no image import, lock, journal, signal or network download."""
    try:
        body, _ = observe(profile, runtime or Docker(profile), previous_release)
        return {"status": "PLANNED", "planSha256": digest(body), "plan": body}
    except Exception as exc:
        return {"status": "HELD", "reason": reason(exc), "rollback":
                "BLOCKED" if reason(exc) == "MIGRATION_ROLLBACK_BLOCKED" else "UNVERIFIED"}


def sync_dir(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def record(root, name, data):
    # Never expose a partially written claim or receipt after process loss.
    with tempfile.NamedTemporaryFile(dir=root, delete=False) as out:
        tmp = Path(out.name)
        try:
            out.write(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
            out.flush()
            os.fsync(out.fileno())
        except BaseException:
            out.close()
            tmp.unlink()
            raise
    try:
        os.link(tmp, root / name)
        sync_dir(root)
    finally:
        tmp.unlink(missing_ok=True)


def read(root, name):
    return json.loads((root / name).read_bytes())


def confirm(root, name, data):
    if (root / name).exists():
        require(read(root, name) == data, "JOURNAL_BINDING_CHANGED")
    else:
        record(root, name, data)


def unlock_module(lock):
    (lock / "owner.json").unlink(missing_ok=True)
    lock.rmdir()
    sync_dir(lock.parent)


def retained(p, rt, old):
    doc = rt.inspect(old["Id"])
    check_body(old, doc, old["Image"], old["Config"]["Image"])
    require(doc["Id"] == old["Id"] and doc["Name"] == "/" + p["retainedName"] and
            not doc["State"]["Running"] and doc["State"]["Pid"] == 0 and
            doc["State"]["StartedAt"] == old["State"]["StartedAt"] and doc["RestartCount"] == old["RestartCount"]
            and not doc["NetworkSettings"]["Networks"],
            "PREDECESSOR_NOT_RETAINED")


def park(rt, cid, name, networks):
    doc = rt.inspect(cid)
    require(doc["Id"] == cid, "CONTAINER_ID_CHANGED")
    if doc["State"]["Running"]:
        rt.stop(cid)
    doc = rt.inspect(cid)
    require(not doc["State"]["Running"] and doc["State"]["Pid"] == 0, "STOP_UNCONFIRMED")
    primary = doc["HostConfig"].get("NetworkMode")
    for net in sorted(doc["NetworkSettings"]["Networks"], key=lambda n: n == primary):
        require(net in networks and doc["NetworkSettings"]["Networks"][net].get("NetworkID")
                in ("", networks[net]["NetworkID"]), "UNEXPECTED_NETWORK")
        rt.disconnect(cid, networks[net]["NetworkID"])
    if doc["Name"] != "/" + name:
        rt.rename(cid, name)
    doc = rt.inspect(cid)
    require(doc["Name"] == "/" + name and not doc["State"]["Running"]
            and not doc["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")


def checked_generation(p, rt, old, cid, restoring=False):
    image = old["Image"] if restoring else p["ci"]["imageId"]
    config_image = old["Config"]["Image"] if restoring else image
    first = rt.inspect(cid)
    require(first["State"]["Running"] and first["State"]["Pid"] > 0, "GATE_NOT_RUNNING")
    generation = snapshot(first)

    defaults = None if restoring else rt.image_defaults(image)

    def checked():
        doc = rt.inspect(cid)
        require(doc["Id"] == cid and doc["Name"] == "/" + p["container"], "SERVICE_IDENTITY_CHANGED")
        check_body(old, doc, image, config_image, labels=None if restoring else provenance_labels(p),
                   image_defaults=defaults, candidate=None if restoring else p.get("candidate"))
        check_live_networks(old, doc)
        require(snapshot(doc) == generation, "GENERATION_CHANGED")
        return doc

    checked()
    return generation, checked


def waiting_gate(p, rt, old, cid, restoring=False):
    generation, checked = checked_generation(p, rt, old, cid, restoring)
    for _ in range(p["readiness"]["attempts"]):
        if rt.process(checked(), gated=True):
            break
        rt.pause()
    else:
        raise Held("GATE_NOT_PROVEN")
    return generation, checked


def load_predecessor(p, rt, root):
    saved = json.loads((root / "baseline.private.json").read_bytes())
    if "Config" in saved:  # original full-frame journals
        return saved
    # Recover immutable fields from the retained CID; its original frame digest
    # authenticates them. DSNs and other Config.Env values never enter this journal.
    return {**rt.inspect(saved["Id"]), **saved}


def verify_database(p, rt, old, root, *, migrated=False):
    if "database" in p["migration"]:
        state = json.loads((root / "database.private.json").read_bytes())
        plan = json.loads((root / "plan.json").read_bytes())
        require(digest(plan) == root.name and digest(state) == plan["databaseSha256"], "DATABASE_BASELINE_CHANGED")
        postgres.verify(rt, old, state, p["migration"], migrated=migrated)
        return plan["databaseSha256"]


def verify_flyway_return(p, rt, old, root):
    if "flyway" in p["migration"]:
        if (root / "release-signal.json").exists():
            stage = read(root, "migration-plan.json")
            require(stage["planSha256"] == root.name and stage["profileSha256"] == digest(p)
                    and read(root, "migration-review-consumed.json") == {"digest": digest(stage)},
                    "FLYWAY_REVIEW_CHANGED")
            flyway.verify(rt, old, stage["flywayReview"], predecessor=True)
        else:
            require(flyway.baseline(flyway.observe(rt, old, predecessor=True)) == read(root, "plan.json")["flywayBaseline"],
                    "FLYWAY_BASELINE_CHANGED")


def finish_migration(p, rt, old, cid, root, checked, expected_generation):
    migration = p["migration"]
    intent = {"cid": cid}
    if "database" in migration:
        require(expected_generation is not None, "MIGRATION_REVIEW_REQUIRED")
        retained(p, rt, old)
        intent.update(databaseSha256=read(root, "plan.json")["databaseSha256"],
                      migrationsSha256=digest(migration["migrations"]))
    success = {"cid": cid, "status": "SUCCEEDED"}
    if (root / "migration-intent.json").exists():
        require(read(root, "migration-intent.json") == intent, "MIGRATION_INTENT_CHANGED")
        if (root / "migration-complete.json").exists():
            require(read(root, "migration-complete.json") == success, "MIGRATION_FAILED")
        else:
            require("database" in migration and migration["migrations"], "MIGRATION_OUTCOME_UNCONFIRMED")
            verify_database(p, rt, old, root, migrated=True)
            record(root, "migration-complete.json", success)
        return
    verify_database(p, rt, old, root)
    require(rt.process(checked(), gated=True), "GATE_CHANGED")
    record(root, "migration-intent.json", intent)
    try:
        rt.migrate(cid, migration["command"])
    except Exception as exc:
        if isinstance(exc, Held) and str(exc) == "MIGRATION_FAILED":
            record(root, "migration-complete.json", {"cid": cid, "status": "FAILED"})
            raise
        require("database" in migration and migration["migrations"], "MIGRATION_OUTCOME_UNCONFIRMED")
        verify_database(p, rt, old, root, migrated=True)
    verify_database(p, rt, old, root, migrated=True)
    record(root, "migration-complete.json", success)


def release(p, rt, old, cid, root, restoring=False, expected_generation=None):
    signal_file = "restore-signal.json" if restoring else "release-signal.json"
    signalled = (root / signal_file).exists()
    check = checked_generation if signalled else waiting_gate
    generation, checked = check(p, rt, old, cid, restoring)
    require(expected_generation is None or generation == expected_generation, "MIGRATION_GENERATION_CHANGED")
    dedicated = not restoring and p["migration"]["mode"] == "dedicated"
    if dedicated:
        require(not signalled or (root / "migration-intent.json").is_file(), "MIGRATION_OUTCOME_UNCONFIRMED")
        finish_migration(p, rt, old, cid, root, checked, expected_generation)
    if not restoring:
        retained(p, rt, old)
    verify_database(p, rt, old, root, migrated=dedicated)
    signal_claim = {"cid": cid, "epoch": epoch(checked())}
    spring = not restoring and p["migration"]["mode"] == "spring-flyway"
    if signalled:
        require(read(root, signal_file) == signal_claim, "SIGNAL_GENERATION_CHANGED")
    else:
        require(rt.process(checked(), gated=True), "GATE_CHANGED")
        if spring and "flyway" in p["migration"]:
            proof = flyway.checkpoint(rt, checked())
            require(proof == read(root, "migration-plan.json")["flywayReview"], "FLYWAY_REVIEW_CHANGED")
            confirm(root, "flyway-plan.json", proof)
            require(rt.process(checked(), gated=True), "GATE_CHANGED")
        elif spring and getattr(rt, "flyway_peer", None):
            # The existing profile also permits deployments without a provable
            # Flyway reader. Preserve their normal launch; uncertainty stays HELD.
            try:
                proof = flyway.checkpoint(rt, checked())
            except Held as exc:
                if str(exc) not in ("FLYWAY_BINDING_UNPROVEN", "FLYWAY_DATASOURCE_UNPROVEN", "FLYWAY_READ_FAILED"):
                    raise
                confirm(root, "flyway-reader.json", {"reason": reason(exc)})
            else:
                confirm(root, "flyway-plan.json", proof)
            require(rt.process(checked(), gated=True), "GATE_CHANGED")
        record(root, signal_file, signal_claim)
        try:
            rt.signal(cid)
        except Exception as exc:
            signalled = True
            record(root, signal_file + ".failure", {"reason": reason(exc)})
            # The daemon may have delivered the signal before losing the response.
    for _ in range(p["readiness"]["attempts"]):
        status = ready_status(rt, checked(), p["readiness"])
        if status:
            if spring and (signalled or (root / "flyway-plan.json").exists()):
                require((root / "flyway-plan.json").exists(), "FLYWAY_OUTCOME_UNCONFIRMED")
                try:
                    flyway.verify(rt, checked(), read(root, "flyway-plan.json"))
                except Exception as exc:
                    raise Held("FLYWAY_OUTCOME_UNCONFIRMED/" + reason(exc)) from None
            verify_database(p, rt, old, root, migrated=not restoring)
            if restoring:
                verify_flyway_return(p, rt, old, root)
            return {"successorFrameSha256": snapshot(checked()), "readyHttp": status}
        rt.pause()
    if spring and (signalled or "flyway" in p["migration"]):
        raise Held("FLYWAY_OUTCOME_UNCONFIRMED")
    raise Held("PREDECESSOR_READINESS_NOT_UP" if restoring else "READINESS_NOT_UP")


def restore(p, rt, old, new, root):
    networks = old["NetworkSettings"]["Networks"]
    cid = old["Id"]
    doc = rt.inspect(cid)
    check_body(old, doc, old["Image"], old["Config"]["Image"])
    require(doc["Id"] == cid and doc["Name"] in (old["Name"], "/" + p["retainedName"])
            and (doc["State"]["StartedAt"] == old["State"]["StartedAt"] or
                 (root / "restore-start.json").exists()), "RESTORE_IDENTITY_CHANGED")
    verify_database(p, rt, old, root)
    verify_flyway_return(p, rt, old, root)
    attached = doc["NetworkSettings"]["Networks"]
    require(set(attached) <= set(networks) and all(ep.get("NetworkID") in ("", networks[name]["NetworkID"])
            for name, ep in attached.items()), "RESTORE_NETWORK_SET_CHANGED")
    service = rt.inspect(p["container"], missing=True)
    failed = rt.inspect(p["failedName"], missing=True)
    require(service is None or service["Id"] in (cid, new), "UNKNOWN_SERVICE_OWNER")
    require(failed is None or failed["Id"] == new, "CUSTODY_NAME_OCCUPIED")
    if new:
        candidate = rt.inspect(new)
        require(candidate["Id"] == new and candidate["Image"] == p["ci"]["imageId"] and
                candidate["Name"] in (old["Name"], "/" + p["failedName"]), "RESTORE_SUCCESSOR_CHANGED")
        park(rt, new, p["failedName"], networks)
    owner = rt.inspect(p["container"], missing=True)
    require(owner is None or owner["Id"] == cid, "UNKNOWN_SERVICE_OWNER")
    if doc["State"]["Running"]:
        if (root / "restore-start.json").exists():
            require(read(root, "restore-start.json") == {"cid": cid} and
                    (root / "restore-generation.json").is_file() and read(root, "restore-generation.json") == {"generation": snapshot(doc)},
                    "RESTORE_GENERATION_UNCONFIRMED")
            return release(p, rt, old, cid, root, restoring=True)["readyHttp"]
        require(epoch(doc) == epoch(old) and snapshot(doc) == snapshot(old), "OLD_SERVICE_CHANGED")
        status = ready_status(rt, doc, p["readiness"])
        require(status, "OLD_SERVICE_CHANGED")
        return status
    if doc["Name"] != old["Name"]:
        rt.rename(cid, p["container"])
    primary = old["HostConfig"].get("NetworkMode")
    for name in sorted(networks, key=lambda n: n != primary):
        ep = networks[name]
        if name not in attached:
            rt.connect(cid, ep["NetworkID"], endpoint(ep))
    record(root, "restore-start.json", {"cid": cid})
    rt.start(cid)
    record(root, "restore-generation.json", {"generation": snapshot(rt.inspect(cid))})
    return release(p, rt, old, cid, root, restoring=True)["readyHttp"]


def never_started(doc):
    state = doc["State"]
    return (state["Status"] == "created" and state.get("Running") is False and state.get("Pid") == 0
            and doc["RestartCount"] == 0 and state.get("StartedAt") == state.get("FinishedAt") == "0001-01-01T00:00:00Z")


def verify_never_started(p, rt, old, doc, root):
    require(never_started(doc)
            and not any((root / f).exists() for f in ("start-generation.json", "migration-plan.json", "release-signal.json")),
            "NEVER_STARTED_UNPROVEN")
    image = p["ci"]["imageId"]
    check_body(old, doc, image, image, created=True, labels=provenance_labels(p),
               image_defaults=rt.image_defaults(image), candidate=p.get("candidate"))
    check_created_networks(old, doc)


def start_candidate(p, rt, old, cid, root):
    confirm(root, "start-intent.json", {"cid": cid})
    rt.start(cid)
    generation, _ = checked_generation(p, rt, old, cid)
    record(root, "start-generation.json", {"cid": cid, "generation": generation})


def finish_apply(p, rt, body, old, new, root, result, defer_migration):
    start = read(root, "start-generation.json")
    require(start == {"cid": new, "generation": snapshot(rt.inspect(new))}, "START_GENERATION_CHANGED")
    review = defer_migration or "database" in p["migration"] or "flyway" in p["migration"]
    if review and p["migration"]["mode"] != "none":
        generation, checked = waiting_gate(p, rt, old, new)
        require(generation == start["generation"], "START_GENERATION_CHANGED")
        retained(p, rt, old)
        stage = {"planSha256": digest(body), "profileSha256": digest(p), "cid": new,
                 "generation": generation, "predecessorFrame": body["oldFrameSha256"], "migration": p["migration"]}
        if "flyway" in p["migration"]:
            proof = flyway.checkpoint(rt, checked())
            require(all(proof[k] == v for k, v in body["flywayBaseline"].items()), "FLYWAY_BASELINE_CHANGED")
            require(rt.process(checked(), gated=True), "GATE_CHANGED")
            stage["flywayReview"] = proof
        confirm(root, "migration-plan.json", stage)
        result.update(status="GATED", migrationSha256=digest(stage))
        return
    proof = release(p, rt, old, new, root, expected_generation=start["generation"])
    retained(p, rt, old)
    result.update(status="READY", readiness="UP")
    result.update(proof)


def execute(p, rt, body, old, root, result, defer_migration):
    new = None
    result["predecessorCid"] = old["Id"]
    saved = {key: old[key] for key in ("Id", "Name", "NetworkSettings", "RestartCount")}
    saved["State"] = {key: old["State"][key] for key in ("Running", "Pid", "StartedAt")}
    record(root, "plan.json", body)
    record(root, "baseline.private.json", saved)
    with tempfile.TemporaryFile(dir=root) as archive:
        actual = package(p, archive)
        require(all(body[k] == v for k, v in actual.items()), "ARTIFACT_CHANGED")
        archive.seek(0)
        rt.load(archive, actual)
    require(snapshot(rt.inspect(old["Id"])) == body["oldFrameSha256"], "PRE_STOP_DRIFT")
    image = p["ci"]["imageId"]
    req = request(old, image, provenance_labels(p), candidate=p.get("candidate"),
                  image_defaults=rt.image_defaults(image) if "candidate" in p else None)
    require(digest(req) == body["requestSha256"], "CREATE_REQUEST_CHANGED")
    networks = old["NetworkSettings"]["Networks"]
    if "database" in p["migration"]:
        state = postgres.observe(rt, old)
        require(digest(state) == body["databaseSha256"], "DATABASE_CHANGED")
        record(root, "database.private.json", state)
    verify_flyway_return(p, rt, old, root)
    record(root, "stop-intent.json", {"cid": old["Id"]})
    try:
        park(rt, old["Id"], p["retainedName"], networks)
        retained(p, rt, old)
        record(root, "create-intent.json", {"requestSha256": digest(req)})
        new = rt.create(p["container"], req)
        require(matches(SHA, new) and new != old["Id"], "CREATE_ID_UNCONFIRMED")
        result["successorCid"] = new
        record(root, "created.json", {"cid": new})
        doc = rt.inspect(new)
        require(doc["Id"] == new and doc["Name"] == old["Name"] and doc["State"]["Status"] == "created"
                and not doc["State"]["Running"], "CREATED_IDENTITY_CHANGED")
        check_body(old, doc, p["ci"]["imageId"], p["ci"]["imageId"], created=True, labels=provenance_labels(p),
                   image_defaults=rt.image_defaults(image), candidate=p.get("candidate"))
        check_created_networks(old, doc)
        start_candidate(p, rt, old, new, root)
        finish_apply(p, rt, body, old, new, root, result, defer_migration)
    except Exception as exc:
        rollback(p, rt, old, root, result, exc)


def rollback(p, rt, old, root, result, exc):
    result.update(status="HELD", reason=reason(exc), rollback="HELD")
    try:
        require(not reason(exc).startswith("FLYWAY_OUTCOME_UNCONFIRMED"), "FLYWAY_OUTCOME_UNCONFIRMED")
        record(root, "rollback-intent.json", {"cid": old["Id"]})
        if ((root / "migration-intent.json").exists()
                and not (root / "migration-complete.json").exists()):
            verify_database(p, rt, old, root)
            raise Held("MIGRATION_OUTCOME_UNCONFIRMED")
        status = restore(p, rt, old, result.get("successorCid"), root)
        result.update(rollback="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP",
                      predecessorReadyHttp=status)
    except Exception as rollback_exc:
        result["rollbackReason"] = reason(rollback_exc)
        if reason(rollback_exc) == "DATABASE_CHANGED":
            result["releaseReason"] = result["reason"]
            result["reason"] = "DATABASE_CHANGED"


def apply(profile: dict, plan_sha256: str, runtime=None, *, defer_migration=False, previous_release=None) -> dict:
    """Replan under exclusion; consume once, write a private receipt even on ordinary failure."""
    result = {"operation": "module-release", "status": "HELD"}
    try:
        require(matches(SHA, plan_sha256), "PLAN_DIGEST_REQUIRED")
        result["planSha256"] = plan_sha256
        validate(profile)
        if not profile["migration"]["rollbackCompatible"]:
            result["rollback"] = "BLOCKED"
            raise Held("MIGRATION_ROLLBACK_BLOCKED")
        parent = Path(profile["journal"])
        lock = parent / (profile["module"] + ".lock")
        try:
            lock.mkdir(mode=0o700)
        except FileExistsError:
            raise Held("OPERATION_IN_PROGRESS_OR_INTERRUPTED") from None
        unlock = True
        try:
            rt = runtime or Docker(profile)
            body, old = observe(profile, rt, previous_release)
            require(digest(body) == plan_sha256, "PLAN_CHANGED")
            root = parent / plan_sha256
            try:
                root.mkdir(mode=0o700)
            except FileExistsError:
                raise Held("PLAN_ALREADY_CONSUMED") from None
            sync_dir(parent)
            unlock = False
            try:
                record(lock, "owner.json", {"planSha256": plan_sha256})
                execute(profile, rt, body, old, root, result, defer_migration)
            except Exception as exc:
                result["reason"] = reason(exc)
            gated = result["status"] == "GATED"
            record(root, "stage.json" if gated else "receipt.json", result)
            unlock = not gated and result.get("rollback") != "HELD"
        finally:
            if unlock:
                unlock_module(lock)
    except Exception as exc:
        result.update(status="HELD", reason=reason(exc))
    return result


def migrate(profile, plan_sha256, migration_sha256, runtime=None, *, recover=False):
    """Resume the exact staged generation under the executor's installation lock."""
    validate(profile)
    require(matches(SHA, plan_sha256) and matches(SHA, migration_sha256), "MIGRATION_DIGEST_REQUIRED")
    parent = Path(profile["journal"])
    root = parent / plan_sha256
    lock = parent / (profile["module"] + ".lock")

    def read(name):
        return json.loads((root / name).read_bytes())

    stage = read("migration-plan.json")
    staged = read("stage.json")
    require(lock.is_dir() and not (root / "receipt.json").exists() and staged["status"] == "GATED"
            and staged["migrationSha256"] == migration_sha256 == digest(stage)
            and stage["planSha256"] == plan_sha256 and stage["profileSha256"] == digest(profile),
            "MIGRATION_PLAN_CHANGED")
    rt = runtime or Docker(profile)
    old = load_predecessor(profile, rt, root)
    cid = stage["cid"]
    require(cid == staged["successorCid"] and snapshot(old) == stage["predecessorFrame"], "STAGED_FRAME_CHANGED")
    retained(profile, rt, old)
    check = checked_generation if (root / "release-signal.json").exists() else waiting_gate
    generation, _ = check(profile, rt, old, cid)
    require(generation == stage["generation"], "MIGRATION_GENERATION_CHANGED")
    publish = confirm if recover else record
    publish(root, "migration-review-consumed.json", {"digest": migration_sha256})
    result = {**staged, "status": "HELD"}
    try:
        proof = release(profile, rt, old, cid, root, expected_generation=generation)
        retained(profile, rt, old)
        result.update(status="READY", readiness="UP")
        result.update(proof)
    except Exception as exc:
        rollback(profile, rt, old, root, result, exc)
    if ("flyway" in profile["migration"] and result.get("rollback") == "HELD"
            and not (root / "rollback-intent.json").exists()):
        # An uncertain signal may finish while no executor is running. Retain
        # the reviewed stage for a fresh dispatch to reconcile it read-only.
        return result
    record(root, "receipt.json", result)
    if result.get("rollback") != "HELD":
        unlock_module(lock)
    return result
