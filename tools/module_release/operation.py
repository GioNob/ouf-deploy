"""Typed module-release entry points. Caller authenticates phase and owns the installation lock."""

import json
import os
from pathlib import Path
import tempfile

from .contract import Held, SHA, digest, matches, package, require, validate
from .docker import Docker
from .frame import baseline, check_body, check_created_networks, check_live_networks, endpoint, epoch, request, snapshot


def reason(exc):
    return str(exc) if isinstance(exc, Held) else "RELEASE_IO_OR_INPUT_ERROR"


def ready(rt, doc, contract):
    if not rt.process(doc, gated=False):
        return False
    status, body = rt.probe(doc)
    if status not in contract["acceptStatus"]:
        return False
    if "jsonStatus" in contract:
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            return False
        if not isinstance(value, dict) or value.get("status") != contract["jsonStatus"]:
            return False
    after = rt.inspect(doc["Id"])
    return snapshot(after) == snapshot(doc) and rt.process(after, gated=False)


def observe(p, rt):
    validate(p)
    require(p["migration"]["rollbackCompatible"], "MIGRATION_ROLLBACK_BLOCKED")
    artifact = package(p)
    old = rt.inspect(p["container"])
    baseline(p, old)
    require(old["Image"] != p["ci"]["imageId"], "ALREADY_INSTALLED")
    require(all(rt.inspect(p[k], missing=True) is None for k in ("retainedName", "failedName")),
            "CUSTODY_NAME_OCCUPIED")
    require(ready(rt, old, p["readiness"]), "PREDECESSOR_NOT_READY")
    coordinates = ("repository", "workflow", "pullRequest", "runId", "runAttempt", "artifactId", "zipSha256",
                   "sourceCommit", "sourceTree", "imageName", "imageId", "manifestSchema")
    body = {
        "operation": "module-release", "module": p["module"], "profileSha256": digest(p),
        "oldCid": old["Id"], "oldFrameSha256": snapshot(old), "requestSha256": digest(request(old, p["ci"]["imageId"])),
        "oldImage": old["Image"], "ci": {k: p["ci"][k] for k in coordinates}, **artifact,
        "migrationMode": p["migration"]["mode"], "rollback": "AVAILABLE",
    }
    return body, old


def plan(profile: dict, runtime=None) -> dict:
    """Read-only; no image import, lock, journal, signal or network download."""
    try:
        body, _ = observe(profile, runtime or Docker(profile))
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
    with (root / name).open("x", encoding="utf-8") as out:
        json.dump(data, out, sort_keys=True, separators=(",", ":"))
        out.flush()
        os.fsync(out.fileno())
    sync_dir(root)


def retained(p, rt, old):
    doc = rt.inspect(old["Id"])
    check_body(old, doc, old["Image"], old["Config"]["Image"])
    require(doc["Id"] == old["Id"] and doc["Name"] == "/" + p["retainedName"] and
            not doc["State"]["Running"] and doc["State"]["Pid"] == 0 and
            doc["State"]["StartedAt"] == old["State"]["StartedAt"] and not doc["NetworkSettings"]["Networks"],
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
        require(net in networks, "UNEXPECTED_NETWORK")
        rt.disconnect(cid, networks[net]["NetworkID"])
    rt.rename(cid, name)
    doc = rt.inspect(cid)
    require(doc["Name"] == "/" + name and not doc["State"]["Running"]
            and not doc["NetworkSettings"]["Networks"], "PARK_UNCONFIRMED")


def waiting_gate(p, rt, old, cid, restoring=False):
    image = old["Image"] if restoring else p["ci"]["imageId"]
    config_image = old["Config"]["Image"] if restoring else image
    first = rt.inspect(cid)
    require(first["State"]["Running"] and first["State"]["Pid"] > 0, "GATE_NOT_RUNNING")
    generation = snapshot(first)

    def checked():
        doc = rt.inspect(cid)
        require(doc["Id"] == cid and doc["Name"] == "/" + p["container"], "SERVICE_IDENTITY_CHANGED")
        check_body(old, doc, image, config_image)
        check_live_networks(old, doc)
        require(snapshot(doc) == generation, "GENERATION_CHANGED")
        return doc

    for _ in range(p["readiness"]["attempts"]):
        if rt.process(checked(), gated=True):
            break
        rt.pause()
    else:
        raise Held("GATE_NOT_PROVEN")
    return generation, checked


def release(p, rt, old, cid, root, restoring=False, expected_generation=None):
    generation, checked = waiting_gate(p, rt, old, cid, restoring)
    require(expected_generation is None or generation == expected_generation, "MIGRATION_GENERATION_CHANGED")
    if not restoring and p["migration"]["mode"] == "dedicated":
        record(root, "migration-intent.json", {"cid": cid})
        rt.migrate(cid, p["migration"]["command"])
    if not restoring:
        retained(p, rt, old)
    require(rt.process(checked(), gated=True), "GATE_CHANGED")
    record(root, "restore-signal.json" if restoring else "release-signal.json", {"cid": cid, "epoch": epoch(checked())})
    rt.signal(cid)
    for _ in range(p["readiness"]["attempts"]):
        if ready(rt, checked(), p["readiness"]):
            return
        rt.pause()
    raise Held("READINESS_NOT_UP")


def restore(p, rt, old, new, root):
    networks = old["NetworkSettings"]["Networks"]
    cid = old["Id"]
    doc = rt.inspect(cid)
    check_body(old, doc, old["Image"], old["Config"]["Image"])
    require(doc["Id"] == cid and doc["Name"] in (old["Name"], "/" + p["retainedName"])
            and doc["State"]["StartedAt"] == old["State"]["StartedAt"], "RESTORE_IDENTITY_CHANGED")
    if new:
        park(rt, new, p["failedName"], networks)
    owner = rt.inspect(p["container"], missing=True)
    require(owner is None or owner["Id"] == cid, "UNKNOWN_SERVICE_OWNER")
    if doc["State"]["Running"]:
        require(epoch(doc) == epoch(old) and snapshot(doc) == snapshot(old)
                and ready(rt, doc, p["readiness"]), "OLD_SERVICE_CHANGED")
        return
    if doc["Name"] != old["Name"]:
        rt.rename(cid, p["container"])
    attached = doc["NetworkSettings"]["Networks"]
    require(set(attached) <= set(networks), "RESTORE_NETWORK_SET_CHANGED")
    primary = old["HostConfig"].get("NetworkMode")
    for name in sorted(networks, key=lambda n: n != primary):
        ep = networks[name]
        if name not in attached:
            rt.connect(cid, ep["NetworkID"], endpoint(ep))
    rt.start(cid)
    release(p, rt, old, cid, root, restoring=True)


def execute(p, rt, body, old, root, result, defer_migration):
    new = None
    result["predecessorCid"] = old["Id"]
    record(root, "baseline.private.json", old)
    with tempfile.TemporaryFile(dir=root) as archive:
        actual = package(p, archive)
        require(all(body[k] == v for k, v in actual.items()), "ARTIFACT_CHANGED")
        archive.seek(0)
        rt.load(archive, actual)
    require(snapshot(rt.inspect(old["Id"])) == body["oldFrameSha256"], "PRE_STOP_DRIFT")
    networks = old["NetworkSettings"]["Networks"]
    record(root, "stop-intent.json", {"cid": old["Id"]})
    try:
        park(rt, old["Id"], p["retainedName"], networks)
        retained(p, rt, old)
        req = request(old, p["ci"]["imageId"])
        record(root, "create-intent.json", {"requestSha256": digest(req)})
        new = rt.create(p["container"], req)
        require(matches(SHA, new) and new != old["Id"], "CREATE_ID_UNCONFIRMED")
        result["successorCid"] = new
        record(root, "created.json", {"cid": new})
        doc = rt.inspect(new)
        require(doc["Id"] == new and doc["Name"] == old["Name"] and doc["State"]["Status"] == "created"
                and not doc["State"]["Running"], "CREATED_IDENTITY_CHANGED")
        check_body(old, doc, p["ci"]["imageId"], p["ci"]["imageId"], created=True)
        check_created_networks(old, doc)
        rt.start(new)
        if defer_migration and p["migration"]["mode"] != "none":
            generation, _ = waiting_gate(p, rt, old, new)
            retained(p, rt, old)
            stage = {"planSha256": digest(body), "profileSha256": digest(p), "cid": new,
                     "generation": generation, "predecessorFrame": body["oldFrameSha256"], "migration": p["migration"]}
            record(root, "migration-plan.json", stage)
            result.update(status="GATED", migrationSha256=digest(stage))
            return
        release(p, rt, old, new, root)
        retained(p, rt, old)
        result.update(status="READY", readiness="UP")
    except Exception as exc:
        rollback(p, rt, old, root, result, exc)


def rollback(p, rt, old, root, result, exc):
    result.update(status="HELD", reason=reason(exc), rollback="HELD")
    try:
        record(root, "rollback-intent.json", {"cid": old["Id"]})
        restore(p, rt, old, result.get("successorCid"), root)
        result.update(rollback="ROLLED_BACK", restoredCid=old["Id"], predecessorReadiness="UP")
    except Exception as rollback_exc:
        result["rollbackReason"] = reason(rollback_exc)


def apply(profile: dict, plan_sha256: str, runtime=None, *, defer_migration=False) -> dict:
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
            body, old = observe(profile, rt)
            require(digest(body) == plan_sha256, "PLAN_CHANGED")
            root = parent / plan_sha256
            try:
                root.mkdir(mode=0o700)
            except FileExistsError:
                raise Held("PLAN_ALREADY_CONSUMED") from None
            sync_dir(parent)
            unlock = False
            try:
                execute(profile, rt, body, old, root, result, defer_migration)
            except Exception as exc:
                result["reason"] = reason(exc)
            gated = result["status"] == "GATED"
            record(root, "stage.json" if gated else "receipt.json", result)
            unlock = not gated and result.get("rollback") != "HELD"
        finally:
            if unlock:
                lock.rmdir()
    except Exception as exc:
        result.update(status="HELD", reason=reason(exc))
    return result


def migrate(profile, plan_sha256, migration_sha256, runtime=None):
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
    old = read("baseline.private.json")
    cid = stage["cid"]
    require(cid == staged["successorCid"] and snapshot(old) == stage["predecessorFrame"], "STAGED_FRAME_CHANGED")
    retained(profile, rt, old)
    generation, _ = waiting_gate(profile, rt, old, cid)
    require(generation == stage["generation"], "MIGRATION_GENERATION_CHANGED")
    record(root, "migration-review-consumed.json", {"digest": migration_sha256})
    result = {**staged, "status": "HELD"}
    try:
        release(profile, rt, old, cid, root, expected_generation=generation)
        retained(profile, rt, old)
        result.update(status="READY", readiness="UP")
    except Exception as exc:
        rollback(profile, rt, old, root, result, exc)
    record(root, "receipt.json", result)
    if result.get("rollback") != "HELD":
        lock.rmdir()
    return result
