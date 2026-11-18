"""D-052 publication for the retained R3 v14 installation."""

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import secrets
import types

from . import custody as C
from .routes import MAX_BYTES, canonical, declared_destination, decode, project, regenerate, require, sha


SNAPSHOTS = Path("/etc/ouf/deploy-snapshots")
SOURCE = SNAPSHOTS / "semantic-provider-v2-inputs-XE7IwlGm/apisix.yaml"
SOURCE_META = (636, 636, 0o600)
OLD_SHA = "dd340bd652bd5c7763ea47fd53573626bc3541b0a2d97415a113c4877e2c7e80"
CLAIM = SNAPSHOTS / "semantic-provider-routes-d052"
TARGET = "/run/ouf-semantic-provider/historical-apisix.yaml"
INSTALL = SNAPSHOTS / "semantic-provider-r3-install-v1"
CODE = INSTALL / "versions/14"
WRAPPER = Path("/usr/local/sbin/ouf-semantic-admitted-v2")
GUARD = Path("/run/ouf-semantic-boot-guard/guard.lock")
CIDS = {
    "adapter": "85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef",
    "southbound": "622a150067244ae8dbb4ac0f1889bc9e4b9823ed761820495f5c0849738dbc0d",
}
OLD_REGISTRY = SNAPSHOTS / "semantic-provider-v2-transaction-mf9x0eqd/registry"
DECLARATIONS = {
    "southbound": (OLD_REGISTRY / "1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916/preparer-template.json",
                   "7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894"),
    "adapter": (OLD_REGISTRY / "f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67/preparer-template.json",
                "0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53"),
    "coordinator": (Path("/etc/ouf/lease-kernel-generations/g2-20261117T122656/coordinated-configuration.json"),
                    "899f39c193b88017b88931dcd9713ed80d7f63b87594c2cd00636a695e06b02f"),
}
RUNTIME = "tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py"
RUNTIME_SHA = "117c9c86bb173742e4da7051d18bdef68526d3a8172cf231c41a27d2ea815911"
ROOT = Path(__file__).resolve().parents[2]
SETTINGS_SHA = "4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150"
AUTHORIZATION = INSTALL / "authorization"
MODULES = {
    "authorizationModule": ("tools/semantic_provider_operation/authorization.py",
                            "8f5dd2fd86efb7add1bdb5325b6428db41cc539b7b00a3b33efa4d692ab958fc"),
    "epochsModule": ("tools/semantic_provider_operation/epochs.py",
                     "b5188406c935079b35f2a81ba670df9578d6ef97a5d7308cbb9cf502a72635bb"),
    "mandatesModule": ("tools/semantic_authority_mandates/mandates.py",
                       "86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79"),
}
SCHEMA = "ouf.semantic-provider-routes-d052.v1"
FLAGS = {"secretValuesPrinted": False, "startAuthorized": False, "leaseAuthorized": False}


def binding(path, digest):
    return {"path": str(path), "sha256": digest}


def route_source(expected=None):
    return C.read(SOURCE, expected, metadata=SOURCE_META, limit=MAX_BYTES)


def declarations():
    docs = {name: decode(C.read(path, digest)) for name, (path, digest) in DECLARATIONS.items()}
    return declared_destination(**docs), docs["coordinator"]


def checked_head(heads):
    require(len(heads) == 2 and heads[0] == heads[1] and heads[0]["decision"] == "OPERATE",
            "R3_OPERATE_HEAD_UNPROVEN")
    return {key: heads[0][key] for key in ("sequence", "sha256", "decision")}


def checked_lease(raw, binding_fields):
    journal = decode(raw)
    require(all(journal.get(key) == value for key, value in binding_fields.items())
            and journal["state"] == "QUIESCED" and journal["leaseAuthorized"] is False
            and journal["startAuthorized"] is False, "R3_LEASE_NOT_QUIESCED")
    return {"state": journal["state"], "sha256": sha(raw)}


@contextmanager
def fenced():
    """Borrow the installed CID and boot/lease locks, then the issuer lock."""
    with ExitStack() as stack:
        for cid in sorted(CIDS.values()):
            stack.enter_context(C.locked(INSTALL / "registry" / cid / "operation.lock"))
        stack.enter_context(C.locked(GUARD))
        stack.enter_context(C.locked(AUTHORIZATION, is_directory=True))
        yield


def observe_r3(coordinator):
    C.directory(CODE, private=True)
    src = CODE / "source"
    runtime_path = src / RUNTIME
    raw = C.read(runtime_path, RUNTIME_SHA)
    runtime = types.ModuleType("_d052_r3_v14")
    runtime.__file__ = str(runtime_path)
    exec(compile(raw, str(runtime_path), "exec"), vars(runtime))
    cfg, cfg_raw = runtime.load_configuration(CODE / "runtime-configuration.json")
    wrapper = (f'#!/bin/sh\nexec {cfg["pythonPath"]} -I -B {runtime_path} '
               f'--configuration {CODE}/runtime-configuration.json "$@"\n').encode("ascii")
    require(C.read(WRAPPER, metadata=(0, 0, 0o755)) == wrapper, "R3_V14_WRAPPER_UNPROVEN")
    settings = decode(C.read(ROOT / "ops/vps/r3-settings.json", SETTINGS_SHA))
    op = cfg["operation"]
    require(cfg["registryRoot"] == str(INSTALL / "registry") and op["authorizationRoot"] == str(AUTHORIZATION)
            and {item["role"]: cid for cid, item in cfg["candidates"].items()} == CIDS
            and cfg["opensslBinding"] == settings["opensslBinding"]
            and all(op[key] == settings[key] for key in ("anchorBinding", "mandateRoot", "installationRef",
                                                         "issuerRef", "entityRef")),
            "R3_CONFIGURATION_UNPROVEN")
    for name, (path, digest) in MODULES.items():
        require((cfg | op)[name] == binding(src / path, digest), "R3_AUTHORITY_CLOSURE_UNPROVEN")
    runtime.verify_files(cfg)
    authorization, epochs = runtime.operation_modules(cfg)
    head = checked_head([runtime.authorization_head(cfg, cfg_raw, cid, authorization) for cid in sorted(CIDS.values())])
    historical = {}
    for role, cid in CIDS.items():
        current = epochs.current(cfg["registryRoot"], cid)
        require(current is None or current["state"] in epochs.TERMINAL, "R3_EPOCH_NOT_TERMINAL")
        historical[role] = sha(canonical(current))
    supervisor = decode(runtime.bound_bytes(cfg["leaseQuiesce"]["configuration"]))
    lease = supervisor["coordinator"]
    require(lease["ownerConfiguration"] == binding(*DECLARATIONS["coordinator"])
            and lease["journalPath"] == coordinator["journalFile"]
            and lease["commonLockPath"] == coordinator["commonLockFile"] == str(GUARD),
            "R3_COORDINATOR_BINDING_UNPROVEN")
    return {"configurationSha256": sha(cfg_raw), "epochHashes": historical,
            "authorization": head, "lease": checked_lease(C.read(lease["journalPath"]), coordinator["binding"])}


def safety(docker, coordinator):
    authority = observe_r3(coordinator)
    inventory, candidates = C.mount_scan(docker, CIDS, SOURCE)
    south = candidates[CIDS["southbound"]]
    require(south["HostConfig"]["RestartPolicy"]["Name"] == "no"
            and candidates[CIDS["adapter"]]["HostConfig"]["RestartPolicy"]["Name"] == "no",
            "PROVIDER_AUTO_RESTART_CONFIGURED")
    matches = [m for m in south["Mounts"] if m["Destination"] == TARGET]
    require(len(matches) == 1 and matches[0]["Type"] == "bind"
            and matches[0]["Source"] == str(SOURCE) and matches[0]["RW"] is False,
            "SOUTHBOUND_ROUTE_MOUNT_UNPROVEN")
    return {"r3": authority, "docker": inventory, "dockerBinary": binding(C.DOCKER, C.DOCKER_SHA)}, candidates


def plan(docker, original, *, expected_live):
    target, coordinator = declarations()
    observed, _ = safety(docker, coordinator)
    updated, changes, before, after = regenerate(SOURCE, original, OLD_SHA, target)
    require(route_source(sha(expected_live)) == expected_live, "ROUTES_LIVE_BYTES_CHANGED")
    return {"schema": SCHEMA, "claim": str(CLAIM), "containers": CIDS,
            "declarations": {name: binding(*pins) for name, pins in DECLARATIONS.items()},
            "metadata": dict(zip(("uid", "gid", "mode"), SOURCE_META)),
            "before": before, "after": after, "diff": changes, "observed": observed, **FLAGS}, updated


def replace_routes(raw, previous, recheck, progress):
    # Write and fsync a complete file in the same protected directory before rename.
    staged = SOURCE.parent / (".routes-d052-" + secrets.token_hex(16))
    try:
        C.write_once(staged, raw, SOURCE_META)
        recheck()
        route_source(sha(previous))
        os.replace(staged, SOURCE)
        progress["sourceReplaced"] = True
        C.sync_dir(SOURCE.parent)
        require(route_source(sha(raw)) == raw, "ROUTES_READBACK_MISMATCH")
    finally:
        staged.unlink(missing_ok=True)


def receipt(status, proposal):
    return {"schema": SCHEMA, "status": status, "planSha256": sha(canonical(proposal)),
            "source": str(SOURCE), "oldSha256": proposal["before"]["sha256"],
            "newSha256": proposal["after"]["sha256"], "diff": proposal["diff"],
            "containers": CIDS, **FLAGS}


def execute(mode, plan_sha256=None, *, docker=None, progress=None):
    docker = C.Docker() if docker is None else docker
    progress = {} if progress is None else progress
    with fenced():
        if mode == "restore":
            C.directory(CLAIM, private=True)
            require(not os.path.lexists(CLAIM / "restored.json"), "RESTORE_ALREADY_RECORDED")
            previous = decode(C.read(CLAIM / "plan.json"))
            require(previous["schema"] == SCHEMA and previous["claim"] == str(CLAIM)
                    and (plan_sha256 is None or sha(canonical(previous)) == plan_sha256), "RESTORE_PLAN_MISMATCH")
            original = C.read(CLAIM / "original.apisix.yaml", OLD_SHA, limit=MAX_BYTES)
            live = route_source(previous["after"]["sha256"])
            observed, updated = plan(docker, original, expected_live=live)
            require(live == updated and all(observed[key] == previous[key] for key in observed if key != "observed"),
                    "RESTORE_BYTES_UNPROVEN")
            def recheck():
                require(plan(docker, original, expected_live=live) == (observed, updated), "RESTORE_PREFLIGHT_CHANGED")

            replace_routes(original, live, recheck, progress)
            require(plan(docker, original, expected_live=original) == (observed, updated),
                    "RESTORE_POSTFLIGHT_CHANGED")
            result = receipt("ROUTES_D052_RESTORED", previous) | {"restoredSha256": sha(original)}
            C.write_document(CLAIM / "restored.json", result)
            return result
        require(not os.path.lexists(CLAIM), "CLAIM_ALREADY_EXISTS")
        original = route_source(OLD_SHA)
        proposal, updated = plan(docker, original, expected_live=original)
        digest = sha(canonical(proposal))
        if mode == "plan":
            return {"status": "PLAN_READY", "planSha256": digest, "plan": proposal}
        require(mode == "apply" and digest == plan_sha256, "PLAN_DIGEST_MISMATCH")
        C.directory(CLAIM.parent)
        CLAIM.mkdir(mode=0o700)
        progress["claimCreated"] = True
        C.sync_dir(CLAIM.parent)
        C.write_once(CLAIM / "original.apisix.yaml", original)
        C.write_document(CLAIM / "plan.json", proposal)
        def recheck():
            require(plan(docker, original, expected_live=original) == (proposal, updated), "PLAN_CHANGED_BEFORE_WRITE")

        replace_routes(updated, original, recheck, progress)
        require(plan(docker, original, expected_live=updated) == (proposal, updated), "PUBLICATION_POSTFLIGHT_CHANGED")
        result = receipt("ROUTES_D052_PUBLISHED", proposal)
        C.write_document(CLAIM / "result.json", result)
        return result


def public_error(error):
    code = error.args[0] if len(error.args) == 1 and type(error).__name__ in {
        "Held", "Denied", "OperationDenied", "MandateDenied"} else None
    return code if type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) else "REDACTED_INPUT_OR_IO_FAILURE"


def projection():
    return project(SOURCE, route_source())
