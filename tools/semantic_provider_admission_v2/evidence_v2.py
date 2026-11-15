"""Unsigned live evidence. Expectations come exclusively from operation-bound bytes."""
import copy
import os
from pathlib import Path
import time

from tools.semantic_provider_operation import authorization
from .consumption_v2 import generation, hashed, require

SCHEMA = "ouf.semantic-provider-epoch-evidence.v1"
FIELDS = {"schema", "containerId", "epoch", "authorizationSha256", "generation", "bundleHash",
          "applicationHash", "creationFrameHash", "rootfsSeal", "transportSha256", "observedAt"}
DOCUMENTS = {"framePolicy": "framePolicySha256", "rootfsSeal": "rootfsSealSha256", "transport": "transportSha256"}


def seal(value):
    require(type(value) is dict and set(value) == {"schema", "sha256", "entries", "bytes"}
            and value["schema"] == "ouf.semantic-rootfs-seal.v1" and hashed(value["sha256"])
            and type(value["entries"]) is int and 1 <= value["entries"] <= 100000
            and type(value["bytes"]) is int and 0 <= value["bytes"] <= 8589934592,
            "EXACT_ROOTFS_SEAL_REQUIRED")


def validate(value):
    require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA,
            "EXACT_EPOCH_EVIDENCE_REQUIRED")
    require(all(hashed(value[k]) for k in ("containerId", "authorizationSha256", "bundleHash",
            "applicationHash", "creationFrameHash", "transportSha256")), "EPOCH_EVIDENCE_HASH_REQUIRED")
    require(type(value["epoch"]) is int and 1 <= value["epoch"] <= 10 ** 9
            and type(value["observedAt"]) is int and value["observedAt"] > 0, "EPOCH_EVIDENCE_TIME_REQUIRED")
    generation(value["generation"])
    seal(value["rootfsSeal"])
    return copy.deepcopy(value)


def documents(authorization_role, bound_documents):
    require(type(bound_documents) is dict and set(bound_documents) == set(DOCUMENTS),
            "EXACT_EVIDENCE_DOCUMENTS_REQUIRED")
    decoded = {}
    for name, field in DOCUMENTS.items():
        raw = bound_documents[name]
        require(type(raw) is bytes and authorization.sha(raw) == authorization_role[field],
                "EVIDENCE_" + name.upper() + "_BINDING_DRIFT")
        decoded[name] = authorization.decode(raw)
    policy = decoded["framePolicy"]
    require(type(policy.get("expectedOci")) is dict, "FRAME_EXPECTED_OCI_REQUIRED")
    seal(decoded["rootfsSeal"])
    transport = decoded["transport"]
    require(set(transport) == {"networkBindings", "transport", "tableName"}
            and transport["tableName"] == authorization_role["tableName"], "EXACT_BOUND_TRANSPORT_REQUIRED")
    return decoded


def verify(evidence, authorization_role, bound_documents):
    value = validate(evidence)
    expected = documents(authorization_role, bound_documents)
    require(value["containerId"] == authorization_role["containerId"], "EVIDENCE_CONTAINER_DRIFT")
    require(value["applicationHash"] == value["bundleHash"]
            == authorization.sha(authorization.canonical(expected["framePolicy"]["expectedOci"])),
            "EVIDENCE_APPLICATION_DRIFT")
    require(value["rootfsSeal"] == expected["rootfsSeal"], "EVIDENCE_ROOTFS_DRIFT")
    require(value["transportSha256"] == authorization_role["transportSha256"], "EVIDENCE_TRANSPORT_DRIFT")
    return value


def observe(*, container_id, epoch, authorization_sha256, authorization_role, bound_documents,
            bundle, registry_root, runtime_root, runtime_root_parent, runtime_binding, commands, rootfs_limits,
            creation_frame_observer_binding, budget, clock=time.time):
    from tools.semantic_provider_deployment_authentication import CreatedFrameObserver, private_bytes, decode
    from tools.semantic_provider_deployment_admission import application_hash, transport_hash
    from tools.semantic_provider_node_observation import NodeObservation
    from tools.semantic_provider_preexec_native import NativeBackend

    expected = documents(authorization_role, bound_documents)
    bundle = Path(bundle)
    require(bundle == Path(registry_root) / container_id / "epochs" / str(epoch) / "bundle",
            "EVIDENCE_EPOCH_BUNDLE_DRIFT")
    raw = private_bytes(bundle / "config.json")
    app = application_hash(decode(raw, 131072))
    require(app == authorization.sha(authorization.canonical(expected["framePolicy"]["expectedOci"])),
            "EVIDENCE_APPLICATION_DRIFT")
    cfg = {"runtimeRootParents": [runtime_root_parent], "bundleParents": [registry_root],
           "runtimeBinding": runtime_binding, "commands": commands, "candidate": expected["transport"],
           "rootfsLimits": rootfs_limits}
    observer = NodeObservation(cfg, budget)
    state = decode(observer.run(runtime_binding, ["--root", runtime_root, "state", container_id], 16384), 16384)
    require(state.get("id") == container_id and state.get("bundle") == str(bundle)
            and state.get("status") == "created", "EVIDENCE_CREATED_STATE_DRIFT")
    live_generation = NativeBackend.generation(None, state.get("pid"))
    # transactionId is an internal correlation field of live_profile, not an authority.
    correlation = authorization.sha(authorization.canonical({"containerId": container_id, "epoch": epoch,
                                                            "authorizationSha256": authorization_sha256}))
    candidate = {**expected["transport"], "containerId": container_id, "transactionId": correlation}
    request = {"containerId": container_id, "transactionId": correlation, "applicationHash": app,
               "generation": live_generation, "transportHash": transport_hash(candidate)}
    require(request["transportHash"] == authorization_role["transportSha256"], "EVIDENCE_TRANSPORT_DRIFT")
    observed = observer.observe(request, {"runtimeRoot": runtime_root, "bundleHash": app}, private_bytes)
    require(observed["bundle"] == str(bundle) and observed["state"] == state, "EVIDENCE_CREATED_STATE_DRIFT")
    frame = CreatedFrameObserver(creation_frame_observer_binding, budget)
    frame_hash, inputs = frame.observe(live_generation, bundle / "config.json", app,
                                      authorization_role["framePolicySha256"])
    require(NativeBackend.generation(None, state["pid"]) == live_generation
            and private_bytes(bundle / "config.json") == raw, "EVIDENCE_GENERATION_DRIFT")
    for path, content in inputs.items():
        require(private_bytes(path) == content, "EVIDENCE_FRAME_INPUT_DRIFT")
    value = {"schema": SCHEMA, "containerId": container_id, "epoch": epoch,
             "authorizationSha256": authorization_sha256, "generation": live_generation, "bundleHash": app,
             "applicationHash": app, "creationFrameHash": frame_hash, "rootfsSeal": observed["rootfsSeal"],
             "transportSha256": authorization_role["transportSha256"], "observedAt": int(clock())}
    return verify(value, authorization_role, bound_documents)


def write_exclusive(path, value):
    """Initial publication only; CAS replacements belong to the v1 journal."""
    raw = authorization.canonical(value)
    require(len(raw) <= 131072, "EPOCH_RESULT_UNBOUNDED")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return authorization.sha(raw)


def write(path, value):
    validate(value)
    return write_exclusive(path, value)
