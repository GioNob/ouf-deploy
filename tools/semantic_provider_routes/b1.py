"""Revise the B1 recipes for the same stopped Docker successors."""

import copy
import os
from pathlib import Path
import re
import sys
import types

from . import custody as C
from . import publication as P
from .routes import canonical, decode, require, sha


ROLES = ("adapter", "southbound")
PARTS = ("template", "launch", "context", "policy")
PREVIOUS = P.SNAPSHOTS / "semantic-provider-b1-recipes-20261114-v2/result.json"
OUTPUT = P.SNAPSHOTS / "semantic-provider-b1-recipes-20261118-v3"
ROOTFS = Path("/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-20261116-mountpoint-0711/result.json")
ROOTFS_SHA = "49a82a05f7f935e63b76cfacdda742f928c112a1de2a61353436ef1cdac3f2b8"
SUCCESSORS = Path("/var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113/successors.json")
SUCCESSORS_SHA = "394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb"
RECREATION = P.binding(P.SNAPSHOTS / "southbound-recreate-20261113-d022-v1/result.json",
                       "56528cb24df9ce1d48f18ee67ac8105d308db8ee1602dd604a9573b08b22b79c")
SEALER_SOURCE = P.SNAPSHOTS / "semantic-provider-v2-offline-rootfs-s3BU0nDX/source"
SEALER_SHA = "fb797f12eb838bfdc5eae7cd28617f6d7d17531968d710735df248354496e250"
COMPILER = "tools/semantic_frame_compiler/compile_creation_frame_policy.py"
IMAGE_ROOTFS = "tools/semantic_image_rootfs/prepare_provider_image_rootfs.py"
STOPPED_EXPORT = "tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py"
SOFTWARE = {
    COMPILER: "36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d",
    IMAGE_ROOTFS: "cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32",
    STOPPED_EXPORT: "fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5",
}
# Independently pinned in R3 v14, each in the existing v2 B1 output.
RECIPE_PINS = {
    "adapter": (
        "b5b7c915588c29141f77cab2526cf65d601a3c2f03fe5c0813db6673eb3d3067",
        "061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943",
        "d6a76226bc5626ad4e5bcf87c21005063caaca41b747a4ae074511e8d4037b99",
        "42677046162cf340080c4062321be2c5881fbe0ef299b869ce812569c8a634f3",
    ),
    "southbound": (
        "02e6d4253b36c2744aec542d831d62929210d691c2848868e9a78c8309531f05",
        "f066a65cffc7766bbf77b9de15fe9d527ce8ca68a9bb0d74cadfe8370c6ad63b",
        "18a1df8d45fbe0914514478910041d3a49ecf402b8c78a06c8148cf95c06a1c9",
        "e489068bc8a86f226dadfa5a3870dc05aaae65437d638a8b9ce56c4c42e218a8",
    ),
}
SCHEMA = "ouf.semantic-provider-b1-recipes.v1"  # the v5.1 emitter's existing contract
CREATED_STAMP = "0001-01-01T00:00:00Z"
CREATED_STATE = {"Status": "created", "Running": False, "Paused": False, "Restarting": False,
                 "OOMKilled": False, "Dead": False, "Pid": 0, "ExitCode": 0, "Error": "",
                 "StartedAt": CREATED_STAMP, "FinishedAt": CREATED_STAMP}
CONFIG_FIELDS = ("Id", "Name", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings")
OWNER_LABEL = "ouf.semantic.provider.successor.creation"


def retained_frame(row, prior):
    """Compare all configuration fields to A2 with its original created-state envelope."""
    C.stopped(row)
    state = row["State"]
    require(set(state) == set(CREATED_STATE) and state["Status"] == "exited"
            and type(row["RestartCount"]) is int and row["RestartCount"] >= 0
            and type(state["StartedAt"]) is str and state["StartedAt"] != CREATED_STAMP
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", state["StartedAt"]),
            "RETAINED_PREVIOUSLY_STARTED_STATE_UNPROVEN")
    config = {field: row[field] for field in CONFIG_FIELDS}
    require(row["Id"] == prior["containerId"] and row["Name"] == prior["name"] and row["Image"] == prior["image"]
            and row["Config"]["Labels"][OWNER_LABEL] == prior["transaction"],
            "RETAINED_PROVIDER_IDENTITY_CHANGED")
    # The A2 created-state frame hash is not comparable after a start: Docker no longer
    # reports the never-started envelope (proved on the VPS, 18/11: no reconstruction of
    # MAC/DNSNames/Ports matches). Equality is proven instead against the accepted recipe
    # launch (retained_config); R3 start re-proves OCI, networks and rootfs every time.
    entrypoint = row["Config"]["Entrypoint"]
    command = row["Config"]["Cmd"]
    require(type(entrypoint) is list and entrypoint and type(command) is list
            and [row["Path"], *row["Args"]] == entrypoint + command, "RETAINED_PROCESS_CONFIGURATION_CHANGED")
    return {"configurationSha256": sha(canonical(config)), "stateSha256": sha(canonical(state)),
            "status": state["Status"], "startedAt": state["StartedAt"]}


def retained_config(row, role, launch):
    """Exact equality with the configuration the accepted B1 launch encodes (no normalization)."""
    config, host = row["Config"], row["HostConfig"]
    manifest, startup = launch["manifest"], launch["startup"]
    mounts = host.get("Mounts")
    require(type(mounts) is list and mounts and not host.get("Binds")
            and all(m.get("Type") == "bind" and m.get("ReadOnly") is True for m in mounts),
            "RETAINED_MOUNTS_CHANGED")
    live = {"user": config["User"], "readOnlyRoot": host["ReadonlyRootfs"], "memoryBytes": host["Memory"],
            "pidsLimit": host["PidsLimit"],
            "mounts": [{"source": m["Source"], "target": m["Target"], "readOnly": True} for m in mounts]}
    if role == "southbound":
        live["tmpfs"] = dict(host.get("Tmpfs") or {})
    else:
        require(not host.get("Tmpfs"), "RETAINED_DOCKER_CONFIGURATION_CHANGED")
    require(live == manifest, "RETAINED_DOCKER_CONFIGURATION_CHANGED")
    require([(s["source"], s["target"]) for s in launch["sources"]] == [(m["Source"], m["Target"]) for m in mounts],
            "RETAINED_MOUNTS_CHANGED")
    require(type(config["User"]) is str and re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", config["User"]),
            "RETAINED_PROCESS_CONFIGURATION_CHANGED")
    uid, gid = map(int, config["User"].split(":"))
    args = (config.get("Entrypoint") or []) + (config.get("Cmd") or [])
    require((uid, gid, config["WorkingDir"], args) == (startup["uid"], startup["gid"], startup["cwd"], startup["args"])
            and [row["Path"], *row["Args"]] == args, "RETAINED_PROCESS_CONFIGURATION_CHANGED")
    # Docker merges image ENV into Config.Env: every recipe entry must be present verbatim.
    env = set(config.get("Env") or [])
    require(all(item in env for item in startup["env"] if not item.startswith(("PATH=", "HOSTNAME="))),
            "RETAINED_DOCKER_CONFIGURATION_CHANGED")
    return {"recipeLaunchEqual": True}


def compiler_module():
    return load_modules([(COMPILER, "_d052_frame_compiler")])[0]


def load_modules(selected):
    modules = []
    for path, alias in selected:
        filename = P.ROOT / path
        raw = C.read(filename, SOFTWARE[path])
        module = types.ModuleType(alias)
        module.__file__ = str(filename)
        sys.modules[alias] = module
        exec(compile(raw, str(filename), "exec"), vars(module))
        modules.append(module)
    return modules


def verify_rootfs(role, context, recipe, rf, rootfs_result):
    require(rf["containerId"] == context["containerId"] == P.CIDS[role], "ROOTFS_CANDIDATE_CHANGED")
    comparison = decode(C.read(rf["comparison"]["path"], rf["comparison"]["sha256"]))
    offline = decode(C.read(rf["offlineDockerReceipt"]["path"], rf["offlineDockerReceipt"]["sha256"]))
    oci = decode(C.read(comparison["ociConfig"]["path"], comparison["ociConfig"]["sha256"]))
    root = C.absolute(context["rootfsPath"])
    require(comparison["nodeRootfsPath"] == str(root) == oci["root"]["path"]
            and oci == recipe["expectedOci"] and comparison["containerId"] == context["containerId"]
            and comparison["imageId"] == offline["manifestDigest"] == rf["imageId"]
            and comparison["rule"] == rootfs_result["rule"] == "D-042"
            and comparison["nodeRootfsSeal"] == comparison["effectiveSeal"] ==
                comparison["expectedSeal"] == rf["effectiveSeal"]
            and rootfs_result["sourceManifestSha256"] == SEALER_SHA
            and rootfs_result["engine"]["dockerSocket"] == C.DOCKER_SOCKET
            and root == Path(rootfs_result["engine"]["dockerRoot"]) / "rootfs/overlayfs" / context["containerId"],
            "D042_ROOTFS_BINDING_CHANGED")
    # Reuse D-042's stopped export view and sealer. Contents go to the sealer;
    # the tar stream is discarded and no OCI bundle or filesystem is modified.
    previous = sys.modules.copy()
    try:
        image, export = load_modules([(IMAGE_ROOTFS, "prepare_provider_image_rootfs"),
                                      (STOPPED_EXPORT, "_d052_stopped_export")])
        sealer = image.load_sealer(SEALER_SOURCE, SEALER_SHA)
        require(not os.path.lexists(C.DOCKER_CONFIG), "DOCKER_CONFIG_UNPROVEN")
        with export.stopped_export_view((Path(C.DOCKER), C.DOCKER_SHA), C.DOCKER_SOCKET,
                                        C.DOCKER_CONFIG, context["containerId"], root) as mounted:
            seal = sealer(mounted, offline["rootfsLimits"], image.Budget())
    finally:
        for name in set(sys.modules) - previous.keys():
            del sys.modules[name]
        sys.modules.update(previous)
    if seal == rf["effectiveSeal"]:
        return seal
    # Southbound only: APISIX leaves the D-047 allowlisted volatiles in the upper
    # after every run. R3 start removes exactly those and re-proves this same D-042
    # seal (volatile_restore.removals/verify) before the process starts, so D-047
    # stays the rootfs gate. The adapter has no volatiles and remains strict.
    require(role == "southbound", "RETAINED_ROOTFS_CHANGED_FROM_D042")
    return {"liveSeal": seal, "matchesD042": False, "rootfsGate": "D-047"}


def revise(role, previous, new_hash, compiler):
    docs = {part: decode(raw) for part, raw in previous.items()}
    template, launch, context, policy = (docs[part] for part in PARTS)
    require(compiler.compile_policy(template, launch, context) == policy, "PREVIOUS_POLICY_MISMATCH")
    new_launch = copy.deepcopy(launch)
    matches = [item for item in new_launch["sources"] if item["source"] == str(P.SOURCE)
               or item["target"] == P.TARGET]
    if role == "adapter":
        require(not matches, "ADAPTER_ROUTE_SOURCE_UNEXPECTED")
        return previous
    require(len(matches) == 1, "SOUTHBOUND_ROUTE_SOURCE_UNPROVEN")
    source = matches[0]
    require(source["source"] == str(P.SOURCE) and source["target"] == P.TARGET
            and source["sha256"] == P.OLD_SHA and source["readOnly"] is True
            and (source["uid"], source["gid"], source["mode"]) == P.SOURCE_META, "SOUTHBOUND_ROUTE_SOURCE_UNPROVEN")
    source["sha256"] = new_hash
    new_policy = compiler.compile_policy(template, new_launch, context)
    require(new_policy == policy | {"sources": new_launch["sources"]}, "REVISED_POLICY_ONLY_SOURCES_REQUIRED")
    return previous | {"launch": canonical(new_launch) + b"\n", "policy": canonical(new_policy) + b"\n"}


def published_routes(receipt_sha):
    path = P.CLAIM / "result.json"
    result = decode(C.read(path, receipt_sha))
    plan = decode(C.read(P.CLAIM / "plan.json"))
    require(not os.path.lexists(P.CLAIM / "restored.json")
            and result == P.receipt("ROUTES_D052_PUBLISHED", plan)
            and result["oldSha256"] == P.OLD_SHA, "ROUTES_PUBLICATION_RECEIPT_UNPROVEN")
    original = C.read(P.CLAIM / "original.apisix.yaml", P.OLD_SHA, limit=P.MAX_BYTES)
    target, coordinator = P.declarations()
    updated, diff, before, after = P.regenerate(P.SOURCE, original, P.OLD_SHA, target)
    require(diff == result["diff"] and before == plan["before"] and after == plan["after"]
            and P.route_source(result["newSha256"]) == updated, "PUBLISHED_ROUTE_DIFF_UNPROVEN")
    return result["newSha256"], coordinator


def observe(docker, receipt_hash, *, seal_rootfs=verify_rootfs):
    new_hash, coordinator = published_routes(receipt_hash)
    observed, candidates = P.safety(docker, coordinator)
    previous_raw = C.read(PREVIOUS)
    previous = decode(previous_raw)
    successors = decode(C.read(SUCCESSORS, SUCCESSORS_SHA))
    rootfs_result = decode(C.read(ROOTFS, ROOTFS_SHA))
    a2 = previous["preparationA"]
    require(previous["schema"] == SCHEMA and previous["status"] == "SEMANTIC_PROVIDER_B1_RECIPES_PREPARED"
            and previous["recreation"] == RECREATION
            and a2["files"]["successors"] == rootfs_result["aSuccessors"] == P.binding(SUCCESSORS, SUCCESSORS_SHA)
            and rootfs_result["schema"] == "ouf.semantic-provider-b1-rootfs-evidence.v1"
            and rootfs_result["status"] == "SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED"
            and set(previous["roles"]) == set(rootfs_result["roles"]) == set(ROLES),
            "B1_PREVIOUS_EVIDENCE_UNPROVEN")
    compiler = compiler_module()
    artifacts, retained, roles = {}, {}, {}
    for role in ROLES:
        cid = P.CIDS[role]
        old_role = previous["roles"][role]
        pinned = next(row for row in successors["containers"] if row["containerId"] == cid)
        retained[role] = retained_frame(candidates[cid], pinned)
        rf = rootfs_result["roles"][role]
        require(old_role["containerId"] == cid and old_role["transaction"] == pinned["transaction"]
                and rf["imageId"] == pinned["image"], "B1_RECIPE_IDENTITY_CHANGED")
        raw = {}
        for part, digest in zip(PARTS, RECIPE_PINS[role]):
            path = PREVIOUS.parent / role / (part + ".json")
            require(old_role["recipe"][part] == P.binding(path, digest), "B1_PREVIOUS_RECIPE_UNPROVEN")
            raw[part] = C.read(path, digest)
        retained[role] |= retained_config(candidates[cid], role, decode(raw["launch"]))
        retained[role]["rootfsSeal"] = seal_rootfs(role, decode(raw["context"]), decode(raw["policy"]), rf, rootfs_result)
        artifacts[role] = revise(role, raw, new_hash, compiler)
        roles[role] = {"containerId": cid, "transaction": pinned["transaction"],
                       "recipe": {part: P.binding(OUTPUT / role / (part + ".json"), sha(content))
                                  for part, content in artifacts[role].items()}}
    again, candidates_after = P.safety(docker, coordinator)
    for cid in P.CIDS.values():
        require(candidates_after[cid] == candidates[cid], "PROVIDER_CHANGED_DURING_B1_OBSERVATION")
    require(again == observed and P.route_source(new_hash), "B1_INPUT_CHANGED_DURING_OBSERVATION")
    proposal = {"schema": "ouf.semantic-provider-b1-recipes-plan.v3", "output": str(OUTPUT),
                "previousRecipes": P.binding(PREVIOUS, sha(previous_raw)), "rootfs": P.binding(ROOTFS, ROOTFS_SHA),
                "routePublication": P.binding(P.CLAIM / "result.json", receipt_hash), "routeSha256": new_hash,
                "preparationA": a2, "recreation": RECREATION, "roles": roles, "softwareHashes": SOFTWARE,
                "retained": retained, "observed": observed, **P.FLAGS, "acceptanceGranted": False}
    return proposal, artifacts


def execute(mode, receipt_sha256, expected_plan, *, docker=None, progress=None):
    docker = C.Docker() if docker is None else docker
    progress = {} if progress is None else progress
    with P.fenced():
        C.directory(OUTPUT.parent)
        require(not os.path.lexists(OUTPUT), "B1_OUTPUT_ALREADY_EXISTS")
        plan, artifacts = observe(docker, receipt_sha256)
        digest = sha(canonical(plan))
        if mode == "plan":
            return {"status": "PLAN_READY", "planSha256": digest, "plan": plan}
        require(mode == "apply" and digest == expected_plan, "PLAN_DIGEST_MISMATCH")
        OUTPUT.mkdir(mode=0o700)
        progress["outputCreated"] = True
        C.sync_dir(OUTPUT.parent)
        for role in ROLES:
            directory = OUTPUT / role
            directory.mkdir(mode=0o700)
            C.sync_dir(OUTPUT)
            for part, raw in artifacts[role].items():
                C.write_once(directory / (part + ".json"), raw)
        result = plan | {"schema": SCHEMA, "recipeRevision": 3, "planSha256": digest,
                         "status": "SEMANTIC_PROVIDER_B1_RECIPES_PREPARED"}
        C.write_document(OUTPUT / "result.json", result)
        return result
