"""Shared read-only observation for the v5.1 installation and its restore (task-29b).

Nothing here writes, acquires the guard lock, reads a private key or calls a
container lifecycle operation. Every module that is executed (installed v5,
delivered or installed v5.1, mandates.py) is compiled from bytes whose SHA-256
was checked first; nothing is imported by path.
"""
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import types

V5_SOURCE = "tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py"
V5_SOURCE_SHA256 = "572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255"
V5_SCHEMA = "ouf.semantic-docker-runtime-adapter.v5"
V51_SCHEMA = "ouf.semantic-docker-runtime-adapter.v5.1"
B1_STATUS = "SEMANTIC_PROVIDER_B1_INSTALLED_INACTIVE"
ACCEPTANCE_STATUS = "SEMANTIC_PROVIDER_ACCEPTANCE_V51_ISSUED"
# The closure signed by acceptance generation 3 (task-29a, commit c25dca54).
CLOSURE_COMMIT = "c25dca54a6a991f5e9f8812f544692952a67c0ce"
RUNTIME = "tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py"
VERIFIER = "tools/semantic_runtime_v51/arming_verifier_v51.py"
MANDATES = "tools/semantic_authority_mandates/mandates.py"
CLOSURE = {
    RUNTIME: "8c7a166b299cb602afcfad4ceb6fc474e08cb1125cb00f6b4eb7c16a819c6f88",
    VERIFIER: "142bb726001d5f36224dc9b70374df3b86ddda6026b65a06d9917a634dc925c4",
    MANDATES: "86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79",
}
MINIMUM_GENERATION = 3
# Fields allowed to differ between acceptance generation 2 and 3 (D-027).
ACCEPTANCE_DELTA = frozenset({"generation", "softwareClosure", "issuedAt"})
WRAPPER = re.compile(
    rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+) '
    rb'--configuration (/[A-Za-z0-9_./-]+) "\$@"\n')
HEX = re.compile(r"[0-9a-f]{64}")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
EMPTY_ARMING = {"armingGenerations": [], "consumedMarkers": []}
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)
PUBLIC_ERRORS = ("Held", "Denied", "MandateDenied", "AuthorityDenied", "AcceptanceDenied",
                 "TransactionDenied")


class Held(RuntimeError):
    def __init__(self, reason, diagnosis=None):
        super().__init__(reason)
        self.details = dict(diagnosis or {})


def require(ok, reason):
    if not ok:
        raise Held(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hashed(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def absolute(value):
    require(type(value) is str, "EXPLICIT_ABSOLUTE_PATH_REQUIRED")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and path.as_posix() == value,
            "EXPLICIT_ABSOLUTE_PATH_REQUIRED")
    return path


def public_reason(error):
    """Stable public code only: never exception input text or paths."""
    text = str(error)
    if type(error).__name__ in PUBLIC_ERRORS and re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", text):
        return text
    diagnosis = getattr(error, "diagnosis", None)
    if type(diagnosis) is dict and type(diagnosis.get("reason")) is str:
        return diagnosis["reason"]
    return type(error).__name__


def compiled(raw, path, name, expected, reason):
    """Execute exactly the checked bytes as a private module (no import by path)."""
    require(type(raw) is bytes and sha(raw) == expected, reason)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def parse(raw, reason):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, reason)
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise Held(reason) from None
    require(type(value) is dict, reason)
    return value


def wrapper_targets(raw):
    match = WRAPPER.fullmatch(raw)
    require(match is not None, "WRAPPER_SHAPE_UNPROVEN")
    return tuple(part.decode("ascii") for part in match.groups())


def wrapper_bytes(python, root):
    base = Path(root).as_posix()
    raw = (f'#!/bin/sh\nexec {python} -I -B {base}/source/{RUNTIME} '
           f'--configuration {base}/runtime-configuration.json "$@"\n').encode("ascii")
    wrapper_targets(raw)
    return raw


def private_directory(path):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_DIRECTORY_REQUIRED")


def empty_directory(path, S, reason):
    path = absolute(str(path))
    for ancestor in path.parents:
        S.directory(ancestor)
    private_directory(path)
    require(not any(path.iterdir()), reason)


def executable_hash(path, expected):
    path = absolute(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o111, "EXECUTABLE_CUSTODY_UNPROVEN")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1048576):
            digest.update(chunk)
    require(digest.hexdigest() == expected, "EXECUTABLE_HASH_DRIFT")
    return str(path)


def b1_state(S, b1_root, b1_plan_sha256):
    """B1 as installed by task-25: receipt, v5 source/configuration and empty v5 arming.

    Uses the installed v5's own load_configuration, verify_files and
    arming_absence, compiled from bytes pinned to the B1 closure.
    """
    root = absolute(b1_root)
    receipt_raw, receipt_identity = S.custody(root / "result.json", 0o600)
    receipt = parse(receipt_raw, "B1_RECEIPT_UNPROVEN")
    after = receipt.get("wrapperAfter")
    require(receipt.get("status") == B1_STATUS and receipt.get("planSha256") == b1_plan_sha256
            and type(after) is dict and hashed(after.get("sha256"))
            and hashed(receipt.get("configurationSha256"))
            and type(receipt.get("containerIds")) is list, "B1_RECEIPT_UNPROVEN")
    source_path = root / "source" / V5_SOURCE
    config_path = root / "runtime-configuration.json"
    source_raw, source_identity = S.custody(source_path, 0o600)
    v5 = compiled(source_raw, source_path, "ouf_installed_runtime_v5", V5_SOURCE_SHA256, "B1_V5_SOURCE_DRIFT")
    config, config_raw = v5.load_configuration(config_path)
    require(config["schema"] == V5_SCHEMA and sha(config_raw) == receipt["configurationSha256"],
            "B1_V5_CONFIGURATION_DRIFT")
    v5.verify_files(config)
    require(v5.arming_absence(config_path) == EMPTY_ARMING, "B1_V5_ARMING_PRESENT")
    require(sorted(config["candidates"]) == receipt["containerIds"]
            and len(receipt["containerIds"]) == 2, "B1_CANDIDATES_DRIFT")
    _, config_identity = S.custody(config_path, 0o600)
    return {"v5": v5, "config": config, "configRaw": config_raw,
            "evidence": {"root": str(root), "planSha256": b1_plan_sha256,
                         "receiptSha256": sha(receipt_raw), "receiptIdentity": list(receipt_identity),
                         "installedWrapperSha256": after["sha256"],
                         "source": {"path": str(source_path), "sha256": sha(source_raw),
                                    "identity": list(source_identity)},
                         "configuration": {"path": str(config_path), "sha256": sha(config_raw),
                                           "identity": list(config_identity)},
                         "armingRoot": config["armingRoot"], "containerIds": sorted(config["candidates"])}}


def docker_inspect(docker, docker_sha256, socket, cid):
    binary = executable_hash(docker, docker_sha256)
    result = subprocess.run([binary, "--host", socket, "inspect", cid], stdin=subprocess.DEVNULL,
                            capture_output=True, env=ENV, timeout=30)
    require(result.returncode == 0 and len(result.stdout) <= 4194304, "SUCCESSOR_INSPECT_FAILED")
    executable_hash(docker, docker_sha256)
    try:
        rows = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise Held("SUCCESSOR_INSPECT_FAILED") from None
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and rows[0].get("Id") == cid,
            "SUCCESSOR_IDENTITY_UNPROVEN")
    return rows[0]


def successor_frames(docker, docker_sha256, socket, cids):
    """Both successors exist, were created and never started; frame digests for stability."""
    frames = {}
    for cid in cids:
        doc = docker_inspect(docker, docker_sha256, socket, cid)
        state = doc.get("State") or {}
        require(state.get("Status") == "created" and state.get("Running") is False and state.get("Pid") == 0
                and state.get("StartedAt") == "0001-01-01T00:00:00Z" and doc.get("RestartCount") == 0,
                "SUCCESSOR_EVER_STARTED")
        frames[cid] = sha(encoded({k: doc.get(k) for k in ("Id", "Image", "Config", "HostConfig", "Mounts")}))
    return frames


def guard_lock(S, path):
    raw, identity = S.custody(path, 0o600)
    require(raw == b"", "GUARD_LOCK_NOT_EMPTY")
    return {"path": str(path), "identity": list(identity)}


def mandates_module(raw, path):
    return compiled(raw, path, "ouf_bound_authority_mandates_install_v51", CLOSURE[MANDATES],
                    "MANDATES_MODULE_DRIFT")


def ledger_valid(M, anchor, mandate_root, installation, entity):
    try:
        M.MandateLedger(anchor, mandate_root, installation, entity).refresh()
    except M.MandateDenied:
        raise Held("V51_MANDATE_LEDGER_INVALID") from None


def acceptance_v51(S, B, M, acceptance_root, gen2_raw, anchor, mandate_root, openssl, issuer):
    """Generation-3 receipt, manifest and signature (ledger-backed) for the v5.1 closure.

    Every manifest field except generation, softwareClosure and issuedAt must
    equal the generation-2 manifest that B1 verified against the live P/A state.
    """
    root = absolute(acceptance_root)
    receipt_raw, _ = S.custody(root / "result.json", 0o600)
    receipt = parse(receipt_raw, "ACCEPTANCE_V51_RECEIPT_UNPROVEN")
    payload = receipt.get("payloadSha256")
    signature = receipt.get("signature")
    require(receipt.get("status") == ACCEPTANCE_STATUS and hashed(payload)
            and receipt.get("manifest") == {"path": str(root / "manifest.json"), "sha256": payload}
            and type(signature) is dict and set(signature) == {"path", "sha256"}
            and signature["path"] == str(root / (payload + ".ARTIFACT_ACCEPTANCE.json"))
            and hashed(signature["sha256"]) and receipt.get("startAuthorized") is False
            and receipt.get("leaseAuthorized") is False, "ACCEPTANCE_V51_RECEIPT_UNPROVEN")
    manifest_raw, _ = S.custody(root / "manifest.json", 0o600)
    signature_raw, _ = S.custody(Path(signature["path"]), 0o600)
    require(sha(manifest_raw) == payload and sha(signature_raw) == signature["sha256"],
            "ACCEPTANCE_V51_BYTES_DRIFT")
    manifest = B.decode_manifest(manifest_raw)
    previous = B.decode_manifest(gen2_raw)
    require(manifest["trustPolicy"] == anchor == previous["trustPolicy"], "ACCEPTANCE_V51_TRUST_POLICY_MISMATCH")
    # The ledger the v5.1 configuration will name must be valid on its own, first.
    ledger_valid(M, anchor, mandate_root, previous["installationRef"], previous["entityRef"])
    try:
        verified = M.MandateAuthenticator(anchor, mandate_root, openssl).verify_b1b2_detached(
            manifest_raw, signature_raw, "ARTIFACT_ACCEPTANCE", issuer,
            manifest["installationRef"], manifest["entityRef"])
    except M.MandateDenied as error:
        raise Held("ACCEPTANCE_V51_SIGNATURE_DENIED", {"mandateReason": public_reason(error)}) from None
    require(verified is True, "ACCEPTANCE_V51_SIGNATURE_DENIED")
    require(manifest["generation"] >= MINIMUM_GENERATION and manifest["generation"] > previous["generation"],
            "ACCEPTANCE_V51_GENERATION_REQUIRED")
    require(manifest["softwareClosure"] == {"sourceCommit": CLOSURE_COMMIT, "files": CLOSURE},
            "ACCEPTANCE_V51_CLOSURE_MISMATCH")
    differing = sorted(key for key in manifest if key not in ACCEPTANCE_DELTA and manifest[key] != previous[key])
    if differing:
        raise Held("ACCEPTANCE_V51_CONTEXT_DRIFT", {"differingFields": differing})
    return {"root": str(root), "receiptSha256": sha(receipt_raw), "payloadSha256": payload,
            "signatureSha256": signature["sha256"], "generation": manifest["generation"],
            "issuedAt": manifest["issuedAt"], "previousGeneration": previous["generation"],
            "installationRef": manifest["installationRef"], "entityRef": manifest["entityRef"],
            "containerIds": sorted(row["containerId"] for row in manifest["roles"].values()),
            "binding": {"path": str(root / "manifest.json"), "sha256": payload}}
