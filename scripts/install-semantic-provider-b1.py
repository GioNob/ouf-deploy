#!/usr/bin/env python3
"""Human-invoked B1 publication and guarded switch. No container lifecycle calls."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "ouf.semantic-provider-b1-installation.v1"
CLOSURE_COMMIT = "1cd6ea7c9c1da35a745cfd2c0d3755d99dfc7efd"
RUNTIME = "tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py"
VERIFIER = "tools/semantic_runtime_v5/arming_verifier.py"
AUTHORITY = "tools/semantic_b1b2_authority/authority.py"
CLOSURE = {
    RUNTIME: "572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255",
    VERIFIER: "c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338",
    AUTHORITY: "04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728",
}
COHORT = "tools/semantic_cohort_admission/cohort-draft"
DEPENDENCIES = (
    "scripts/install-semantic-provider-b1.py", "scripts/prepare-semantic-provider-installation.py",
    "tools/semantic_b1_acceptance/__init__.py", "tools/semantic_b1_acceptance/acceptance.py",
    "tools/semantic_b1b2_authority/__init__.py",
    "tools/semantic_transaction_profiles/guarded_runtime_switch.py",
    "tools/semantic_transaction_profiles/authenticate_provider_transaction.py",
    "tools/semantic_transaction_profiles/assemble_provider_profiles.py",
    "tools/semantic_transaction_profiles/publish_provider_transaction.py",
    "tools/semantic_frame_compiler/compile_creation_frame_policy.py",
    *(COHORT + "/tools/" + name + ".py" for name in (
        "semantic_provider_deployment_authentication", "semantic_provider_deployment_protocol",
        "semantic_provider_preexec", "semantic_provider_deployment_admission",
        "materialize_semantic_shared_faces", "materialize_southbound_kernel",
        "semantic_provider_preexec_native", "semantic_provider_peer_bindings",
        "semantic_provider_lease_coordination", "semantic_provider_lease_nft")),
    *CLOSURE,
)
P_ARGUMENTS = (
    "installation-ref", "installation-root", "a-root", "a-plan-sha256", "guard-pointer",
    "docker-socket", "docker-socket-unit", "docker-service-unit", "docker-socket-owner",
    "guard-service-unit", "guard-service-file", "docker-drop-in-file", "docker-socket-group",
    "docker-socket-mode", "dockerd", "generation-receipt", "generation-receipt-sha256",
    "authority-profile", "authority-sha256", "trust-policy", "trust-policy-sha256",
)
WRAPPER = re.compile(
    rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+) '
    rb'--configuration (/[A-Za-z0-9_./-]+) "\$@"\n')
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
COUNTERS = dict(containerLifecycleOperations=0, dockerStartRequests=0, nftWrites=0,
                daemonRestarted=False, privateKeysRead=0, signaturesIssued=0,
                startAuthorized=False, leaseAuthorized=False)


class Held(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Held(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dependencies():
    """Only the explicitly delivered trees are added to isolated Python's path.

    The tools namespace has no initializer or fallback to an ambient package.
    The launcher's full hash-verified closure must precede this import boundary.
    """
    namespace = types.ModuleType("tools")
    namespace.__path__ = [str(ROOT / "tools"), str(ROOT / COHORT / "tools")]
    sys.modules["tools"] = namespace
    sys.path[:0] = [str(ROOT / "tools/semantic_transaction_profiles"),
                   str(ROOT / "tools/semantic_frame_compiler")]
    from tools.semantic_b1_acceptance import acceptance
    from tools.semantic_b1b2_authority import authority
    import guarded_runtime_switch
    p = load(ROOT / "scripts/prepare-semantic-provider-installation.py", "b1_profile_observer")
    v5 = load(ROOT / RUNTIME, "b1_runtime_v5")
    return types.SimpleNamespace(P=p, A=authority, B=acceptance, S=guarded_runtime_switch, V=v5)


def delivered(path):
    """Stable plan key: delivered files by relative name, every other input absolute."""
    path = Path(path)
    if path.is_relative_to(ROOT):
        return "delivery:" + path.relative_to(ROOT).as_posix()
    return str(path)


def binding(args, name):
    return {"path": getattr(args, name), "sha256": getattr(args, name + "_sha256")}


def reader_for(d, args):
    class Reader(d.P.Reader):
        private_paths = frozenset()

        def read(self, name, *positional, **options):
            path = d.P.absolute(str(name))
            require(not any(path == key or key in path.parents for key in self.private_paths),
                    "PRIVATE_KEY_AS_INPUT_FORBIDDEN")
            return super().read(path, *positional, **options)

        def recheck(self):
            # P.verify checks identity. B1 also rehashes every byte, including executables.
            for path, (identity, pin) in list(self.inputs.items()):
                info = path.lstat()
                self.read(path, pin, uid=info.st_uid, gid=info.st_gid,
                          mode=stat.S_IMODE(info.st_mode), minimum=0, maximum=268435456,
                          hash_only=True)
            return self.verify()

    reader = Reader()
    authority = reader.document(args.authority_profile, args.authority_sha256)
    reader.private_paths = frozenset(d.P.absolute(row["path"]) for row in authority["keyBindings"].values())
    require(not reader.private_paths.intersection(reader.inputs), "PRIVATE_KEY_AS_INPUT_FORBIDDEN")
    return reader, authority


def output_path(args, d, existing=False):
    parent = d.P.absolute(args.output_root)
    for path in (parent, *parent.parents):
        d.S.directory(path)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.output_name),
            "RESTRICTED_OUTPUT_NAME_REQUIRED")
    root = parent / args.output_name
    require(existing or not os.path.lexists(root), "B1_OUTPUT_ALREADY_EXISTS")
    return root


def syntax_configuration(config, v5):
    """Plan-time replica of load_configuration, excluding filesystem custody.

    Native tests compare acceptance/rejection to the unchanged real v5 loader.
    No temporary configuration, prospective directory or monkeypatched loader.
    """
    require(type(config) is dict and set(config) == v5.CONFIG_FIELDS
            and config["schema"] == v5.SCHEMA, "EXACT_RUNTIME_V5_CONFIGURATION_REQUIRED")
    for key in ("sourceHash", "runtimeSha256", "pythonSha256", "driverSha256",
                "admissionSha256", "armingVerifierSha256"):
        require(v5.hashed(config[key]), "V5_SHA256_REQUIRED")
    for key in ("runtimePath", "pythonPath", "driverPath", "admissionPath", "registryRoot",
                "runtimeStateRoot", "armingRoot", "armingVerifierPath"):
        v5.absolute(config[key])
    for key in ("acceptance", "b1b2TrustPolicy", "b1b2AuthorityModule"):
        v5.file_binding(config[key])
    ssl = config["opensslBinding"]
    require(type(ssl) is dict and set(ssl) == {"path", "sha256", "version"}
            and type(ssl["version"]) is str
            and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+[a-z]?", ssl["version"]),
            "EXACT_V5_OPENSSL_BINDING_REQUIRED")
    v5.file_binding({key: ssl[key] for key in ("path", "sha256")})
    require(v5.identity(config["armingIssuerRef"]), "V5_ISSUER_REQUIRED")
    candidates = config["candidates"]
    require(type(candidates) is dict and len(candidates) == 2
            and all(v5.hashed(cid) for cid in candidates), "EXACT_V5_CANDIDATES_REQUIRED")
    for entry in candidates.values():
        require(type(entry) is dict and set(entry) == {"phase", "bundleParents"}
                and entry["phase"] == "INACTIVE" and type(entry["bundleParents"]) is list
                and 1 <= len(entry["bundleParents"]) <= 4, "EXACT_INACTIVE_CANDIDATE_REQUIRED")
        for parent in entry["bundleParents"]:
            v5.absolute(parent)


def configuration(args, old, root, cids, v5):
    copied = ("runtimePath", "runtimeSha256", "pythonPath", "pythonSha256", "driverPath",
              "driverSha256", "admissionPath", "admissionSha256", "registryRoot", "runtimeStateRoot")
    config = {key: old[key] for key in copied}
    config.update(schema=v5.SCHEMA, sourceHash=CLOSURE[RUNTIME],
                  acceptance=binding(args, "acceptance_manifest"),
                  b1b2TrustPolicy=binding(args, "b1b2_trust_policy"), armingRoot=str(root / "arming"),
                  armingVerifierPath=str(root / "source" / VERIFIER),
                  armingVerifierSha256=CLOSURE[VERIFIER],
                  b1b2AuthorityModule={"path": str(root / "source" / AUTHORITY), "sha256": CLOSURE[AUTHORITY]},
                  opensslBinding={**binding(args, "openssl"), "version": args.openssl_version},
                  armingIssuerRef=args.arming_issuer_ref,
                  candidates={cid: {"phase": "INACTIVE", "bundleParents": [args.bundle_parent]} for cid in cids})
    syntax_configuration(config, v5)
    return config


def proposed_wrapper(config, root):
    base = Path(root).as_posix()
    raw = (f'#!/bin/sh\nexec {config["pythonPath"]} -I -B {base}/source/{RUNTIME} '
           f'--configuration {base}/runtime-configuration.json "$@"\n').encode("ascii")
    require(WRAPPER.fullmatch(raw), "B1_PROPOSED_WRAPPER_SHAPE_UNPROVEN")
    return {"text": raw.decode("ascii"), "base64": base64.b64encode(raw).decode("ascii"),
            "byteLength": len(raw), "sha256": sha(raw)}


def observation(args, d, *, baseline=None, phase=None, fd=None):
    """Fresh full P/A observation. No lock acquisition, publication or signer."""
    reader, authority = reader_for(d, args)
    root = output_path(args, d, existing=baseline is not None)
    profile_path = d.P.absolute(args.installation_root) / args.installation_ref / "semantic-provider.json"
    published = reader.read(profile_path)
    require(sha(published) == args.p_profile_sha256, "B1_PROFILE_DRIFT")
    observed = d.P.observe_profile(args, reader)
    require(observed["profileBytes"] == published, "B1_PROFILE_DRIFT")
    profile = observed["profile"]
    require(args.revise_from_sha256 is None or args.revise_from_sha256 == args.p_profile_sha256,
            "B1_PROFILE_REVISION_NOT_PERMITTED")
    require(str(root.parent) == profile["paths"]["snapshotRoot"], "B1_SNAPSHOT_ROOT_MISMATCH")
    lock = profile["paths"]["guard"]["lock"]
    lock_raw, lock_identity = d.S.custody(lock, 0o600)
    require(lock_raw == b"", "B1_GUARD_LOCK_NOT_EMPTY")
    if fd is not None:
        require(baseline is not None and phase in ("BEFORE_CLAIM", "BEFORE_RENAME", "AFTER_RENAME")
                and (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == lock_identity[:2]
                and tuple(baseline["lock"]["identity"]) == lock_identity, "B1_BORROWED_LOCK_DRIFT")
    peer, successors = d.P.receipt_a(reader, args.a_root, args.a_plan_sha256)
    docker = d.P.Docker(reader, args, profile["paths"]["binaries"]["systemctl"])
    docs = d.P.read_roles(docker, peer, successors)
    require(docker.proof == observed["dockerPeerProof"], "B1_DOCKER_PEER_CHANGED")
    frames, roles = {}, {}
    for role in ("adapter", "southbound"):
        doc = docs[role]
        require(doc["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
                and doc["State"]["Pid"] == 0 and doc["State"]["Status"] == "created"
                and doc["State"]["Running"] is False and doc["RestartCount"] == 0,
                "B1_SUCCESSOR_EVER_STARTED")
        rows = [row for row in successors["containers"] if row["containerId"] == doc["Id"]]
        require(len(rows) == 1 and rows[0]["image"] == doc["Image"]
                and rows[0]["runtime"] == profile["runtime"]["name"]
                and rows[0]["transaction"] == successors["transactions"][doc["Id"]],
                "B1_SUCCESSOR_A2_MISMATCH")
        roles[role] = {"containerId": doc["Id"], "imageId": rows[0]["image"]}
        frames[role] = d.P.frame(doc)
    prep_hashes = {}
    for field, name in (("manifest", "manifest.json"), ("result", "result.json"),
                        ("semanticPeer", "semantic-peer.json"), ("successors", "successors.json")):
        prep_hashes[field] = sha(reader.read(d.P.absolute(args.a_root) / name))
    recreation = {key: successors["lineage"]["recreation"][key] for key in ("path", "sha256")}
    reader.read(recreation["path"], recreation["sha256"])
    policy_binding = binding(args, "b1b2_trust_policy")
    policy = d.A.policy(reader.read(args.b1b2_trust_policy, args.b1b2_trust_policy_sha256),
                        profile["installationRef"], profile["entityRef"])
    require(policy["authorityProfile"] == {"path": args.authority_profile, "sha256": args.authority_sha256}
            and policy["basePolicy"] == {"path": args.trust_policy, "sha256": args.trust_policy_sha256},
            "B1_TRUST_POLICY_BINDING_DRIFT")
    expected = {"installationRef": profile["installationRef"], "entityRef": profile["entityRef"],
                "issuerRef": authority["authorities"]["approvalIssuerRef"],
                "profileSha256": args.p_profile_sha256,
                "preparationA": {"planSha256": args.a_plan_sha256, "files": prep_hashes},
                "transactions": {role: successors["transactions"][row["containerId"]] for role, row in roles.items()},
                "recreation": recreation, "roles": roles, "trustPolicy": policy_binding, "minimumGeneration": 1}
    openssl = {**binding(args, "openssl"), "version": args.openssl_version}
    authenticator = d.A.B1B2Authenticator(policy_binding, openssl)
    verified = d.B.verify_acceptance(
        reader.read(args.acceptance_manifest, args.acceptance_manifest_sha256),
        reader.read(args.acceptance_signature, args.acceptance_signature_sha256),
        expected=expected, authenticator=authenticator)
    manifest = verified["manifest"]
    require(manifest["profile"]["path"] == str(profile_path)
            and manifest["preparationA"]["root"] == args.a_root
            and all(manifest["preparationA"]["files"][field]["path"] == str(Path(args.a_root) / name)
                    for field, name in (("manifest", "manifest.json"), ("result", "result.json"),
                                        ("semanticPeer", "semantic-peer.json"), ("successors", "successors.json"))),
            "B1_ACCEPTANCE_PATH_DRIFT")
    require(manifest["softwareClosure"] == {"sourceCommit": CLOSURE_COMMIT, "files": CLOSURE},
            "B1_CLOSURE_BINDING_DRIFT")
    for name in DEPENDENCIES:
        path = ROOT / name
        mode = stat.S_IMODE(path.lstat().st_mode)
        require(mode in (0o600, 0o644, 0o755), "B1_DELIVERY_CUSTODY_UNPROVEN")
        reader.read(path, CLOSURE.get(name), mode=mode)
    wrapper = profile["runtime"]["wrapper"]
    prior, wrapper_identity = d.S.custody(wrapper, 0o755)
    match = WRAPPER.fullmatch(prior)
    require(match is not None, "B1_CURRENT_WRAPPER_SHAPE_UNPROVEN")
    python, source, current_config_path = (item.decode("ascii") for item in match.groups())
    current = reader.document(current_config_path)
    after = phase == "AFTER_RENAME" or phase == "FINAL"
    if baseline is None:
        require(current["schema"] == "ouf.semantic-docker-runtime-adapter.v4", "B1_CURRENT_RUNTIME_NOT_V4")
        config = configuration(args, current, root, [row["containerId"] for row in roles.values()], d.V)
    else:
        config = baseline["configuration"]
        require(current == (config if after else baseline["priorConfiguration"]), "B1_CURRENT_CONFIG_DRIFT")
        old = baseline["wrapperBefore"]
        require((prior == baseline["wrapperProposed"]["text"].encode() if after else
                 sha(prior) == old["sha256"] and tuple(old["identity"]) == wrapper_identity),
                "B1_CURRENT_WRAPPER_DRIFT")
    require(python == config["pythonPath"], "B1_CURRENT_PYTHON_DRIFT")
    # Use v5's actual custody primitives for every inherited file, before writing.
    for prefix in ("runtime", "python"):
        path = config[prefix + "Path"]
        require(d.P.absolute(path) not in reader.private_paths, "PRIVATE_KEY_AS_INPUT_FORBIDDEN")
        d.V.executable(path, config[prefix + "Sha256"])
        reader.read(path, config[prefix + "Sha256"], mode=stat.S_IMODE(Path(path).lstat().st_mode),
                    maximum=64000000, hash_only=True)
    for prefix in ("driver", "admission"):
        path = config[prefix + "Path"]
        require(d.P.absolute(path) not in reader.private_paths, "PRIVATE_KEY_AS_INPUT_FORBIDDEN")
        require(sha(d.V.read(Path(path))) == config[prefix + "Sha256"], "B1_INHERITED_FILE_DRIFT")
        reader.read(path, config[prefix + "Sha256"])
    reader.read(args.openssl, args.openssl_sha256, mode=stat.S_IMODE(Path(args.openssl).lstat().st_mode),
                maximum=64000000, hash_only=True)
    if baseline is not None:
        verify_publication(root, config, d)
        # Old source/configuration remain rollback evidence after rename. P now
        # follows v5, so retain explicit fresh custody of inputs it no longer visits.
        for path, pin in baseline["inputHashes"].items():
            if path.startswith("delivery:"):
                continue
            if path != wrapper and Path(path) not in reader.inputs:
                info = Path(path).lstat()
                reader.read(path, pin, uid=info.st_uid, gid=info.st_gid,
                            mode=stat.S_IMODE(info.st_mode), minimum=0, maximum=268435456,
                            hash_only=True)
    # Delivery paths change at every launcher run: bind them by relative name so the
    # same reviewed plan digest is reproduced by a fresh delivery of identical bytes.
    input_hashes = {delivered(path): pin for path, pin in reader.recheck().items()}
    input_identities = {delivered(path): list(item[0]) for path, item in reader.inputs.items()
                        if not Path(path).is_relative_to(ROOT)}
    state = {"profileSha256": sha(published), "inputHashes": input_hashes,
             "inputIdentities": input_identities,
             "frames": frames, "roles": roles, "acceptancePayloadSha256": verified["payloadSha256"],
             "lock": {"path": lock, "identity": list(lock_identity)},
             "wrapperBefore": {"path": wrapper, "sha256": sha(prior), "identity": list(wrapper_identity)},
             "priorConfiguration": current, "configuration": config, "root": str(root),
             "dockerPeerProof": observed["dockerPeerProof"], "networkIds": observed["networkIds"]}
    if baseline is not None:
        require(frames == baseline["frames"] and state["lock"] == baseline["lock"]
                and state["dockerPeerProof"] == baseline["dockerPeerProof"]
                and state["networkIds"] == baseline["networkIds"], "B1_OBSERVATION_DRIFT")
        # The switch changes exactly the wrapper and the observed configuration/source closure.
        allowed = {wrapper, *(str(root / "source" / name) for name in CLOSURE),
                   str(root / "runtime-configuration.json")}
        old_inputs = baseline["inputHashes"]
        for path, pin in old_inputs.items():
            if path not in allowed:
                require(input_hashes.get(path) == pin
                        and input_identities.get(path) == baseline["inputIdentities"].get(path),
                        "B1_INPUT_DRIFT")
        require(all(path in old_inputs or path in allowed for path in input_hashes), "B1_INPUT_SET_DRIFT")
    return state


def plan(args, d):
    state = observation(args, d)
    root = Path(state["root"])
    config = state["configuration"]
    state.update(schema=SCHEMA, wrapperProposed=proposed_wrapper(config, root),
                 configurationSha256=sha(encoded(config) + b"\n"), softwareClosureCommit=CLOSURE_COMMIT,
                 writes={"directories": [str(root), str(root / "source"), str(root / "source/tools"),
                            str(root / "source/tools/semantic_runtime_v5"),
                            str(root / "source/tools/semantic_b1b2_authority"), str(root / "arming"), str(root / "switch")],
                         "directoryMode": "0700", "fileMode": "0600", "owner": "root:root",
                         "files": {**{str(root / "source" / name): pin for name, pin in CLOSURE.items()},
                                   str(root / "runtime-configuration.json"): sha(encoded(config) + b"\n")},
                         "resultFile": str(root / "result.json"),
                         "switchEvidenceRoot": str(root / "switch")}, **COUNTERS)
    state["planSha256"] = sha(encoded(state))
    return state


def verify_publication(root, config, d):
    for path in (root, root / "source", root / "source/tools", root / "source/tools/semantic_runtime_v5",
                 root / "source/tools/semantic_b1b2_authority", root / "switch", root / "arming"):
        d.V.private_directory(path)
    require(not any((root / "arming").iterdir()), "B1_ARMING_ROOT_NOT_EMPTY")
    for name, pin in CLOSURE.items():
        require(sha(d.V.read(root / "source" / name)) == pin, "B1_INSTALLED_CLOSURE_DRIFT")
    actual, raw = d.V.load_configuration(root / "runtime-configuration.json")
    require(actual == config and raw == encoded(config) + b"\n", "B1_INSTALLED_CONFIG_DRIFT")
    installed_v5 = load(root / "source" / RUNTIME, "b1_installed_v5")
    installed_v5.verify_files(config)


def smoke(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=ENV, timeout=12)
    require(result.returncode == 0, "B1_SMOKE_FAILED")


def apply(args, d, proposal, report):
    require(args.plan_sha256 == proposal["planSha256"], "B1_PLAN_DIGEST_CHANGED")
    root = Path(proposal["root"])
    # mkdir is exclusive: it fails even for an empty pre-existing output root.
    root.mkdir(mode=0o700)
    report.update(root=str(root), outputCreated=True, doNotRerunApply=True,
                  planSha256=proposal["planSha256"], wrapperBefore=proposal["wrapperBefore"],
                  configurationSha256=proposal["configurationSha256"],
                  acceptancePayloadSha256=proposal["acceptancePayloadSha256"],
                  containerIds=sorted(proposal["configuration"]["candidates"]))
    d.S.sync(root.parent)
    for path in proposal["writes"]["directories"][1:]:
        Path(path).mkdir(mode=0o700)
        d.S.sync(Path(path).parent)
    # Bounded publication uses the unchanged primitive's O_EXCL/nofollow/fsync writer.
    reader, _ = reader_for(d, args)
    for name, pin in CLOSURE.items():
        path = ROOT / name
        raw = reader.read(path, pin, mode=stat.S_IMODE(path.lstat().st_mode))
        d.S.publish_once(root / "source" / name, raw)
    reader.recheck()
    config = proposal["configuration"]
    d.S.publish_once(root / "runtime-configuration.json", encoded(config) + b"\n")
    for path in reversed(proposal["writes"]["directories"]):
        d.S.sync(path)
    verify_publication(root, config, d)
    smoke([config["pythonPath"], "-I", "-B", str(root / "source" / RUNTIME),
           "--configuration", str(root / "runtime-configuration.json"), "--version"])

    def verify_locked(fd, phase):
        observation(args, d, baseline=proposal, phase=phase, fd=fd)

    before = proposal["wrapperBefore"]
    outcome = d.S.switch_existing_wrapper(
        before["path"], before["sha256"], proposal["wrapperProposed"]["text"].encode("ascii"),
        root / "switch", proposal["lock"]["path"], proposal["lock"]["identity"], verify_locked)
    report.update(switchOutcome="REPLACED", wrapperReplaced=True, primitiveResult=outcome)
    raw, identity = d.S.custody(before["path"], 0o755)
    require(raw == proposal["wrapperProposed"]["text"].encode("ascii"), "B1_WRAPPER_READBACK_DRIFT")
    smoke([before["path"], "--version"])
    observation(args, d, baseline=proposal, phase="FINAL")
    report.update(status="SEMANTIC_PROVIDER_B1_INSTALLED_INACTIVE", planSha256=proposal["planSha256"],
                  wrapperBefore=before, wrapperAfter={"path": before["path"], "sha256": sha(raw),
                                                     "identity": list(identity)},
                  configurationSha256=proposal["configurationSha256"],
                  acceptancePayloadSha256=proposal["acceptancePayloadSha256"],
                  containerIds=sorted(config["candidates"]), profileSha256=proposal["profileSha256"])
    d.S.publish_once(root / "result.json", encoded(report) + b"\n")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--revise-from-sha256")
    parser.add_argument("--docker-socket-activation", choices=("systemd-socket", "daemon"), required=True)
    for name in (*P_ARGUMENTS, "p-profile-sha256", "acceptance-manifest", "acceptance-manifest-sha256",
                 "acceptance-signature", "acceptance-signature-sha256", "b1b2-trust-policy",
                 "b1b2-trust-policy-sha256", "openssl", "openssl-sha256", "openssl-version",
                 "arming-issuer-ref", "bundle-parent", "output-root", "output-name"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    for name, value in vars(args).items():
        if name.endswith("sha256") and value is not None and not re.fullmatch("[0-9a-f]{64}", value):
            parser.error("expected exact lowercase SHA-256 bindings")
    if (args.apply and args.plan_sha256 is None) or (args.plan and args.plan_sha256 is not None):
        parser.error("apply requires --plan-sha256; plan forbids it")
    return args


def main(argv=None):
    args = arguments(argv)
    report = {"schema": SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED",
              "doNotRerunApply": False, **COUNTERS}
    try:
        require(os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        d = dependencies()
        proposal = plan(args, d)
        if args.plan:
            report.update(proposal, status="PLAN_READY")
        else:
            apply(args, d, proposal, report)
    except Exception as error:
        # Retain the primitive's exact public diagnosis, never exception input text.
        diagnosis = getattr(error, "diagnosis", {})
        reason = str(error) if isinstance(error, (Held,)) or type(error).__name__ in (
            "Held", "Denied", "AuthorityDenied", "AcceptanceDenied") else type(error).__name__
        report.update(diagnosis, status="HELD", reason=diagnosis.get("reason", reason))
        report.update(COUNTERS)
        if report["reason"] == "B1_OUTPUT_ALREADY_EXISTS":
            report["doNotRerunApply"] = True
        if report.get("outputCreated"):
            report["doNotRerunApply"] = True
            root = Path(report["root"])
            try:
                d.S.publish_once(root / "result.json", encoded(report) + b"\n")
            except Exception:
                report["diagnosisSaved"] = False
    print(encoded(report).decode(), flush=True)
    return 1 if report["status"] == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
