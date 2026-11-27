#!/usr/bin/env python3
"""Issue exactly one R3 operation authorization. No installation or runtime actions."""
import argparse
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_r3 import compose as C
from tools.semantic_provider_operation import authorization as A
from tools.semantic_lease_kernel_migration import boot_dispatcher as boot
from tools.semantic_b1b2_authority import authority as AUTH
from tools.semantic_acceptance_v51.issuance import load_mandates

SCHEMA = "ouf.semantic-provider-operation-issuance.v1"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
require, canonical, sha = A.require, A.canonical, A.sha


class Reader:
    def __init__(self, private_paths):
        self.private_paths = {AUTH.absolute(p) for p in private_paths}
        self.hashes = {}

    def read(self, path, expected, limit=8388608):
        path = AUTH.absolute(str(path))
        require(path not in self.private_paths and not any(k in path.parents for k in self.private_paths),
                "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN")
        require(type(expected) is str and A.HEX64.fullmatch(expected), "EXPLICIT_INPUT_HASH_REQUIRED")
        AUTH.ancestors(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and not before.st_mode & 0o022 and 0 < before.st_size <= limit, "INPUT_FILE_CUSTODY_REQUIRED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            require(len(raw) == before.st_size and AUTH.attributes(before) == AUTH.attributes(os.fstat(fd))
                    == AUTH.attributes(path.lstat()), "INPUT_CHANGED_DURING_READ")
        finally:
            os.close(fd)
        require(sha(raw) == expected and (str(path) not in self.hashes or self.hashes[str(path)] == expected),
                "INPUT_SHA256_MISMATCH")
        self.hashes[str(path)] = expected
        return raw

    def bound(self, value):
        require(type(value) is dict and set(value) == {"path", "sha256"}, "EXACT_INPUT_BINDING_REQUIRED")
        return self.read(value["path"], value["sha256"])

    def verify(self):
        for path, digest in list(self.hashes.items()):
            self.read(path, digest, 64000000)


def mandate(M, ledger, key_ref, issuer, at):
    row = ledger.at(key_ref, at)
    require(not ledger.ever_revoked(key_ref) and row["issuerRef"] == issuer and row["state"] == "ACTIVE"
            and A.ROLE in row["roles"] and row["notBefore"] <= at < row["expiresAt"], "ACTIVE_INSTALLER_MANDATE_REQUIRED")
    return row


def authority_now(M, ledger, key_ref, issuer, clock):
    now = clock()
    ledger.refresh(now)
    current = ledger.current(key_ref, A.ROLE, now)
    require(current == mandate(M, ledger, key_ref, issuer, now), "ACTIVE_INSTALLER_MANDATE_REQUIRED")
    return current


def observe(args, clock):
    reader = Reader(args.private_key_path)
    # All key paths are excluded before even the authority profile is opened.
    profile_raw = reader.read(args.authority_profile, args.authority_profile_sha256)
    profile = C.document(profile_raw)
    require(profile["schema"] == "ouf.semantic-existing-installation-authority-bindings.v1",
            "EXACT_AUTHORITY_PROFILE_REQUIRED")
    key_paths = {AUTH.absolute(AUTH.binding(v)["path"]) for v in profile["keyBindings"].values()}
    require(key_paths == reader.private_paths, "EXACT_PRIVATE_KEY_PATH_EXCLUSIONS_REQUIRED")
    bundle = C.document(reader.read(args.inputs, args.inputs_sha256))
    require(set(bundle) == {"schema", "files", "sources"} and bundle["schema"] == "ouf.semantic-provider-r3-inputs.v1"
            and C.input_set(bundle["files"], bundle["sources"]),
            "EXACT_R3_INPUT_MANIFEST_REQUIRED")
    files = {k: reader.bound(v) for k, v in bundle["files"].items()}
    sources = {k: reader.bound(v) for k, v in bundle["sources"].items()}
    settings = C.document(files["settings"])
    tables = {}
    for item in args.table_name:
        role, sep, name = item.partition("=")
        require(sep and role in A.ROLES and role not in tables, "EXACT_TABLE_NAME_ARGUMENTS_REQUIRED")
        tables[role] = name
    settings.update(installRoot=args.install_root, issuedAt=args.issued_at, tableNames=tables)
    require(type(args.issued_at) is int and 0 < args.issued_at <= clock(), "ISSUED_AT_FUTURE_OR_INVALID")
    files["settings"] = canonical(settings)
    scope = {k: settings[k] for k in ("installationRef", "entityRef", "issuerRef")}
    auth = profile["authorities"]
    require(all(auth[k] == scope[k] for k in ("installationRef", "entityRef"))
            and auth["intentIssuerRef"] == auth["approvalIssuerRef"] == scope["issuerRef"], "AUTHORITY_SCOPE_DRIFT")
    anchor = settings["anchorBinding"]
    anchor_doc = C.document(reader.bound(anchor))
    require(anchor_doc["authorityProfile"] == {"path": args.authority_profile, "sha256": args.authority_profile_sha256}
            and anchor_doc["basePolicy"] == profile["policyBinding"], "AUTHORITY_PROFILE_BINDING_MISMATCH")
    reader.bound(settings["coordinatorBinding"])
    require(reader.hashes[settings["coordinatorBinding"]["path"]] == sha(files["coordinator"]),
            "COORDINATOR_INPUT_DRIFT")
    M = load_mandates(sources[C.MANDATES], sha(sources[C.MANDATES]), C.MANDATES)
    ledger = M.MandateLedger(anchor, settings["mandateRoot"], scope["installationRef"], scope["entityRef"], clock)
    key_ref = profile["keyRefs"]["installer"]
    current = authority_now(M, ledger, key_ref, scope["issuerRef"], clock)
    issued = mandate(M, ledger, key_ref, scope["issuerRef"], args.issued_at)
    require(issued["publicKey"] == current["publicKey"], "INSTALLER_PUBLIC_KEY_DRIFT")
    verifier = M.MandateAuthenticator(anchor, settings["mandateRoot"], settings["opensslBinding"], clock)
    ssl = settings["opensslBinding"]
    reader.read(ssl["path"], ssl["sha256"], 64000000)
    version = native(verifier, ["version"], 256)
    match = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", version)
    require(match is not None and match[1].decode() == ssl["version"], "DETACHED_OPENSSL_VERSION_UNPROVEN")
    previous = None
    if args.supersede:
        from tools.semantic_provider_operation import supersede_gate as gate
        gate.exclude_keys(AUTH.absolute(args.install_root), reader.private_paths)
        previous = authorization_head(args, M, settings, clock)
    if 'migrationReceipt' in files:
        from tools.semantic_provider_r3 import install_common as I
        I.coordinator_state(settings, files, reader)
    composed = compose_next({"files": files, "sources": sources}, previous, args.issued_at)
    payload = A.validate(composed["authorization"])
    sequence = payload["sequence"]
    if C.composition_version(sequence, payload) >= 25:
        from tools.semantic_provider_r3.semantic_identity_v25 import semantic_kernel_probe
        supervisor = C.document(composed["documents"][f"versions/{sequence}/supervisor/configuration.json"])
        semantic_kernel_probe(supervisor["semanticIngress"]["commands"]["ip"])
    reader.verify()
    plan = {"schema": SCHEMA, "payload": payload,
        "payloadSha256": sha(composed["authorization"]), "documentHashes": composed["hashes"],
        "layout": composed["layout"], "audit": composed["audit"], "inputHashes": reader.hashes.copy(),
        "compositionInputHashes": composed["inputHashes"], "ledger": ledger.snapshot(),
        "keyRef": key_ref, "privateKeysRead": 0,
        "outputDirectory": args.output_directory, "previousHead": previous}
    return plan, composed, reader, M, ledger, verifier, profile["keyBindings"]["installer"], key_ref, settings


def compose_next(inputs, previous, issued_at):
    if previous is not None:
        require(previous["decision"] == "OPERATE", "SUPERSEDE_REQUIRES_OPERATE_HEAD")
        require(issued_at >= previous["authorization"]["issuedAt"], "OPERATION_CHAIN_TIME_REGRESSED")
    number = previous["sequence"] + 1 if previous else 1
    if C.composition_version(number, C.document(inputs["files"]["settings"])) == 12:
        C.migration_bindings(inputs['files'])
        plan = C.document(inputs['files']['migrationPlan'])
        require(plan['observation']['authorization']['sha256'] == previous['sha256']
                and previous['authorization']['lease']['ownerConfigurationSha256']
                    == sha(canonical(plan['context']['owner'])), 'R3_LEASE_KERNEL_MIGRATION_HEAD_DRIFT')
    return C.compose(inputs, version=number, sequence=number,
                     supersedes=previous["sha256"] if previous else None)


def native(verifier, argv, limit):
    executable = verifier.executable()
    try:
        result = subprocess.run([executable, *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=verifier.timeout(), env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        raise A.OperationDenied("EXISTING_KEY_SIGNING_UNPROVEN") from None
    require(result.returncode == 0 and len(result.stdout) <= limit, "EXISTING_KEY_SIGNING_UNPROVEN")
    verifier.executable()
    return result.stdout


def directory(path, absent=False):
    path = AUTH.absolute(str(path))
    AUTH.ancestors(path)
    if not os.path.lexists(path):
        require(absent, "PRIVATE_DIRECTORY_REQUIRED")
        return None
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_DIRECTORY_REQUIRED")
    return AUTH.attributes(info)


def authorization_head(args, M, settings, clock):
    return A.head(M, settings["anchorBinding"], settings["mandateRoot"], settings["opensslBinding"],
                  str(AUTH.absolute(args.install_root) / "authorization"), settings["installationRef"],
                  settings["entityRef"], settings["issuerRef"], clock)


def destinations(args):
    out = AUTH.absolute(args.output_directory)
    require(directory(out, absent=True) is None, "OUTPUT_ALREADY_EXISTS")
    install = AUTH.absolute(args.install_root)
    install_identity = directory(install, absent=True)
    chain = install / "authorization"
    identity = directory(chain, absent=True) if install_identity is not None else None
    if args.supersede:
        require(identity is not None, "SUPERSEDE_REQUIRES_EXISTING_CHAIN")
    else:
        require(identity is None or not os.listdir(chain), "AUTHORIZATION_ROOT_NOT_EMPTY")
    require(not out.is_relative_to(install) and not install.is_relative_to(out), "OUTPUT_LAYOUT_COLLISION")
    return out, chain, identity, install_identity


def write_once(directory_fd, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def progress_initial():
    return {"phase": "PREFLIGHT", "doNotRerunApply": False, "privateKeysRead": 0,
            "signaturesIssued": 0, "signingAttempted": False, "writtenFiles": []}


def chain_lock(locks, chain):
    import fcntl
    fd = os.open(chain, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    locks.callback(os.close, fd)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    require(AUTH.attributes(os.fstat(fd)) == directory(chain), "AUTHORIZATION_ROOT_CHANGED")
    return fd


def publication_lock(root, previous, owner, binding):
    """Use the common flock after the CID and authorization-directory locks."""
    require(sha(owner) == binding['sha256'], "COORDINATOR_INPUT_DRIFT")
    path = C.document(owner)['commonLockFile']
    if previous and previous['authorization']['lease']['ownerConfigurationSha256'] != binding['sha256']:
        from tools.semantic_provider_operation import supersede_gate as gate
        cfg, runtime, _ = gate.installed(root, previous)
        sup = C.document(runtime.bound_bytes(cfg['leaseQuiesce']['configuration']))
        prior = sup['coordinator']
        require(prior['ownerConfiguration']['sha256'] ==
                previous['authorization']['lease']['ownerConfigurationSha256']
                and prior['commonLockPath'] == path, "COORDINATOR_LOCK_CHANGED")
    return boot.lock(path)


def execute(args, progress, clock=time.time):
    paths = destinations(args)
    _, chain, _, _ = paths
    observation = observe(args, clock)
    plan, _, reader, M, _, _, _, _, settings = observation
    if args.supersede:
        from tools.semantic_provider_operation import supersede_gate as gate
        plan["supersession"] = gate.observe(chain.parent, plan["previousHead"])
    digest = sha(canonical(plan))
    if args.plan:
        return {"status": "PLAN_READY", **plan, "planSha256": digest}
    require(args.plan_sha256 == digest, "PLAN_DIGEST_MISMATCH")
    with ExitStack() as locks:
        chain_fd = None
        if args.supersede:
            # Match runtime create and kernel migration: CID locks first, then authorization.
            locks.enter_context(gate.operation_locks(chain.parent, plan["supersession"]))
            chain_fd = chain_lock(locks, chain)
            head = authorization_head(args, M, settings, clock)
            require(head == plan["previousHead"], "OPERATION_CHAIN_CHANGED_DURING_ISSUANCE")
            require(gate.observe(chain.parent, head) == plan["supersession"], "PLAN_DIGEST_MISMATCH")
            binding = settings['coordinatorBinding']
            locks.enter_context(publication_lock(chain.parent, head, reader.bound(binding), binding))
        require(destinations(args) == paths, "OUTPUT_CUSTODY_CHANGED")
        return publish(args, progress, clock, observation, paths, digest, locks, chain_fd)


def publish(args, progress, clock, observation, paths, digest, locks, chain_fd):
    plan, composed, reader, M, ledger, _, key, key_ref, s = observation
    out, chain, identity, install_identity = paths
    # Exclusive output directory is the durable claim. Every later failure is partial.
    os.mkdir(out, 0o700)
    progress.update(phase="CLAIMED", doNotRerunApply=True)
    parent = os.open(out.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    output_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(output_fd, 0o700)
        require(directory(chain.parent, absent=True) == install_identity, "INSTALL_ROOT_CHANGED")
        if install_identity is None:
            os.mkdir(chain.parent, 0o700)
            parent = os.open(chain.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        require(directory(chain, absent=True) == identity, "AUTHORIZATION_ROOT_CHANGED")
        if identity is None:
            os.mkdir(chain, 0o700)  # exclusive, never parents=True
            parent = os.open(chain.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        if chain_fd is None:
            require(not os.listdir(chain), "AUTHORIZATION_ROOT_NOT_EMPTY")
            chain_fd = chain_lock(locks, chain)
            binding = s['coordinatorBinding']
            locks.enter_context(publication_lock(chain.parent, None, reader.bound(binding), binding))

        def chain_unchanged():
            if args.supersede:
                require(authorization_head(args, M, s, clock) == plan["previousHead"],
                        "OPERATION_CHAIN_CHANGED_DURING_ISSUANCE")
            else:
                require(not os.listdir(chain_fd), "AUTHORIZATION_ROOT_NOT_EMPTY")
        chain_unchanged()
        reader.verify()
        # A fresh verifier gives issuance its own bounded verification budget.
        verifier = M.MandateAuthenticator(s["anchorBinding"], s["mandateRoot"], s["opensslBinding"], clock)
        current = authority_now(M, ledger, key_ref, s["issuerRef"], clock)
        snapshot = ledger.snapshot()
        mandate(M, ledger, key_ref, s["issuerRef"], args.issued_at)
        require(snapshot == plan["ledger"], "SIGNING_LEDGER_CHANGED")
        # As in task-29a: the key is never copied. OpenSSL reads the original
        # custody path; its hash is checked before and after signing.
        progress["phase"] = "READ_INSTALLER_KEY"
        private = Path(key["path"])
        require(sha(AUTH.public_bytes(private, 4096)) == key["sha256"], "EXISTING_SIGNING_KEY_DRIFT")
        progress["privateKeysRead"] = 1
        raw = composed["authorization"]
        scope = {k: s[k] for k in ("issuerRef", "installationRef", "entityRef")}
        header = {"schema": A.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": key_ref,
                  "role": A.ROLE, **scope, "payloadHash": sha(raw)}
        with tempfile.TemporaryDirectory(prefix="ouf-operation-signing-", dir=out) as temp:
            os.chmod(temp, 0o700)
            frame = Path(temp) / "frame.bin"
            frame.write_bytes(A.signing_bytes(raw, header))
            frame.chmod(0o600)
            pub = native(verifier, ["pkey", "-in", str(private), "-pubout", "-outform", "DER"], 44)
            require(pub == AUTH.DER_PREFIX + bytes.fromhex(current["publicKey"]), "SIGNING_KEY_PUBLIC_MANDATE_DRIFT")
            progress.update(phase="SIGNING", signingAttempted=True, signaturesIssued=None)
            signature = native(verifier, ["pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(frame)], 64)
            progress.update(phase="SIGNATURE_RETURNED", signaturesIssued=1)
        require(sha(AUTH.public_bytes(private, 4096)) == key["sha256"], "SIGNING_KEY_CHANGED_DURING_ISSUANCE")
        require(len(signature) == 64, "EXACT_ED25519_SIGNATURE_REQUIRED")
        envelope = canonical({**header, "signature": signature.hex()})
        require(authority_now(M, ledger, key_ref, s["issuerRef"], clock) == current and ledger.snapshot() == snapshot,
                "SIGNING_MANDATE_CHANGED_OR_EXPIRED")
        A.verify_entry(M, ledger, verifier, raw, envelope, (s["installationRef"], s["entityRef"], s["issuerRef"]))
        reader.verify()
        chain_unchanged()
        require(AUTH.attributes(os.fstat(chain_fd)) == directory(chain), "AUTHORIZATION_ROOT_CHANGED")
        number = plan["payload"]["sequence"]
        write_once(chain_fd, f"{number}.json", raw)
        progress["writtenFiles"].append(f"{number}.json")
        write_once(chain_fd, f"{number}.signature.json", envelope)
        progress["writtenFiles"].append(f"{number}.signature.json")
        progress["phase"] = "READBACK"
        head = A.head(M, s["anchorBinding"], s["mandateRoot"], s["opensslBinding"], str(chain),
                      s["installationRef"], s["entityRef"], s["issuerRef"], clock)
        require((head["sequence"], head["decision"], head["sha256"]) == (number, "OPERATE", sha(raw)),
                "OPERATION_READBACK_DRIFT")
        result = {"schema": SCHEMA, "status": "SEMANTIC_PROVIDER_OPERATION_AUTHORIZATION_ISSUED",
            "planSha256": digest, "payloadSha256": sha(raw), "sequence": number, "decision": "OPERATE",
            "authorizationRoot": str(chain), "privateKeysRead": 1, "signaturesIssued": 1,
            "doNotRerunApply": True, "installationDocumentsPublished": 0, "runtimeActions": 0}
        write_once(output_fd, "result.json", canonical(result))
        progress["phase"] = "COMPLETE"
        return result
    finally:
        os.close(output_fd)


def arguments(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise A.OperationDenied("INVALID_ARGUMENTS")
    parser = Parser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--supersede", action="store_true")
    for field in ("inputs", "authority-profile"):
        parser.add_argument("--" + field, required=True)
        parser.add_argument("--" + field + "-sha256", required=True)
    for field in ("install-root", "output-directory"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--issued-at", type=int, required=True)
    parser.add_argument("--table-name", nargs="+", required=True)
    parser.add_argument("--private-key-path", action="append", required=True)
    args = parser.parse_args(argv)
    require((args.plan and args.plan_sha256 is None) or (args.apply and type(args.plan_sha256) is str
            and A.HEX64.fullmatch(args.plan_sha256)), "PLAN_SHA256_REQUIRED_ONLY_FOR_APPLY")
    return args


def public(error):
    if isinstance(error, (A.OperationDenied, AUTH.AuthorityDenied)) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", str(error)):
        return str(error)
    return "INPUT_OR_IO_UNPROVEN"


def main(argv=None):
    progress = progress_initial()
    try:
        args = arguments(argv)
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
                and sys.dont_write_bytecode, "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        result = execute(args, progress)
        print(canonical(result).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(canonical({"schema": SCHEMA, "status": "PARTIAL" if progress["doNotRerunApply"] else "HELD",
            "reason": public(error), **progress, "automaticRollback": False}).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
