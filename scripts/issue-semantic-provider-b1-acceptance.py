#!/usr/bin/env python3
"""Plan, issue and read back B1 v2 acceptance. No runtime or network actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_b1_acceptance import acceptance as B
from tools.semantic_b1b2_authority import authority as A
from tools.semantic_b1b2_authority.signer import ExistingB1B2Ed25519Signer

SCHEMA = "ouf.semantic-provider-b1-acceptance-issuance.v1"
CLOSURE = frozenset({"tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py",
                     "tools/semantic_runtime_v5/arming_verifier.py",
                     "tools/semantic_b1b2_authority/authority.py"})
A_FILES = {"manifest": "manifest.json", "result": "result.json",
           "semanticPeer": "semantic-peer.json", "successors": "successors.json"}
require = A.require


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Reader:
    def __init__(self):
        self.hashes = {}
        self.private_paths = set()

    def read(self, path, expected=None, limit=8388608):
        path = A.absolute(str(path))
        require(not any(path == key or key in path.parents for key in self.private_paths),
                "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN")
        require(expected is None or A.hashed(expected), "EXPLICIT_INPUT_HASH_REQUIRED")
        A.ancestors(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and before.st_nlink == 1 and not before.st_mode & 0o022
                    and 0 < before.st_size <= limit, "INPUT_FILE_CUSTODY_REQUIRED")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            require(len(raw) == before.st_size and A.attributes(before) == A.attributes(os.fstat(fd))
                    == A.attributes(path.lstat()), "INPUT_CHANGED_DURING_READ")
        finally:
            os.close(fd)
        digest = sha(raw)
        require(expected is None or digest == expected, "INPUT_SHA256_MISMATCH")
        require(str(path) not in self.hashes or self.hashes[str(path)] == digest, "INPUT_CHANGED_DURING_PLAN")
        self.hashes[str(path)] = digest
        return raw

    def document(self, path, expected=None):
        return A.decode(self.read(path, expected), 8388608)

    def bound(self, binding):
        item = A.binding(binding)
        return self.read(item["path"], item["sha256"])

    def verify(self):
        for path, digest in list(self.hashes.items()):
            self.read(path, digest, 64000000)


def cli_binding(args, field):
    return A.binding({"path": getattr(args, field), "sha256": getattr(args, field + "_sha256")})


def receipt_a(reader, args, profile):
    root = A.absolute(args.a2_root)
    result = reader.document(root / "result.json")
    manifest = reader.document(root / "manifest.json")
    require(result["status"] == "SEMANTIC_PROVIDER_PREPARATION_A_STAGED"
            and result["planSha256"] == manifest["planSha256"] == args.a2_plan_sha256
            and result["manifest"] == manifest["manifest"] and result["replayAllowed"] is False,
            "PREPARATION_A_RECEIPT_UNPROVEN")
    body = result["manifest"]
    require(body["directory"]["path"] == str(root)
            and body["schema"] == "ouf.semantic-provider-preparation-a.manifest.v1", "PREPARATION_A_SCOPE_CHANGED")
    pins = {row["path"]: row.get("sha256") for row in body["filesCreated"]}
    for field in ("semanticPeer", "successors"):
        path = str(root / A_FILES[field])
        require(A.hashed(pins[path]), "PREPARATION_A_PIN_UNPROVEN")
        require(reader.document(path, pins[path]) == body[field], "PREPARATION_A_ARTIFACT_CHANGED")
    successors = body["successors"]
    require(reader.hashes[str(root / "successors.json")] == args.a2_successors_sha256,
            "A2_SUCCESSORS_HASH_MISMATCH")
    # A2 retains names, not endpoint aliases. Match those names to the role
    # profiles in P; P's southbound role is the one carrying the certificate SNI.
    sni = successors["southboundCertificate"]["sni"]
    require(successors["southboundCertificate"]["configuredDerMatches"] is True
            and sni in {alias for ep in profile["roles"]["southbound"]["networks"].values()
                           for alias in ep["aliases"]}
            and sni not in {alias for ep in profile["roles"]["adapter"]["networks"].values()
                               for alias in ep["aliases"]}, "SUCCESSOR_ROLE_UNPROVEN")
    require(len(successors["containers"]) == 2, "EXACT_A2_SUCCESSORS_REQUIRED")
    roles = {}
    for role in B.ROLES:
        matches = [row for row in successors["containers"]
                   if row["name"].removeprefix("/") == profile["roles"][role]["containerName"]]
        require(len(matches) == 1, "SUCCESSOR_ROLE_UNPROVEN")
        row = matches[0]
        require(A.hashed(row["containerId"]) and row["status"] == "created"
                and row["transaction"] == getattr(args, role + "_transaction"), "A2_TRANSACTION_MISMATCH")
        roles[role] = row
    require(roles["adapter"]["containerId"] != roles["southbound"]["containerId"]
            and successors["transactions"] == {r["containerId"]: r["transaction"] for r in roles.values()},
            "A2_TRANSACTIONS_MISMATCH")
    preparation = {"root": str(root), "planSha256": args.a2_plan_sha256,
                   "files": {field: {"path": str(root / name), "sha256": reader.hashes[str(root / name)]}
                             for field, name in A_FILES.items()}}
    return preparation, roles


def output(args):
    root = A.absolute(args.output_root)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.output_name) is not None,
            "RESTRICTED_OUTPUT_NAME_REQUIRED")
    A.ancestors(root / "placeholder")
    entry = A.directory(root)
    require(entry.st_gid == 0, "OUTPUT_ROOT_CUSTODY_REQUIRED")
    require(not os.path.lexists(root / args.output_name), "OUTPUT_ALREADY_EXISTS")
    return root, A.attributes(entry)


def check_openssl(verifier):
    # PIPE is memory only: planning must not spool even public bytes to disk.
    executable = verifier.executable()
    try:
        result = subprocess.run([executable, "version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=verifier.timeout(),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
    except (OSError, subprocess.TimeoutExpired):
        raise A.AuthorityDenied("DETACHED_OPENSSL_VERSION_UNPROVEN") from None
    match = re.match(rb"OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b", result.stdout)
    require(result.returncode == 0 and len(result.stdout) <= 256 and match is not None
            and match[1].decode() == verifier.openssl_binding["version"], "DETACHED_OPENSSL_VERSION_UNPROVEN")
    verifier.executable()


def observe(args):
    require(type(args.issued_at) is int and 0 <= args.issued_at <= time.time() + 300,
            "ISSUED_AT_FUTURE_OR_INVALID")
    require(type(args.generation) is int and args.generation >= 1, "ACCEPTANCE_GENERATION_REQUIRED")
    reader = Reader()
    profile_binding = cli_binding(args, "installation_profile")
    trust_binding = cli_binding(args, "trust_policy")
    authority_binding = cli_binding(args, "authority_profile")
    profile = reader.document(**dict(path=profile_binding["path"], expected=profile_binding["sha256"]))
    require(profile["paths"]["authorityProfile"] == args.authority_profile, "PROFILE_AUTHORITY_PATH_MISMATCH")
    authority = reader.document(args.authority_profile, args.authority_profile_sha256)
    # Prevent even a referenced evidence/recipe from opening a declared key.
    reader.private_paths = {A.absolute(A.binding(b)["path"]) for b in authority["keyBindings"].values()}
    require(not reader.private_paths.intersection(A.absolute(p) for p in reader.hashes),
            "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN")
    policy_raw = reader.read(args.trust_policy, args.trust_policy_sha256)
    scope = A.decode(policy_raw)
    configured = A.policy(policy_raw, profile["installationRef"], scope["entityRef"])
    require(profile["entityRef"] == configured["entityRef"]
            and configured["authorityProfile"] == authority_binding
            and authority["schema"] == "ouf.semantic-existing-installation-authority-bindings.v1",
            "AUTHORITY_PROFILE_BINDING_MISMATCH")
    auth = authority["authorities"]
    require((auth["installationRef"], auth["entityRef"]) == (configured["installationRef"], configured["entityRef"]),
            "AUTHORITY_SCOPE_MISMATCH")
    mandates = [k for k in configured["keys"] if "ARTIFACT_ACCEPTANCE" in k["roles"]
                and k["state"] == "ACTIVE" and k["notBefore"] <= args.issued_at < k["expiresAt"]]
    require(len(mandates) == 1, "EXACT_ACCEPTANCE_MANDATE_REQUIRED")
    mandate = mandates[0]
    require(mandate["keyRef"] == authority["keyRefs"]["installer"]
            and mandate["issuerRef"] == auth["intentIssuerRef"] == auth["approvalIssuerRef"],
            "INSTALLER_MANDATE_MISMATCH")
    key_binding = A.binding(authority["keyBindings"]["installer"])  # Never stat/open in plan.
    require(configured["basePolicy"] == A.binding(authority["policyBinding"]), "BASE_POLICY_BINDING_MISMATCH")
    preparation, a_roles = receipt_a(reader, args, profile)
    recreation_binding = cli_binding(args, "recreation_receipt")
    recreation = reader.document(args.recreation_receipt, args.recreation_receipt_sha256)
    require(recreation["schema"] == "ouf.semantic-southbound-successor-recreation.v1"
            and recreation["status"] == "SOUTHBOUND_RECREATED_STOPPED"
            and recreation["newCid"] == a_roles["southbound"]["containerId"]
            and recreation["newTransaction"] == args.southbound_transaction, "RECREATION_RECEIPT_MISMATCH")
    rootfs = reader.document(args.rootfs_result, args.rootfs_result_sha256)
    require(rootfs["schema"] == "ouf.semantic-provider-b1-rootfs-evidence.v1"
            and rootfs["status"] == "SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED"
            and rootfs["aSuccessors"] == preparation["files"]["successors"], "ROOTFS_RESULT_MISMATCH")
    recipes = reader.document(args.recipes_result, args.recipes_result_sha256)
    require(recipes["schema"] == "ouf.semantic-provider-b1-recipes.v1"
            and recipes["status"] == "SEMANTIC_PROVIDER_B1_RECIPES_PREPARED"
            and recipes["preparationA"] == preparation and recipes["recreation"] == recreation_binding,
            "RECIPES_RESULT_MISMATCH")
    roles, expected_roles = {}, {}
    require(set(rootfs["roles"]) == set(recipes["roles"]) == set(B.ROLES), "EXACT_EVIDENCE_ROLES_REQUIRED")
    for role in B.ROLES:
        rf, recipe, a = rootfs["roles"][role], recipes["roles"][role], a_roles[role]
        require(rf["containerId"] == recipe["containerId"] == a["containerId"]
                and rf["imageId"] == a["image"] and recipe["transaction"] == a["transaction"],
                "EVIDENCE_ROLE_MISMATCH")
        for field in ("offlineImageReceipt", "offlineDockerReceipt", "comparison"):
            reader.bound(rf[field])
        require(set(recipe["recipe"]) == set(B.RECIPE_PARTS), "EXACT_RECIPES_REQUIRED")
        for item in recipe["recipe"].values():
            reader.bound(item)
        expected_roles[role] = {"containerId": a["containerId"], "imageId": a["image"]}
        roles[role] = {**expected_roles[role], "recipe": recipe["recipe"],
                       "rootfs": {f: rf[f] for f in ("offlineImageReceipt", "offlineDockerReceipt", "comparison", "effectiveSeal")}}
    closure = {}
    for row in args.closure_file:
        name, sep, digest = row.partition("=")
        require(sep and name not in closure and A.hashed(digest), "ACCEPTANCE_CLOSURE_SET_UNEXPECTED")
        closure[name] = digest
    require(set(closure) == CLOSURE, "ACCEPTANCE_CLOSURE_SET_UNEXPECTED")
    for name, digest in closure.items():
        reader.read(ROOT / name, digest)
    openssl = {**cli_binding(args, "openssl"), "version": args.openssl_version}
    verifier = A.B1B2Authenticator(trust_binding, openssl)
    check_openssl(verifier)
    reader.read(args.openssl, args.openssl_sha256, 64000000)
    raw = B.build_acceptance(schema=B.SCHEMA, installationRef=configured["installationRef"],
        entityRef=configured["entityRef"], generation=args.generation, profile=profile_binding,
        preparationA=preparation, creation={"evidence": "PREPARATION_A2",
            "roles": {r: {"transactionRef": getattr(args, r + "_transaction")} for r in B.ROLES},
            "recreation": recreation_binding, "declaredGaps": args.declared_gap}, roles=roles,
        softwareClosure={"sourceCommit": args.closure_source_commit, "files": closure}, trustPolicy=trust_binding,
        startAuthorized=False, leaseAuthorized=False, issuedAt=args.issued_at)
    B.validate_acceptance(B.decode_manifest(raw))
    expected = {"installationRef": configured["installationRef"], "entityRef": configured["entityRef"],
        "issuerRef": mandate["issuerRef"], "profileSha256": args.installation_profile_sha256,
        "preparationA": {"planSha256": args.a2_plan_sha256,
                         "files": {k: v["sha256"] for k, v in preparation["files"].items()}},
        "transactions": {r: getattr(args, r + "_transaction") for r in B.ROLES},
        "recreation": recreation_binding, "roles": expected_roles, "trustPolicy": trust_binding,
        "minimumGeneration": args.generation}
    B.validate_expected(expected)
    reader.verify()
    plan = {"schema": SCHEMA, "manifestRaw": raw.decode("ascii"), "payloadSha256": sha(raw),
        "signaturePath": str(Path(args.output_root) / args.output_name / (sha(raw) + ".ARTIFACT_ACCEPTANCE.json")),
        "manifestPath": str(Path(args.output_root) / args.output_name / "manifest.json"),
        "mandate": {k: mandate[k] for k in ("keyRef", "issuerRef", "notBefore", "expiresAt")},
        "inputHashes": dict(reader.hashes), "openssl": openssl, "privateKeysRead": 0}
    return plan, raw, expected, mandate, key_binding, reader


def write_once(directory, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def execute(args, progress):
    root, root_identity = output(args)
    plan, raw, expected, mandate, key, reader = observe(args)
    digest = sha(A.canonical(plan))
    if args.plan:
        return {"status": "PLAN_READY", **plan, "planSha256": digest}
    require(args.plan_sha256 == digest, "PLAN_DIGEST_MISMATCH")
    progress["payloadSha256"] = sha(raw)
    require(output(args) == (root, root_identity), "OUTPUT_ROOT_CHANGED")
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = None
    try:
        require(A.attributes(os.fstat(parent)) == root_identity, "OUTPUT_ROOT_CHANGED")
        # mkdir is the atomic exclusive directory primitive; O_EXCL is for files.
        os.mkdir(args.output_name, 0o700, dir_fd=parent)
        progress.update(outputCreated=True, phase="OUTPUT_CREATED")
        os.fsync(parent)
        directory = os.open(args.output_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fchmod(directory, 0o700)
        reader.verify()
        verifier = A.B1B2Authenticator(expected["trustPolicy"], plan["openssl"])
        signer = ExistingB1B2Ed25519Signer(key, mandate, verifier,
            {f: expected[f] for f in ("issuerRef", "installationRef", "entityRef")}, progress)
        signature = signer.sign(raw)
        progress["phase"] = "VERIFY_ACCEPTANCE"
        B.verify_acceptance(raw, signature, expected=expected, authenticator=verifier)
        reader.verify()
        progress["phase"] = "WRITE_MANIFEST"
        write_once(directory, "manifest.json", raw)
        progress["writtenFiles"].append("manifest.json")
        filename = sha(raw) + ".ARTIFACT_ACCEPTANCE.json"
        progress["phase"] = "WRITE_SIGNATURE"
        write_once(directory, filename, signature)
        progress["writtenFiles"].append(filename)
        destination = root / args.output_name
        progress["phase"] = "READBACK_VERIFY"
        readback = Reader()
        manifest_raw = readback.read(destination / "manifest.json", sha(raw))
        signature_raw = readback.read(destination / filename, sha(signature))
        B.verify_acceptance(manifest_raw, signature_raw, expected=expected,
            authenticator=A.B1B2Authenticator(expected["trustPolicy"], plan["openssl"]))
        result = {"schema": SCHEMA, "status": "SEMANTIC_PROVIDER_B1_ACCEPTANCE_ISSUED", "planSha256": digest,
            "payloadSha256": sha(raw), "manifest": {"path": str(destination / "manifest.json"), "sha256": sha(raw)},
            "signature": {"path": str(destination / filename), "sha256": sha(signature)},
            "privateKeysRead": 1, "signaturesIssued": 1, "startAuthorized": False, "leaseAuthorized": False}
        progress["phase"] = "WRITE_RESULT"
        result_raw = A.canonical(result) + b"\n"
        write_once(directory, "result.json", result_raw)
        progress["writtenFiles"].append("result.json")
        readback.read(destination / "result.json", sha(result_raw))
        progress["phase"] = "COMPLETE"
        return result
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for field in ("installation-profile", "trust-policy", "authority-profile", "recreation-receipt",
                  "rootfs-result", "recipes-result", "openssl"):
        parser.add_argument("--" + field, required=True)
        parser.add_argument("--" + field + "-sha256", required=True)
    for field in ("a2-root", "a2-plan-sha256", "a2-successors-sha256", "adapter-transaction",
                  "southbound-transaction", "closure-source-commit", "openssl-version", "output-root", "output-name"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--issued-at", type=int, required=True)
    parser.add_argument("--closure-file", action="append", required=True)
    parser.add_argument("--declared-gap", action="append", default=[])
    args = parser.parse_args(argv)
    if args.apply and not A.hashed(args.plan_sha256) or args.plan and args.plan_sha256 is not None:
        parser.error("--plan-sha256 required only with --apply")
    return args


def retained_output(args, progress):
    if not progress["outputCreated"]:
        return {"observed": True, "files": []}
    try:
        root = A.absolute(args.output_root) / args.output_name
        A.ancestors(root / "placeholder")
        names = ("manifest.json", progress["payloadSha256"] + ".ARTIFACT_ACCEPTANCE.json", "result.json")
        files = []
        for name in names:
            try:
                entry = (root / name).lstat()
            except FileNotFoundError:
                continue
            files.append({"name": name, "regular": stat.S_ISREG(entry.st_mode), "bytes": entry.st_size})
        return {"observed": True, "files": files}
    except OSError:
        return {"observed": False}
    except A.AuthorityDenied:
        return {"observed": False}


def main(argv=None):
    args = arguments(argv)
    progress = {"phase": "PREFLIGHT", "outputCreated": False, "privateKeysRead": 0,
                "signaturesIssued": 0, "signingAttempted": False, "writtenFiles": []}
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                "ISOLATED_ROOT_REQUIRED")
        os.umask(0o077)
        result = execute(args, progress)
        print(A.canonical(result).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, (A.AuthorityDenied, B.AcceptanceDenied)) else "INPUT_OR_IO_UNPROVEN"
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason) is None:
            reason = "INPUT_OR_IO_UNPROVEN"
        print(A.canonical({"schema": SCHEMA, "status": "PARTIAL" if progress["outputCreated"] else "HELD",
            "reason": reason, **progress, "outputDirectory": str(Path(args.output_root) / args.output_name),
            "retainedOutput": retained_output(args, progress),
            "automaticRollback": False, "startAuthorized": False, "leaseAuthorized": False}).decode(), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
