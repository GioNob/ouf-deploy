#!/usr/bin/env python3
"""Plan/apply a separate B1/B2 public policy from an existing installer grant."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import types


# -I deliberately ignores ambient PYTHONPATH. The launcher preloads this exact
# module from hash-checked bytes; direct checkout execution uses the explicit file.
MODULE_NAME = "_ouf_semantic_b1b2_authority"
if MODULE_NAME not in sys.modules:
    source = Path(__file__).resolve().parents[1] / "tools/semantic_b1b2_authority/authority.py"
    module = types.ModuleType(MODULE_NAME)
    module.__file__ = str(source)
    exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
    sys.modules[MODULE_NAME] = module
A = sys.modules[MODULE_NAME]


class Held(RuntimeError):
    def __init__(self, reason, **details):
        super().__init__(reason)
        self.details = details


def require(value, reason, **details):
    if not value:
        raise Held(reason, **details)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Reader:
    """Only the two explicit public input documents enter this reader."""

    def __init__(self):
        self.inputs = {}

    def read(self, name, expected):
        path = A.absolute(name)
        before = A.attributes(path.lstat())
        raw = A.public_bytes(path, 2097152)
        require(digest(raw) == expected, "BOUND_INPUT_HASH_CHANGED")
        observed = (before, expected)
        require(before == A.attributes(path.lstat()) and
                (name not in self.inputs or self.inputs[name] == observed), "INPUT_CHANGED_DURING_READ")
        self.inputs[name] = observed
        return raw

    def verify(self):
        for path, (_, expected) in tuple(self.inputs.items()):
            self.read(path, expected)
        return {path: value[1] for path, value in self.inputs.items()}


def installer_from_profile(raw, args, base_binding, base):
    value = A.decode(raw, 2097152)
    require(set(value) == {"schema", "sourceCommit", "sourceRoot", "sourceHashes", "authorities", "keyRefs",
                           "keyBindings", "policyBinding", "custodyReceiptBinding"}
            and value["schema"] == "ouf.semantic-existing-installation-authority-bindings.v1",
            "EXACT_EXISTING_AUTHORITY_PROFILE_REQUIRED")
    require(type(value["sourceCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["sourceCommit"])
            and type(value["sourceHashes"]) is dict and bool(value["sourceHashes"])
            and all(type(name) is str and A.hashed(pin) for name, pin in value["sourceHashes"].items()),
            "AUTHORITY_SOURCE_BINDINGS_UNPROVEN")
    A.absolute(value["sourceRoot"])
    A.binding(value["custodyReceiptBinding"])
    require(A.binding(value["policyBinding"]) == base_binding, "AUTHORITY_BASE_POLICY_BINDING_DIFFERS")
    refs = value["keyRefs"]
    require(type(refs) is dict and set(refs) == {"installer", "attestor"}
            and all(A.identity(ref) for ref in refs.values()) and refs["installer"] != refs["attestor"],
            "AUTHORITY_KEY_REFS_UNPROVEN")
    bindings = value["keyBindings"]
    require(type(bindings) is dict and set(bindings) == {"installer", "attestor"}, "AUTHORITY_KEY_BINDINGS_UNPROVEN")
    # Syntax only. In particular, no stat/open/resolve of either private-key path.
    for item in bindings.values():
        A.binding(item)
    require(bindings["installer"]["path"] != bindings["attestor"]["path"], "AUTHORITY_KEY_BINDINGS_UNPROVEN")
    authorities = value["authorities"]
    require(type(authorities) is dict and set(authorities) == {"installationRef", "entityRef", "intentIssuerRef",
                                                            "approvalIssuerRef", "attestorRef"}
            and all(A.identity(ref) for ref in authorities.values())
            and (authorities["installationRef"], authorities["entityRef"]) == (args.installation_ref, args.entity_ref),
            "AUTHORITY_SCOPE_DIFFERS")
    keys = [key for key in base["keys"] if key["keyRef"] == refs["installer"]]
    require(len(keys) == 1, "INSTALLER_KEY_NOT_FOUND")
    key = keys[0]
    require(set(key["roles"]) == {"DEPLOYMENT_INTENT", "FINAL_DEPLOYMENT_APPROVAL"} and key["state"] == "ACTIVE"
            and key["issuerRef"] == authorities["intentIssuerRef"] == authorities["approvalIssuerRef"],
            "INSTALLER_GRANT_NONCONFORMING")
    return key


def output(args):
    root = A.absolute(args.output_root)
    require(type(args.output_name) is str and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.output_name), "RESTRICTED_OUTPUT_NAME_REQUIRED")
    A.ancestors(root / "placeholder")
    info = A.directory(root)
    require(info.st_gid == 0, "OUTPUT_ROOT_CUSTODY_REQUIRED")
    destination = root / args.output_name
    require(not os.path.lexists(destination), "OUTPUT_ALREADY_EXISTS")
    return root, destination, A.attributes(info)


def observe(args):
    require(A.identity(args.installation_ref) and A.identity(args.entity_ref), "EXPLICIT_SCOPE_REQUIRED")
    base_binding = A.binding({"path": args.base_policy, "sha256": args.base_policy_sha256})
    authority_binding = A.binding({"path": args.authority_profile, "sha256": args.authority_sha256})
    require(args.base_policy != args.authority_profile, "DISTINCT_PUBLIC_INPUTS_REQUIRED")
    reader = Reader()
    base = A.base_policy(reader.read(args.base_policy, args.base_policy_sha256), args.installation_ref, args.entity_ref)
    key = installer_from_profile(reader.read(args.authority_profile, args.authority_sha256), args, base_binding, base)
    require(type(args.not_before) is int and type(args.expires_at) is int
            and key["notBefore"] <= args.not_before < args.expires_at <= key["expiresAt"],
            "B1B2_WINDOW_OUTSIDE_BASE", baseNotBefore=key["notBefore"], baseExpiresAt=key["expiresAt"],
            requestedNotBefore=args.not_before, requestedExpiresAt=args.expires_at)
    root, destination, root_identity = output(args)
    policy = {"schema": A.POLICY_SCHEMA, "installationRef": args.installation_ref, "entityRef": args.entity_ref,
              "basePolicy": base_binding, "authorityProfile": authority_binding,
              "keys": [{name: key[name] for name in ("keyRef", "issuerRef", "publicKey")} |
                       {"roles": ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"], "state": "ACTIVE",
                        "notBefore": args.not_before, "expiresAt": args.expires_at}]}
    raw = A.canonical(policy) + b"\n"
    A.policy(raw, args.installation_ref, args.entity_ref)
    projection = {"schema": "ouf.semantic-provider-b1b2-trust-policy.plan.v1", "policy": policy,
                  "policySha256": digest(raw), "inputHashes": reader.verify(),
                  "outputRootIdentity": list(root_identity), "privateKeysRead": 0,
                  "writes": {"directory": str(destination), "directoryMode": "0700", "owner": "root:root",
                             "policyFile": str(destination / "trust-policy.json"), "fileMode": "0600"}}
    require(output(args) == (root, destination, root_identity), "OUTPUT_ROOT_CHANGED_DURING_PLAN")
    return projection | {"planSha256": digest(A.canonical(projection))}


def publish(proposal, outcome):
    destination = Path(proposal["writes"]["directory"])
    root = destination.parent
    A.ancestors(root / "placeholder")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child_fd = None
    try:
        require(list(A.attributes(os.fstat(root_fd))) == proposal["outputRootIdentity"]
                and A.attributes(os.fstat(root_fd)) == A.attributes(root.lstat()), "OUTPUT_ROOT_CHANGED_BEFORE_WRITE")
        os.mkdir(destination.name, mode=0o700, dir_fd=root_fd)  # exclusive; never exist_ok
        outcome["directoryCreated"] = True
        os.fsync(root_fd)
        child_fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        os.fchown(child_fd, 0, 0)
        os.fchmod(child_fd, 0o700)
        child_identity = A.attributes(os.fstat(child_fd))[:2]
        temporary = ".trust-policy-" + secrets.token_hex(16)
        outcome["temporaryFile"] = str(destination / temporary)
        raw = A.canonical(proposal["policy"]) + b"\n"
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=child_fd), "wb") as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, "trust-policy.json", src_dir_fd=child_fd, dst_dir_fd=child_fd, follow_symlinks=False)
        outcome["policyLinked"] = True
        os.fsync(child_fd)
        os.unlink(temporary, dir_fd=child_fd)  # successful publication's extra link only
        outcome["temporaryFile"] = None
        os.fsync(child_fd)
        require(A.attributes(destination.lstat())[:2] == child_identity
                and stat.S_IMODE(destination.lstat().st_mode) == 0o700
                and A.attributes(root.lstat())[:2] == A.attributes(os.fstat(root_fd))[:2], "OUTPUT_DIRECTORY_CHANGED")
        reader = Reader()
        require(reader.read(proposal["writes"]["policyFile"], proposal["policySha256"]) == raw,
                "POLICY_READBACK_UNPROVEN")
        A.policy(raw, proposal["policy"]["installationRef"], proposal["policy"]["entityRef"])
        for path, expected in proposal["inputHashes"].items():
            reader.read(path, expected)
        reader.verify()
        outcome["readbackVerified"] = True
    finally:
        # Failures retain the directory and any partial file; no automatic rollback.
        if child_fd is not None:
            os.close(child_fd)
        os.close(root_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("base-policy", "base-policy-sha256", "authority-profile", "authority-sha256", "installation-ref",
                 "entity-ref", "output-root", "output-name"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--not-before", required=True, type=int)
    parser.add_argument("--expires-at", required=True, type=int)
    args = parser.parse_args(argv)
    report = {"schema": "ouf.semantic-provider-b1b2-trust-policy.plan.v1", "status": "HELD", "privateKeysRead": 0}
    try:
        require(hasattr(os, "geteuid") and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        os.umask(0o077)
        require(A.hashed(args.base_policy_sha256) and A.hashed(args.authority_sha256)
                and ((args.apply and A.hashed(args.plan_sha256)) or (args.plan and args.plan_sha256 is None)),
                "EXACT_INPUT_AND_PLAN_HASHES_REQUIRED")
        proposal = observe(args)
        report.update(proposal)
        if args.plan:
            report["status"] = "PLAN_READY"
        else:
            require(args.plan_sha256 == proposal["planSha256"], "PLAN_DIGEST_CHANGED")
            report["publication"] = {"directoryCreated": False, "policyLinked": False, "readbackVerified": False}
            publish(proposal, report["publication"])
            report["status"] = "SEMANTIC_PROVIDER_B1B2_TRUST_POLICY_PREPARED"
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError) as error:
        reason = str(error) if isinstance(error, (Held, A.AuthorityDenied)) else type(error).__name__
        report.update(status="HELD", reason=reason)
        if isinstance(error, Held):
            report.update(error.details)
    print(A.canonical(report).decode("ascii"), flush=True)
    return 1 if report["status"] == "HELD" else 0


if __name__ == "__main__":
    raise SystemExit(main())
