"""Read the installed R3 closure and prove its epoch history safe to supersede."""
from contextlib import contextmanager, ExitStack
from pathlib import Path

from tools.semantic_provider_r3 import install_common as I

A, C = I.A, I.C
require, sha = A.require, A.sha
WRAPPER = Path("/usr/local/sbin/ouf-semantic-admitted-v2")
CONFIGURATION = "ISSUE_SUPERSEDE_INSTALLED_CONFIGURATION_UNPROVEN"
BINDING = "ISSUE_SUPERSEDE_EPOCH_BINDING_UNPROVEN"
NOT_STOPPED = "ISSUE_SUPERSEDE_PROVIDER_NOT_STOPPED"
CLEANUP = "ISSUE_SUPERSEDE_PREPARED_CLEANUP_PENDING"
LOCK = "ISSUE_SUPERSEDE_OPERATION_LOCK_UNPROVEN"


def exclude_keys(root, private_paths):
    require(all(root != key and root not in key.parents and key not in root.parents
                and WRAPPER != key and key not in WRAPPER.parents for key in private_paths),
            "PRIVATE_KEY_AS_PUBLIC_INPUT_FORBIDDEN")


def installed(root, head):
    """Select the active wrapper's configuration and authenticate it before loading code."""
    try:
        custody = I.native_switch().custody
        wrapper, _ = custody(WRAPPER, 0o755)
        code_root = I.wrapper_code_root(root, wrapper)
        expected = root if head["sequence"] == 1 else root / "versions" / str(head["sequence"])
        require(code_root == expected, CONFIGURATION)
        I.V.private_directory(code_root)
        payload = head["authorization"]
        path = code_root / "runtime-configuration.json"
        raw, _ = custody(path, 0o600)
        require(sha(raw) == payload["runtimeConfigurationSha256"], CONFIGURATION)
        cfg = C.document(raw)
        source_root = code_root / "source"
        runtime_path = source_root / C.RUNTIME
        runtime = I.compiled(custody(runtime_path, 0o600)[0], runtime_path,
                             "r3_issuer_installed_runtime", cfg["sourceHash"])
        require(runtime.load_configuration(path) == (cfg, raw)
                and wrapper == I.wrapper_bytes(cfg["pythonPath"], code_root)
                and cfg["registryRoot"] == str(root / "registry")
                and cfg["operation"]["authorizationRoot"] == str(root / "authorization")
                and all(cfg["operation"][key] == payload[key] for key in
                        ("installationRef", "entityRef", "issuerRef")), CONFIGURATION)
        for cid, candidate in cfg["candidates"].items():
            role = payload["roles"][candidate["role"]]
            require(role["containerId"] == cid and role["admissionConfigurationSha256"]
                    == cfg["admissionConfigurations"][cid]["sha256"], CONFIGURATION)
        for field, name in (("authorizationModule", "authorization"), ("epochsModule", "epochs")):
            require(cfg[field]["path"] == str(source_root / f"tools/semantic_provider_operation/{name}.py"),
                    CONFIGURATION)
        _, epochs = runtime.operation_modules(cfg)
    except Exception:
        raise A.OperationDenied(CONFIGURATION) from None

    def read_epoch(path, limit=65536):
        # Match the epoch reader's bound while using the runtime's nonblocking custody checks.
        raw = runtime.read(path)
        require(len(raw) <= limit, BINDING)
        return raw

    epochs.file_bytes = read_epoch
    return cfg, runtime, epochs


def chain_bindings(chain, head):
    """Follow the authenticated head's hash links through the retained public payloads."""
    digest = head["sha256"]
    bindings = {}
    try:
        for sequence in range(head["sequence"], 0, -1):
            raw = A.private_file(chain / f"{sequence}.json")
            payload = A.validate(raw)
            require(sha(raw) == digest and payload["sequence"] == sequence, BINDING)
            bindings[digest] = payload
            digest = payload["supersedes"]
        require(digest is None, BINDING)
    except Exception:
        raise A.OperationDenied(BINDING) from None
    return bindings


def observe(root, head):
    require(head["decision"] == "OPERATE", "SUPERSEDE_REQUIRES_OPERATE_HEAD")
    cfg, runtime, epochs = installed(root, head)
    registry = Path(cfg["registryRoot"])
    bindings = chain_bindings(root / "authorization", head)
    candidates = {}
    for cid, candidate in sorted(cfg["candidates"].items()):
        base = registry / cid
        try:
            runtime.private_directory(base)
            require(runtime.read(base / "operation.lock") == b"", BINDING)
            current = epochs.current(registry, cid)
            rows = runtime.epoch_inventory(base, epochs, current)
            require(not rows or max(rows, key=lambda row: row["epoch"]) == current, BINDING)
        except Exception:
            raise A.OperationDenied(BINDING) from None
        history = {}
        for row in rows:
            require(type(row["epoch"]) is int, BINDING)
            require(row["state"] in epochs.TERMINAL, NOT_STOPPED)
            authorization = bindings.get(row["authorizationSha256"])
            require(authorization is not None and authorization["decision"] == "OPERATE"
                    and authorization["runtimeConfigurationSha256"] == row["configurationHash"]
                    and authorization["roles"][candidate["role"]]["containerId"] == cid, BINDING)
            receipt = None
            number = str(row["epoch"])
            if row["state"] == "FAILED" and row["driverHash"] is not None:
                try:
                    receipt = runtime.cleanup_receipt(base / "epochs" / number, row, None)
                except Exception:
                    raise A.OperationDenied(CLEANUP) from None
                require(receipt is not None, CLEANUP)
            history[number] = {"journalSha256": sha(A.canonical(row)), "cleanupReceipt": receipt}
        candidates[cid] = history
    return candidates


@contextmanager
def operation_locks(root, cids):
    with ExitStack() as stack:
        try:
            stack.enter_context(I.operation_locks(root, cids))
        except Exception:
            raise A.OperationDenied(LOCK) from None
        yield
