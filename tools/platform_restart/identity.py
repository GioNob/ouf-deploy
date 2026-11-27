"""Read-only interpretation of the privileged executor's two release journals."""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess

if __package__ == "platform_restart":  # Installed archive or staged operator entry point.
    from module_release.frame import provenance_labels, request, snapshot
else:
    from ..module_release.frame import provenance_labels, request, snapshot
from .profile import HEX, Held, canonical, custody, require, sha, unique, validate_command

RUN = re.compile(r"[1-9][0-9]{0,19}")
SPKI = bytes.fromhex("302a300506032b6570032100")


def digest(value):
    return sha(canonical(value))


def read(path):
    custody(path)
    with path.open("rb") as stream:
        raw = stream.read((8 << 20) + 1)
    require(len(raw) <= 8 << 20, "RELEASE_JOURNAL_INVALID")
    return json.loads(raw, object_pairs_hook=unique)


class OpenTransaction(Held):
    def __init__(self, residue):
        super().__init__("RELEASE_TRANSACTION_OPEN")
        self.residue = residue


@contextmanager
def release_locks(identities):
    """Hold the same installation and dispatch locks as scripts/ouf-a2-executor."""
    with ExitStack() as stack:
        for root in sorted({Path(i["executorRoot"]) for i in identities}):
            import fcntl
            custody(root.parent, stat.S_ISDIR)
            fd = os.open(root.parent, os.O_DIRECTORY)
            stack.callback(os.close, fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                custody(root / "lock")
                lock = stack.enter_context((root / "lock").open("rb"))
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OpenTransaction("executor-lock") from None
        yield


def read_head(path):
    head = read(path)
    if head.get("status") == "PENDING" or head.get("state") == "PENDING":
        raise OpenTransaction(path.name)
    return head


def verify_signature(binding, receipt, returning, context):
    signature = receipt.with_suffix(".ed25519")
    present = os.path.lexists(signature)
    field = "returnSignature" if returning else "readySignature"
    context[field] = "unverified" if present else "absent"
    if not present:
        require((returning and receipt.name == "return-receipt.json") or not binding,
                "MODULE_RECEIPT_SIGNATURE_REQUIRED")
        return
    require(binding, "MODULE_RECEIPT_SIGNER_REQUIRED")
    public, openssl = (Path(binding[key]["path"]) for key in ("publicKey", "openssl"))
    for key, path in (("publicKey", public), ("openssl", openssl)):
        custody(path)
        require(sha(path.read_bytes()) == binding[key]["sha256"], "SIGNATURE_BINDING_CHANGED")
    der = public.read_bytes()
    require(len(der) == len(SPKI) + 32 and der.startswith(SPKI), "MODULE_RECEIPT_PUBLIC_KEY")
    custody(signature)
    custody(receipt)
    require(signature.stat().st_size == 64, "MODULE_RECEIPT_SIGNATURE_INVALID")
    result = subprocess.run([str(openssl), "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                             "-inkey", str(public), "-in", str(receipt), "-sigfile", str(signature)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=10, env={"OPENSSL_CONF": os.devnull})
    require(result.returncode == 0, "MODULE_RECEIPT_SIGNATURE_INVALID")
    context[field] = "verified"


def module_history(state, journal, module):
    """Identify effectful dispatches, including a rollback with no published READY pointer."""
    if os.path.lexists(journal / (module + ".lock")):
        raise OpenTransaction("module-lock")
    transactions = {}
    restored = set()
    before_ready = set()
    for directory in journal.iterdir():
        if not HEX.fullmatch(directory.name):
            continue
        if not (directory / "plan.json").is_file():
            raise OpenTransaction("unpublished-plan")
        plan = read(directory / "plan.json")
        if plan["module"] != module:
            continue
        returned = os.path.lexists(directory / "return-intent.json")
        if not returned and os.path.lexists(directory / "return-receipt.json"):
            raise Held("MODULE_RETURN_DRIFT")
        terminal = directory / ("return-receipt.json" if returned else "receipt.json")
        if not terminal.is_file():
            raise OpenTransaction(terminal.name)
        receipt = read(terminal)
        compensated = not returned and receipt.get("status") == "HELD" and receipt.get("rollback") == "ROLLED_BACK"
        if not compensated and receipt.get("status") != ("ROLLED_BACK" if returned else "READY"):
            raise OpenTransaction(terminal.name)
        if returned or compensated:
            restored.add(directory.name)
            if compensated or not (directory / "receipt.json").exists():
                before_ready.add(directory.name)
        require(receipt["planSha256"] == directory.name, "MODULE_RECEIPT_DRIFT")
        require(digest(plan) == directory.name and plan["operation"] == "module-release",
                "MODULE_RECEIPT_DRIFT")
        transactions[directory.name] = (plan, terminal)
    returns = set()
    represented = set()
    primary_runs = {}
    partial_apply = set()
    for run in state.iterdir():
        if not RUN.fullmatch(run.name):
            continue
        approvals = read(run / "approvals") if (run / "approvals").exists() else []
        origin = run / "plan.review"
        request = read(origin)["request"] if origin.exists() else {}
        for claimed in approvals:
            if claimed in ("apply", "rollback", "migrate") and not (run / (claimed + ".review")).exists():
                if not request or request.get("module") == module:
                    raise OpenTransaction(claimed + ".approval")
        for phase in ("apply", "rollback"):
            path = run / (phase + ".review")
            if not os.path.lexists(path):
                continue
            review = read(path)
            req = review["request"]
            if req.get("operation") != "module-release" or req["module"] != module:
                continue
            require(req["run"] == run.name and req["phase"] == phase and HEX.fullmatch(review["review"])
                    and phase in read(run / "approvals"), "MODULE_APPROVAL_DRIFT")
            source = req["digest"]
            if phase == "apply":
                proposal = read(run / "plan")
                require(source == proposal["planSha256"] == digest(proposal["plan"]), "MODULE_APPROVAL_DRIFT")
                if "sourcePlan" not in proposal["plan"]:
                    primary_runs.setdefault(source, set()).add(run.name)
                source = proposal["plan"].get("sourcePlan", source)
                if not (run / "apply.result").is_file():
                    partial_apply.add(source)
            if source not in transactions:
                raise OpenTransaction(phase + ".review")
            if phase == "apply":
                represented.add(source)
                continue
            if source not in restored:
                raise OpenTransaction("rollback.review")
            terminal = transactions[source][1]
            result_path = run / "rollback.result"
            if result_path.is_file():
                result = read(result_path)
                # Older dispatches closed a failed verification or a denied replay with HELD.
                if result.get("status") != "HELD":
                    require(result == read(terminal), "MODULE_RETURN_DRIFT")
            if terminal.name == "return-receipt.json" and review.get("returnAlreadyConsumed") is not True:
                represented.add(source)
                returns.add(source)
    for source in partial_apply:
        # A return may close the original interrupted apply. A second primary
        # dispatch for that digest with no result is a separate outstanding intent.
        if len(primary_runs.get(source, ())) != 1:
            raise OpenTransaction("apply.review")
    require(represented == transactions.keys() and represented, "MODULE_RELEASE_HISTORY_UNPROVEN")
    for source, (_, terminal) in transactions.items():
        require((source in returns) == (terminal.name == "return-receipt.json"), "MODULE_RETURN_DRIFT")

    # A GitHub run ID orders dispatch creation, not the executor's effects. Only the
    # READY pointer orders forward completions. A return before READY has no pointer:
    # attach it by its baseline CID to the terminal state of that pointer.
    pointer = state / ("module-" + module + ".ready")
    if os.path.lexists(pointer):
        source = read_head(pointer)["planSha256"]
        require(source in transactions, "MODULE_RELEASE_HEAD_DRIFT")
        plan, terminal = transactions[source]
        result = read(terminal)
        require(source not in before_ready, "MODULE_RELEASE_HEAD_DRIFT")
        active = result["restoredCid"] if source in restored else result["successorCid"]
        if any(s != source and s not in restored and candidate["oldCid"] == active
               for s, (candidate, _) in transactions.items()):
            raise OpenTransaction("ready-pointer")
        interrupted = [s for s in before_ready if transactions[s][0]["oldCid"] == active]
        if not interrupted:
            return plan, terminal
        require(source not in returns, "MODULE_RETURN_ORDER_UNPROVEN")
    else:
        if before_ready != transactions.keys():
            raise OpenTransaction("ready-pointer")
        interrupted = list(before_ready)
    require(len(interrupted) == 1, "MODULE_RETURN_ORDER_UNPROVEN")
    return transactions[interrupted[0]]


def ready_head(state, module, source, plan, receipt):
    # Same pointer, proposal, reviews and result bindings as ModuleRelease.previous_release (B7).
    tip = read(state / ("module-" + module + ".ready"))
    phase = tip["phase"]
    require(RUN.fullmatch(tip["run"]) and phase in ("apply", "migrate") and tip["planSha256"] == source,
            "MODULE_RECEIPT_DRIFT")
    run = state / tip["run"]
    require(receipt == read(run / (phase + ".result")) and receipt["operation"] == "module-release"
            and receipt["readiness"] == "UP" and receipt["predecessorCid"] == plan["oldCid"]
            and HEX.fullmatch(receipt["successorFrameSha256"]), "MODULE_RECEIPT_DRIFT")
    req = read(run / "apply.review")["request"]
    proposal = read(run / "plan")
    require(req["module"] == module and req["operation"] == "module-release" and req["run"] == run.name
            and req["phase"] == "apply" and req["digest"] == proposal["planSha256"] == digest(proposal["plan"])
            and proposal["plan"].get("sourcePlan", req["digest"]) == source, "MODULE_APPROVAL_DRIFT")
    if phase == "migrate":
        review = read(run / "migrate.review")
        staged = read(run / "apply.result")
        require("migrate" in read(run / "approvals") and HEX.fullmatch(review["review"])
                and staged["status"] == "GATED" and staged["planSha256"] == source
                and staged["migrationSha256"] == receipt["migrationSha256"]
                and review["request"] == {**req, "phase": phase, "digest": staged["migrationSha256"]},
                "MODULE_APPROVAL_DRIFT")


def module_gate(identity, state, profile, transaction, name, live, docker, context):
    module = identity["module"]
    journal = Path(identity["journalRoot"])
    require(Path(profile["journal"]) == journal and profile["container"] == name, "MODULE_PROFILE_DRIFT")
    plan, path = transaction
    source = path.parent.name
    receipt = read(path)
    reviewed_return = path.name == "return-receipt.json"
    returning = reviewed_return or (receipt.get("status") == "HELD" and receipt.get("rollback") == "ROLLED_BACK")
    context.update(planSha256=source, terminal=path.name)
    binding = identity.get("receiptSigning")
    require((binding or {}).get("publicKey") == profile.get("receiptSigning", {}).get("publicKey"),
            "SIGNATURE_BINDING_CHANGED")
    verify_signature(binding, path, returning, context)
    require(receipt["planSha256"] == source, "MODULE_RECEIPT_DRIFT")
    baseline = read(path.parent / "baseline.private.json")
    require(baseline["Id"] == plan["oldCid"] and baseline["Name"] == "/" + name, "MODULE_BASELINE_DRIFT")
    if returning:
        created = path.parent / "created.json"
        candidate = read(created)["cid"] if created.exists() else None
        require(not (path.parent / "create-intent.json").exists() or candidate, "MODULE_RETURN_DRIFT")
        require(receipt["restoredCid"] == baseline["Id"] and receipt["predecessorReadiness"] == "UP",
                "MODULE_RETURN_DRIFT")
        if reviewed_return:
            require(read(path.parent / "return-intent.json") == {"cid": candidate, "planSha256": source},
                    "MODULE_RETURN_DRIFT")
        else:
            require(receipt["operation"] == "module-release" and receipt["predecessorCid"] == baseline["Id"]
                    and receipt.get("successorCid") == candidate
                    and read(path.parent / "rollback-intent.json") == {"cid": baseline["Id"]},
                    "MODULE_RETURN_DRIFT")
        cid, image = baseline["Id"], plan["oldImage"]
    else:
        ready_head(state, module, source, plan, receipt)
        cid, image = receipt["successorCid"], plan["ci"]["imageId"]
    require(cid == live["Id"], "RELEASE_CID_MISMATCH")
    require(image == live["Image"], "RELEASE_IMAGE_MISMATCH")
    if "Config" not in baseline:
        old = docker.release_frame(baseline["Id"])
        require(old["Id"] == baseline["Id"], "MODULE_BASELINE_DRIFT")
        baseline = {**old, **baseline}
    require(baseline["Image"] == plan["oldImage"] and snapshot(baseline) == plan["oldFrameSha256"],
            "MODULE_BASELINE_DRIFT")
    if returning:
        return baseline["Config"]["Entrypoint"], baseline["Config"]["Cmd"]

    # execute() journals the digest, not the private CREATE body. Rebuild that
    # body with the producer's builder and the CI coordinates of this release.
    candidate = profile["candidate"] if "candidateReview" in plan else None
    approved = request(baseline, image, provenance_labels({**profile, "ci": plan["ci"]}),
                       candidate=candidate, image_defaults=docker.image_defaults(image) if candidate else None)
    require(digest(approved) == plan["requestSha256"]
            and read(path.parent / "create-intent.json") == {"requestSha256": plan["requestSha256"]}
            and read(path.parent / "created.json") == {"cid": cid}, "MODULE_CREATE_DRIFT")
    if "candidateReview" in plan:
        review = plan["candidateReview"]
        require(review["predecessorCmdSha256"] == digest(baseline["Config"]["Cmd"])
                and review["candidateCmdSha256"] == digest(approved["Cmd"]), "RELEASE_COMMAND_MISMATCH")
    return approved["Entrypoint"], approved["Cmd"]


def semantic_gate(state, name, context):
    tip = read_head(state / "completed-forward")
    require(RUN.fullmatch(tip["run"]), "CLOSURE_POINTER_DRIFT")
    run = state / tip["run"]
    archive = read(run / "closed-forward")
    require(digest(archive) == tip["archive"] and archive["pointers"]["forward-stage"]["run"] == run.name,
            "CLOSURE_POINTER_DRIFT")
    origin = archive["pointers"]["forward"]
    require(RUN.fullmatch(origin["run"]), "CLOSURE_POINTER_DRIFT")
    plan = read(state / origin["run"] / "plan")
    staged = read(run / "stage")
    result = read(run / "result")
    creation_run = plan.get("createdFrom", plan.get("beforeCreate", origin["run"]))
    require(RUN.fullmatch(creation_run), "CLOSURE_POINTER_DRIFT")
    creation = state / creation_run
    first = read(creation / "plan")
    claim = read(creation / "create.claim")
    created = read(creation / "create.receipt")
    require(claim == {"request": digest(first["request"]), "parent": digest(first)}
            and created["planSha256"] == digest(claim) and staged["cid"] == created["result"],
            "CLOSURE_CREATE_DRIFT")
    for attempt in state.iterdir():
        if not RUN.fullmatch(attempt.name) or not (attempt / "approvals").is_file():
            continue
        approvals = read(attempt / "approvals")
        if "apply" not in approvals or not (attempt / "plan.review").exists():
            continue
        request = read(attempt / "plan.review")["request"]
        if request.get("direction") not in ("forward", "return"):
            continue
        candidate = read(attempt / "plan")
        if candidate["head"] >= archive["head"] and not (attempt / "closed-transaction").exists():
            raise OpenTransaction("apply.approval")
    require(digest(plan) == origin["plan"] and digest(result) == archive["result"]
            and staged["parent"] == digest(read(run / "plan"))
            and archive["head"] == plan["sequence"] == plan["head"] + 1
            and all(result[k] == v for k, v in dict(worker="on", readiness="UP", ingress="VERIFIED",
                                                     probe="C_PROBE_PASSED").items()), "CLOSURE_RESULT_DRIFT")
    require(staged["profile"]["containerName"] == name, "RELEASE_NAME_MISMATCH")
    require(staged["profile"]["image"] == plan["target"]["image"], "CLOSURE_IMAGE_DRIFT")
    context.update(terminal="completed-forward", archiveSha256=tip["archive"], head=archive["head"])
    return staged["cid"], plan["target"]["image"], plan["request"]["Entrypoint"], plan["request"]["Cmd"]


def resolve(gate, name, row, docker, context):
    identity = gate["identity"]
    root = Path(identity["executorRoot"])
    state = root / "state"
    try:
        custody(state, stat.S_ISDIR)
        module = identity["source"] == "module-release"
        if module:
            journal = Path(identity["journalRoot"])
            custody(journal, stat.S_ISDIR)
            transaction = module_history(state, journal, identity["module"])
        else:
            for marker in ("forward", "return", "forward-stage", "return-stage"):
                if os.path.lexists(state / marker):
                    raise OpenTransaction(marker)
            cid, image, entry, cmd = semantic_gate(state, name, context)
        require(row is not None, "MISSING_CONTAINER")
        live = docker.release_launch(row["cid"])
        require(live["Name"] == "/" + name and live["Id"] == row["cid"], "RELEASE_CID_MISMATCH")
        policy = read(root / "profile.json")
        if module:
            profile = policy["modules"][identity["module"]]
            require(profile["dockerSocket"] == docker.cfg["dockerSocket"], "MODULE_PROFILE_DRIFT")
            entry, cmd = module_gate(identity, state, profile, transaction, name, live, docker, context)
        else:
            require(policy["socket"] == docker.cfg["dockerSocket"] and policy["originalProfile"]["containerName"] == name,
                    "SEMANTIC_PROFILE_DRIFT")
            require(cid == live["Id"], "RELEASE_CID_MISMATCH")
            require(image == live["Image"], "RELEASE_IMAGE_MISMATCH")
        require(entry == gate["entrypoint"] == live["Config"]["Entrypoint"], "RELEASE_ENTRYPOINT_MISMATCH")
        require(cmd == live["Config"]["Cmd"], "RELEASE_COMMAND_MISMATCH")
        validate_command(cmd)
        context.update(cid=row["cid"], imageId=live["Image"], commandSha256=digest(cmd))
        return dict(entrypoint=entry, command=cmd, imageId=live["Image"])
    except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError, RecursionError):
        raise Held("RELEASE_JOURNAL_UNVERIFIED") from None
