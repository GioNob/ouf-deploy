#!/usr/bin/python3 -I
"""Install or update from a private root-owned checkout of the reviewed commit."""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
from uuid import uuid4

ROOT = Path("/opt/ouf-a2")
ENTRY = Path("/usr/local/sbin/ouf-a2")
RULE = Path("/etc/sudoers.d/ouf-a2")
REPO = Path(__file__).resolve().parents[1]
LIB = ("mandate", "store", "queue_inventory", "runbooks", "semantic", "ingress", "pipeline", "module_operation", "successor_image")
LIB += ("gateway_policy", "gateway_bundle", "gateway_admin", "gateway_operation", "semantic_database", "module_receipt")
MODELS = ("transition_journal", "gated_creation_plan", "gated_process_observation")


def check(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(path):
    check(path.is_absolute() and path.resolve() == path, "ROOT_TREE_REQUIRED")
    for p in (path, *path.parents):
        s = p.lstat()
        check(s.st_uid == 0 and not s.st_mode & 0o022, "ROOT_TREE_REQUIRED")


def inspect(profile):
    safe(profile)
    check(profile.is_file() and not profile.stat().st_mode & 0o077, "PRIVATE_PROFILE_REQUIRED")
    raw = profile.read_bytes()
    cfg = json.loads(raw)
    required = {"runner", "repository", "repositoryId", "environmentId", "reviewerIds", "branch", "commit",
                "environment", "installRoot", "leaseJournal", "socket", "roleCids", "roleTables", "originalProfile",
                "retainedName", "failedName", "readinessPort", "runbooks", "probe", "queue", "modules"}
    check(required <= set(cfg) and set(cfg) - required <= {"successorImage", "nextSuccessorImage", "gateway", "runnerName", "semanticDatabase"} and all(type(cfg[k]) is int and cfg[k] > 0 for k in ("repositoryId","environmentId"))
          and type(cfg["readinessPort"]) is int and 0 < cfg["readinessPort"] < 65536, "INSTALL_PROFILE_FIELDS")
    check(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg["repository"]) and cfg["branch"]
          and all(Path(cfg[k]).is_absolute() for k in ("installRoot","leaseJournal","socket")),
          "INSTALL_PROFILE_BINDINGS")
    queue = cfg["queue"]
    required_queue = {"container", "socket", "role", "database", "subjectTenants"}
    check(set(queue) in (required_queue, required_queue | {"proof", "proofWaitSeconds"})
          and all(re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", queue[k]) for k in ("container", "role", "database"))
          and re.fullmatch(r"/[A-Za-z0-9_./-]+", queue["socket"]) and ".." not in Path(queue["socket"]).parts
          and isinstance(queue["subjectTenants"], dict)
          and all(isinstance(v, str) and v for v in queue["subjectTenants"].values()), "QUEUE_PROFILE")
    if "proof" in queue:
        proof = queue["proof"]
        check(type(queue["proofWaitSeconds"]) is int and queue["proofWaitSeconds"] > 0
              and set(proof) == {"subject","keyHash","fingerprint","provider","uri"}
              and proof["subject"] in queue["subjectTenants"] and all(isinstance(v,str) and v for v in proof.values())
              and all(re.fullmatch("[0-9a-f]{64}", proof[k]) for k in ("keyHash","fingerprint")),
              "WORKER_PROOF_PROFILE")
    check(set(cfg["probe"]) == {"C_R3_INPUTS","C_R3_INPUTS_SHA256","C_INSTALLATION_PROFILE",
                                "C_INSTALLATION_PROFILE_SHA256"}, "PROBE_BINDINGS")
    import pwd
    user = cfg["runner"]
    check(re.fullmatch("[a-z_][a-z0-9_-]{0,30}", user) and pwd.getpwnam(user).pw_uid != 0, "RUNNER_ACCOUNT")
    check(isinstance(cfg.get("runnerName", user), str) and cfg.get("runnerName", user).strip(), "RUNNER_NAME")
    check(cfg["environment"] == "ouf-vps-privileged" and isinstance(cfg["reviewerIds"], list)
          and cfg["reviewerIds"] and all(type(i) is int and i > 0 for i in cfg["reviewerIds"]),
          "REVIEW_POLICY")
    check(re.fullmatch("[0-9a-f]{40}", cfg["commit"]), "COMMIT_REQUIRED")
    # Read blobs from the trusted commit, including on hosts with checkout filters.
    safe(REPO)
    safe(REPO / ".git")
    check((REPO / ".git").is_dir(), "ROOT_OWNED_CLONE_REQUIRED")
    def git(*args):
        return subprocess.check_output(["/usr/bin/git", "-C", str(REPO), *args], stderr=subprocess.DEVNULL,
                                       env={"PATH": "/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1"})
    check(git("rev-parse", "HEAD").decode().strip() == cfg["commit"], "CHECKOUT_COMMIT_DRIFT")
    def blob(name):
        return git("cat-file", "blob", cfg["commit"] + ":" + name)
    safe(Path(__file__).absolute())
    check(Path(__file__).read_bytes() == blob("scripts/install-ouf-a2.py"), "BOOTSTRAP_DRIFT")
    files = {ROOT / "lock": (b"", 0o600),
             ENTRY: (blob("scripts/ouf-a2-executor"), 0o755),
             RULE: (f'{user} ALL=(root) NOPASSWD: NOSETENV: {ENTRY} ""\n'.encode(), 0o440)}
    ops = ("start", "stop", "issue", "upgrade", "probe")
    roles = set(cfg["runbooks"])
    last = max((int(role.removeprefix("start-")) for role in roles
                if re.fullmatch(r"start-[1-9][0-9]{1,2}", role)), default=0)
    check(29 <= last <= 256, "RUNBOOK_SET_REQUIRED")  # R3 authorization.MAX_CHAIN
    expected = {f"{op}-{version}" for op in ops
                for version in range(28 if op in ("issue", "upgrade") else 27, last + 1)}
    check(roles == expected, "RUNBOOK_SET_REQUIRED")
    for role in sorted(roles):
        op, version = role.split("-")
        spec = cfg["runbooks"][role]
        check(set(spec) == {"artifactCommit", "sourceCommit", "sha256"} and
              all(re.fullmatch("[0-9a-f]{40}", spec[k]) for k in ("artifactCommit","sourceCommit")),
              "RUNBOOK_BINDING_REQUIRED")
        name = {"start":"r3-operate.sh", "stop":"r3-operate.sh", "probe":"c-probe.sh"}.get(op, f"r3-{op}-v{version}.sh")
        raw_book = git("cat-file", "blob", spec["artifactCommit"] + ":ops/vps/" + name)
        check(sha(raw_book) == spec["sha256"] and
              re.findall(rb"^C=([0-9a-f]{40})$", raw_book, re.M) == [spec["sourceCommit"].encode()]
              and spec["sourceCommit"] != "0"*40, "RUNBOOK_PIN_DRIFT")
        book = ROOT / "books" / role
        spec["path"] = str(book)
        files[book] = (raw_book, 0o600)
    files[ROOT / "profile.json"] = (json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode(), 0o600)
    for module, directory in [(n, "privileged_executor") for n in LIB] + [
            (n, "semantic_application_cutover") for n in MODELS] + [("semantic_identity_v25", "semantic_provider_r3")]:
        files[ROOT / "lib" / (module + ".py")] = (blob(f"tools/{directory}/{module}.py"), 0o600)
    sql = "discovery-queue.sql"
    files[ROOT / "lib" / sql] = (blob("tools/privileged_executor/" + sql), 0o600)
    package = ROOT / "lib/module_release"
    for module in ("__init__", "contract", "docker", "flyway", "frame", "mcp_artifact", "operation",
                   "postgres", "provenance", "recovery", "retention", "return_operation", "transport"):
        files[package / (module + ".py")] = (blob(f"tools/module_release/{module}.py"), 0o600)
    # Use the same validated commit bytes that the installed executor will import.
    contract = types.ModuleType("release_contract")
    exec(compile(files[package / "contract.py"][0], "contract.py", "exec"), contract.__dict__)
    if "semanticDatabase" in cfg:
        check(contract.valid_semantic_database(cfg["semanticDatabase"]), "SEMANTIC_DATABASE_PROFILE_REQUIRED")
    for spec in (cfg[k] for k in ("successorImage", "nextSuccessorImage") if k in cfg):
        check(set(spec) == {"ci", "inbox", "migrationsField", "predecessorMigrations"}
              and set(spec["ci"]) == set(contract.CI_COORDINATES)
              and Path(spec["inbox"]).is_absolute() and isinstance(spec["predecessorMigrations"], list)
              and contract.matches(contract.NAME, spec["migrationsField"]), "SUCCESSOR_IMAGE_PROFILE")
        contract.validate_ci(spec["ci"])
    if "gateway" in cfg:
        gateway = types.ModuleType("gateway_policy")
        exec(compile(files[ROOT / "lib/gateway_policy.py"][0], "gateway_policy.py", "exec"), gateway.__dict__)
        check(gateway.valid_profile(cfg["gateway"]), "GATEWAY_INSTALL_PROFILE")
    check(isinstance(cfg["modules"], dict) and "onboarding" in cfg["modules"], "MODULE_PROFILE_REQUIRED")
    for name, module_profile in cfg["modules"].items():
        contract.validate(module_profile)
        check(module_profile["module"] == name, "MODULE_ID_DRIFT")
        journal = Path(module_profile["journal"])
        safe(journal.parent)
        check(journal != Path(module_profile["inbox"]) and not journal.is_relative_to(Path(module_profile["inbox"])),
              "PRIVATE_MODULE_JOURNAL")
        if os.path.lexists(journal):
            safe(journal)
            check(journal.is_dir() and stat.S_IMODE(journal.stat().st_mode) == 0o700, "PRIVATE_MODULE_JOURNAL")
        safe(Path(module_profile["nsenter"]))
    check(len({cfg["retainedName"], cfg["failedName"], cfg["originalProfile"]["containerName"]}) == 3
          and len(set(cfg["roleCids"])) == len(set(cfg["roleTables"])) == 2, "INSTALLATION_IDENTITIES")
    if "nextSuccessorImage" in cfg:
        check(all(f"{cfg['retainedName']}-v{head}" not in (cfg["failedName"], cfg["originalProfile"]["containerName"])
                  for head in (28, *range(29, last - 1))),
              "INSTALLATION_IDENTITIES")
    # Older installers delivered these same lib/books paths without an inventory.
    # Adopt only the reviewed paths on the first upgrade, never scan the tree.
    owned = sorted(p.relative_to(ROOT).as_posix() for p in files
                   if p.is_relative_to(ROOT / "lib") or p.is_relative_to(ROOT / "books"))
    files[ROOT / "managed-files.json"] = (json.dumps(owned).encode(), 0o600)
    return files


def existing(path):
    parent = path.parent
    while not os.path.lexists(parent):
        parent = parent.parent
    safe(parent)
    check(parent.is_dir(), "INSTALL_PARENT_REQUIRED")
    if os.path.lexists(path):
        safe(path)
        check(path.is_file(), "REGULAR_FILE_REQUIRED")
        return True
    return False


def fingerprint(data, mode):
    return {"sha256": sha(data), "mode": oct(mode)}


def journals(profile_bytes):
    return {Path(m["journal"]) for m in json.loads(profile_bytes).get("modules", {}).values()}


def manifest(files):
    inventory = ROOT / "managed-files.json"
    paths = set(files)
    if existing(inventory):
        names = json.loads(inventory.read_bytes())
        check(isinstance(names, list), "INVALID_INSTALL_INVENTORY")
        for name in names:
            rel = Path(name)
            check(len(rel.parts) >= 2 and rel.parts[0] in ("lib", "books")
                  and rel.as_posix() == name and ".." not in rel.parts, "INVALID_INSTALL_INVENTORY")
            paths.add(ROOT / rel)
    profile = ROOT / "profile.json"
    new_journals = journals(files[profile][0])
    protected = {ROOT / "state"} | new_journals
    if existing(profile):
        protected.update(journals(profile.read_bytes()))
    for directory in new_journals:
        if not directory.exists():
            check(not any(p in directory.parents for p in protected), "PROTECTED_INSTALL_STATE")
    spec = {}
    for path in sorted(paths):
        check(not any(path.is_relative_to(p) for p in protected), "PROTECTED_INSTALL_STATE")
        before = fingerprint(path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) if existing(path) else None
        after = fingerprint(*files[path]) if path in files else None
        if before is None and after is None:
            continue
        if before == after:
            action = "unchanged"
        elif before is None:
            action = "create"
        elif after is None:
            action = "delete"
        else:
            action = "replace"
        spec[str(path)] = {"action": action, "before": before, "after": after}
    return spec


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def stage(path, data, mode, cleanup):
    # sudo skips names containing a dot in an @includedir.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ouf-a2-", delete=False) as stream:
        tmp = Path(stream.name)
        cleanup.callback(tmp.unlink, missing_ok=True)
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    return tmp


def visudo(*args):
    subprocess.run(["/usr/sbin/visudo", "-c", *args], check=True, stdout=subprocess.DEVNULL)


def install(files, spec):
    changed = [Path(p) for p, row in spec.items() if row["action"] != "unchanged"]
    changed.sort(key=lambda p: p == RULE)
    visudo()
    with ExitStack() as cleanup:
        staged = {}
        if RULE in changed:
            staged[RULE] = stage(RULE, *files[RULE], cleanup)
            visudo("-f", str(staged[RULE]))
        for directory in (ROOT, ROOT / "lib", ROOT / "lib/module_release", ROOT / "books",
                          ROOT / "state", *journals(files[ROOT / "profile.json"][0])):
            if not directory.exists():
                directory.mkdir(mode=0o700)
                sync_dir(directory.parent)
            safe(directory)
            check(directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) == 0o700,
                  "PRIVATE_DIRECTORY_REQUIRED")
        backups = {}
        published = []
        try:
            for path in changed:
                if path in files and path != RULE:
                    staged[path] = stage(path, *files[path], cleanup)
                if spec[str(path)]["before"] is not None:
                    backup = path.with_name(".ouf-a2-old-" + uuid4().hex)
                    os.link(path, backup)
                    backups[path] = backup
            for path in changed:
                if path in staged:
                    os.replace(staged[path], path)
                else:
                    path.unlink()
                published.append(path)
                sync_dir(path.parent)
            visudo()
            check(all(row["action"] == "unchanged" for row in manifest(files).values()), "INSTALL_READBACK")
        except BaseException:
            while published:
                path = published[-1]
                if path in backups:
                    os.replace(backups[path], path)
                else:
                    path.unlink()
                published.pop()
                sync_dir(path.parent)
            raise
        else:
            published.clear()
        finally:
            # Preserve remaining originals if even the rollback encounters an I/O error.
            for path, backup in backups.items():
                if path not in published:
                    backup.unlink(missing_ok=True)


@contextmanager
def installation_lock():
    import fcntl
    fd = os.open(ROOT.parent, os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with ExitStack() as locks:
            # Older installed executors hold only the per-run lock.
            if existing(ROOT / "lock"):
                active = locks.enter_context((ROOT / "lock").open("rb"))
                fcntl.flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bootstrap", "plan", "apply"))
    parser.add_argument("profile", type=Path)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args()
    check(os.geteuid() == 0 and sys.flags.isolated, "ROOT_ISOLATED_REQUIRED")
    os.umask(0o077)
    files = inspect(args.profile)
    spec = manifest(files)
    stamp = sha(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode())
    print(json.dumps({"files": spec, "planSha256": stamp}, indent=2))
    if args.mode == "plan":
        return
    approved = input("Per installare, trascrivere il digest del plan: ") if args.mode == "bootstrap" else args.plan_sha256
    check(approved == stamp, "INSTALL_PLAN_DRIFT")
    with installation_lock():
        files = inspect(args.profile)
        check(manifest(files) == spec, "INSTALL_PLAN_DRIFT")
        install(files, spec)
    print("OUF_A2_INSTALLED")


if __name__ == "__main__":
    main()
