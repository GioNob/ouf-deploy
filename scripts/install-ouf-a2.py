#!/usr/bin/python3 -I
"""One-time bootstrap from a private root-owned checkout of the reviewed commit."""
import argparse
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

ROOT = Path("/opt/ouf-a2")
ENTRY = Path("/usr/local/sbin/ouf-a2")
RULE = Path("/etc/sudoers.d/ouf-a2")
REPO = Path(__file__).resolve().parents[1]
LIB = ("mandate", "store", "queue_inventory", "runbooks", "semantic", "ingress", "pipeline", "module_operation")
LIB += ("gateway_policy", "gateway_bundle", "gateway_admin", "gateway_operation")
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
    check(set(cfg) in (required, required | {"gateway"}) and all(type(cfg[k]) is int and cfg[k] > 0 for k in ("repositoryId","environmentId"))
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
    for op in ("start", "stop", "issue", "upgrade", "probe"):
        for version in ((28, 29) if op in ("issue", "upgrade") else (27, 28, 29)):
            role = f"{op}-{version}"
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
    for module in ("__init__", "contract", "docker", "frame", "operation", "transport"):
        files[package / (module + ".py")] = (blob(f"tools/module_release/{module}.py"), 0o600)
    # Use the same validated commit bytes that the installed executor will import.
    contract = types.ModuleType("release_contract")
    exec(compile(files[package / "contract.py"][0], "contract.py", "exec"), contract.__dict__)
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
    for path, (data, mode) in files.items():
        parent = path.parent
        while not parent.exists():
            parent = parent.parent
        safe(parent)
        if os.path.lexists(path):
            safe(path)
            check(path.is_file() and path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == mode,
                  "INSTALLED_FILE_CONFLICT")
    return files


def manifest(files):
    return {str(p): {"sha256": sha(b), "mode": oct(m)} for p, (b, m) in files.items()}


def publish(path, data, mode):
    if path.exists():
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        tmp = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            if path == RULE:
                subprocess.run(["/usr/sbin/visudo", "-cf", str(tmp)], check=True, stdout=subprocess.DEVNULL)
            os.link(tmp, path)
            fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            tmp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bootstrap", "plan", "apply"))
    parser.add_argument("profile", type=Path)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args()
    check(os.geteuid() == 0 and sys.flags.isolated, "ROOT_ISOLATED_REQUIRED")
    os.umask(0o077)
    import fcntl
    files = inspect(args.profile)
    spec = manifest(files)
    stamp = sha(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode())
    print(json.dumps({"files": spec, "planSha256": stamp}, indent=2))
    if args.mode == "plan":
        return
    approved = input("Per installare, trascrivere il digest del plan: ") if args.mode == "bootstrap" else args.plan_sha256
    check(approved == stamp, "INSTALL_PLAN_DRIFT")
    fd = os.open(ROOT.parent, os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        check(manifest(inspect(args.profile)) == spec, "INSTALL_PLAN_DRIFT")
        subprocess.run(["/usr/sbin/visudo", "-c"], check=True, stdout=subprocess.DEVNULL)
        installed_cfg = json.loads(files[ROOT / "profile.json"][0])
        journals = [Path(module["journal"]) for module in installed_cfg["modules"].values()]
        for p in (*journals, ROOT, ROOT / "lib", ROOT / "lib/module_release", ROOT / "books", ROOT / "state"):
            p.mkdir(exist_ok=True, mode=0o700)
            safe(p)
            check(stat.S_IMODE(p.stat().st_mode) == 0o700, "PRIVATE_DIRECTORY_REQUIRED")
        for path in (*[p for p in files if p != RULE], RULE):
            publish(path, *files[path])
        inspect(args.profile)
        subprocess.run(["/usr/sbin/visudo", "-c"], check=True, stdout=subprocess.DEVNULL)
    finally:
        os.close(fd)
    print("OUF_A2_INSTALLED")


if __name__ == "__main__":
    main()
