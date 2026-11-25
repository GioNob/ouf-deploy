"""Bounded D-045 boot orchestration. Only operate owns lifecycle changes."""
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
import time

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "ouf.semantic-provider-r3-autostart.v1"
OPERATE_SCHEMA = "ouf.semantic-provider-r3-operate.v1"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
HEX = re.compile(r"[0-9a-f]{64}")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SUCCESS = {"start": "SEMANTIC_PROVIDER_R3_STARTED", "stop": "SEMANTIC_PROVIDER_R3_STOPPED"}


class Denied(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "R3_AUTOSTART_DUPLICATE_FIELD")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Denied("R3_AUTOSTART_INVALID_JSON")))


def custody(path, directory=False):
    """Native boundary; tests substitute custody, never the orchestration rules."""
    path = Path(path)
    require(path.is_absolute(), "R3_AUTOSTART_ABSOLUTE_PATH_REQUIRED")
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, "R3_AUTOSTART_PARENT_CUSTODY_REQUIRED")
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
            and (directory or info.st_nlink == 1), "R3_AUTOSTART_CUSTODY_REQUIRED")


def read(path):
    custody(path)
    with open(path, "rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "R3_AUTOSTART_FILE_TOO_LARGE")
    return raw


def write_once(path, value):
    with open(path, "xb") as stream:
        os.chmod(path, 0o600)
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    if sys.platform == "linux":
        fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def config(raw):
    cfg = decode(raw)
    required = {"schema", "bindings", "dockerSocket", "installRoot", "volatileRestore", "outputRoot"}
    require(type(cfg) is dict and required <= cfg.keys()
            and cfg.keys() <= required | {"attempts", "waitSeconds", "platformReceipts"}
            and cfg["schema"] == SCHEMA, "R3_AUTOSTART_CONFIG_INVALID")
    require(type(cfg["bindings"]) is dict and set(cfg["bindings"]) == {"docker", "nft", "systemctl", "wrapper"},
            "R3_AUTOSTART_BINDINGS_INVALID")
    paths = [cfg["installRoot"], cfg["outputRoot"]]
    if "platformReceipts" in cfg:
        paths.append(cfg["platformReceipts"])
    for binding in cfg["bindings"].values():
        require(type(binding) is dict and set(binding) == {"path", "sha256"}
                and type(binding["sha256"]) is str and HEX.fullmatch(binding["sha256"]),
                "R3_AUTOSTART_BINDING_INVALID")
        paths.append(binding["path"])
    vr = cfg["volatileRestore"]
    require(type(vr) is dict and set(vr) == {"result", "sha256", "source"}
            and type(vr["sha256"]) is str and HEX.fullmatch(vr["sha256"]), "R3_AUTOSTART_RESTORE_INVALID")
    paths += [vr["result"], vr["source"]]
    require(all(type(p) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", p)
                and ".." not in p.split("/") for p in paths), "R3_AUTOSTART_PATH_INVALID")
    require(type(cfg["dockerSocket"]) is str
            and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", cfg["dockerSocket"]), "R3_AUTOSTART_LOCAL_SOCKET_REQUIRED")
    cfg.setdefault("attempts", 3)
    cfg.setdefault("waitSeconds", [30, 90, 180])
    # D-045 closes the incident after the third denial, never a fourth try.
    require(type(cfg["attempts"]) is int and cfg["attempts"] == 3
            and type(cfg["waitSeconds"]) is list and len(cfg["waitSeconds"]) == 3
            and all(type(n) is int and 1 <= n <= 180 for n in cfg["waitSeconds"])
            and all(a < b for a, b in zip(cfg["waitSeconds"], cfg["waitSeconds"][1:])),
            "R3_AUTOSTART_RETRY_POLICY_INVALID")
    return cfg


def desired(cfg):
    """Order successful receipts by monotonic per-CID epochs, stop after start
    at equal epochs. Never infer intent from directory names, mtime or HELD.
    A new cohort or incomparable epoch pairs requires human reconciliation.
    """
    root = Path(cfg["outputRoot"])
    custody(root, directory=True)
    successes = []
    for folder in sorted(root.iterdir()):
        if not re.fullmatch(r"semantic-provider-r3-(?:operate-(?:start|stop)|autostart-start)-[A-Za-z0-9-]+", folder.name):
            continue
        custody(folder, directory=True)
        result = folder / "result.json"
        if not result.exists():
            continue  # partial claim is never a successful intent
        report = decode(read(result))
        action = report.get("action")
        if action not in SUCCESS or report.get("status") != SUCCESS[action]:
            continue
        claim = decode(read(folder / "operate-claim.json"))
        require(claim.get("schema") == report.get("schema") == OPERATE_SCHEMA
                and claim.get("action") == action, "R3_AUTOSTART_HISTORY_INVALID")
        if claim.get("installRoot") != cfg["installRoot"]:
            continue
        digest = claim.pop("planSha256", None)
        require(type(digest) is str and HEX.fullmatch(digest)
                and digest == report.get("planSha256") == hashlib.sha256(canonical(claim)).hexdigest(),
                "R3_AUTOSTART_HISTORY_CLAIM_INVALID")
        rows = report["lastObservation"]["candidates"]
        require(set(rows) == {"adapter", "southbound"}, "R3_AUTOSTART_HISTORY_INVALID")
        cids, epochs = [], []
        for role in ("adapter", "southbound"):
            row = rows[role]
            require(type(row["cid"]) is str and HEX.fullmatch(row["cid"])
                    and row["cid"] == claim["observation"]["candidates"][role]["cid"]
                    and type(row["epoch"]["epoch"]) is int and row["epoch"]["epoch"] >= 1,
                    "R3_AUTOSTART_HISTORY_INVALID")
            cids.append(row["cid"])
            epochs.append(row["epoch"]["epoch"])
        successes.append((tuple(cids), tuple(epochs), action, folder.name))
    require(successes, "R3_AUTOSTART_DESIRED_STATE_UNPROVEN")
    require(len({s[0] for s in successes}) == 1, "R3_AUTOSTART_HISTORY_COHORT_AMBIGUOUS")
    latest = [s for s in successes if all(
        all(a >= b for a, b in zip(s[1], other[1]))
        and (s[1] != other[1] or s[2] == "stop" or other[2] == "start") for other in successes)]
    require(latest, "R3_AUTOSTART_HISTORY_ORDER_AMBIGUOUS")
    return {"action": latest[0][2], "receipt": latest[0][3], "epochs": list(latest[0][1])}


def require_platform(cfg, boot):
    if "platformReceipts" not in cfg:
        return
    root = Path(cfg["platformReceipts"])
    try:
        custody(root, directory=True)
        path = root / ("boot-" + boot.replace("-", "") + ".json")
        record = decode(read(path))
        if (record.get("schema") == "ouf.platform-restart-receipt.v1"
                and record.get("mode") == "boot" and record.get("action") == "start"
                and record.get("bootId") == boot and record.get("status") == "SUCCEEDED"):
            return
    except (Denied, OSError, ValueError, AttributeError):
        pass
    raise Denied("R3_PLATFORM_NOT_READY")


def argv(cfg, output):
    args = ["--action", "start", "--install-root", cfg["installRoot"],
            "--docker-socket", cfg["dockerSocket"], "--output-directory", str(output)]
    for name, binding in sorted(cfg["bindings"].items()):
        args += ["--" + name, binding["path"], "--" + name + "-sha256", binding["sha256"]]
    vr = cfg["volatileRestore"]
    return args + ["--volatile-rootfs-result", vr["result"], "--volatile-rootfs-result-sha256", vr["sha256"],
                   "--volatile-source", vr["source"]]


def invoke(args):
    # Installed delivery only; operate verifies every native binding itself.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/operate-semantic-provider-r3.py"), *args],
                                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                env=ENV, timeout=900)
        output.seek(0)
        raw = output.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "R3_AUTOSTART_OPERATE_OUTPUT_TOO_LARGE")
    report = decode(raw)
    require(type(report) is dict and report.get("schema") == OPERATE_SCHEMA
            and report.get("action") == "start" and report.get("status") in {"PLAN_READY", "HELD", SUCCESS["start"]}
            and result.returncode == int(report["status"] == "HELD"), "R3_AUTOSTART_OPERATE_REPLY_INVALID")
    return report


def reason(report):
    value = report.get("reason", "R3_AUTOSTART_OPERATE_REPLY_INVALID")
    return value if type(value) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", value) else "R3_AUTOSTART_REASON_INVALID"


def journal(incident):
    # systemd StandardError=journal + SyslogLevelPrefix=yes maps <3> to err.
    print("<3>" + canonical(incident).decode("ascii"), file=sys.stderr, flush=True)


def run(cfg, boot, *, operate=invoke, sleep=time.sleep, emit=journal):
    require(type(boot) is str and BOOT.fullmatch(boot), "R3_AUTOSTART_BOOT_ID_INVALID")
    intent = desired(cfg)
    if intent["action"] == "stop":
        return 0, {"schema": SCHEMA, "status": "R3_AUTOSTART_NOT_DESIRED", "desired": intent}
    root = Path(cfg["outputRoot"])
    marker = root / f"r3-autostart-{boot}.json"
    # Survives unit restarts within a boot, including interruption after apply.
    require(not marker.exists(), "R3_AUTOSTART_BOOT_ALREADY_ATTEMPTED")
    write_once(marker, {"schema": SCHEMA, "bootId": boot, "desired": intent})
    attempts = []
    terminal = "R3_AUTOSTART_EXHAUSTED"

    def save_attempt(output, item):
        if not output.exists():
            output.mkdir(mode=0o700)
        write_once(output / "autostart-attempt.json", item)

    for number, delay in enumerate(cfg["waitSeconds"], 1):
        # Delay BEFORE each attempt (including the first): 30/90/180 seconds.
        sleep(delay)
        intent = desired(cfg)  # honor a successful operator stop during the wait
        if intent["action"] == "stop":
            return 0, {"schema": SCHEMA, "status": "R3_AUTOSTART_NOT_DESIRED", "desired": intent}
        output = root / f"semantic-provider-r3-autostart-start-{boot}-{number}"
        require(not os.path.lexists(output), "R3_AUTOSTART_OUTPUT_ALREADY_EXISTS")
        args = argv(cfg, output)
        applying = False
        try:
            require_platform(cfg, boot)
            plan = operate(["--plan", *args])
            report = plan
            if plan["status"] == "PLAN_READY":
                digest = plan.get("planSha256")
                require(type(digest) is str and HEX.fullmatch(digest), "R3_AUTOSTART_PLAN_INVALID")
                intent = desired(cfg)
                if intent["action"] == "stop":
                    return 0, {"schema": SCHEMA, "status": "R3_AUTOSTART_NOT_DESIRED", "desired": intent}
                applying = True
                report = operate(["--apply", "--plan-sha256", digest, *args])
            require(report["status"] in {"HELD", SUCCESS["start"]}, "R3_AUTOSTART_OPERATE_REPLY_INVALID")
            if applying and report["status"] == SUCCESS["start"]:
                return 0, {"schema": SCHEMA, "status": SUCCESS["start"], "bootId": boot,
                           "attempt": number, "outputDirectory": str(output)}
            item = {"attempt": number, "reason": reason(report), "outputDirectory": str(output)}
            consumed = report.get("doNotRerunApply") or report.get("outputCreated") or os.path.lexists(output)
        except Exception as error:
            item = {"attempt": number, "reason": str(error) if isinstance(error, Denied)
                    else "R3_AUTOSTART_OPERATE_FAILED", "outputDirectory": str(output)}
            # An interrupted/unparseable apply is uncertain even without a receipt.
            consumed = applying or os.path.lexists(output)
        attempts.append(item)
        save_attempt(output, item)
        if consumed:
            terminal = "R3_AUTOSTART_APPLY_NOT_RETRYABLE"
            break
    incident = {"schema": SCHEMA, "status": terminal, "bootId": boot, "attempts": attempts}
    write_once(root / f"r3-autostart-incident-{boot}.json", incident)
    emit(incident)
    return 1, incident


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        cfg = config(read(args.config))
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        # Serialize driver instances without touching runtime/guard locks.
        import fcntl
        custody(cfg["outputRoot"], directory=True)
        with open(Path(cfg["outputRoot"]) / ".r3-autostart.lock", "a+b") as lock:
            custody(lock.name)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, report = run(cfg, boot)
    except Exception as error:
        code, report = 1, {"schema": SCHEMA, "status": "HELD", "reason": str(error) if isinstance(error, Denied)
                           else "R3_AUTOSTART_FAILED"}
        journal(report)
    print(canonical(report).decode("ascii"), flush=True)
    return code
