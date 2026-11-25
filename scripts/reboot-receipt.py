"""Observe a Linux host without installing the reader, or compare two private receipts."""
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid


RECEIPT = "ouf.reboot-receipt.v1"
ROLES = {"adapter", "southbound"}
UNIT_FIELDS = ("ActiveState", "SubState", "UnitFileState", "ActiveEnterTimestamp")
DOCKER_FIELDS = {
    "name": ".Name", "cid": ".Id", "imageId": ".Image", "state": ".State.Status",
    "StartedAt": ".State.StartedAt", "RestartPolicy": ".HostConfig.RestartPolicy",
}
# JSON-quote each individual field. Network endpoints never leave the daemon.
INSPECT = "\t".join("{{json " + field + "}}" for field in DOCKER_FIELDS.values())
INSPECT += "\t{{range $name, $_ := .NetworkSettings.Networks}}{{json $name}}\t{{end}}"
PACKAGE_FORMAT = r"${Package}\t${Architecture}\t${Version}\t${db:Status-Status}\n"


def require(condition):
    if not condition:
        raise ValueError("invalid data")


def digest(doc):
    payload = {key: value for key, value in doc.items() if key != "digest"}
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("ascii")).hexdigest()


def check(checks, name, status, observed):
    checks.append({"id": name, "status": status, "observed": observed})


def error_code(exc):
    if isinstance(exc, subprocess.TimeoutExpired):
        return "TIMEOUT"
    if isinstance(exc, subprocess.CalledProcessError):
        return f"EXIT_{exc.returncode}"
    if isinstance(exc, OSError):
        return errno.errorcode.get(exc.errno, "OS_ERROR")
    return "INVALID_DATA"


READ_ERRORS = (OSError, ValueError, TypeError, IndexError, KeyError, AttributeError, subprocess.SubprocessError)


def run(argv, timeout):
    require(argv and all(isinstance(arg, str) and arg for arg in argv))
    program = shutil.which(argv[0])
    if not program:
        raise FileNotFoundError(errno.ENOENT, "command")
    return subprocess.run(
        [program, *argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"}, encoding="utf-8",
        check=True, timeout=timeout, shell=False,
    ).stdout


def docker_package(name):
    return name.split(":")[0].startswith(("docker", "containerd"))


def packages(args):
    rows = run([args.dpkg_query, "-W", "-f=" + PACKAGE_FORMAT], args.timeout)
    kernel, docker = {}, {}
    for row in rows.splitlines():
        name, arch, version, status = row.split("\t")
        if status == "installed":
            key = f"{name}:{arch}"
            if name.startswith("linux-image-"):
                kernel[key] = version
            elif docker_package(name):
                docker[key] = version
    require(rows)
    return {"kernel": kernel, "docker": docker}


def grub_entry(args):
    """Read the generated selector, including common next_entry/saved_entry forms."""
    grub_dir = args.boot_root / "grub"
    config = (args.grub_config or grub_dir / "grub.cfg").read_text(encoding="utf-8")
    selectors = []
    for match in re.finditer(r"^\s*set\s+default=(.+)$", config, re.MULTILINE):
        words = shlex.split(match[1], comments=True)
        require(len(words) == 1)
        selectors.append(words[0])
    if selectors[:1] == ["${next_entry}"] or "${saved_entry}" in selectors:
        # A missing grubenv is an empty environment for GRUB's load_env.
        try:
            env = (args.grub_env or grub_dir / "grubenv").read_bytes()
        except FileNotFoundError:
            env = b""
        values = {}
        for line in env.splitlines():
            key, _, value = line.partition(b"=")
            if key in (b"next_entry", b"saved_entry"):
                values[key] = value.decode("utf-8")
        if selectors[:1] == ["${next_entry}"]:
            selectors.pop(0)
            if values.get(b"next_entry"):
                selectors = [values[b"next_entry"]]
        if selectors == ["${saved_entry}"]:
            selectors = [values.get(b"saved_entry", "")]
    require(len(selectors) == 1 and selectors[0] and "$" not in selectors[0])
    return selectors[0]


def inventory(args):
    def ids():
        rows = run([args.docker, "ps", "-a", "--no-trunc", "-q"], args.timeout).splitlines()
        require(len(set(rows)) == len(rows) and all(re.fullmatch("[a-f0-9]{64}", i) for i in rows))
        return sorted(rows)

    initial = ids()
    result = {}
    for cid in initial:
        raw = run([args.docker, "inspect", "--format", INSPECT, cid], args.timeout)
        fields = [json.loads(s) for s in raw.rstrip("\r\n").rstrip("\t").split("\t")]
        row = dict(zip(DOCKER_FIELDS, fields[:len(DOCKER_FIELDS)], strict=True))
        name = row.pop("name").removeprefix("/")
        require(name and name not in result and row["cid"] == cid)
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", row["imageId"]) and row["state"])
        policy = row["RestartPolicy"]
        row["RestartPolicy"] = {k: policy[k] for k in ("Name", "MaximumRetryCount")}
        row["networks"] = sorted(fields[len(DOCKER_FIELDS):])
        result[name] = row
    require(ids() == initial)
    return result


def unit(args, name):
    require(re.fullmatch(r"[\w@.\\:-]+", name) and not name.startswith("-"))
    fields = ",".join((*UNIT_FIELDS, "LoadState"))
    raw = run([args.systemctl, "show", "--all", "--property=" + fields, "--", name], args.timeout)
    values = dict(line.split("=", 1) for line in raw.splitlines())
    require(values["LoadState"] == "loaded" and values["ActiveState"] and values["SubState"])
    return {key: values[key] for key in UNIT_FIELDS}


def state(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:+-]{1,160}", value))
    return value


def r3_status(args):
    raw = run(shlex.split(args.r3_status), args.timeout)
    roles, result = {}, {}
    for line in raw.splitlines():
        row = json.loads(line)
        step = row["step"]
        if step == "role":
            role, epoch = row["role"], row["epoch"]
            require(role in ROLES and role not in roles)
            if epoch is not None:
                require(type(epoch["epoch"]) is int and epoch["epoch"] > 0)
                require(type(epoch["live"]) is bool)
                epoch = {"epoch": epoch["epoch"], "state": state(epoch["state"]), "live": epoch["live"]}
            roles[role] = epoch
        elif step in ("supervisor", "lease"):
            require(step not in result)
            result[step] = {"state": state(row["state"])}
            if step == "supervisor":
                epochs = {r: row["epochs"][r] for r in sorted(ROLES)}
                require(all(e is None or type(e) is int for e in epochs.values()))
                result[step]["epochs"] = epochs
    require(roles.keys() == ROLES and result.keys() == {"supervisor", "lease"})
    result["roles"] = roles
    return result


def observe(args):
    checks = []

    def read(key, operation):
        try:
            value = operation()
        except READ_ERRORS as exc:
            if key == "grubDefault" and isinstance(exc, (FileNotFoundError, PermissionError)):
                check(checks, key, "INFO", {"code": error_code(exc)})
                return "unreadable"
            check(checks, key, "FAIL", {"code": error_code(exc)})
            return "unreadable" if key == "grubDefault" else None
        check(checks, key, "PASS", {"count": len(value)} if isinstance(value, (dict, list)) else value)
        return value

    def proc(file):
        return (args.proc_root / file).read_text(encoding="ascii").strip()

    def uptime():
        seconds = float(proc("uptime").split()[0])
        require(math.isfinite(seconds) and seconds >= 0)
        return seconds

    def images():
        return sorted(p.name for p in args.boot_root.iterdir() if p.name.startswith("vmlinuz-"))

    doc = {
        "schema": RECEIPT, "phase": args.phase, "checks": checks,
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "bootId": read("bootId", lambda: str(uuid.UUID(proc("sys/kernel/random/boot_id")))),
        "kernelRelease": read("kernelRelease", lambda: state(proc("sys/kernel/osrelease"))),
        "uptimeSeconds": read("uptimeSeconds", uptime),
        "bootImages": read("bootImages", images),
        "grubDefault": read("grubDefault", lambda: grub_entry(args)),
        "packages": read("packages", lambda: packages(args)),
        "holds": read("holds", lambda: sorted(run([args.apt_mark, "showhold"], args.timeout).splitlines())),
        "containers": read("containers", lambda: inventory(args)),
        "units": {n: read("unit." + n, lambda: unit(args, n)) for n in sorted(set(args.unit))},
        "r3": read("r3", lambda: r3_status(args)) if args.r3_status is not None else None,
        "freeBytes": {k: read("disk." + k, lambda: shutil.disk_usage(path).free)
                      for k, path in (("root", args.root), ("receipts", args.receipts_dir))},
    }
    doc["digest"] = digest(doc)
    return doc, any(c["status"] == "FAIL" for c in checks)


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj)
        obj[key] = value
    return obj


def compare(args):
    checks = []

    def test(name, passed, observed):
        check(checks, name, "PASS" if passed else "FAIL", observed)

    def load(path, phase):
        try:
            data = json.loads(path.read_bytes(), object_pairs_hook=unique_keys)
            require(isinstance(data, dict))
            valid = data.get("digest") == digest(data)
            test(phase + ".digest", valid, "MATCH" if valid else "MISMATCH")
            if valid:
                require(data["schema"] == RECEIPT and data["phase"] == phase)
                require(isinstance(data["checks"], list) and data["checks"])
                for c in data["checks"]:
                    if c["status"] not in ("PASS", "INFO"):
                        test(phase + "." + c["id"], False, c["observed"])
                return data
        except READ_ERRORS as exc:
            test(phase + ".receipt", False, {"code": error_code(exc)})
        return None

    pre, post = load(args.pre, "pre"), load(args.post, "post")
    if pre and post and all(c["status"] == "PASS" for c in checks):
        try:
            test("bootId", pre["bootId"] != post["bootId"], [pre["bootId"], post["bootId"]])
            expected = args.expect_kernel or pre["kernelRelease"]
            test("kernelRelease", post["kernelRelease"] == expected, [expected, post["kernelRelease"]])
            before, after = pre["containers"], post["containers"]
            for name in sorted(set(args.managed)):
                old, new = before.get(name), after.get(name)
                if old is None or new is None:
                    test("managed." + name, False, "MISSING")
                    continue
                for field in ("cid", "imageId"):
                    test(f"managed.{name}.{field}", old[field] == new[field], [old[field], new[field]])
                test(f"managed.{name}.state", new["state"] == "running", new["state"])
            old_by_cid = {c["cid"]: c for c in before.values()}
            for name, new in sorted(after.items()):
                if name in args.managed:
                    continue
                old = old_by_cid.get(new["cid"])
                was_running = old is not None and old["state"] == "running"
                was_stopped_by_name = name in before and before[name]["state"] != "running"
                if not was_running or was_stopped_by_name:
                    restarted = old is not None and new["StartedAt"] != old["StartedAt"]
                    started = new["state"] == "running" or restarted
                    test("unmanaged." + name, not started, "STARTED" if started else new["state"])
            for name in sorted(pre["units"].keys() | post["units"].keys()):
                current = post["units"].get(name, {}).get("ActiveState")
                test("unit." + name, name in pre["units"] and current == "active", current)
            if args.expect_r3:
                for role in sorted(ROLES):
                    epoch = ((post["r3"] or {}).get("roles", {}).get(role) or {})
                    ok = epoch.get("state") == args.expect_r3
                    if args.expect_r3 == "STARTED":
                        ok = ok and epoch.get("live") is True
                        # After a reboot R3 must run in a new epoch, never the previous boot's one.
                        before_epoch = ((pre["r3"] or {}).get("roles", {}).get(role) or {}).get("epoch")
                        if before_epoch is not None:
                            ok = ok and type(epoch.get("epoch")) is int and epoch["epoch"] > before_epoch
                    test("r3." + role, ok, epoch)
            for key in ("packages", "holds"):
                if key == "packages":
                    old, new = pre[key]["docker"], post[key]["docker"]
                else:
                    old, new = ([n for n in d[key] if docker_package(n)] for d in (pre, post))
                test("docker." + key, old == new or args.allow_docker_change,
                     "UNCHANGED" if old == new else {"pre": old, "post": new})
        except READ_ERRORS:
            test("receipt.fields", False, "INVALID_DATA")
    failed = any(c["status"] == "FAIL" for c in checks)
    return {"schema": "ouf.reboot-comparison.v1", "status": "FAIL" if failed else "PASS",
            "checks": checks}, failed


def positive_timeout(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("expected a positive finite timeout")
    return seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    obs = sub.add_parser("observe")
    obs.add_argument("--phase", choices=("pre", "post"), required=True)
    for key, default in (("proc-root", "/proc"), ("boot-root", "/boot"), ("root", "/"),
                         ("receipts-dir", "."), ("grub-config", None), ("grub-env", None)):
        obs.add_argument("--" + key, type=Path, default=default)
    for command in ("docker", "systemctl", "dpkg-query", "apt-mark"):
        obs.add_argument("--" + command, default=command)
    obs.add_argument("--unit", action="append", default=[])
    obs.add_argument("--r3-status", help="fixed status reader argv, with POSIX quoting")
    obs.add_argument("--timeout", type=positive_timeout, default=10)
    cmp = sub.add_parser("compare")
    cmp.add_argument("pre", type=Path)
    cmp.add_argument("post", type=Path)
    cmp.add_argument("--expect-kernel")
    cmp.add_argument("--managed", action="append", default=[])
    cmp.add_argument("--expect-r3", help="expected epoch state for both roles")
    cmp.add_argument("--allow-docker-change", action="store_true")
    args = parser.parse_args()
    doc, failed = observe(args) if args.operation == "observe" else compare(args)
    print(json.dumps(doc, sort_keys=True, allow_nan=False))
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
