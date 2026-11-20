"""Install and administer the pinned delivery. Invoked from the runbooks' private staging directory."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / "tools"))
from platform_restart.profile import Held, canonical, custody, load_profile, private_dir, require, safe_path, sha
from platform_restart.controller import receipt, stamp

UNIT = "ouf-platform-start.service"
TEMPLATE = SOURCE / "ops/vps/systemd" / UNIT
MODULES = ("__init__", "profile", "docker", "controller")


def archive():
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as delivery:
        files = {"__main__.py": SOURCE / "scripts/platform-restart.py"}
        files.update({f"platform_restart/{m}.py": SOURCE / f"tools/platform_restart/{m}.py" for m in MODULES})
        for member, path in files.items():
            delivery.writestr(zipfile.ZipInfo(member), path.read_bytes())
    return result.getvalue()


def filehash(path):
    custody(path)
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def systemctl(binary, *args, check=True):
    return subprocess.run([binary, *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={"LC_ALL": "C", "PATH": os.defpath}, stdin=subprocess.DEVNULL,
                          timeout=60, text=True).stdout.strip()


def property_value(binary, field):
    return systemctl(binary, "show", "--property", field, "--value", UNIT)


def installed_fragment(binary):
    state = systemctl(binary, "show", "--property", "LoadState", "--value", UNIT, check=False)
    if state == "not-found":
        return ""
    require(state == "loaded", "UNIT_STATE_UNAVAILABLE")
    require(not property_value(binary, "DropInPaths"), "UNIT_NAME_IN_USE")
    return property_value(binary, "FragmentPath")


def checked_unit(meta):
    binary = meta["systemctl"]
    require(filehash(binary) == meta["systemctlSha256"], "SYSTEMCTL_CHANGED")
    require(property_value(binary, "FragmentPath") == meta["unit"]
            and not property_value(binary, "DropInPaths")
            and property_value(binary, "NeedDaemonReload") == "no", "LOADED_UNIT_CHANGED")


def publish(path, data, mode):
    # Publish only complete bytes. Exact partial installs can be planned again.
    if path.exists():
        require(filehash(path) == sha(data), "INSTALL_TARGET_CHANGED")
        return
    stream = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    temporary = Path(stream.name)
    try:
        with stream:
            os.chmod(temporary, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink()
    if sys.platform == "linux":
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def configure(args, dest, commit):
    started = stamp()
    require(all((args.profile, args.profile_sha256, args.unit_dir, args.systemctl, args.checksum)),
            "INSTALL_ARGUMENT_REQUIRED")
    source_profile = safe_path(args.profile)
    custody(source_profile)
    profile = source_profile.read_bytes()
    cfg = load_profile(profile, args.profile_sha256)
    private_dir(cfg["receipts"])
    report = dict(schema="ouf.platform-restart-install-receipt.v1", startedAt=started,
                  mode="install-" + args.mode, commit=commit, profileSha256=sha(profile))
    try:
        report.update(install_files(args, dest, commit, profile, cfg))
    except (Held, OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="HELD", reason=str(error) if isinstance(error, Held) else "INSTALL_IO_FAILED")
        receipt(cfg["receipts"], report)
        raise
    filename = receipt(cfg["receipts"], report)
    return {**report, "receipt": filename}


def install_files(args, dest, commit, profile, cfg):
    unit_dir = safe_path(args.unit_dir)
    unit_path = unit_dir / UNIT
    custody(unit_dir, stat.S_ISDIR)
    binary = str(safe_path(args.systemctl))
    python = str(safe_path(str(Path(sys.executable).resolve())))
    checksum = str(safe_path(args.checksum))
    require(sys.version_info[:2] == (3, 13), "PYTHON_313_REQUIRED")
    for directory in [cfg["receipts"], cfg["incidents"]]:
        private_dir(directory)
        require(not (dest.is_relative_to(directory) or Path(directory).is_relative_to(dest)
                     or unit_dir.is_relative_to(directory)), "OUTPUT_OVERLAPS_INSTALLATION")
    require(filehash(cfg["docker"]["path"]) == cfg["docker"]["sha256"], "DOCKER_HASH_CHANGED")
    custody(cfg["dockerSocket"], stat.S_ISSOCK)
    pyz = archive()
    meta = dict(commit=commit, unit=str(unit_path), systemctl=binary, systemctlSha256=filehash(binary),
                python=python, pythonSha256=filehash(python), checksum=checksum, checksumSha256=filehash(checksum),
                receipts=cfg["receipts"], incidents=cfg["incidents"], profileSha256=sha(profile), sourceSha256=sha(pyz))
    unit = TEMPLATE.read_text(encoding="utf8")
    delays = cfg["bootRetryDelaysSeconds"]
    inventory = cfg["inventoryTimeoutSeconds"]
    # Two initial observations, then at most one new inventory per level retry.
    boot_timeout = 60 + 2 * inventory + sum(
        (1 + len(delays)) * level["timeoutSeconds"] + sum(delays) + len(delays) * inventory
        for level in cfg["levels"])
    for key, value in dict(CHECKSUM=checksum, DEST=str(dest), PYTHON=python, PROFILE_SHA=sha(profile),
                           RECEIPTS=cfg["receipts"], INCIDENTS=cfg["incidents"], BOOT_TIMEOUT=str(boot_timeout)).items():
        unit = unit.replace(f"@{key}@", value)
    meta["unitSha256"] = sha(unit.encode())
    sums = "".join(f"{digest}  {path}\n" for path, digest in
                   [(dest / "platform.pyz", sha(pyz)), (python, meta["pythonSha256"])])
    meta["bootBindingsSha256"] = sha(sums.encode())
    files = {dest / "profile.json": profile, dest / "platform.pyz": pyz, dest / "boot.sha256": sums.encode(),
             dest / "installation.json": canonical(meta), unit_path: unit.encode()}
    custody(dest.parent, stat.S_ISDIR)
    if dest.exists():
        private_dir(dest)
        require(set(dest.iterdir()) <= set(files), "INSTALL_DIRECTORY_IN_USE")
    state = {}
    for path, raw in files.items():
        state[str(path)] = filehash(path) if os.path.lexists(path) else None
        require(state[str(path)] in (None, sha(raw)), "INSTALL_TARGET_CHANGED")
    fragment = installed_fragment(binary)
    require(fragment in ("", str(unit_path)), "UNIT_NAME_IN_USE")
    enabled = systemctl(binary, "is-enabled", UNIT, check=False)
    require(enabled in ("", "not-found", "disabled"), "UNIT_ALREADY_ENABLED")
    plan = dict(action="install", destination=str(dest), files={str(p): sha(b) for p, b in files.items()},
                before=state, enabled=enabled, fragment=fragment, daemonReload=True, enable=False, start=False)
    digest = sha(canonical(plan))
    if args.mode == "plan":
        return dict(status="PLAN_READY", plan=plan, planSha256=digest)
    require(args.plan_sha256 == digest, "INSTALL_PLAN_CHANGED")
    dest.mkdir(mode=0o700, exist_ok=True)
    for path, raw in files.items():
        publish(path, raw, 0o644 if path == unit_path else 0o600)
    systemctl(binary, "daemon-reload")
    checked_unit(meta)
    require(systemctl(binary, "is-enabled", UNIT, check=False) == "disabled", "UNIT_NOT_DISABLED")
    return dict(status="INSTALLED", planSha256=digest)


def administer(args, dest, commit):
    private_dir(dest)
    manifest = dest / "installation.json"
    custody(manifest)
    meta = json.loads(manifest.read_bytes())
    require(meta["commit"] == commit, "INSTALL_COMMIT_CHANGED")
    if args.mode in ("enable", "disable"):
        checked_unit(meta)
    if args.mode == "disable":
        systemctl(meta["systemctl"], "disable", UNIT)
        require(systemctl(meta["systemctl"], "is-enabled", UNIT, check=False) == "disabled", "DISABLE_UNCONFIRMED")
        return dict(status="DISABLED")
    for path, expected in [(dest / "platform.pyz", sha(archive())), (dest / "boot.sha256", meta["bootBindingsSha256"]),
                           (meta["unit"], meta["unitSha256"]),
                           (meta["python"], meta["pythonSha256"]), (meta["checksum"], meta["checksumSha256"])]:
        require(filehash(path) == expected, "INSTALLED_FILE_CHANGED")
    profile = dest / "profile.json"
    if args.mode == "enable":
        require(filehash(profile) == meta["profileSha256"], "PROFILE_HASH_CHANGED")
        require(args.receipt and re.fullmatch(r"apply-[0-9a-f]{32}\.json", args.receipt), "START_RECEIPT_REQUIRED")
        private_dir(meta["receipts"])
        proof = Path(meta["receipts"]) / args.receipt
        custody(proof)
        record = json.loads(proof.read_bytes())
        require(record.get("schema") == "ouf.platform-restart-receipt.v1" and record.get("mode") == "apply"
                and record.get("action") == "start" and record.get("status") == "SUCCEEDED"
                and record.get("profileSha256") == meta["profileSha256"]
                and record.get("sourceSha256") == meta["sourceSha256"], "START_RECEIPT_REQUIRED")
        systemctl(meta["systemctl"], "enable", UNIT)
        require(systemctl(meta["systemctl"], "is-enabled", UNIT) == "enabled", "ENABLE_UNCONFIRMED")
        return dict(status="ENABLED", receipt=args.receipt)
    require(args.action and args.operation, "OPERATION_REQUIRED")
    command = [meta["python"], "-I", "-B", str(dest / "platform.pyz"), args.operation, "--action", args.action,
               "--profile", str(profile), "--profile-sha256", meta["profileSha256"],
               "--receipts", meta["receipts"], "--incidents", meta["incidents"]]
    if args.plan_sha256:
        command += ["--plan-sha256", args.plan_sha256]
    os.execve(command[0], command, {"LC_ALL": "C"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("commit")
    parser.add_argument("mode", choices=["plan", "apply", "operate", "enable", "disable"])
    parser.add_argument("--dest", required=True)
    for arg in ("profile", "profile-sha256", "unit-dir", "systemctl", "checksum", "plan-sha256", "receipt"):
        parser.add_argument("--" + arg)
    parser.add_argument("--action", choices=["start", "stop"])
    parser.add_argument("--operation", choices=["plan", "apply"])
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "ROOT_REQUIRED")
    dest = safe_path(args.dest)
    if args.mode != "operate":
        # Serialize installation and enablement on the existing root-owned parent.
        import fcntl
        custody(dest.parent, stat.S_ISDIR)
        fd = os.open(dest.parent, os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.mode in ("plan", "apply"):
                result = configure(args, dest, args.commit)
            else:
                result = administer(args, dest, args.commit)
        finally:
            os.close(fd)
    else:
        result = administer(args, dest, args.commit)
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        main()
    except (Held, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(canonical(dict(status="HELD", reason=str(error) if isinstance(error, Held) else "INSTALL_IO_FAILED")).decode(),
              file=sys.stderr)
        sys.exit(1)
