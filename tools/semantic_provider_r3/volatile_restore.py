"""D-047: closed, upper-only APISIX cleanup before a governed R3 start.

Predictions use the historical sealer's records/encoder. Verification always
runs its unchanged walker, including on Docker's held stopped-export view.
No accepted seal, installed closure, epoch, or container configuration is written.
"""
from contextlib import contextmanager, ExitStack
from collections import Counter
import copy
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

from tools.semantic_provider_r3 import install_common as I

require, canonical, sha = I.require, I.canonical, I.sha
DENIED = "R3_VOLATILE_UNDECLARED_ENTRY"
MISMATCH = "R3_VOLATILE_RESTORE_SEAL_MISMATCH"
TEMPS = tuple("usr/local/apisix/" + p for p in
              ("fastcgi_temp", "scgi_temp", "client_body_temp", "proxy_temp", "uwsgi_temp"))
FILES = ("usr/local/apisix/conf/nginx.conf", "usr/local/apisix/conf/apisix.uid")
LINK = "usr/local/apisix/conf/apisix.yaml"
TARGET = "/run/ouf-southbound-runtime/apisix.yaml"
COPYUPS = ("usr", "usr/local", "usr/local/apisix", "usr/local/apisix/conf")
MAX_ENTRIES, MAX_BYTES, MAX_DEPTH = 10000, 256 * 1024 * 1024, 8
IMPURE, ORIGIN = "trusted.overlay.impure", "trusted.overlay.origin"
IMPURE_ROW = "overlay-impure-xattr"


def parent_of(path):
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def historical():
    """Import the delivered v3 unchanged (and its unchanged v1 dependencies)."""
    path = I.ROOT / "scripts/prepare-semantic-provider-b1-rootfs-v3.py"
    spec = importlib.util.spec_from_file_location("r3_volatile_rootfs_v3", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def idle(observation):
    rows = observation["candidates"]
    require(set(rows) == {"adapter", "southbound"}, "R3_VOLATILE_IDLE_REQUIRED")
    require(all(v["docker"]["Status"] in {"created", "exited"}
                and v["docker"]["Running"] is False and v["docker"]["Pid"] == 0
                and (v["epoch"] is None or v["epoch"]["state"] in {"DELETED", "FAILED", "ABANDONED"}
                     and v["epoch"].get("live") is False) for v in rows.values()),
            "R3_VOLATILE_IDLE_REQUIRED")


def unmounted(snapshot, rows):
    """Also reject nested/bind mounts and another overlay using this upper."""
    protected = (snapshot["root"], snapshot["upper"])
    for row in rows:
        target = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), row["target"])
        require(not any(target == p or target.startswith(p + "/") for p in protected),
                "R3_VOLATILE_OVERLAY_MOUNTED")
        for option in row["super"]:
            key, _, value = option.partition("=")
            value = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
            if key in {"upperdir", "lowerdir", "workdir"}:
                require(not any(p == snapshot["upper"] or p.startswith(snapshot["upper"] + "/")
                                for p in value.split(":")), "R3_VOLATILE_OVERLAY_MOUNTED")


def volatile(path):
    return next((p for p in TEMPS if path == p or path.startswith(p + "/")), None)


def validate_entry(path, entry, image, user, physical):
    """All removable entries are metadata-constrained; never infer user 636."""
    try:
        normalized = physical(entry, new=path not in COPYUPS)
    except Exception:
        require(False, DENIED)
    if path in COPYUPS:
        expected = image.get(path)
        require(expected is not None and expected["kind"] == entry["kind"] == "directory"
                and all(normalized[k] == expected[k] for k in ("mode", "uid", "gid", "xattrs")), DENIED)
        return
    require((entry["uid"], entry["gid"]) == (user["uid"], user["gid"])
            and entry["mode"] & 0o7000 == 0, DENIED)
    temp = volatile(path)
    if temp:
        require(entry["kind"] in {"directory", "file"}
                and (path != temp or entry["kind"] == "directory")
                and len(PurePosixPath(path).parts) - len(PurePosixPath(temp).parts) <= MAX_DEPTH, DENIED)
    elif path in FILES:
        require(entry["kind"] == "file" and entry["links"] == 1 and entry["size"] <= 1048576, DENIED)
    elif path == LINK:
        require(entry["kind"] == "symlink" and entry["target"] == TARGET
                and entry["links"] == 1, DENIED)
    else:
        require(False, DENIED)


def predicted_seal(records, encoder):
    """Exact historical framing/order; prediction only, never an accepted seal."""
    digest = hashlib.sha256(b"OUF-ROOTFS-SEAL\x00V1\x00")
    total = 0
    # Input is insertion-ordered by the unchanged historical depth-first walker.
    for entry in records.values():
        raw = encoder(entry)
        digest.update(len(raw).to_bytes(4, "big")); digest.update(raw)
        if entry["kind"] == "file":
            total += entry["size"]
    return dict(schema="ouf.semantic-rootfs-seal.v1", sha256=digest.hexdigest(), entries=len(records), bytes=total)


def removals(upper, image, user, expected, encoder, physical):
    """Prove the entire projected upper seal before the first unlink."""
    selected = set()
    count = size = 0
    directory_children = Counter(str(PurePosixPath(p).parent) for p, v in upper.items()
                                 if p and v["kind"] == "directory")
    for path, entry in upper.items():
        if volatile(path) or path in FILES or path == LINK:
            # An allowlisted name must not replace an image entry.
            require(path not in image, DENIED)
            validate_entry(path, entry, image, user, physical)
            if entry["kind"] == "directory":
                require(entry["links"] == 2 + directory_children[path], DENIED)
            selected.add(path)
            if volatile(path):
                count += 1
                size += entry.get("size", 0)
                require(count <= MAX_ENTRIES and size <= MAX_BYTES, DENIED)
    # Copy-ups are optional, removed only if empty after child removals.
    for path in reversed(COPYUPS):
        if path not in upper:
            continue
        validate_entry(path, upper[path], image, user, physical)
        require(upper[path]["links"] == 2 + directory_children[path], DENIED)
        if not any(p != path and p.startswith(path + "/") and p not in selected for p in upper):
            selected.add(path)
    projected = copy.deepcopy(upper)
    for path in selected:
        del projected[path]
    removed_children = Counter(str(PurePosixPath(p).parent) for p in selected if upper[p]["kind"] == "directory")
    for path, entry in projected.items():
        if entry["kind"] == "directory":
            entry["links"] -= removed_children[path or "."]
    # Copy-up into an upper directory makes the kernel mark that parent impure.
    # Once the copied-up children are gone, the marker is cleared only where no
    # remaining child carries an origin: the exact seal proof below still decides.
    cleared = []
    for parent in sorted({parent_of(p) for p in selected} - selected):
        entry = projected.get(parent)
        if entry is None or entry["kind"] != "directory" or IMPURE not in entry["xattrs"]:
            continue
        if any(ORIGIN in projected[c]["xattrs"] for c in projected if c and parent_of(c) == parent):
            continue
        del entry["xattrs"][IMPURE]
        cleared.append(parent)
    require(predicted_seal(projected, encoder) == expected, DENIED)
    return [{"path": p, "kind": upper[p]["kind"]} for p in
            sorted(selected, key=lambda p: (-len(PurePosixPath(p).parts), p))] + \
           [{"path": p, "kind": IMPURE_ROW} for p in cleared]


@contextmanager
def held_tree(root, directory_fd, mount_rows, snapshot):
    """Pin and inventory every entry via no-follow descriptors, without contents.

    Inventory precedes historical hashing, bounding volatile bytes before reads.
    Refuse mount crossings, including same-device bind mounts via mountinfo.
    """
    unmounted(snapshot, mount_rows())
    with ExitStack() as stack:
        base = stack.enter_context(directory_fd(root))
        device = os.fstat(base).st_dev
        held = {}
        count = total = 0
        def walk(fd, path):
            nonlocal count, total
            require(len(held) < 100000 and len(PurePosixPath(path).parts) <= 64, DENIED)
            held[path] = (fd, os.fstat(fd))
            for name in sorted(os.listdir(fd)):
                child = path + "/" + name if path else name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(info.st_dev == device, DENIED)
                require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), DENIED)
                if volatile(child):
                    count += 1; total += info.st_size if stat.S_ISREG(info.st_mode) else 0
                    require(count <= MAX_ENTRIES and total <= MAX_BYTES
                            and len(PurePosixPath(child).parts) - len(PurePosixPath(volatile(child)).parts) <= MAX_DEPTH
                            and not stat.S_ISLNK(info.st_mode), DENIED)
                if stat.S_ISDIR(info.st_mode):
                    nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    stack.callback(os.close, nested)
                    require(identity(info) == identity(os.fstat(nested)), DENIED)
                    walk(nested, child)
                else:
                    held[child] = (None, info)
        walk(base, "")
        yield held


def identity(info):
    return tuple(getattr(info, k) for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def inspect_upper(context):
    H, snapshot = context["historical"], context["comparison"]["snapshot"]
    with held_tree(Path(snapshot["upper"]), H.directory_fd, H.mount_rows, snapshot):
        try:
            seal, upper = H.entries(context["sealer"], Path(snapshot["upper"]), context["limits"])
        except Exception:
            require(False, DENIED)
    return seal, upper


@contextmanager
def export_view(args, context):
    """Historical observation transport; works before the claim directory exists."""
    output = Path(args.output_directory)
    config = output.with_name(output.name + ".volatile-docker-config-absent")
    require(not os.path.lexists(config), "R3_VOLATILE_CONFIG_PRESENT")
    H, snapshot = context["historical"], context["comparison"]["snapshot"]
    try:
        with H.V1.stopped_export_view((args.docker, args.docker_sha256), args.docker_socket,
                                      config, context["cid"], Path(snapshot["root"])) as root:
            yield root
    finally:
        require(not os.path.lexists(config), "R3_VOLATILE_CONFIG_PRESENT")


def confirm_snapshot(args, context):
    """Bind CURRENT Engine snapshot before admitting any upper-layer mutation."""
    H, snapshot = context["historical"], context["comparison"]["snapshot"]
    unmounted(snapshot, H.mount_rows())
    with export_view(args, context) as root:
        require(H.overlay_binding(root, Path(context["dockerRoot"])) == snapshot,
                "R3_VOLATILE_SNAPSHOT_DRIFT")
    unmounted(snapshot, H.mount_rows())


def load(args, observation):
    idle(observation)
    require(all(getattr(args, k, None) is not None for k in
                ("volatile_rootfs_result", "volatile_rootfs_result_sha256", "volatile_source")),
            "R3_VOLATILE_INPUTS_REQUIRED")
    H, reader = historical(), I.Reader()
    result = H.decode(reader.read(args.volatile_rootfs_result, args.volatile_rootfs_result_sha256))
    require(result["status"] == H.PREPARED and result["rule"] == "D-042", "R3_VOLATILE_ROOTFS_RESULT_REQUIRED")
    wrapper = I.native_switch().custody(args.wrapper, 0o755)[0]
    require(sha(wrapper) == args.wrapper_sha256, "R3_WRAPPER_DRIFT")
    code_root = I.wrapper_code_root(Path(args.install_root), wrapper)
    cfg = I.C.document(reader.read(code_root / "runtime-configuration.json", observation["configurationSha256"]))
    require(result["engine"]["dockerSocket"] == args.docker_socket, "R3_VOLATILE_ENGINE_DRIFT")
    contexts = {}
    with I.module_scope():
        sealer = H.load_sealer(Path(args.volatile_source), result["sourceManifestSha256"])
    for role in ("adapter", "southbound"):
        rf = result["roles"][role]
        cid = observation["candidates"][role]["cid"]
        broker = I.C.document(reader.bound(cfg["admissionConfigurations"][cid]))
        accepted = I.C.document(reader.bound(broker["rootfsSealBinding"]))
        comparison = H.decode(reader.bound(rf["comparison"]))
        policy = I.C.document(reader.bound(broker["framePolicyBinding"]))
        oci = H.decode(reader.bound(comparison["ociConfig"]))
        require(rf["containerId"] == comparison["containerId"] == cid
                and rf["imageId"] == comparison["imageId"]
                and comparison["rule"] == "D-042"
                and rf["effectiveSeal"] == accepted == comparison["effectiveSeal"] == comparison["expectedSeal"]
                and oci == policy["expectedOci"], "R3_VOLATILE_ACCEPTANCE_DRIFT")
        snapshot = comparison["snapshot"]
        docker_root = Path(result["engine"]["dockerRoot"])
        require(snapshot["root"] == oci["root"]["path"] == str(docker_root / "rootfs/overlayfs" / cid),
                "R3_VOLATILE_SNAPSHOT_DRIFT")
        # Reuse v3's exact path/options/layout validator on the retained mount row.
        row = dict(target=snapshot["root"], type="overlay", options=[], super=snapshot["options"])
        validator = types.FunctionType(H.overlay_binding.__code__,
            {**H.overlay_binding.__globals__, "mount_rows": lambda: [row]})
        require(validator(Path(snapshot["root"]), docker_root) == snapshot, "R3_VOLATILE_SNAPSHOT_DRIFT")
        unmounted(snapshot, H.mount_rows())
        receipt = H.decode(reader.bound(rf["offlineDockerReceipt"]))
        limits = receipt["rootfsLimits"]
        require(limits == broker["rootfsLimits"], "R3_VOLATILE_LIMITS_DRIFT")
        image_path = Path(rf["offlineDockerReceipt"]["path"]).parent / "bundle/rootfs"
        image_seal, image = H.entries(sealer, image_path, limits)
        require(image_seal == receipt["rootfsSeal"], "R3_VOLATILE_IMAGE_DRIFT")
        user = oci["process"]["user"]
        require(all(type(user[k]) is int and 0 <= user[k] <= 4294967295 for k in ("uid", "gid")), DENIED)
        contexts[role] = dict(historical=H, sealer=sealer, comparison=comparison, limits=limits,
                              image=image, user=user, expected=accepted, cid=cid,
                              sourceRoot=args.volatile_source, dockerRoot=str(docker_root))
    reader.verify()
    for context in contexts.values():
        confirm_snapshot(args, context)
    reader.verify()
    return contexts, reader


def describe(contexts, reader):
    roles = {}
    for role, context in contexts.items():
        seal, upper = inspect_upper(context)
        comparison = context["comparison"]
        expected = comparison["expectedUpperSeal"]
        rows = removals(upper, context["image"], context["user"], expected,
                        context["sealer"].__globals__["encoded"], context["historical"].physical
                        ) if role == "southbound" and seal != expected else []
        if role == "adapter":
            require(seal == expected, DENIED)
        roles[role] = dict(snapshot=comparison["snapshot"], upperSeal=seal, expectedUpperSeal=expected,
                           effectiveSeal=context["expected"], removals=rows)
    reader.verify()
    return dict(rule="D-047", sourceRoot=contexts["southbound"]["sourceRoot"],
                inputHashes=reader.hashes.copy(), roles=roles)


def plan(args, observation):
    return describe(*load(args, observation))


def remove(context, rows, output, report):
    """Full revalidation while descriptors are pinned, then relative unlink/rmdir."""
    H, snapshot = context["historical"], context["comparison"]["snapshot"]
    with held_tree(Path(snapshot["upper"]), H.directory_fd, H.mount_rows, snapshot) as held:
        seal, _ = H.entries(context["sealer"], Path(snapshot["upper"]), context["limits"])
        require(seal == context["beforeSeal"], "R3_PLAN_DIGEST_CHANGED")
        for path, (fd, before) in held.items():
            if not path:
                continue
            parent = str(PurePosixPath(path).parent)
            parent = "" if parent == "." else parent
            current = os.stat(PurePosixPath(path).name, dir_fd=held[parent][0], follow_symlinks=False)
            require(identity(current) == identity(before), DENIED)
            if fd is not None:
                require(identity(os.fstat(fd)) == identity(before), DENIED)
        unmounted(snapshot, H.mount_rows())
        unlinked = {}
        for row in rows:
            if row["kind"] == IMPURE_ROW:
                # Pinned directory descriptor; only the kernel bookkeeping marker is removed.
                fd = held[row["path"]][0]
                require(fd is not None and IMPURE in os.listxattr(fd), DENIED)
                os.removexattr(fd, IMPURE)
                report["volatileEntriesRemoved"] += 1
                report.setdefault("volatileRemovals", []).append(row)
                I.write_once(output / ("volatile-removal-%05d.json" % report["volatileEntriesRemoved"]),
                             canonical(row), report)
                os.fsync(fd)
                continue
            path = PurePosixPath(row["path"])
            parent = "" if str(path.parent) == "." else str(path.parent)
            fd = held[parent][0]
            current = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            before = held[str(path)][1]
            # Directory size/link/timestamps change as declared children disappear.
            require((current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid)
                    == (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid), DENIED)
            if row["kind"] == "directory":
                require(not os.listdir(held[str(path)][0]), DENIED)
                os.rmdir(path.name, dir_fd=fd)
            else:
                key = (before.st_dev, before.st_ino)
                previous = unlinked.get(key, 0)
                # A declared regular hardlink inside a temp tree may have lost
                # siblings during this apply. Only our own unlink count is
                # allowed to change its nlink/ctime; all other fields stay exact.
                if previous:
                    require(row["kind"] == "file" and current.st_nlink == before.st_nlink - previous
                            and current.st_size == before.st_size and current.st_mtime_ns == before.st_mtime_ns, DENIED)
                else:
                    require(identity(current) == identity(before), DENIED)
                os.unlink(path.name, dir_fd=fd)
                unlinked[key] = previous + 1
            report["volatileEntriesRemoved"] += 1
            report.setdefault("volatileRemovals", []).append(row)
            I.write_once(output / ("volatile-removal-%05d.json" % report["volatileEntriesRemoved"]), canonical(row), report)
            os.fsync(fd)


def verify(args, context):
    H, snapshot = context["historical"], context["comparison"]["snapshot"]
    unmounted(snapshot, H.mount_rows())
    def seal(path):
        try:
            return H.entries(context["sealer"], path, context["limits"])[0]
        except Exception:
            require(False, MISMATCH)
    upper = seal(Path(snapshot["upper"]))
    require(upper == context["comparison"]["expectedUpperSeal"], MISMATCH)
    with export_view(args, context) as root:
        require(H.overlay_binding(root, Path(context["dockerRoot"])) == snapshot, MISMATCH)
        merged = seal(root)
        require(merged == context["expected"], MISMATCH)
    unmounted(snapshot, H.mount_rows())
    require(seal(Path(snapshot["upper"])) == upper, MISMATCH)
    return dict(upperSeal=upper, effectiveSeal=merged)


def apply(args, observation, expected, report, reobserve):
    with I.operation_locks(Path(args.install_root), [v["cid"] for v in observation["candidates"].values()]):
        current = reobserve()
        require(current == observation, "R3_PLAN_DIGEST_CHANGED")
        contexts, reader = load(args, current)
        require(describe(contexts, reader) == expected, "R3_PLAN_DIGEST_CHANGED")
        for role, context in contexts.items():
            context["beforeSeal"] = expected["roles"][role]["upperSeal"]
        # Both roles and all inputs have been validated before the first deletion.
        require(reobserve() == observation, "R3_PLAN_DIGEST_CHANGED")
        reader.verify()
        remove(contexts["southbound"], expected["roles"]["southbound"]["removals"], Path(args.output_directory), report)
        report["volatileVerification"] = {}
        for role, context in contexts.items():
            report["volatileVerification"][role] = verify(args, context)
        reader.verify()
        require(reobserve() == observation, "R3_PLAN_DIGEST_CHANGED")
