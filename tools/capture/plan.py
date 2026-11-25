"""Classify the inventory before opening any source for capture."""
from fnmatch import fnmatchcase
import os
from pathlib import Path
import stat

from .contract import GIB, MIB, canonical, mapping, require, sha


def file_state(info):
    return [info.st_mode, info.st_uid, info.st_gid, info.st_size if stat.S_ISREG(info.st_mode) else 0,
            info.st_mtime_ns, info.st_nlink if stat.S_ISREG(info.st_mode) else 0]


def file_ref(path):
    return sha(str(path).encode())


def make_plan(host, cfg, entries, profile_path, commit):
    for tool in ("age", "nice", "docker"):
        host.binary(tool)
    inv = host.inventory()
    reasons, files, skipped, families = set(), {}, {}, {}
    unknown = set()
    roots = {Path(k): v for k, v in mapping(cfg["paths"], "path").items()}
    exclusions = {Path(k): v for k, v in mapping(cfg["excludePaths"], "path").items()}
    roots[profile_path] = "capture.profile"
    volumes = mapping(cfg["volumes"], "name")
    # Classify physical backing paths before walking any broader host inclusion.
    for name, _, _, mountpoint in inv["volumes"]:
        entry = volumes.get(name)
        if not entry or not mountpoint:
            continue
        p = Path(mountpoint)
        require(p.is_absolute(), "VOLUME_MOUNTPOINT_REQUIRED")
        kind = entries[entry]["kind"]
        if kind in ("excluded", "postgres-cluster", "etcd-snapshot"):
            require(exclusions.setdefault(p, entry) == entry, "AMBIGUOUS_VOLUME_SOURCE")
        elif kind == "host-path":
            require(roots.setdefault(p, entry) == entry, "AMBIGUOUS_VOLUME_SOURCE")
    databases = mapping(cfg["postgres"]["databases"], "name")
    units = mapping(cfg["units"], "pattern")
    output = Path(cfg["outputDir"])
    if any(output.is_relative_to(p) or p.is_relative_to(output) for p in roots):
        reasons.add("CAPTURE_OUTPUT_OVERLAP")

    def skip(key, entry, reason, size=0):
        skipped[str(key)] = dict(ref=file_ref(key), id=entry, reason=reason, bytes=size)

    def unclassified(kind, value):
        reasons.add("CAPTURE_UNCLASSIFIED")
        unknown.add((kind, file_ref(value)))

    def add(name, ids, size, **counts):
        families[name] = dict(ids=sorted(set(ids)), estimate=size, counts=counts)

    def path_binding(p, rules):
        return next((rules[q] for q in (p, *p.parents) if q in rules), None)

    def skip_path(p, entry):
        reason = {"excluded": "D064", "regenerated": "REGENERATED",
                  "postgres-cluster": "LOGICAL_DUMP", "etcd-snapshot": "LOGICAL_DUMP"}
        skip(p, entry, reason[entries[entry]["kind"]])

    def visit(p, inherited=None):
        if p in files:
            return
        if p == output or p.is_relative_to(output):
            reasons.add("CAPTURE_OUTPUT_OVERLAP")
            return
        excluded = path_binding(p, exclusions)
        if excluded:
            skip_path(p, excluded)
            return
        entry = path_binding(p, roots) or inherited
        if entry is None:
            unclassified("path", p)
            return
        # Refuse a link anywhere above an explicitly discovered root.
        require(all(not q.is_symlink() for q in p.parents), "SOURCE_ANCESTOR_LINK")
        info = p.lstat()
        state = file_state(info)
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, "SOURCE_HARDLINK")
            if info.st_size > cfg["maxFileMiB"] * MIB:
                skip(p, entry, "MAX_FILE", info.st_size)
                return
        elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            reasons.add("CAPTURE_SPECIAL_FILE")
            return
        files[p] = dict(id=entry, state=state, link=os.readlink(p) if p.is_symlink() else "")
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(p.iterdir()):
                visit(child, entry)

    for d in host.unit_dirs:
        if not d.exists():
            continue
        paths = list(d.iterdir())
        for folder in paths.copy():
            if folder.name.endswith((".wants", ".requires")) and folder.is_dir() and not folder.is_symlink():
                paths.extend(folder.iterdir())
        for p in sorted(paths):
            unit = p.name.removesuffix(".d")
            if unit.startswith("ouf-") or p.name == "docker.service.d":
                matches = {v for k, v in units.items() if fnmatchcase(unit, k) or fnmatchcase(p.name, k)}
                registered = {k for k, row in entries.items() for pat in
                              row.get("selector", {}).get("unitPatterns", [])
                              if fnmatchcase(unit, pat) or fnmatchcase(p.name, pat)}
                if registered:
                    matches &= registered
                if len(matches) == 1:
                    roots[p] = matches.pop()
                else:
                    unclassified("unit", p.name)
    if host.sudoers.exists():
        for p in sorted(host.sudoers.iterdir()):
            visit(p)
    for p in sorted(roots):
        visit(p)
    if profile_path not in files:
        reasons.add("CAPTURE_PROFILE_EXCLUDED")
    for p, entry in exclusions.items():
        if os.path.lexists(p):
            skip_path(p, entry)

    volume_ids = set()
    for vol, _, _, mountpoint in inv["volumes"]:
        entry = volumes.get(vol)
        if not entry:
            unclassified("volume", vol)
        elif entries[entry]["kind"] == "excluded":
            skip("volume/" + vol, entry, "D064")
        elif entries[entry]["kind"] == "docker-volume":
            volume_ids.add(entry)
        elif entries[entry]["kind"] == "host-path":
            require(mountpoint and Path(mountpoint) in roots, "VOLUME_MOUNTPOINT_REQUIRED")
        else:
            owner = cfg["postgres"] if entries[entry]["kind"] == "postgres-cluster" else cfg["etcd"]
            mounted = any(c["name"] == owner["container"] and
                          any(m[:2] == ["volume", vol] for m in c["mounts"]) for c in inv["containers"])
            require(mounted, "LOGICAL_VOLUME_SOURCE_MISMATCH")
    for c in inv["containers"]:
        for kind, source, _, _ in c["mounts"]:
            if kind == "bind":
                visit(Path(source))
            elif (kind == "volume" and source not in volumes) or kind not in ("bind", "volume", "tmpfs"):
                unclassified("mount", source or kind)
    if set(volumes) - {v[0] for v in inv["volumes"]}:
        reasons.add("CAPTURE_VOLUME_MISSING")
    db_ids = {cfg["postgres"]["id"]}
    pg_bytes = db_count = 0
    for name, connect, size in inv["databases"]:
        if name not in databases:
            unclassified("database", name)
        else:
            db_ids.add(databases[name])
        require(type(size) is int and size >= 0 and type(connect) is bool, "INVALID_DB_INVENTORY")
        if connect:
            pg_bytes += size
            db_count += 1
        elif name != "template0":
            reasons.add("CAPTURE_DATABASE_INACCESSIBLE")
    if set(databases) != {row[0] for row in inv["databases"]}:
        reasons.add("CAPTURE_DATABASE_DRIFT")
    add("postgres", db_ids, pg_bytes, databases=db_count)
    for rule in cfg["postgres"]["omitTableData"]:
        key = "/".join(rule[field] for field in ("database", "schema", "table"))
        skip("db/" + key, rule["id"], "D064")
    add("etcd", [cfg["etcd"]["id"]], inv["etcdBytes"], snapshots=1)
    local = sorted(key for key, item in inv["images"].items() if not item["digests"])
    inv["exclusionRefs"] = {row["ref"]: key for key, row in skipped.items()}
    inv["registerInstances"] = dict(files={str(p): row["id"] for p, row in files.items()},
                                    databases=databases, volumes=volumes,
                                    localImages={image: cfg["images"]["id"] for image in local})
    add("docker-inventory", [cfg["inventory"]["id"], *volume_ids], len(canonical(inv)),
        containers=len(inv["containers"]), volumes=len(inv["volumes"]), localImages=len(local))
    for i, image in enumerate(local, 1):
        add(f"images-{i}", [cfg["images"]["id"]], inv["images"][image]["size"], images=1)
    if not local:
        skip("images", cfg["images"]["id"], "NO_INSTANCES")
    ordered = {str(p): files[p] for p in sorted(files)}
    tar_bytes = sum(1536 + ((v["state"][3] + 511) // 512) * 512 for v in files.values())
    add("host-files", [f["id"] for f in files.values()], tar_bytes + 10240, files=len(files))
    skip("manifest", "capture.manifest", "GENERATED_MANIFEST")
    covered = {i for f in families.values() for i in f["ids"]} | {s["id"] for s in skipped.values()}
    for row in cfg["absent"]:
        if row["id"] in covered:
            reasons.add("CAPTURE_ABSENCE_CONFLICT")
        skip("absent/" + row["id"], row["id"], row["reason"])
    covered.update(row["id"] for row in cfg["absent"])
    for missing in covered.symmetric_difference(k for k, e in entries.items() if e.get("kind")):
        unclassified("register", missing)
    total = sum(f["estimate"] for f in families.values())
    if total > cfg["maxTotalGiB"] * GIB:
        reasons.add("CAPTURE_TOTAL_CAP")
    plan = dict(version="1", commit=commit, bootId=host.boot_id(), profileSha256=sha(canonical(cfg)),
                registerSha256=sha(canonical(entries)), inventory=inv, files=ordered, localImages=local,
                families=families, excluded=sorted(skipped.values(), key=lambda e: e["ref"]),
                reasons=sorted(reasons), unclassified=sorted(unknown), estimatedBytes=total)
    return plan, sha(canonical(plan))
