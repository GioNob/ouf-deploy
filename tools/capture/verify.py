"""Portable off-host verification. Archive members are inspected, never extracted."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

from .apply import valid_cipher
from .contract import CHUNK, canonical, read_json, require, sha

BASE = {"postgres": "postgres", "etcd": "etcd", "docker-inventory": "inventory", "host-files": "paths"}
HASH = re.compile(r"[0-9a-f]{64}")


def check_manifest(document, entries):
    require(document["schema"] == "ouf.capture-manifest.v1" and document["complete"] is True
            and document["version"] == "1" and document["registerSha256"] == sha(canonical(entries))
            and HASH.fullmatch(document["planSha256"]), "MANIFEST_CONTRACT")
    rows, families = document["archives"], document["families"]
    require(rows.keys() == families.keys() and BASE.keys() <= rows.keys(), "MISSING_FAMILY")
    covered = set()
    for name, row in rows.items():
        image = re.fullmatch(r"images-([1-9][0-9]*)", name)
        require(name in BASE or image, "UNKNOWN_FAMILY")
        family = families[name]
        ids, counts = row["ids"], row["counts"]
        require(ids and ids == family["ids"] and counts == family["counts"], "ARCHIVE_CONTRACT")
        require(all(k in entries and "kind" in entries[k] for k in ids), "REGISTER_COVERAGE")
        bindings = {b for k in ids for b in entries[k]["selector"]["bindings"]}
        expected = BASE.get(name, "images")
        require(expected in bindings and all(type(n) is int and n >= 0 for n in counts.values()),
                "FAMILY_BINDING")
        kinds = {entries[k]["kind"] for k in ids}
        allowed = {"postgres": {"postgres-cluster", "iam-realm"},
                   "etcd": {"etcd-snapshot"}, "docker-inventory": {"docker-inventory", "docker-volume"},
                   "host-files": {"host-path", "systemd-unit"}}
        require(kinds <= allowed.get(name, {"docker-image"}), "FAMILY_BINDING")
        if name == "postgres":
            require("iam-realm" in kinds, "IAM_DATABASE_REQUIRED")
        require(all(type(row[k]) is int and row[k] > 0 for k in ("plainBytes", "cipherBytes"))
                and all(HASH.fullmatch(row[k]) for k in ("plainSha256", "cipherSha256")), "ARCHIVE_CONTRACT")
        covered.update(ids)
    count = rows["docker-inventory"]["counts"]["localImages"]
    require(count == len(rows) - len(BASE) and
            all(f"images-{i+1}" in rows for i in range(count)),
            "MISSING_IMAGE_FAMILY")
    for excluded in document["excluded"]:
        entry = entries.get(excluded["id"], {})
        reason = excluded["reason"]
        allowed = {"MAX_FILE", "NOT_INSTALLED", "NO_INSTANCES"}
        if entry.get("kind") == "regenerated":
            allowed.add("REGENERATED")
        if entry.get("kind") == "excluded":
            allowed.add("D064")
        if entry.get("kind") in ("postgres-cluster", "etcd-snapshot"):
            allowed.add("LOGICAL_DUMP")
        if excluded["id"] == "capture.manifest":
            allowed.add("GENERATED_MANIFEST")
        require(HASH.fullmatch(excluded["ref"]) and reason in allowed, "INVALID_EXCLUSION")
        covered.add(excluded["id"])
    require(covered == {k for k, e in entries.items() if e.get("kind")}, "REGISTER_COVERAGE")


def sql_structure(path, expected):
    databases = 0
    last_marker = None
    with path.open("rb") as stream:
        while line := stream.readline(65536):
            if not line.endswith(b"\n") and len(line) == 65536:
                while line and not line.endswith(b"\n"):
                    line = stream.readline(65536)
                continue
            line = line.strip()
            if line == b"-- PostgreSQL database dump complete":
                databases += 1
            if line and line != b"--" and not line.startswith(b"\\unrestrict "):
                last_marker = line
    require(databases == expected and last_marker == b"-- PostgreSQL database cluster dump complete",
            "INVALID_POSTGRES_DUMP")


def image_structure(archive):
    files = {m.name.removeprefix("./"): m for m in archive if m.isfile()}

    def metadata(name):
        require(name in files and files[name].size <= 16 * 1024 ** 2, "INVALID_IMAGE_MANIFEST")
        return json.load(archive.extractfile(files[name]))

    if "manifest.json" in files and "oci-layout" not in files:
        manifest = metadata("manifest.json")
        require(isinstance(manifest, list) and len(manifest) > 0, "INVALID_IMAGE_MANIFEST")
        for row in manifest:
            require(isinstance(row["Layers"], list) and row["Config"] in files
                    and all(layer in files for layer in row["Layers"]), "INVALID_IMAGE_LAYER")
            config = metadata(row["Config"])
            roots = config["rootfs"]
            require(config["architecture"] and config["os"] and roots["type"] == "layers"
                    and len(roots["diff_ids"]) == len(row["Layers"]), "INVALID_IMAGE_CONFIG")
            for layer, expected in zip(row["Layers"], roots["diff_ids"]):
                # Legacy docker save contains uncompressed layer tars. Hybrid archives
                # use the OCI descriptor graph below, including compressed blobs.
                with archive.extractfile(files[layer]) as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    require(expected == "sha256:" + digest, "INVALID_IMAGE_LAYER")
                    stream.seek(0)
                    with tarfile.open(fileobj=stream, mode="r|") as inner:
                        for _ in inner:
                            pass
    else:
        require(metadata("oci-layout")["imageLayoutVersion"] == "1.0.0", "INVALID_OCI_LAYOUT")
        visited = set()

        def descriptor(desc, depth):
            digest = desc["digest"]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) and depth < 12, "INVALID_OCI_DIGEST")
            name = "blobs/sha256/" + digest[7:]
            require(name in files and desc["size"] == files[name].size, "INVALID_IMAGE_LAYER")
            if name in visited:
                return
            visited.add(name)
            with archive.extractfile(files[name]) as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == digest[7:],
                        "INVALID_OCI_DIGEST")
            if "manifest" in desc["mediaType"] or "index" in desc["mediaType"]:
                node = metadata(name)
                require(node.get("schemaVersion") == 2, "INVALID_OCI_MANIFEST")
                children = node["manifests"] if "manifests" in node else [node["config"], *node["layers"]]
                require(children, "INVALID_OCI_MANIFEST")
                for child in children:
                    descriptor(child, depth + 1)
        index = metadata("index.json")
        require(index["schemaVersion"] == 2 and index["manifests"], "INVALID_OCI_INDEX")
        for desc in index["manifests"]:
            require("manifest" in desc["mediaType"] or "index" in desc["mediaType"], "INVALID_OCI_INDEX")
            descriptor(desc, 0)


def structure(name, path, counts):
    if name == "postgres":
        sql_structure(path, counts["databases"])
    elif name == "etcd":
        with path.open("rb") as stream:
            header = stream.read(24)
        # bbolt meta page: little-endian magic 0xed0cdaed, version 2.
        require(header[16:24] == bytes.fromhex("edda0ced02000000"), "INVALID_ETCD_HEADER")
    elif name == "docker-inventory":
        inv = read_json(path)
        require(len(inv["containers"]) == counts["containers"] and len(inv["volumes"]) == counts["volumes"]
                and sum(not i["digests"] for i in inv["images"].values()) == counts["localImages"],
                "INVALID_INVENTORY")
    else:
        with tarfile.open(path, "r:") as archive:
            if name == "host-files":
                names = set()
                for item in archive:
                    p = PurePosixPath(item.name)
                    require(not p.is_absolute() and ".." not in p.parts and p not in names
                            and (item.isfile() or item.isdir() or item.issym()), "INVALID_HOST_ARCHIVE")
                    names.add(p)
                require(len(names) == counts["files"], "FILE_COUNT_CHANGED")
            else:
                image_structure(archive)


def decrypt(binary, identity, source, path, row):
    with subprocess.Popen([str(binary), "-d", "-i", str(identity), str(source)], stdin=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, stdout=subprocess.PIPE) as child:
        size = 0
        digest = hashlib.sha256()
        try:
            with path.open("xb") as target:
                while chunk := child.stdout.read(CHUNK):
                    size += len(chunk)
                    require(size <= row["plainBytes"], "PLAIN_SIZE_MISMATCH")
                    digest.update(chunk)
                    target.write(chunk)
            require(child.wait() == 0, "DECRYPT_FAILED")
        finally:
            if child.poll() is None:
                child.kill()
    require(size == row["plainBytes"] and digest.hexdigest() == row["plainSha256"], "PLAIN_MISMATCH")


def verify(folder, entries, identity=None, age="age"):
    document = read_json(folder / "manifest.json")
    check_manifest(document, entries)
    require(all(p.stem in document["archives"] for p in folder.glob("*.age")), "UNKNOWN_ARCHIVE")
    result = {}
    for name, row in document["archives"].items():
        source = folder / (name + ".age")
        valid_cipher(source, row)
        if identity is not None:
            with tempfile.TemporaryDirectory() as private:
                plain = Path(private) / "archive"
                decrypt(age, identity, source, plain, row)
                structure(name, plain, row["counts"])
        result[name] = dict(bytes=row["cipherBytes"], counts=row["counts"], status="OK")
    return result
