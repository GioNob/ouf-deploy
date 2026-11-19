"""Read-only verification of original module ZIP/go.mod inputs for vendor builds.

Hashes describe original inputs, never patched vendor files. No module cache
files are written, no downloads occur and raw build-info is left unchanged.
"""
import base64
import hashlib
import json
from pathlib import Path
import zipfile

MAX_MODULE_BYTES = 500 << 20
ICEBERG = "github.com/apache/iceberg-go"
ICEBERG_ZIP_SHA256 = "a042ec87708c376362859041b1741213dc4e05400cad7ad0220ea4361a250d55"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def h1_summary(rows):
    summary = "".join(checksum + "  " + name + "\n" for name, checksum in sorted(rows))
    return "h1:" + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def zip_h1(path, module, version):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_MODULE_BYTES,
            "REGULAR_BOUNDED_MODULE_ZIP_REQUIRED")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)) and sum(info.file_size for info in infos) <= MAX_MODULE_BYTES,
                "INVALID_OR_OVERSIZED_MODULE_ZIP")
        prefix = module + "@" + version + "/"
        require(names and all(name.startswith(prefix) and "\n" not in name and "\r" not in name
                              and ".." not in name.split("/") for name in names), "EXACT_MODULE_ZIP_PREFIX_REQUIRED")
        rows = []
        for info in infos:
            with archive.open(info) as stream:
                rows.append((info.filename, hashlib.file_digest(stream, "sha256").hexdigest()))
    return h1_summary(rows)


def parse_records(data):
    """Accept go mod download's concatenated JSON objects or one JSON array."""
    decoder = json.JSONDecoder()
    text = data.decode()
    records = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        records.extend(value if isinstance(value, list) else [value])
    require(all(isinstance(row, dict) for row in records), "MODULE_DOWNLOAD_RECORDS_REQUIRED")
    return records


def collect(build_info, root_go_sum, download_records):
    require(not any(line.startswith("\t=>\t") for line in build_info.splitlines()), "REPLACED_MODULE_ORIGIN_UNSUPPORTED")
    module_rows = [line.split("\t")[2:4] for line in build_info.splitlines() if line.startswith("\tdep\t")]
    require(module_rows and all(len(row) == 2 for row in module_rows), "BINARY_MODULE_INVENTORY_REQUIRED")
    identities = [tuple(row) for row in module_rows]
    require(len(identities) == len(set(identities)) and len({row[0] for row in identities}) == len(identities),
            "DUPLICATE_BINARY_MODULE")
    sums = {}
    for line in root_go_sum.splitlines():
        fields = line.split()
        require(len(fields) == 3, "VALID_GO_SUM_RECORD_REQUIRED")
        key = tuple(fields[:2])
        require(key not in sums or sums[key] == fields[2], "CONFLICTING_GO_SUM_RECORD")
        sums[key] = fields[2]
    rows = []
    for module, version in sorted(identities):
        records = [r for r in download_records if (r.get("Path"), r.get("Version")) == (module, version)]
        require(len(records) == 1 and not records[0].get("Error") and not records[0].get("Replace"),
                "EXACT_ORIGINAL_MODULE_DOWNLOAD_REQUIRED:" + module)
        record = records[0]
        require(record.get("Sum") == sums.get((module, version)) and isinstance(record.get("Sum"), str)
                and record.get("GoModSum") == sums.get((module, version + "/go.mod"))
                and isinstance(record.get("GoModSum"), str), "INPUT_SUM_NOT_IN_LOCK:" + module)
        archive, gomod = Path(record["Zip"]), Path(record["GoMod"])
        require(gomod.is_file() and not gomod.is_symlink(), "REGULAR_MODULE_GOMOD_REQUIRED")
        require(zip_h1(archive, module, version) == record["Sum"], "MODULE_ZIP_H1_MISMATCH:" + module)
        gomod_sha = file_sha(gomod)
        require(h1_summary([("go.mod", gomod_sha)]) == record["GoModSum"], "MODULE_GOMOD_H1_MISMATCH:" + module)
        archive_sha = file_sha(archive)
        if module == ICEBERG:
            require(version == "v0.7.0" and archive_sha == ICEBERG_ZIP_SHA256,
                    "EXACT_ICEBERG_INPUT_ZIP_REQUIRED")
        rows.append({
            "module": module, "version": version,
            "inputZipH1": record["Sum"], "inputGoModH1": record["GoModSum"],
            "inputZipSha256": archive_sha, "inputGoModSha256": gomod_sha,
            "sourceOrigin": record.get("Origin"), "modifiedInVendor": module == ICEBERG,
            "checksumsDescribeOriginalInputsOnly": True,
        })
    return {"schema": "ouf.vendor-original-module-origins.v1", "status": "ORIGINAL_INPUTS_VERIFIED_NOT_RELEASE_ADMITTED",
            "moduleCount": len(rows), "modules": rows, "moduleCacheMutated": False,
            "rootGoSumSha256": sha(root_go_sum.encode()), "buildInfoSha256": sha(build_info.encode())}
