"""Gateway v1 publisher contract. Only verified canonical bytes reach the planner."""
import hashlib
import http.client
import io
import json
import re
import stat
import zipfile
from urllib.parse import urlsplit

from mandate import Held, canonical, digest, github_reader, need
from module_release.contract import Held as SourceHeld
from module_release.provenance import select_artifact


KINDS = ("upstreams", "services", "plugin_configs", "plugin_metadata", "global_rules", "routes")
NAME = r"[A-Za-z][A-Za-z0-9_.-]{0,127}"  # contratto v1 rev. 1: nomi del registro D-065
ID = r"[A-Za-z0-9._-]{1,64}"
LIMIT = 32 << 20


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def fields(obj, names):
    return type(obj) is dict and set(obj) == set(names.split())


def substitute(value, types, values, used):
    if isinstance(value, list):
        return [substitute(item, types, values, used) for item in value]
    if isinstance(value, dict):
        if "$installation" in value:
            name = value["$installation"]
            need(len(value) == 1 and matches(NAME, name) and name in types, "GATEWAY_PLACEHOLDER")
            actual = values.get(name)
            if types[name] == "integer":
                # Contract rev. 2: APISIX numeric fields (upstream ports) need a JSON integer, never a bool.
                need(type(actual) is int, "GATEWAY_INSTALLATION_VALUE")
                used.add(name)
                return actual
            need(isinstance(actual, str), "GATEWAY_INSTALLATION_VALUE")
            if types[name] == "url":
                url = urlsplit(actual)
                need(url.scheme in ("http", "https") and url.hostname, "GATEWAY_INSTALLATION_URL")
            if types[name] == "secret":
                need(actual, "GATEWAY_INSTALLATION_VALUE")
            used.add(name)
            return actual
        return {k: substitute(v, types, values, used) for k, v in value.items()}
    return value


def verify(raw, ci, values):
    need(len(raw) <= LIMIT and sha(raw) == ci["zipSha256"], "GATEWAY_ZIP_DIGEST")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        need(sorted(i.orig_filename for i in members) == ["SHA256SUMS", "bundle.json", "manifest.json"]
             and all(stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG) for i in members)
             and sum(i.file_size for i in members) <= LIMIT, "GATEWAY_ZIP_LAYOUT")
        bundle_raw = archive.read("bundle.json")
        manifest_raw = archive.read("manifest.json")
        sums = f"{sha(bundle_raw)}  bundle.json\n{sha(manifest_raw)}  manifest.json\n"
        need(archive.read("SHA256SUMS") == sums.encode("ascii"), "GATEWAY_CHECKSUMS")
    bundle, manifest = json.loads(bundle_raw), json.loads(manifest_raw)
    need(canonical(bundle) == bundle_raw and canonical(manifest) == manifest_raw, "GATEWAY_CANONICAL_JSON")
    need(fields(bundle, "schema sourceRepository sourceCommit resources placeholders resourcesSha256")
         and bundle["schema"] == "ouf.gateway-release-bundle.v1"
         and bundle["sourceRepository"] == ci["repository"] and bundle["sourceCommit"] == ci["sourceCommit"],
         "GATEWAY_BUNDLE_SCHEMA")
    resources, declarations = bundle["resources"], bundle["placeholders"]
    need(type(resources) is list and digest(resources) == bundle["resourcesSha256"]
         and type(declarations) is list, "GATEWAY_RESOURCES")
    types = {}
    for item in declarations:
        need(fields(item, "name type") and matches(NAME, item["name"])
             and item["name"] not in types and item["type"] in ("string", "url", "secret", "integer"), "GATEWAY_DECLARATION")
        types[item["name"]] = item["type"]
    need(list(types) == sorted(types) and manifest == {
        "schema": "ouf.gateway-release-manifest.v1", "sourceRepository": ci["repository"],
        "sourceCommit": ci["sourceCommit"], "workflowPath": ".github/workflows/" + ci["workflow"],
        "runId": str(ci["runId"]), "bundleSha256": sha(bundle_raw), "resourcesSha256": digest(resources),
        "placeholders": list(types)}, "GATEWAY_MANIFEST")
    result, used = [], set()
    previous = (-1, "")
    for row in resources:
        need(fields(row, "kind id body") and row["kind"] in KINDS and matches(ID, row["id"])
             and row["id"] not in (".", "..") and type(row["body"]) is dict
             and not {"id", "create_time", "update_time", "$installation"}.intersection(row["body"]),
             "GATEWAY_RESOURCE_SCHEMA")
        key = KINDS.index(row["kind"]), row["id"]
        need(key > previous, "GATEWAY_RESOURCE_ORDER")
        previous = key
        result.append({**row, "body": substitute(row["body"], types, values, used)})
    need(used == set(types), "GATEWAY_UNUSED_PLACEHOLDER")
    return result


def download(ci, token):
    # GitHub issues one short-lived HTTPS download URL. The bearer stays at api.github.com.
    conn = http.client.HTTPSConnection("api.github.com", timeout=30)
    try:
        path = f"/repos/{ci['repository']}/actions/artifacts/{ci['artifactId']}/zip"
        conn.request("GET", path, headers={"Authorization": "Bearer " + token, "User-Agent": "ouf-a2-executor"})
        response = conn.getresponse()
        need(response.status == 302, "GATEWAY_DOWNLOAD")
        location = urlsplit(response.getheader("Location") or "")
    finally:
        conn.close()
    need(location.scheme == "https" and location.hostname and location.username is None
         and location.password is None and location.port in (443, None), "GATEWAY_DOWNLOAD")
    conn = http.client.HTTPSConnection(location.hostname, timeout=60)
    try:
        conn.request("GET", location.path + ("?" + location.query if location.query else ""))
        response = conn.getresponse()
        need(response.status == 200, "GATEWAY_DOWNLOAD")
        raw = response.read(LIMIT + 1)
        need(len(raw) <= LIMIT, "GATEWAY_ZIP_SIZE")
        return raw
    finally:
        conn.close()


def package(profile, req, token):
    source = profile["source"]
    ci = dict(repository=source["repository"], workflow=source["workflow"],
              sourceCommit=req["sourceCommit"], pullRequest=int(req["sourcePr"]))
    get = github_reader(ci["repository"], token)
    try:
        ci = select_artifact(ci, int(req["sourceRun"]), int(req["artifact"]), get,
                             artifact_prefix="gateway-release-bundle")
        return ci, verify(download(ci, token), ci, profile["values"])
    except SourceHeld as exc:
        raise Held("GATEWAY_CI_PROVENANCE") from exc
    except (ValueError, zipfile.BadZipFile, KeyError, TypeError, RecursionError) as exc:
        raise Held("GATEWAY_INVALID_ARTIFACT") from exc
