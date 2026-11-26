"""Unprivileged transport of the reviewed module CI ZIP. Python standard library only: no gh CLI on the host."""

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from .contract import SEMANTIC_SCHEMA, Held, checksum, package, require, validate_ci
from .provenance import select_artifact, verify_tested_tree


API_LIMIT = 4 << 20
CHUNK = 1 << 20


def _token():
    token = os.environ.get("GH_TOKEN", "")
    require(re.fullmatch(r"[A-Za-z0-9_.-]{1,4095}", token) is not None, "TRANSPORT_TOKEN_REQUIRED")
    return token


def github(path, output=None):
    """GET api.github.com/<path>: JSON, or stream an artifact ZIP to output through one HTTPS redirect.

    The bearer goes only to api.github.com; the short-lived download URL is fetched without it.
    """
    require(re.fullmatch(r"repos/[\w.-]+/[\w.-]+/[\w./-]+", path) is not None and ".." not in path,
            "TRANSPORT_API_PATH")
    headers = {"Authorization": "Bearer " + _token(), "User-Agent": "ouf-module-release-transport",
               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    conn = http.client.HTTPSConnection("api.github.com", timeout=60)
    try:
        conn.request("GET", "/" + path, headers=headers)
        response = conn.getresponse()
        if output is None:
            require(response.status == 200, "TRANSPORT_GITHUB_API")
            raw = response.read(API_LIMIT + 1)
            require(len(raw) <= API_LIMIT, "TRANSPORT_GITHUB_API")
            return json.loads(raw)
        require(response.status == 302, "TRANSPORT_DOWNLOAD")
        location = urlsplit(response.getheader("Location") or "")
    finally:
        conn.close()
    require(location.scheme == "https" and bool(location.hostname) and location.username is None
            and location.password is None and location.port in (443, None), "TRANSPORT_DOWNLOAD")
    conn = http.client.HTTPSConnection(location.hostname, timeout=360)
    try:
        conn.request("GET", location.path + ("?" + location.query if location.query else ""),
                     headers={"User-Agent": "ouf-module-release-transport"})
        response = conn.getresponse()
        require(response.status == 200, "TRANSPORT_DOWNLOAD")
        while True:
            chunk = response.read(CHUNK)
            if not chunk:
                break
            output.write(chunk)
    finally:
        conn.close()


def select(ci, run_id, artifact_id, api, *, artifact_prefix=None):
    prefix = "repos/" + ci["repository"]
    if artifact_prefix is None:
        if "artifactPrefix" in ci or ci.get("publisherFormat") or ci.get("manifestSchema") == SEMANTIC_SCHEMA:
            artifact_prefix = ci["artifactPrefix"]
        else:
            artifact_prefix = "source-onboarding-governed-image"
    return select_artifact(ci, run_id, artifact_id, lambda path: api(prefix + path),
                           artifact_prefix=artifact_prefix)


def transport(profile, run_id, artifact_id, inbox):
    ci = select(profile["ci"], run_id, artifact_id, github)
    pinned = profile.get("module") in ("udp", "ingestion")
    if pinned:
        validate_ci(profile["ci"])
        require(all(ci[k] == profile["ci"][k] for k in ("runId", "runAttempt", "artifactId", "zipSha256")),
                "TRANSPORT_PIN_CHANGED")
    prefix = "repos/" + ci["repository"]
    require(inbox.is_absolute() and inbox.is_dir(), "TRANSPORT_INBOX_REQUIRED")
    with tempfile.TemporaryDirectory(dir=inbox) as tmp:
        path = Path(tmp) / (ci["zipSha256"] + ".zip")
        with path.open("xb") as out:
            github(f"{prefix}/actions/artifacts/{artifact_id}/zip", out)
            out.flush()
            os.fsync(out.fileno())
        receipt = package({"ci": ci, "inbox": tmp}, transport=not pinned, migrations_field=profile.get("migrationsField"))
        verify_tested_tree(ci, receipt, lambda path: github(prefix + path))
        final = inbox / path.name
        try:
            os.link(path, final)
        except FileExistsError:
            with final.open("rb") as existing:
                require(checksum(existing) == ci["zipSha256"], "EXISTING_TRANSPORT_CHANGED")
    fields = ("repository", "sourceCommit", "sourceTree", "runId", "runAttempt", "artifactId", "zipSha256")
    if ci.get("publisherFormat") == "acquisition-mcp":
        fields += ("workflow", "pullRequest", "sourceBranch")
    return {k: ci[k] for k in fields} | receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", choices=("udp", "ingestion"))
    parser.add_argument("profile", type=Path)
    parser.add_argument("run_id", type=int)
    parser.add_argument("artifact_id", type=int)
    parser.add_argument("inbox", type=Path)
    args = parse_admitted_args(parser, argv)
    try:
        profile = args.profile_data if hasattr(args, "profile_data") else read_admitted_profile(args.profile)
        require(args.module is None or profile.get("module") == args.module, "MODULE_PROFILE_MISMATCH")
        print(json.dumps(transport(profile, args.run_id,
                                   args.artifact_id, args.inbox), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, Held) else "TRANSPORT_IO_OR_INPUT_ERROR") from None


from .contract import validate_profile_options

_transport = transport


def transport(profile, run_id, artifact_id, inbox):
    validate_profile_options(profile)
    return _transport(profile, run_id, artifact_id, inbox)


def read_admitted_profile(path):
    profile = json.loads(path.read_text(encoding="utf-8"))
    validate_profile_options(profile)
    return profile


def parse_admitted_args(parser, argv):
    # Locate the profile even when later positional arguments are missing or invalid.
    locator = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    locator.add_argument("--module")
    locator.add_argument("profile", nargs="?", type=Path)
    try:
        hint, _ = locator.parse_known_args(argv)
    except argparse.ArgumentError:
        return parser.parse_args(argv)
    args = argparse.Namespace()
    if hint.profile is not None:
        try:
            args.profile_data = read_admitted_profile(hint.profile)
        except (OSError, ValueError, RecursionError):
            pass  # The full parser owns argument diagnostics.
        except Held as error:
            raise SystemExit(str(error)) from None
    return parser.parse_args(argv, namespace=args)


if __name__ == "__main__":
    main()
