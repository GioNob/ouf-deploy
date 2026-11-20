"""Unprivileged transport of the reviewed module CI ZIP. Requires gh on the runner."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .contract import SEMANTIC_SCHEMA, Held, checksum, package, require
from .provenance import select_artifact, verify_tested_tree


def github(path, output=None):
    result = subprocess.run(["gh", "api", path], stdout=output or subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=360)
    if output is None:
        return json.loads(result.stdout)


def select(ci, run_id, artifact_id, api, *, artifact_prefix=None):
    prefix = "repos/" + ci["repository"]
    if artifact_prefix is None:
        if ci.get("publisherFormat") == "acquisition-mcp" or ci.get("manifestSchema") == SEMANTIC_SCHEMA:
            artifact_prefix = ci["artifactPrefix"]
        else:
            artifact_prefix = "source-onboarding-governed-image"
    return select_artifact(ci, run_id, artifact_id, lambda path: api(prefix + path),
                           artifact_prefix=artifact_prefix)


def transport(profile, run_id, artifact_id, inbox):
    ci = select(profile["ci"], run_id, artifact_id, github)
    prefix = "repos/" + ci["repository"]
    require(inbox.is_absolute() and inbox.is_dir(), "TRANSPORT_INBOX_REQUIRED")
    with tempfile.TemporaryDirectory(dir=inbox) as tmp:
        path = Path(tmp) / (ci["zipSha256"] + ".zip")
        with path.open("xb") as out:
            github(f"{prefix}/actions/artifacts/{artifact_id}/zip", out)
            out.flush()
            os.fsync(out.fileno())
        receipt = package({"ci": ci, "inbox": tmp}, transport=True, migrations_field=profile.get("migrationsField"))
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("run_id", type=int)
    parser.add_argument("artifact_id", type=int)
    parser.add_argument("inbox", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(transport(json.loads(args.profile.read_text(encoding="utf-8")), args.run_id,
                                   args.artifact_id, args.inbox), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, Held) else "TRANSPORT_IO_OR_INPUT_ERROR") from None
