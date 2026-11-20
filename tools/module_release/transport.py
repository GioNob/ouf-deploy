"""Unprivileged transport of the original Onboarding CI ZIP. Requires gh on the runner."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .contract import SHA, checksum, matches, package, require


def github(path, output=None):
    result = subprocess.run(["gh", "api", path], stdout=output or subprocess.PIPE, check=True, timeout=360)
    if output is None:
        return json.loads(result.stdout)


def select(ci, run_id, artifact_id, api):
    repo = ci["repository"]
    prefix = "repos/" + repo
    run = api(f"{prefix}/actions/runs/{run_id}")
    require(run["id"] == run_id and run["status"] == "completed" and run["conclusion"] == "success"
            and run["event"] == "pull_request" and run["path"] == ".github/workflows/" + ci["workflow"]
            and run["head_sha"] == ci["sourceCommit"] and run["repository"]["full_name"] == repo
            and run["head_repository"]["full_name"] == repo and any(
                pr["number"] == ci["pullRequest"] and pr["head"]["sha"] == ci["sourceCommit"]
                for pr in run["pull_requests"]), "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED")
    artifact = api(f"{prefix}/actions/artifacts/{artifact_id}")
    require(artifact["id"] == artifact_id and artifact["expired"] is False
            and artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == ci["sourceCommit"]
            and artifact["name"] == f"source-onboarding-governed-image-{run_id}" and
            matches("sha256:" + SHA, artifact["digest"]), "CI_ARTIFACT_CHANGED")
    return dict(ci, runId=run_id, runAttempt=run["run_attempt"], artifactId=artifact_id,
                zipSha256=artifact["digest"][7:])


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
        receipt = package({"ci": ci, "inbox": tmp}, transport=True)
        commit = github(prefix + "/git/commits/" + receipt["testedCommit"])
        require(commit["tree"]["sha"] == ci["sourceTree"] and
                (commit["sha"] == ci["sourceCommit"] or
                 any(p["sha"] == ci["sourceCommit"] for p in commit["parents"])), "TESTED_TREE_CHANGED")
        final = inbox / path.name
        try:
            os.link(path, final)
        except FileExistsError:
            with final.open("rb") as existing:
                require(checksum(existing) == ci["zipSha256"], "EXISTING_TRANSPORT_CHANGED")
    return {k: ci[k] for k in ("repository", "sourceCommit", "sourceTree", "runId", "runAttempt",
                               "artifactId", "zipSha256")} | receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("run_id", type=int)
    parser.add_argument("artifact_id", type=int)
    parser.add_argument("inbox", type=Path)
    args = parser.parse_args()
    print(json.dumps(transport(json.loads(args.profile.read_text(encoding="utf-8")), args.run_id,
                               args.artifact_id, args.inbox), sort_keys=True))
