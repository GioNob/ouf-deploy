"""Verify publisher coordinates using a reader bound to the approved repository."""
from datetime import datetime

from .contract import SHA, matches, require


def select_artifact(ci, run_id, artifact_id, get, *, artifact_prefix):
    repo = ci["repository"]
    run = get(f"/actions/runs/{run_id}")
    mcp = ci.get("publisherFormat") == "acquisition-mcp"
    heads = {ci["sourceCommit"]}
    if mcp:
        heads.add(ci["publisherCommit"])
    require(run["id"] == run_id and run["status"] == "completed" and run["conclusion"] == "success"
            and run["event"] == "pull_request" and run["path"] == ".github/workflows/" + ci["workflow"]
            and run["head_sha"] in heads and run["repository"]["full_name"] == repo
            and run["head_repository"]["full_name"] == repo and any(
                pr["number"] == ci["pullRequest"] and pr["head"]["sha"] == ci["sourceCommit"]
                and ("sourceBranch" not in ci or pr["head"]["ref"] == ci["sourceBranch"])
                for pr in run["pull_requests"]), "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED")
    artifact = get(f"/actions/artifacts/{artifact_id}")
    require(artifact["id"] == artifact_id and artifact["expired"] is False
            and artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == run["head_sha"]
            and artifact["name"] == f"{artifact_prefix}-{run_id}" and
            matches("sha256:" + SHA, artifact["digest"]), "CI_ARTIFACT_CHANGED")
    if mcp and run["run_attempt"] > 1:
        created = datetime.fromisoformat(artifact["created_at"].replace("Z", "+00:00"))
        started = datetime.fromisoformat(run["run_started_at"].replace("Z", "+00:00"))
        require(created >= started, "ARTIFACT_ATTEMPT_CHANGED")
    return dict(ci, runId=run_id, runAttempt=run["run_attempt"], artifactId=artifact_id,
                zipSha256=artifact["digest"][7:])


def verify_tested_tree(ci, receipt, get):
    tested = receipt["testedCommit"]
    commit = get("/git/commits/" + tested)
    require(commit["sha"] == tested and commit["tree"]["sha"] == ci["sourceTree"] and
            (tested == ci["sourceCommit"] or
             any(p["sha"] == ci["sourceCommit"] for p in commit["parents"])), "TESTED_TREE_CHANGED")
    if ci.get("publisherFormat") == "acquisition-mcp":
        source = get("/git/commits/" + ci["sourceCommit"]) if tested != ci["sourceCommit"] else commit
        require(source["sha"] == ci["sourceCommit"] and source["tree"]["sha"] == ci["sourceTree"],
                "SOURCE_TREE_CHANGED")
