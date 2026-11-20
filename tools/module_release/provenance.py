"""Verify publisher coordinates using a reader bound to the approved repository."""
from .contract import SHA, matches, require


def select_artifact(ci, run_id, artifact_id, get, *, artifact_prefix):
    repo = ci["repository"]
    run = get(f"/actions/runs/{run_id}")
    require(run["id"] == run_id and run["status"] == "completed" and run["conclusion"] == "success"
            and run["event"] == "pull_request" and run["path"] == ".github/workflows/" + ci["workflow"]
            and run["head_sha"] == ci["sourceCommit"] and run["repository"]["full_name"] == repo
            and run["head_repository"]["full_name"] == repo and any(
                pr["number"] == ci["pullRequest"] and pr["head"]["sha"] == ci["sourceCommit"]
                for pr in run["pull_requests"]), "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED")
    artifact = get(f"/actions/artifacts/{artifact_id}")
    require(artifact["id"] == artifact_id and artifact["expired"] is False
            and artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == ci["sourceCommit"]
            and artifact["name"] == f"{artifact_prefix}-{run_id}" and
            matches("sha256:" + SHA, artifact["digest"]), "CI_ARTIFACT_CHANGED")
    return dict(ci, runId=run_id, runAttempt=run["run_attempt"], artifactId=artifact_id,
                zipSha256=artifact["digest"][7:])


def verify_tested_tree(ci, receipt, get):
    tested = receipt["testedCommit"]
    commit = get("/git/commits/" + tested)
    require(commit["sha"] == tested and commit["tree"]["sha"] == ci["sourceTree"] and
            (tested == ci["sourceCommit"] or
             any(p["sha"] == ci["sourceCommit"] for p in commit["parents"])), "TESTED_TREE_CHANGED")
