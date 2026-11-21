"""Verify publisher coordinates using a reader bound to the approved repository."""
from datetime import datetime

from .contract import SEMANTIC_SCHEMA, SHA, matches, require


def select_artifact(ci, run_id, artifact_id, get, *, artifact_prefix):
    repo = ci["repository"]
    run = get(f"/actions/runs/{run_id}")
    mcp = ci.get("publisherFormat") == "acquisition-mcp"
    heads = {ci["sourceCommit"]}
    if mcp:
        heads.add(ci["publisherCommit"])
    # Bind a tested merge head to the commit inside the verified Java CI ZIP.
    tested_head = ci.get("manifestSchema") == SEMANTIC_SCHEMA or ("artifactPrefix" in ci and not mcp)
    head = run["head_sha"]
    require(run["id"] == run_id and run["status"] == "completed" and run["conclusion"] == "success"
            and run["event"] == "pull_request" and run["path"] == ".github/workflows/" + ci["workflow"]
            and (head in heads or (tested_head and matches(r"[a-f0-9]{40}", head)))
            and run["repository"]["full_name"] == repo
            and run["head_repository"]["full_name"] == repo and any(
                pr["number"] == ci["pullRequest"] and pr["head"]["sha"] == ci["sourceCommit"]
                and ("sourceBranch" not in ci or pr["head"]["ref"] == ci["sourceBranch"])
                for pr in run["pull_requests"]), "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED")
    artifact = get(f"/actions/artifacts/{artifact_id}")
    require(artifact["id"] == artifact_id and artifact["expired"] is False
            and artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == run["head_sha"]
            and artifact["name"] == f"{artifact_prefix}-{run_id}" and
            matches("sha256:" + SHA, artifact["digest"]), "CI_ARTIFACT_CHANGED")
    if (mcp or tested_head) and run["run_attempt"] > 1:
        created = datetime.fromisoformat(artifact["created_at"].replace("Z", "+00:00"))
        started = datetime.fromisoformat(run["run_started_at"].replace("Z", "+00:00"))
        require(created >= started, "ARTIFACT_ATTEMPT_CHANGED")
    selected = dict(ci, runId=run_id, runAttempt=run["run_attempt"], artifactId=artifact_id,
                    zipSha256=artifact["digest"][7:])
    if tested_head:
        selected["runHead"] = head
    return selected


def verify_tested_tree(ci, receipt, get):
    tested = receipt["testedCommit"]
    tested_head = ci.get("manifestSchema") == SEMANTIC_SCHEMA or ("artifactPrefix" in ci and not ci.get("publisherFormat"))
    if tested_head:
        require(ci["runHead"] in (ci["sourceCommit"], tested), "TESTED_RUN_CHANGED")
    commit = get("/git/commits/" + tested)
    require(commit["sha"] == tested and commit["tree"]["sha"] == ci["sourceTree"] and
            (tested == ci["sourceCommit"] or
             any(p["sha"] == ci["sourceCommit"] for p in commit["parents"])), "TESTED_TREE_CHANGED")
    if ci.get("publisherFormat") == "acquisition-mcp" or tested_head:
        source = get("/git/commits/" + ci["sourceCommit"]) if tested != ci["sourceCommit"] else commit
        require(source["sha"] == ci["sourceCommit"] and source["tree"]["sha"] == ci["sourceTree"],
                "SOURCE_TREE_CHANGED")
