"""Closed request envelope. Only the installed policy and GitHub can grant authority."""
import hashlib
import http.client
import json
import re
from urllib.parse import quote


class Held(Exception):
    """A public, value-free denial code."""


def need(condition, code):
    if not condition:
        raise Held(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hex64(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)


PHASES = ("plan", "apply", "sign", "proof", "migrate")
WORKFLOW = ".github/workflows/semantic-a2-cutover.yml"


def module_workflow(module):
    return f".github/workflows/{module}-module-release.yml"


def validate(req, policy):
    common = {"commit", "run", "attempt", "phase", "digest"}
    if req.get("operation") == "module-release":
        need(set(req) == common | {"operation", "module"} and isinstance(req["module"], str)
             and req["module"] in policy["modules"] and (req["phase"] in ("plan", "apply", "migrate")
             or (req["phase"] == "rollback" and "database" in policy["modules"][req["module"]]["migration"])),
             "MODULE_REQUEST_SCOPE")
    elif req.get("operation") == "gateway-release":
        from gateway_policy import valid_request
        need("gateway" in policy and valid_request(req, common), "GATEWAY_REQUEST_SCOPE")
    else:
        need(set(req) == common | {"direction", "queue"} and req["phase"] in PHASES
             and req["direction"] in ("forward", "return") and req["queue"] in ("empty", "inventory")
             and (req["phase"] not in ("proof", "migrate") or req["direction"] == "forward"), "REQUEST_FIELDS")
    need(req["attempt"] == "1"
         and re.fullmatch("[1-9][0-9]{0,19}", req["run"])
         and re.fullmatch("[0-9a-f]{40}", req["commit"]) and req["commit"] == policy["commit"]
         and hex64(req["digest"]), "MANDATE_SCOPE")
    if req["phase"] == "plan":
        need(req["digest"] == intent(req), "PLAN_INTENT_DRIFT")


def intent(req):
    return digest({k: v for k, v in req.items() if k not in ("phase", "digest")})


def github_reader(repo, token):
    need(re.fullmatch(r"[\w.-]+/[\w.-]+", repo) and re.fullmatch(r"[A-Za-z0-9_.-]{1,4095}", token),
         "API_CREDENTIAL")

    def get(endpoint):
        # Fixed TLS origin, no redirects, proxy configuration or caller-supplied URL.
        conn = http.client.HTTPSConnection("api.github.com", timeout=10)
        try:
            conn.request("GET", "/repos/" + repo + endpoint, headers={
                "Authorization": "Bearer " + token, "User-Agent": "ouf-a2-executor",
                "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
            response = conn.getresponse()
            data = response.read(2**20 + 1)
            need(response.status == 200 and len(data) <= 2**20, "GITHUB_READ_UNPROVEN")
            return json.loads(data)
        finally:
            conn.close()
    return get


def authorize(req, policy, get, state):
    from store import begin_plan, consume_approval

    validate(req, policy)
    path = "/actions/runs/" + req["run"]
    run = get(path)
    workflow = (module_workflow(req["module"]) if req.get("operation") == "module-release" else WORKFLOW)
    if req.get("operation") == "gateway-release":
        workflow = ".github/workflows/gateway-release.yml"
    need(str(run["id"]) == req["run"] and run["run_attempt"] == 1
         and run["event"] == "workflow_dispatch" and run["status"] == "in_progress"
         and run["path"] == workflow and run["head_sha"] == req["commit"]
         and run["head_branch"] == policy["branch"]
         and run["repository"]["id"] == run["head_repository"]["id"] == policy["repositoryId"],
         "RUN_NOT_AUTHORIZED")
    branch = get("/branches/" + quote(policy["branch"], safe=""))
    need(branch["protected"] is True and branch["commit"]["sha"] == req["commit"], "PROTECTED_REF_DRIFT")
    env = get("/environments/" + quote(policy["environment"], safe=""))
    rules = [r for r in env["protection_rules"] if r["type"] == "required_reviewers"]
    need(env["id"] == policy["environmentId"] and env["name"] == policy["environment"]
         and len(rules) == 1, "ENVIRONMENT_UNPROTECTED")
    reviewers = {r["reviewer"]["id"] for r in rules[0]["reviewers"] if r["type"] == "User"}
    allowed = reviewers.intersection(policy["reviewerIds"])
    if req["phase"] == "plan":
        need(allowed, "ENVIRONMENT_UNPROTECTED")
        begin_plan(state / req["run"])
        return digest({"mandate": req, "environmentId": env["id"], "approval": "none"})
    approvals = [r["user"]["id"] for r in get(path + "/approvals") if r.get("state") == "approved"
                 and r["user"]["type"] == "User" and r["user"]["id"] in allowed
                 and any(e["id"] == env["id"] and e["name"] == env["name"] for e in r["environments"])]
    index = len(approvals)
    consume_approval(state / req["run"], req["phase"], index)
    return digest({"mandate": req, "environmentId": env["id"], "approvalIndex": index,
                   "reviewerIds": sorted(set(approvals))})
