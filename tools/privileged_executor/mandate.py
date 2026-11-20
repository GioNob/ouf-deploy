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


PHASES = ("plan", "apply", "sign", "proof")
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
    else:
        need(set(req) == common | {"direction", "queue"} and req["phase"] in PHASES
             and req["direction"] in ("forward", "return") and req["queue"] in ("empty", "inventory")
             and (req["phase"] != "proof" or req["direction"] == "forward"), "REQUEST_FIELDS")
    need(req["attempt"] == "1"
         and re.fullmatch("[1-9][0-9]{0,19}", req["run"])
         and re.fullmatch("[0-9a-f]{40}", req["commit"]) and req["commit"] == policy["commit"]
         and hex64(req["digest"]), "MANDATE_SCOPE")
    if req["phase"] == "plan":
        need(req["digest"] == intent(req), "PLAN_INTENT_DRIFT")


def intent(req):
    return digest({k: v for k, v in req.items() if k not in ("phase", "digest")})


def challenge(req):
    if req.get("operation") == "module-release":
        return " ".join([req["operation"], req["run"], req["attempt"], req["commit"], req["module"],
                         req["phase"], req["digest"]])
    return " ".join(["A2", req["run"], req["attempt"], req["commit"], req["direction"],
                     req["queue"], req["phase"], req["digest"]])


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


def authorize(req, policy, get):
    validate(req, policy)
    path = "/actions/runs/" + req["run"]
    run = get(path)
    need(str(run["id"]) == req["run"] and run["run_attempt"] == 1
         and run["event"] == "workflow_dispatch" and run["status"] == "in_progress"
         and run["path"] == (module_workflow(req["module"]) if req.get("operation") == "module-release" else WORKFLOW) and run["head_sha"] == req["commit"]
         and run["head_branch"] == policy["branch"]
         and run["repository"]["id"] == run["head_repository"]["id"] == policy["repositoryId"],
         "RUN_NOT_AUTHORIZED")
    branch = get("/branches/" + quote(policy["branch"], safe=""))
    need(branch["protected"] is True and branch["commit"]["sha"] == req["commit"], "PROTECTED_REF_DRIFT")
    env = get("/environments/" + quote(policy["environment"], safe=""))
    rules = [r for r in env["protection_rules"] if r["type"] == "required_reviewers"]
    need(env["id"] == policy["environmentId"] and len(rules) == 1, "ENVIRONMENT_UNPROTECTED")
    reviewers = {r["reviewer"]["id"] for r in rules[0]["reviewers"] if r["type"] == "User"}
    matches = [r for r in get(path + "/approvals") if r.get("state") == "approved"
               and r.get("comment") == challenge(req) and r["user"]["type"] == "User"
               and r["user"]["id"] in reviewers.intersection(policy["reviewerIds"])
               and any(e["id"] == env["id"] and e["name"] == env["name"] for e in r["environments"])]
    need(len(matches) == 1, "EXACT_HUMAN_REVIEW_REQUIRED")
    return digest({"mandate": req, "environmentId": env["id"], "reviewerId": matches[0]["user"]["id"]})
