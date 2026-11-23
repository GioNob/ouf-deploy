"""Unprivileged workflow client. Summarizes the Gateway plan for approval."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools/privileged_executor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_review import approval
from gateway_policy import ID, KINDS, MAX_CHANGE_PATHS, match
from mandate import hex64, intent, validate


RESOURCE_ACTIONS = {"create": "nuova", "update": "modificata", "unchanged": "invariata"}
RETIRE_ACTIONS = {"delete": "da rimuovere", "absent": "già assente"}
ACTIONS = RESOURCE_ACTIONS | RETIRE_ACTIONS
# field_differences uses dot names, list indices, and JSON-quoted map keys.
NAME = r"[A-Za-z0-9_-]+"
STRING = r'"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\(?:["\\bfnrt]|u[0-9a-f]{4}))*"'
BRACKET = rf"\[(?:0|[1-9][0-9]*|{STRING})\]"
FIELD_PATH = rf"\$|(?:{NAME}|{BRACKET})(?:\.{NAME}|{BRACKET})*"


def path_cell(paths):
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_CHANGE_PATHS + 1:
        raise ValueError
    cells = []
    for index, path in enumerate(paths):
        if index == MAX_CHANGE_PATHS:
            if not match(r"… [1-9][0-9]* altri", path):
                raise ValueError
            cells.append(path)
        else:
            if not match(FIELD_PATH, path):
                raise ValueError
            # GitHub tables split on pipes even within Markdown code spans.
            fence = "`" * (1 + max((len(run) for run in re.findall(r"`+", path)), default=0))
            cells.append(fence + path.replace("|", r"\|") + fence)
    if len(set(paths)) != len(paths):
        raise ValueError
    return ", ".join(cells)


def changes_table(changes, counts):
    if not isinstance(changes, list):
        raise ValueError
    tally = dict.fromkeys(RESOURCE_ACTIONS, 0)
    if "delete" in counts:
        tally["delete"] = 0
    lines = ["| Risorsa | Azione | Campi che cambiano |", "|---|---|---|"]
    resources = []
    previous = (False, -1, "")
    managed_ids, route_ids = set(), set()
    for change in changes:
        if not isinstance(change, dict):
            raise ValueError
        kind, ident, action = change["kind"], change["id"], change["action"]
        if kind not in KINDS or not match(ID, ident) or ident in (".", "..") or action not in ACTIONS:
            raise ValueError
        fields = {"kind", "id", "action"}
        if action == "update":
            fields.add("paths")
        retired = action in RETIRE_ACTIONS
        if retired and ("delete" not in counts or kind != "routes" or ident in managed_ids):
            raise ValueError
        if action == "delete":
            fields.add("supersededBy")
            if not match(ID, change["supersededBy"]) or change["supersededBy"] not in route_ids:
                raise ValueError
        key = retired, KINDS.index(kind), ident
        if set(change) != fields or key <= previous:
            raise ValueError
        previous = key
        if not retired:
            managed_ids.add(ident)
            if kind == "routes":
                route_ids.add(ident)
        if action in tally:
            tally[action] += 1
        paths = path_cell(change["paths"]) if action == "update" else "—"
        label = ACTIONS[action]
        if action == "delete":
            label += f" (sostituita da {change['supersededBy']})"
        detail = " (" + ", ".join(change["paths"]) + ")" if action == "update" else ""
        resources.append(f"{kind}/{ident}: {label}{detail}")
        lines.append(f"| `{kind}/{ident}` | {label} | {paths} |")
    if tally != counts:
        raise ValueError
    return "\n".join(lines), resources


def main():
    env = os.environ
    inputs = json.loads(env["DISPATCH_INPUTS"])
    req = dict(operation="gateway-release", run=env["GITHUB_RUN_ID"], attempt=env["GITHUB_RUN_ATTEMPT"],
               commit=env["GITHUB_SHA"])
    if inputs["action"] == "return":
        req.update(releaseRun=inputs["releaseRun"], phase="return", digest=inputs["receipt"])
    else:
        req.update({k: inputs[k] for k in ("sourceRun", "sourceCommit", "sourcePr", "artifact")})
        req["phase"] = env.get("PHASE", "plan")
        req["digest"] = env.get("DIGEST") or intent(req)
    validate(req, {"gateway": {}, "commit": env["GITHUB_SHA"]})
    summary = []
    facts = []
    if sys.argv[1] == "intent":
        stamp, phase = req["digest"], req["phase"]
        if phase == "plan":
            summary.append("Source PR {sourcePr}, commit `{sourceCommit}`, CI run {sourceRun}, artifact {artifact}."
                           .format(**req))
        else:
            facts.append("Ripristino dello snapshot del rilascio " + req["releaseRun"])
            summary.append("Return of release run " + req["releaseRun"] + ".")
    else:
        wire = json.dumps({"request": req, "token": env.pop("REVIEW_TOKEN")}).encode()
        response = subprocess.run(["/usr/bin/sudo", "-n", "--", "/usr/local/sbin/ouf-a2"],
                                  input=wire, stdout=subprocess.PIPE, check=True)
        result = json.loads(response.stdout)
        status, stamp = result["status"], result["digest"]
        expected = {"plan": "PLANNED", "apply": "APPLIED", "return": "RETURNED"}
        if status != expected[req["phase"]] or not hex64(stamp):
            raise ValueError
        summary.append("Gateway " + status)
        phase = ""
        if status == "PLANNED":
            facts.append("Gateway · stato PLANNED")
            if "recoveringRun" in result:
                facts.append(f"Le risorse corrispondono allo stato precedente o successivo del run sospeso {result['recoveringRun']}.")
                summary.append(f"Live resources match the before or after state of pending run {result['recoveringRun']}.")
            counts = result["counts"]
            count_keys = list(RESOURCE_ACTIONS)
            count_line = "Risorse: {create} nuove, {update} modificate, {unchanged} invariate"
            if "delete" in counts:
                count_keys.append("delete")
                count_line += ", {delete} da rimuovere"
            for key in count_keys:
                if type(counts[key]) is not int or counts[key] < 0:
                    raise ValueError
                summary.append(f"{key} {counts[key]}")
            facts.append(count_line.format(**counts))
            if "changes" in result or "delete" in counts:
                table, resources = changes_table(result["changes"], counts)
                summary.append(table)
                facts.extend(resources)
            phase = "apply"
        if status == "APPLIED":
            summary.append(f"Return inputs: releaseRun `{req['run']}`, receipt `{stamp}`.")
    if phase:
        summary.append(f"Job `{phase} {stamp}`")
        if phase != "plan":
            summary.append("Approvare il job (nessun commento richiesto)")
    with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        if phase in ("apply", "return"):
            approval(stream, phase, stamp, facts)
        print(*summary, sep="\n\n", file=stream)
    with open(env["GITHUB_OUTPUT"], "a") as stream:
        print("digest=" + stamp, "phase=" + phase, sep="\n", file=stream)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("GATEWAY_WORKFLOW_REQUEST_FAILED")
