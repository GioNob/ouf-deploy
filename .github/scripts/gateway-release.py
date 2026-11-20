"""Unprivileged workflow client. Summarizes the job to approve and public release counts."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools/privileged_executor"))
from mandate import hex64, intent, validate


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
    if sys.argv[1] == "intent":
        stamp, phase = req["digest"], req["phase"]
        if phase == "plan":
            summary.append("Source PR {sourcePr}, commit `{sourceCommit}`, CI run {sourceRun}, artifact {artifact}."
                           .format(**req))
        else:
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
            counts = result["counts"]
            for key in ("create", "update", "unchanged"):
                if type(counts[key]) is not int or counts[key] < 0:
                    raise ValueError
                summary.append(f"{key} {counts[key]}")
            phase = "apply"
        if status == "APPLIED":
            summary.append(f"Return inputs: releaseRun `{req['run']}`, receipt `{stamp}`.")
    if phase:
        summary.append(f"Job `{phase} {stamp}`")
        summary.append("Approvare il job (nessun commento richiesto)")
    with open(env["GITHUB_STEP_SUMMARY"], "a") as stream:
        print(*summary, sep="\n\n", file=stream)
    with open(env["GITHUB_OUTPUT"], "a") as stream:
        print("digest=" + stamp, "phase=" + phase, sep="\n", file=stream)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("GATEWAY_WORKFLOW_REQUEST_FAILED")
