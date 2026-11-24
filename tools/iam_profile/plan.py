"""Read-only planning, inverse projection and verification against custodied observations."""
import re

from .profile import POOLS, Invalid, canonical, digest, exact, fields, require, validate


def sha(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def observation(profile, snapshot):
    exact(snapshot, ("contract", "installationId", "kind", "gatewayBindings", "managed",
                     "foreign", "controlProof", "complete"), "OBSERVATION_INVALID")
    require(snapshot["complete"] is True, "OBSERVATION_INCOMPLETE")
    validate(profile, snapshot["gatewayBindings"])
    require(snapshot["contract"] == "ouf.iam-profile-observation.v1"
            and snapshot["kind"] == profile["kind"]
            and snapshot["installationId"] == profile["installationId"], "TARGET_MISMATCH")
    desired = dict(fields(profile))
    observed = snapshot["managed"]
    require(type(observed) is dict and observed.keys() <= desired.keys(), "OBSERVATION_INVALID")
    for key, value in observed.items():
        # A missing key denotes confirmed absence. Errors/unknowns must abort the export.
        require(type(value) is type(desired[key]), "OBSERVATION_INVALID")
        if type(value) is list:
            require(all(type(item) is str for item in value) and len(set(value)) == len(value),
                    "OBSERVATION_INVALID")
        if key.endswith(("secretRef", "caRef")):
            require(re.fullmatch(r"ref:[A-Za-z0-9][A-Za-z0-9_./-]*", value),
                    "REFERENCE_REQUIRED")
    require(type(snapshot["foreign"]) is list, "OBSERVATION_INVALID")
    occupied = set()
    for item in snapshot["foreign"]:
        exact(item, ("idSha256", "stateSha256"), "OBSERVATION_INVALID")
        ref = item["idSha256"]
        require(sha(ref) and sha(item["stateSha256"]) and ref not in occupied,
                "OBSERVATION_INVALID")
        occupied.add(ref)
    for client in profile["clients"].values():
        require(digest(["client", client["clientId"]]) not in occupied, "FOREIGN_CLIENT")
    return desired


def row(path, action, before, after):
    return {"path": path, "action": action, "beforeSha256": before, "afterSha256": after}


def plan(profile, snapshot):
    desired = observation(profile, snapshot)
    forward, inverse = [], []
    for key, value in sorted(desired.items()):
        present = key in snapshot["managed"]
        current = snapshot["managed"].get(key)
        before = digest(current) if present else None
        after = digest(value)
        if present and key.endswith(".scopes") and set(current) == set(value):
            after = before  # OAuth scope membership is unordered. Preserve the observed order.
        action = "create"
        if present:
            action = "unchanged" if before == after else "update"
        forward.append(row(key, action, before, after))
        inverse.append(row(key, "delete" if action == "create" else action, after, before))
    for item in sorted(snapshot["foreign"], key=lambda entry: entry["idSha256"]):
        entry = row("foreign/" + item["idSha256"], "foreign",
                    item["stateSha256"], item["stateSha256"])
        forward.append(entry)
        inverse.append(entry.copy())
    result = {"contract": "ouf.iam-profile-plan.v1", "profileSha256": digest(profile),
              "observedSha256": digest(snapshot), "diff": forward, "returnDiff": inverse}
    return {**result, "planSha256": digest(result)}


def verify_control(profile, proof):
    code = "CONTROL_UNPROVEN"
    exact(proof, ("profileSha256", "pet", "sourceTraceSha256", "traceSha256", "pools"), code)
    require(proof["profileSha256"] == digest(profile) and proof["pet"] == "55g"
            and sha(proof["sourceTraceSha256"])
            and proof["traceSha256"] == digest({k: v for k, v in proof.items() if k != "traceSha256"}),
            code)
    exact(proof["pools"], POOLS, code)
    for name, pool in profile["pools"].items():
        sample = proof["pools"][name]
        keys = ["occupiedDataSlots", "concurrentControlServed"]
        if name == "Gateway":
            keys.append("concurrentRenewalRelayRequests")
        exact(sample, keys, code)
        require(all(type(value) is int for value in sample.values()), code)
        require(sample["occupiedDataSlots"] == pool["dataSlots"]["value"]
                and sample["concurrentControlServed"] >= profile["capacity"]["ControlReservedSlots"],
                code)
        if name == "Gateway":
            require(sample["concurrentRenewalRelayRequests"] >= 2, code)


def receipt(profile, snapshot):
    result = plan(profile, snapshot)
    require(all(item["action"] in ("unchanged", "foreign") for item in result["diff"]),
            "PROFILE_DRIFT")
    verify_control(profile, snapshot["controlProof"])
    clients = {key: {"clientId": value["clientId"], "scopes": sorted(value["scopes"])}
               for key, value in profile["clients"].items()}
    return {"contract": "ouf.iam-profile-receipt.v1", "status": "VERIFIED",
            "profileSha256": result["profileSha256"], "observedSha256": result["observedSha256"],
            "kind": profile["kind"], "issuer": profile["trust"]["issuer"], "clients": clients,
            "controlProofSha256": digest(snapshot["controlProof"])}


def gate(profile, snapshot, supplied_receipt):
    try:
        require(supplied_receipt is not None, "RECEIPT_MISSING")
        expected = receipt(profile, snapshot)
        require(expected == supplied_receipt, "RECEIPT_MISMATCH")
    except Invalid as exc:
        return {"status": "HELD", "code": str(exc)}
    return {"status": "VERIFIED", "profileSha256": expected["profileSha256"]}

