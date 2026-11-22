"""Reviewed release and return. The shared entrypoint holds the host lock throughout."""
import json
import re
import secrets

from gateway_admin import AdminRequestError, connect
from gateway_bundle import package
from gateway_policy import MAX_CHANGE_PATHS
from module_release.contract import diagnostic
from mandate import Held, canonical, digest, intent, need
from store import Journal, read, save


# Encrypted field used by the published bundle. Source: schema.encrypt_fields in
# https://github.com/apache/apisix/blob/3.18.0/apisix/plugins/openid-connect.lua
ENCRYPTED_PATHS = {("plugins", "openid-connect", "client_secret")}


def field_differences(live, desired, *, exact=False):
    """Report JSON paths only. Never render a value from either body."""
    differences = []

    def report(path, reason):
        name = ""
        for key in path:
            if isinstance(key, int):
                name += f"[{key}]"
            elif key and key.isascii() and all(c.isalnum() or c in "_-" for c in key):
                name += ("." if name else "") + key
            else:
                name += "[" + json.dumps(key) + "]"
        differences.append(f"{name or '$'}: {reason}")

    def compare(actual, expected, path, strict_keys):
        if not exact and path in ENCRYPTED_PATHS and isinstance(expected, str) and expected:
            if not isinstance(actual, str) or not actual:
                report(path, "changed")
        elif type(actual) is not type(expected):
            report(path, "missing" if actual is None and not path else "changed")
        elif isinstance(expected, dict):
            for key in sorted(expected):
                if key in actual:
                    compare(actual[key], expected[key], (*path, key), strict_keys)
                else:
                    report((*path, key), "missing")
            if strict_keys and actual.keys() - expected.keys():
                # An unrequested map key can itself contain response data.
                report(path, "unexpected field")
        elif isinstance(expected, list):
            for index in range(max(len(actual), len(expected))):
                child = (*path, index)
                if index >= len(actual):
                    report(child, "missing")
                elif index >= len(expected):
                    report(child, "unexpected")
                else:
                    compare(actual[index], expected[index], child, True)
        elif canonical(actual) != canonical(expected):
            report(path, "changed")

    compare(live, desired, (), exact)
    return differences


def conforms(live, desired):
    return not field_differences(live, desired)


class GatewayRelease:
    def __init__(self, cfg, root, req):
        self.profile = cfg["gateway"]
        self.req = req
        self.root = root
        self.path = Journal(root / req["run"]).path
        self.head = root / "gateway-head"
        self.error_location = None

    def diagnose(self, stage, row, paths, **metadata):
        path = self.path / ("gateway." + self.req["phase"] + ".diagnostics")
        entries = read(path) if path.exists() else []
        entries.append(dict(stage=stage, kind=row["kind"], id=row["id"], paths=paths, **metadata))
        save(path, entries, replace=True)

    def observe(self, stage, row, operation, *args):
        try:
            return operation(row, *args)
        except Exception as error:
            metadata = {"httpStatus": error.status} if isinstance(error, AdminRequestError) else {}
            self.diagnose(stage, row, ["$: unavailable"], **metadata)
            if isinstance(error, Held):
                raise
            self.error_location = diagnostic("GATEWAY_ADMIN_REQUEST", error)
            raise Held("GATEWAY_ADMIN_REQUEST") from None

    def verify(self, stage, row, live, desired, code, *, exact=False):
        paths = field_differences(live, desired, exact=exact)
        if paths:
            self.diagnose(stage, row, paths)
            raise Held(code)

    def check_state(self, admin, rows, side):
        for row in rows:
            stage = "check-" + side
            live = self.observe(stage, row, admin.get)
            self.verify(stage, row, live, row[side], "GATEWAY_LIVE_DRIFT", exact=side == "before")

    def plan_rows(self, admin, resources, interrupted, changes=None):
        rows = []
        if interrupted is not None:
            need(len(interrupted) == len(resources), "GATEWAY_PENDING_PACKAGE_DRIFT")
        for index, resource in enumerate(resources):
            after = resource["body"]
            if interrupted is not None:
                previous = interrupted[index]  # Verified bundles have a unique, deterministic order.
                need((resource["kind"], resource["id"]) == (previous["kind"], previous["id"]),
                     "GATEWAY_PENDING_PACKAGE_DRIFT")
                # Older journals expanded just these route defaults before saving the desired body.
                legacy = {"priority": 0, "status": 1, **after} if resource["kind"] == "routes" else after
                if canonical(previous["after"]) not in (canonical(after), canonical(legacy)):
                    self.diagnose("pending-package", resource, field_differences(previous["after"], after, exact=True))
                    raise Held("GATEWAY_PENDING_PACKAGE_DRIFT")
                after = previous["after"]
            before = self.observe("plan-get", resource, admin.get)
            diff = field_differences(before, after)
            if interrupted is not None and diff and canonical(before) != canonical(previous["before"]):
                self.diagnose("pending-after", resource, diff)
                self.verify("pending-before", resource, before, previous["before"], "GATEWAY_PENDING_LIVE_DRIFT", exact=True)
            action = "unchanged" if not diff else "create" if before is None else "update"
            rows.append(dict(kind=resource["kind"], id=resource["id"], before=before, after=after, action=action))
            if changes is not None:
                change = dict(kind=resource["kind"], id=resource["id"], action=action)
                if action == "update":
                    # Diagnostics end with ": reason"; a quoted JSON key can itself contain ": ".
                    paths = [entry.rsplit(": ", 1)[0] for entry in diff[:MAX_CHANGE_PATHS]]
                    if len(diff) > MAX_CHANGE_PATHS:
                        paths.append(f"… {len(diff) - MAX_CHANGE_PATHS} altri")
                    change["paths"] = paths
                changes.append(change)
        return rows

    def current(self):
        head = read(self.head) if self.head.exists() else None
        if head is not None:
            need(isinstance(head, dict) and isinstance(head.get("run"), str) and
                 re.fullmatch(r"[1-9][0-9]{0,19}", head["run"]), "GATEWAY_RECONCILIATION_REQUIRED")
            need((head.get("status") == "APPLIED" and isinstance(head.get("digest"), str)
                  and re.fullmatch(r"[a-f0-9]{64}", head["digest"])) or
                 (head.get("status") == "PENDING" and head.get("phase") in ("apply", "return")),
                 "GATEWAY_RECONCILIATION_REQUIRED")
        return head

    def interrupted_snapshot(self, head, identity):
        need(re.fullmatch(r"[1-9][0-9]{0,19}", head["run"]), "GATEWAY_PENDING_JOURNAL")
        directory = self.root / head["run"]
        phase = head["phase"]
        need(phase in ("apply", "return"), "GATEWAY_PENDING_JOURNAL")
        try:
            request = read(directory / f"gateway.{phase}.review")["request"]
            if phase == "return":
                need(re.fullmatch(r"[1-9][0-9]{0,19}", request["releaseRun"]), "GATEWAY_PENDING_JOURNAL")
            source = directory if phase == "apply" else self.root / request["releaseRun"]
            snapshot = read(source / "gateway.snapshot")
            stamp = digest(snapshot) if phase == "apply" else self.return_stamp(snapshot)
            need(request["phase"] == phase and request["run"] == head["run"] and request["digest"] == stamp,
                 "GATEWAY_PENDING_JOURNAL")
            need(snapshot["profile"] == digest(self.profile) and snapshot["generation"] == identity,
                 "GATEWAY_PENDING_TARGET_DRIFT")
            return snapshot
        except (FileNotFoundError, KeyError, TypeError, ValueError):
            raise Held("GATEWAY_PENDING_JOURNAL") from None

    def original_snapshot(self, snapshot, identity):
        seen = set()
        while snapshot["parent"] and snapshot["parent"]["status"] == "PENDING":
            head = snapshot["parent"]
            need(head["run"] not in seen, "GATEWAY_PENDING_JOURNAL")
            seen.add(head["run"])
            snapshot = self.interrupted_snapshot(head, identity)
        return snapshot

    def execute(self, review, token):
        try:
            return self.execute_phase(review, token)
        except Exception as exc:
            reason = str(exc) if isinstance(exc, Held) else diagnostic("GATEWAY_EVIDENCE_UNPROVEN", exc)
            try:
                residual = self.residual()
            except Exception:
                residual = "journal-unobserved"
            row = {"status": "HELD", "owner": "gateway", "residual": residual, "reason": reason}
            if self.error_location:
                row["diagnostic"] = self.error_location
            save(self.path / ("gateway." + self.req["phase"] + ".held"), row, replace=True)
            error = Held(reason)
            error.public_context = "owner=gateway residual=" + residual
            if self.error_location:
                error.public_context += " " + self.error_location
            raise error from None

    def residual(self):
        head = self.current()
        if head is None:
            return "no-head"
        state = f"{head['status']}/run-{head['run']}"
        if head["status"] == "PENDING":
            directory = self.root / head["run"]
            intents = directory.glob(f"gateway.{head['phase']}.*.intent")
            last = max(intents, key=lambda f: int(f.name.split(".")[-2]), default=None)
            if last:
                row = read(last)
                effect = "read-back" if last.with_suffix(".receipt").exists() else "unconfirmed"
                state += f"/{row['kind']}/{row['id']}={effect}"
        return state

    def execute_phase(self, review, token):
        req, phase = self.req, self.req["phase"]
        current = self.current()
        if phase == "return":
            parent = self.root / req["releaseRun"]
            need(current == {"status": "APPLIED", "run": req["releaseRun"], "digest": req["digest"]},
                 "GATEWAY_RETURN_RECEIPT")
            plan = read(parent / "gateway.snapshot")
            receipt = read(parent / "gateway.apply.result")
            need(receipt == current and self.return_stamp(plan) == req["digest"]
                 and plan["profile"] == digest(self.profile), "GATEWAY_RETURN_DRIFT")
            with connect(self.profile) as (admin, identity):
                need(identity == plan["generation"], "GATEWAY_GENERATION_CHANGED")
                original = self.original_snapshot(plan, identity)
                if "returnBaseline" in plan:
                    need(digest(original) == plan["returnBaseline"], "GATEWAY_RETURN_DRIFT")
                self.check_state(admin, original["rows"], "after")
                self.transition(admin, original, review, current, original["parent"])
            return {"status": "RETURNED", "digest": req["digest"]}

        if phase == "plan":
            nonce = secrets.token_hex(32)
        else:
            approved = read(self.path / "gateway.plan.review")["request"]
            prepared = read(self.path / "gateway.plan")
            need(intent(req) == approved["digest"] == intent(approved)
                 and digest(prepared) == req["digest"], "GATEWAY_PLAN_DRIFT")
            nonce = prepared["nonce"]
        ci, resources = package(self.profile, req, token)
        with connect(self.profile) as (admin, identity):
            pending = current is not None and current["status"] == "PENDING"
            original = self.original_snapshot(self.interrupted_snapshot(current, identity), identity) if pending else None
            if pending:
                need(original["ci"] == ci, "GATEWAY_PENDING_PACKAGE_DRIFT")
            changes = [] if phase == "plan" else None
            rows = self.plan_rows(admin, resources, original["rows"] if pending else None, changes)
            plan = dict(scope=intent(req), profile=digest(self.profile), generation=identity, ci=ci,
                        rows=rows, parent=current, nonce=nonce)
            if pending:
                plan["returnBaseline"] = digest(original)
            stamp = digest(plan)
            if phase == "plan":
                save(self.path / "gateway.plan.review", {"request": req, "review": review})
                save(self.path / "gateway.plan", plan)
                counts = {k: sum(r["action"] == k for r in rows) for k in ("create", "update", "unchanged")}
                result = {"status": "PLANNED", "digest": stamp, "counts": counts, "changes": changes}
                if pending:
                    result["recoveringRun"] = current["run"]
                return result
            if stamp != req["digest"]:
                # The approved snapshot binds raw GET bodies, including opaque fields.
                for row, approved_row in zip(rows, prepared["rows"]):
                    if (row["kind"], row["id"]) == (approved_row["kind"], approved_row["id"]):
                        paths = field_differences(row["before"], approved_row["before"], exact=True)
                        if paths:
                            self.diagnose("approved-get", row, paths)
                raise Held("GATEWAY_PLAN_DRIFT")
            save(self.path / "gateway.snapshot", plan)
            head = {"status": "APPLIED", "digest": self.return_stamp(plan), "run": req["run"]}
            self.transition(admin, plan, review, current, head)
            return {"status": "APPLIED", "digest": head["digest"]}

    @staticmethod
    def return_stamp(plan):
        return digest({"phase": "return", "snapshot": digest(plan)})

    def transition(self, admin, plan, review, parent, successor):
        req, rows = self.req, plan["rows"]
        phase = req["phase"]
        prefix = "gateway." + phase
        save(self.path / (prefix + ".review"), {"request": req, "review": review})
        # Keep the interrupted run discoverable until the entire transition is verified.
        save(self.head, {"status": "PENDING", "run": req["run"], "phase": phase}, replace=True)
        forward = phase == "apply"
        old, new = ("before", "after") if forward else ("after", "before")
        attempted = []
        try:
            for index, row in enumerate(rows if forward else reversed(rows)):
                if row["action"] == "unchanged":
                    continue
                live = self.observe("pre-write-get", row, admin.get)
                self.verify("pre-write-get", row, live, row[old], "GATEWAY_LIVE_DRIFT")
                claim = self.path / f"{prefix}.{index}.intent"
                save(claim, {"kind": row["kind"], "id": row["id"]})
                attempted.append((row, row[new]))
                ack = self.observe("write", row, admin.write, row[new])
                attempted[-1] = (row, ack)
                self.verify("write-ack", row, ack, row[new], "GATEWAY_WRITE_READBACK")
                live = self.observe("write-get", row, admin.get)
                self.verify("write-get", row, live, row[new], "GATEWAY_WRITE_READBACK")
                save(self.path / f"{prefix}.{index}.receipt", {"kind": row["kind"], "id": row["id"]})
            self.check_state(admin, rows, new)
        except Exception as exc:
            if not isinstance(exc, Held):
                self.error_location = diagnostic("GATEWAY_EVIDENCE_UNPROVEN", exc)
            try:
                for row, ack in reversed(attempted):
                    live = self.observe("compensation-get", row, admin.get)
                    # GET and PUT may expose different defaults. Even if the old
                    # body is a subset of the new one, PUT it back to remove additions.
                    # A nonconforming ACK can identify only its exact observed body.
                    if not conforms(live, row[new]) and canonical(live) != canonical(ack):
                        self.verify("compensation-drift", row, live, row[old], "GATEWAY_COMPENSATION_DRIFT")
                        continue
                    # A missing old body selects DELETE; GET must then prove absence.
                    self.observe("compensation-write", row, admin.write, row[old])
                    live = self.observe("compensation-readback", row, admin.get)
                    self.verify("compensation-readback", row, live, row[old], "GATEWAY_COMPENSATION_READBACK")
                self.check_state(admin, rows, old)
                save(self.path / (prefix + ".failure"), {"status": "RESTORED"})
                save(self.head, parent, replace=True)
            except Exception as exc:
                if not isinstance(exc, Held):
                    self.error_location = diagnostic("GATEWAY_EVIDENCE_UNPROVEN", exc)
                raise Held("GATEWAY_RECONCILIATION_REQUIRED") from None
            raise Held("GATEWAY_WRITE_FAILED_RESTORED") from None
        save(self.path / (prefix + ".result"), successor if forward else {"status": "RETURNED"})
        save(self.head, successor, replace=True)
