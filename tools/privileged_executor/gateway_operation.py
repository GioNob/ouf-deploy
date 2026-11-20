"""Reviewed release and return. The shared entrypoint holds the host lock throughout."""
import secrets

from gateway_admin import connect
from gateway_bundle import package
from mandate import Held, canonical, digest, intent, need
from store import Journal, read, save


def conforms(live, desired):
    """APISIX may materialize additional object keys, including inside plugins."""
    if isinstance(desired, dict):
        return isinstance(live, dict) and all(
            key in live and conforms(live[key], value) for key, value in desired.items()
        )
    # Arrays are exact, including the objects within them. Distinguish true from 1.
    return canonical(live) == canonical(desired)


def plan_rows(admin, resources, interrupted=None):
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
            need(canonical(previous["after"]) in (canonical(after), canonical(legacy)),
                 "GATEWAY_PENDING_PACKAGE_DRIFT")
            after = previous["after"]
        before = admin.get(resource)
        matches_after = conforms(before, after)
        if interrupted is not None:
            need(matches_after or conforms(before, previous["before"]), "GATEWAY_PENDING_LIVE_DRIFT")
        action = "unchanged" if matches_after else "create" if before is None else "update"
        rows.append(dict(kind=resource["kind"], id=resource["id"], before=before, after=after, action=action))
    return rows


def check_state(admin, rows, side):
    for row in rows:
        need(conforms(admin.get(row), row[side]), "GATEWAY_LIVE_DRIFT")


class GatewayRelease:
    def __init__(self, cfg, root, req):
        self.profile = cfg["gateway"]
        self.req = req
        self.root = root
        self.path = Journal(root / req["run"]).path
        self.head = root / "gateway-head"

    def current(self):
        head = read(self.head) if self.head.exists() else None
        need(head is None or head["status"] in ("APPLIED", "PENDING"), "GATEWAY_RECONCILIATION_REQUIRED")
        return head

    def interrupted_rows(self, head, identity):
        directory = self.root / head["run"]
        phase = head["phase"]
        need(phase in ("apply", "return"), "GATEWAY_PENDING_JOURNAL")
        try:
            request = read(directory / f"gateway.{phase}.review")["request"]
            source = directory if phase == "apply" else self.root / request["releaseRun"]
            snapshot = read(source / "gateway.snapshot")
            stamp = digest(snapshot) if phase == "apply" else self.return_stamp(snapshot)
            need(request["phase"] == phase and request["run"] == head["run"] and request["digest"] == stamp,
                 "GATEWAY_PENDING_JOURNAL")
            need(snapshot["profile"] == digest(self.profile) and snapshot["generation"] == identity,
                 "GATEWAY_PENDING_TARGET_DRIFT")
            return snapshot["rows"]
        except (FileNotFoundError, KeyError, TypeError, ValueError):
            raise Held("GATEWAY_PENDING_JOURNAL") from None

    def execute(self, review, token):
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
                check_state(admin, plan["rows"], "after")
                self.transition(admin, plan, review, current, plan["parent"])
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
            interrupted = self.interrupted_rows(current, identity) if pending else None
            rows = plan_rows(admin, resources, interrupted)
            plan = dict(scope=intent(req), profile=digest(self.profile), generation=identity, ci=ci,
                        rows=rows, parent=current, nonce=nonce)
            stamp = digest(plan)
            if phase == "plan":
                save(self.path / "gateway.plan.review", {"request": req, "review": review})
                save(self.path / "gateway.plan", plan)
                counts = {k: sum(r["action"] == k for r in rows) for k in ("create", "update", "unchanged")}
                result = {"status": "PLANNED", "digest": stamp, "counts": counts}
                if pending:
                    result["recoveringRun"] = current["run"]
                return result
            need(stamp == req["digest"], "GATEWAY_PLAN_DRIFT")
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
                need(conforms(admin.get(row), row[old]), "GATEWAY_LIVE_DRIFT")
                claim = self.path / f"{prefix}.{index}.intent"
                save(claim, {"kind": row["kind"], "id": row["id"]})
                attempted.append((row, row[new]))
                ack = admin.write(row, row[new])
                attempted[-1] = (row, ack)
                need(conforms(ack, row[new]) and conforms(admin.get(row), row[new]), "GATEWAY_WRITE_READBACK")
            check_state(admin, rows, new)
        except Exception:
            try:
                for row, ack in reversed(attempted):
                    live = admin.get(row)
                    # GET and PUT may expose different defaults. Even if the old
                    # body is a subset of the new one, PUT it back to remove additions.
                    # A nonconforming ACK can identify only its exact observed body.
                    if not conforms(live, row[new]) and canonical(live) != canonical(ack):
                        need(conforms(live, row[old]), "GATEWAY_COMPENSATION_DRIFT")
                        continue
                    # A missing old body selects DELETE; GET must then prove absence.
                    admin.write(row, row[old])
                    need(conforms(admin.get(row), row[old]), "GATEWAY_COMPENSATION_READBACK")
                check_state(admin, rows, old)
                save(self.path / (prefix + ".failure"), {"status": "RESTORED"})
                save(self.head, parent, replace=True)
            except Exception:
                raise Held("GATEWAY_RECONCILIATION_REQUIRED") from None
            raise Held("GATEWAY_WRITE_FAILED_RESTORED") from None
        save(self.path / (prefix + ".result"), successor if forward else {"status": "RETURNED"})
        save(self.head, successor, replace=True)
