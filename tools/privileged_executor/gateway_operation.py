"""Reviewed release and return. The shared entrypoint holds the host lock throughout."""
import secrets

from gateway_admin import connect
from gateway_bundle import package
from mandate import Held, canonical, digest, intent, need
from store import Journal, read, save


def equal(left, right):
    # Python considers JSON true equal to 1.
    return canonical(left) == canonical(right)


def plan_rows(admin, resources):
    rows = []
    for resource in resources:
        before = admin.get(resource)
        after = resource["body"].copy()
        if resource["kind"] == "routes":
            # APISIX materializes these schema defaults in the stored representation.
            after.setdefault("priority", 0)
            after.setdefault("status", 1)
        action = "unchanged" if equal(before, after) else "create" if before is None else "update"
        rows.append(dict(kind=resource["kind"], id=resource["id"], before=before, after=after, action=action))
    return rows


def check_state(admin, rows, side):
    for row in rows:
        need(equal(admin.get(row), row[side]), "GATEWAY_LIVE_DRIFT")


class GatewayRelease:
    def __init__(self, cfg, root, req):
        self.profile = cfg["gateway"]
        self.req = req
        self.root = root
        self.path = Journal(root / req["run"]).path
        self.head = root / "gateway-head"

    def current(self):
        head = read(self.head) if self.head.exists() else None
        need(head is None or head["status"] == "APPLIED", "GATEWAY_RECONCILIATION_REQUIRED")
        return head

    def execute(self, review):
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
        ci, resources = package(self.profile, req)
        with connect(self.profile) as (admin, identity):
            rows = plan_rows(admin, resources)
            plan = dict(scope=intent(req), profile=digest(self.profile), generation=identity, ci=ci,
                        rows=rows, parent=current, nonce=nonce)
            stamp = digest(plan)
            if phase == "plan":
                save(self.path / "gateway.plan.review", {"request": req, "review": review})
                save(self.path / "gateway.plan", plan)
                counts = {k: sum(r["action"] == k for r in rows) for k in ("create", "update", "unchanged")}
                return {"status": "PLANNED", "digest": stamp, "counts": counts}
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
        # A crash or an unverified compensation holds later releases on this installation.
        save(self.head, {"status": "PENDING", "run": req["run"], "phase": phase}, replace=True)
        forward = phase == "apply"
        old, new = ("before", "after") if forward else ("after", "before")
        attempted = []
        try:
            for index, row in enumerate(rows if forward else reversed(rows)):
                if row["action"] == "unchanged":
                    continue
                need(equal(admin.get(row), row[old]), "GATEWAY_LIVE_DRIFT")
                claim = self.path / f"{prefix}.{index}.intent"
                save(claim, {"kind": row["kind"], "id": row["id"]})
                attempted.append((row, row[new]))
                ack = admin.write(row, row[new])
                attempted[-1] = (row, ack)
                need(equal(ack, row[new]) and equal(admin.get(row), row[new]), "GATEWAY_WRITE_READBACK")
            check_state(admin, rows, new)
        except Exception:
            try:
                for row, ack in reversed(attempted):
                    live = admin.get(row)
                    if equal(live, row[old]):
                        continue
                    need(equal(live, ack), "GATEWAY_COMPENSATION_DRIFT")
                    admin.write(row, row[old])
                    need(equal(admin.get(row), row[old]), "GATEWAY_COMPENSATION_READBACK")
                check_state(admin, rows, old)
                save(self.path / (prefix + ".failure"), {"status": "RESTORED"})
                save(self.head, parent, replace=True)
            except Exception:
                raise Held("GATEWAY_RECONCILIATION_REQUIRED") from None
            raise Held("GATEWAY_WRITE_FAILED_RESTORED") from None
        save(self.path / (prefix + ".result"), successor if forward else {"status": "RETURNED"})
        save(self.head, successor, replace=True)
