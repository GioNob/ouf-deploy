"""Installed module release phases, serialized by the common root entrypoint."""
from pathlib import Path

from module_release import operation, recovery, return_operation
from module_release.contract import Held as ReleaseHeld
from mandate import Held, digest, intent, need
from store import Journal, read, save


class ModuleRelease:
    def __init__(self, cfg, root, req):
        self.profile = cfg["modules"][req["module"]]
        self.path = Journal(root / req["run"]).path
        self.req = req
        self.runtime = operation.Docker(self.profile)
        peer = cfg["modules"].get("mcp", {})
        if req["module"] == "onboarding" and peer.get("dockerSocket") == self.profile["dockerSocket"]:
            self.runtime.flyway_peer = peer.get("migration", {}).get("database")

    def execute(self, review):
        try:
            return self.execute_phase(review)
        except Exception as error:
            code = str(error) if isinstance(error, (Held, ReleaseHeld)) else operation.reason(error)
            live = recovery.residual(self.profile, self.runtime)
            result = dict(status="HELD", reason=code, owner=self.req["module"], residual=live)
            save(self.path / (self.req["phase"] + ".held"), result)
            residual = ",".join(f"{role}={row['state']}({row['cid']},nets={row['networks']})"
                                if isinstance(row, dict) else f"{role}={row}" for role, row in live.items())
            raise Held(f"{code} owner={self.req['module']} residual={residual}") from None

    def execute_phase(self, review):
        req, path = self.req, self.path
        phase = req["phase"]
        if phase == "rollback":
            save(path / "rollback.review", {"request": req, "review": review})
            result = return_operation.run(self.profile, req["digest"], self.runtime, recover=True)
            save(path / "rollback.result", result)
            need(result["status"] == "ROLLED_BACK", result.get("reason", "MODULE_RETURN_HELD"))
            return {"digest": req["digest"], "status": result["status"]}
        if phase == "plan":
            save(path / "plan.review", {"request": req, "review": review})
            lock = Path(self.profile["journal"]) / (req["module"] + ".lock")
            if lock.exists():
                body = recovery.proposal(self.profile, self.runtime)
                proposal = {"status": "PLANNED", "planSha256": digest(body), "plan": body}
            else:
                proposal = operation.plan(self.profile, self.runtime)
            save(path / "plan", proposal)
            need(proposal["status"] == "PLANNED", proposal.get("reason", "MODULE_PLAN_HELD"))
            response = {"digest": proposal["planSha256"], "status": "PLANNED"}
            if "sourcePlan" in proposal["plan"]:
                response["sourcePlan"] = proposal["plan"]["sourcePlan"]
            if "migrations" in proposal["plan"]:
                response["databaseReview"] = {key: proposal["plan"][key] for key in
                    ("migrations", "migrationsSha256", "databaseSha256", "schemaSha256", "targetSchemaSha256")
                    if key in proposal["plan"]}
            return response
        approved = read(path / "plan.review")["request"]
        proposal = read(path / "plan")
        stamp = proposal["planSha256"]
        need(intent(req) == approved["digest"] == intent(approved)
             and stamp == digest(proposal["plan"]) and proposal["plan"]["profileSha256"] == digest(self.profile),
             "MODULE_PARENT_DRIFT")
        if phase == "apply":
            need(req["digest"] == stamp, "APPROVED_PLAN_DRIFT")
            save(path / "apply.review", {"request": req, "review": review})
            if "sourcePlan" in proposal["plan"]:
                result = recovery.resume(self.profile, self.runtime, proposal["plan"])
            else:
                result = operation.apply(self.profile, stamp, self.runtime, defer_migration=True)
        else:
            stage = read(path / "apply.result")
            source = proposal["plan"].get("sourcePlan", stamp)
            need(read(path / "apply.review")["request"]["digest"] == stamp and stage["status"] == "GATED"
                 and stage["planSha256"] == source and req["digest"] == stage["migrationSha256"],
                 "APPROVED_MIGRATION_DRIFT")
            save(path / "migrate.review", {"request": req, "review": review})
            try:
                result = operation.migrate(self.profile, source, req["digest"], self.runtime,
                                           recover="sourcePlan" in proposal["plan"])
            except ReleaseHeld as error:
                result = {"status": "HELD", "reason": str(error)}
        save(path / (phase + ".result"), result)
        if result["status"] not in ("READY", "GATED"):
            cause = result.get("reason", "MODULE_RELEASE_HELD")
            if result.get("rollback") == "ROLLED_BACK":
                cause += f" rollback=ROLLED_BACK cid={result['restoredCid']} HTTP={result['predecessorReadyHttp']}"
            rollback_reason = result.get("rollbackReason", cause)
            raise Held(rollback_reason if rollback_reason == cause else f"{rollback_reason} cause={cause}")
        if result["status"] == "GATED":
            stage = operation.read(Path(self.profile["journal"]) / result["planSha256"], "migration-plan.json")
            response = {"status": "GATED", "digest": result["migrationSha256"]}
            if "flywayReview" in stage:
                proof = stage["flywayReview"]
                response["databaseReview"] = {k: proof[k] for k in ("before", "after", "pending")}
            return response
        return {"status": result["status"], "digest": result["planSha256"]}
