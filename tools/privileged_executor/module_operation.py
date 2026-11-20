"""Installed module release phases, serialized by the common root entrypoint."""
from module_release import operation
from module_release.contract import Held as ReleaseHeld
from mandate import digest, intent, need
from store import Journal, read, save


class ModuleRelease:
    def __init__(self, cfg, root, req):
        self.profile = cfg["modules"][req["module"]]
        self.path = Journal(root / req["run"]).path
        self.req = req

    def execute(self, review):
        req, path = self.req, self.path
        phase = req["phase"]
        if phase == "plan":
            save(path / "plan.review", {"request": req, "review": review})
            proposal = operation.plan(self.profile)
            save(path / "plan", proposal)
            need(proposal["status"] == "PLANNED", proposal.get("reason", "MODULE_PLAN_HELD"))
            return {"digest": proposal["planSha256"], "status": "PLANNED"}
        approved = read(path / "plan.review")["request"]
        proposal = read(path / "plan")
        stamp = proposal["planSha256"]
        need(intent(req) == approved["digest"] == intent(approved)
             and stamp == digest(proposal["plan"]) and proposal["plan"]["profileSha256"] == digest(self.profile),
             "MODULE_PARENT_DRIFT")
        if phase == "apply":
            need(req["digest"] == stamp, "APPROVED_PLAN_DRIFT")
            save(path / "apply.review", {"request": req, "review": review})
            result = operation.apply(self.profile, stamp, defer_migration=True)
        else:
            stage = read(path / "apply.result")
            need(read(path / "apply.review")["request"]["digest"] == stamp and stage["status"] == "GATED"
                 and stage["planSha256"] == stamp and req["digest"] == stage["migrationSha256"],
                 "APPROVED_MIGRATION_DRIFT")
            save(path / "migrate.review", {"request": req, "review": review})
            try:
                result = operation.migrate(self.profile, stamp, req["digest"])
            except ReleaseHeld as error:
                result = {"status": "HELD", "reason": str(error)}
        save(path / (phase + ".result"), result)
        need(result["status"] in ("READY", "GATED"), result.get("reason", "MODULE_RELEASE_HELD"))
        return {"status": result["status"], "digest": result.get("migrationSha256", stamp)}
