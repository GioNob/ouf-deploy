"""Installed module release phases, serialized by the common root entrypoint."""
from pathlib import Path

from module_release import operation, recovery, return_operation
from module_release.contract import Held as ReleaseHeld, require
import module_receipt
from mandate import Held, digest, hex64, intent, need
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

    def image_ids(self, plan):
        if "sourcePlan" in plan:
            source = plan["sourcePlan"]
            need(hex64(source), "MODULE_PARENT_DRIFT")
            plan = read(Path(self.profile["journal"]) / source / "plan.json")
            need(digest(plan) == source, "MODULE_PARENT_DRIFT")
        return {"candidateImageId": plan["ci"]["imageId"], "predecessorImageId": plan["oldImage"]}

    def previous_release(self):
        """Read the last completion published under the executor lock for this module."""
        module = self.req["module"]
        pointer = self.path.parent / ("module-" + module + ".ready")
        require(pointer.is_file(), "MODULE_PREDECESSOR_RECEIPT_REQUIRED")
        tip = read(pointer)
        run_id, phase, source = tip["run"], tip["phase"], tip["planSha256"]
        require(isinstance(run_id, str) and run_id.isascii() and run_id.isdigit()
                and phase in ("apply", "migrate") and hex64(source), "MODULE_RECEIPT_DRIFT")
        run = self.path.parent / run_id
        directory = Path(self.profile["journal"]) / source
        require(not (directory / "return-intent.json").exists(), "MODULE_RECEIPT_RETURNED")
        module_receipt.attest(self.profile.get("receiptSigning"), directory)
        receipt = read(directory / "receipt.json")
        plan = read(directory / "plan.json")
        require(plan["module"] == module and plan["operation"] == receipt["operation"] == "module-release"
                and digest(plan) == source == receipt["planSha256"] and receipt == read(run / (phase + ".result"))
                and receipt["status"] == "READY" and receipt["readiness"] == "UP"
                and receipt["predecessorCid"] == plan["oldCid"], "MODULE_RECEIPT_DRIFT")
        proposal = read(run / "plan")
        stamp = digest(proposal["plan"])
        review = read(run / "apply.review")
        req = review["request"]
        phases = read(run / "approvals")
        require(req["operation"] == "module-release" and req["module"] == module and req["run"] == run_id
                and req["phase"] == "apply" and hex64(review["review"]) and "apply" in phases
                and req["digest"] == proposal["planSha256"] == stamp
                and proposal["plan"].get("sourcePlan", stamp) == source, "MODULE_APPROVAL_DRIFT")
        if phase == "migrate":
            migration = read(run / "migrate.review")
            stage = read(run / "apply.result")
            require("migrate" in phases and hex64(migration["review"]) and stage["status"] == "GATED"
                    and stage["planSha256"] == source and stage["migrationSha256"] == receipt["migrationSha256"]
                    and migration["request"] == {**req, "phase": phase, "digest": stage["migrationSha256"]},
                    "MODULE_APPROVAL_DRIFT")
        return {"planSha256": source, "imageId": plan["ci"]["imageId"], "successorCid": receipt["successorCid"],
                "successorFrameSha256": receipt["successorFrameSha256"]}

    def last_claim(self, live):
        parent = Path(self.profile["journal"])
        lock = parent / (self.req["module"] + ".lock")
        owner = lock / "owner.json"
        if owner.is_file():
            stamp = read(owner)["planSha256"]
        elif self.req["phase"] == "rollback":
            stamp = self.req["digest"]
        elif (self.path / "plan").is_file():
            proposal = read(self.path / "plan")
            stamp = proposal.get("plan", {}).get("sourcePlan", proposal.get("planSha256"))
        else:
            stamp = None
        if not hex64(stamp):
            # A crash can release the module lock before publishing the ready pointer.
            # For diagnostics only, match the live CID to its immutable CREATE receipt.
            cids = {row["cid"] for row in live.values() if isinstance(row, dict)}
            matches = []
            for receipt in parent.glob("*/created.json"):
                source = receipt.parent.name
                if hex64(source) and read(receipt)["cid"] in cids:
                    plan = read(receipt.parent / "plan.json")
                    if plan["module"] == self.req["module"] and digest(plan) == source:
                        matches.append(source)
            if len(matches) != 1:
                return "unobserved" if matches else "none"
            stamp, = matches
        directory = parent / stamp
        intents = [p for p in directory.glob("*.json") if p.name.endswith(("-intent.json", "-signal.json"))
                   or p.name in ("restore-start.json", "migration-review-consumed.json")]
        latest = max(intents, key=lambda p: (p.stat().st_mtime_ns, p.name), default=None)
        return latest.name if latest else "none"

    def execute(self, review):
        try:
            return self.execute_phase(review)
        except Exception as error:
            code = str(error) if isinstance(error, (Held, ReleaseHeld)) else operation.reason(error)
            live = recovery.residual(self.profile, self.runtime)
            try:
                claim = self.last_claim(live)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, Held):
                claim = "unobserved"
            result = dict(status="HELD", reason=code, owner=self.req["module"], residual=live, lastClaim=claim)
            save(self.path / (self.req["phase"] + ".held"), result)
            residual = ",".join(f"{role}={row['state']}({row['cid']},nets={row['networks']})"
                                if isinstance(row, dict) else f"{role}={row}" for role, row in live.items())
            raise Held(f"{code} owner={self.req['module']} residual={residual} claim={claim}") from None

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
                proposal = operation.plan(self.profile, self.runtime, previous_release=self.previous_release)
            save(path / "plan", proposal)
            need(proposal["status"] == "PLANNED", proposal.get("reason", "MODULE_PLAN_HELD"))
            response = {"digest": proposal["planSha256"], "status": "PLANNED", **self.image_ids(proposal["plan"])}
            if "candidateReview" in proposal["plan"]:
                response["candidateReview"] = proposal["plan"]["candidateReview"]
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
        image_ids = {}
        if phase == "apply":
            need(req["digest"] == stamp, "APPROVED_PLAN_DRIFT")
            image_ids = self.image_ids(proposal["plan"])
            save(path / "apply.review", {"request": req, "review": review})
            if "receiptSigning" in self.profile:
                module_receipt.signing_key(self.profile["receiptSigning"])
            if "sourcePlan" in proposal["plan"]:
                result = recovery.resume(self.profile, self.runtime, proposal["plan"])
            else:
                result = operation.apply(self.profile, stamp, self.runtime, defer_migration=True,
                                         previous_release=self.previous_release)
        else:
            stage = read(path / "apply.result")
            source = proposal["plan"].get("sourcePlan", stamp)
            need(read(path / "apply.review")["request"]["digest"] == stamp and stage["status"] == "GATED"
                 and stage["planSha256"] == source and req["digest"] == stage["migrationSha256"],
                 "APPROVED_MIGRATION_DRIFT")
            save(path / "migrate.review", {"request": req, "review": review})
            if "receiptSigning" in self.profile:
                module_receipt.signing_key(self.profile["receiptSigning"])
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
            response = {"status": "GATED", "digest": result["migrationSha256"], **image_ids}
            if "flywayReview" in stage:
                proof = stage["flywayReview"]
                response["databaseReview"] = {k: proof[k] for k in ("before", "after", "pending")}
            return response
        source = result["planSha256"]
        need(source == proposal["plan"].get("sourcePlan", stamp) and hex64(source), "MODULE_RECEIPT_DRIFT")
        directory = Path(self.profile["journal"]) / source
        need(read(directory / "receipt.json") == result, "MODULE_RECEIPT_DRIFT")
        save(path.parent / ("module-" + req["module"] + ".ready"),
             {"run": req["run"], "phase": phase, "planSha256": source}, replace=True)
        if "receiptSigning" in self.profile:
            module_receipt.attest(self.profile["receiptSigning"], directory, issue=True)
        return {"status": result["status"], "digest": source, **image_ids}
