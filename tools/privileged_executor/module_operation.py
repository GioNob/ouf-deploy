"""Installed module release phases, serialized by the common root entrypoint."""
from pathlib import Path

from module_release import operation, recovery, retention, return_operation
from module_release.contract import Held as ReleaseHeld, require
import module_receipt
from mandate import Held, digest, hex64, intent, need
from store import Journal, read, save


class ModuleInstall:
    def __init__(self, cfg, root, req):
        self.profile = cfg["modules"][req["module"]]
        self.path = root / req["run"]
        self.req = req

    def execute(self, review):
        from module_release import install_operation as install
        req, path, profile = self.req, self.path, self.profile
        phase = req["phase"]
        rt = install.engine(profile)
        operation.confirm(path, phase + ".review", {"request": req, "review": review})
        if phase == "plan":
            result = install.plan(profile, rt, resume=req.get("resumePlan"))
            save(path / "plan", result)
            need(result["status"] == "PLANNED", result.get("reason", "MODULE_INSTALL_PLAN_HELD"))
            return {"status": "PLANNED", "digest": result["planSha256"], "installReview": result["plan"]["review"]}
        stamp = req["digest"]
        if phase == "apply":
            approved = read(path / "plan.review")["request"]
            proposal = read(path / "plan")
            need(intent(req) == approved["digest"] == intent(approved)
                 and proposal["status"] == "PLANNED" and stamp == proposal["planSha256"] == digest(proposal["plan"]),
                 "MODULE_PARENT_DRIFT")
            result = install.apply(profile, stamp, rt)
        else:
            result = install.rollback(profile, stamp, rt)
        if result["status"] == "HELD":
            save(path / (phase + ".held"), result, replace=True)
            raise Held(result["reason"])
        operation.confirm(path, phase + ".result", result)
        if phase == "apply":
            tip = path.parent / ("module-" + req["module"] + ".installed")
            pointer = {"run": req["run"], "phase": phase, "planSha256": stamp}
            if not tip.exists() or read(tip) != pointer:
                current = rt.inspect(profile["container"], missing=True)
                need(current and current["Id"] == result["cid"] and install.snapshot(current) == result["frameSha256"],
                     "INSTALL_POINTER_DRIFT")
                save(tip, pointer, replace=True)
        return {"status": result["status"], "digest": stamp, "receipt": result}


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
        return self.completed_release(require_signature=True)

    def completed_release(self, *, require_signature):
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
        if require_signature or "receiptSigning" in self.profile:
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
        if req["module"] == "mcp" and phase in ("apply", "migrate", "rollback"):
            # A workflow crash can release the executor lock while Docker is
            # still committing on the current release's database.
            tip = path.parent / "module-mcp.ready"
            if tip.is_file():
                source = read(tip)["planSha256"]
                need(hex64(source), "MODULE_RECEIPT_DRIFT")
                for worker_phase in retention.COMMAND:
                    start = Path(self.profile["journal"]) / source / (worker_phase + ".start.json")
                    if start.is_file():
                        cid = read(start)["cid"]
                        need(hex64(cid), "RETENTION_WORKER_DRIFT")
                        worker = self.runtime.inspect(cid, missing=True)
                        need(worker is None or worker["State"]["Status"] == "exited" or operation.never_started(worker),
                             "RETENTION_WORKER_IN_FLIGHT")
        if phase in (retention.ADMIN, retention.BATCH):
            source = req["digest"]
            ready = self.completed_release(require_signature=False)
            need(source == ready["planSha256"], "RETENTION_PLAN_DRIFT")
            if phase == retention.BATCH:
                admin = read(path / (retention.ADMIN + ".result"))
                receipt_path = Path(self.profile["journal"]) / source / retention.RECEIPT
                need(admin["digest"] == source and admin["status"] == "VERIFIED" and receipt_path.is_file()
                     and read(receipt_path) == admin["retentionReview"], "RETENTION_RECEIPT_DRIFT")
            save(path / (phase + ".review"), {"request": req, "review": review})
            receipt = retention.run(self.profile, self.runtime, source, phase, ready)
            response = {"digest": source, "status": "VERIFIED" if phase == retention.ADMIN else "SUCCEEDED",
                        "retentionReview": receipt}
            save(path / (phase + ".result"), response)
            return response
        if phase == "rollback":
            save(path / "rollback.review", {"request": req, "review": review})
            result = self.reviewed_return() if operation.reviewed.enabled(self.profile) else return_operation.run(self.profile, req["digest"], self.runtime, recover=True)
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
            response = {"digest": proposal["planSha256"], "status": "PLANNED", **self.image_ids(proposal["plan"]), **{k: proposal["plan"][k] for k in ("approvalLines",) if k in proposal["plan"]}}
            if retention.ADMIN in proposal["plan"]:
                response["retentionReview"] = proposal["plan"][retention.ADMIN]
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
        response = {"status": result["status"], "digest": source, **image_ids}
        if retention.ADMIN in proposal["plan"]:
            response["retentionReview"] = proposal["plan"][retention.ADMIN]
        return response


from module_release.profile_options import validate_module_profiles

_ModuleInstall = ModuleInstall
_ModuleRelease = ModuleRelease


class ModuleInstall(_ModuleInstall):
    def __init__(self, cfg, root, req):
        if isinstance(req, dict):
            validate_module_profiles(req.get("module"), cfg, release=False, check=need)
        super().__init__(cfg, root, req)


class ModuleRelease(_ModuleRelease):
    def __init__(self, cfg, root, req):
        if isinstance(req, dict):
            validate_module_profiles(req.get("module"), cfg, release=True, check=need)
        super().__init__(cfg, root, req)
        if operation.reviewed.enabled(self.profile):
            self.runtime.release_run = req["run"]

    def execute(self, review):
        with operation.public_output.scope(self.profile):
            try:
                return operation.public_output.public(super().execute(review))
            except Held as exc:
                raise Held(operation.public_output.public(str(exc))) from None

    def reviewed_return(self):
        stamp = self.req["digest"]
        # Look up the already approved dispatch independently of the READY pointer.
        # A crash can leave the original result, pointer or signature unpublished.
        def approved_run(plan_digest):
            need(hex64(plan_digest), "MODULE_APPROVAL_DRIFT")
            claim = read(self.path.parent / ("module-apply-" + plan_digest))
            req = claim["request"]
            need(req["operation"] == "module-release" and req["module"] == self.req["module"] and
                 req["phase"] == "apply" and req["digest"] == plan_digest and hex64(claim["review"])
                 and req["run"].isascii() and req["run"].isdigit(), "MODULE_APPROVAL_DRIFT")
            run = self.path.parent / req["run"]
            proposal = read(run / "plan")
            need(read(run / "plan.review")["request"] == dict(req, phase="plan", digest=intent(req)) and
                 proposal["status"] == "PLANNED" and proposal["planSha256"] == digest(proposal["plan"]) == plan_digest
                 and proposal["plan"].get("sourcePlan", plan_digest) == stamp, "MODULE_APPROVAL_DRIFT")
            if (run / "apply.review").exists():
                need(read(run / "apply.review") == claim, "MODULE_APPROVAL_DRIFT")
            return run, proposal["plan"]

        original, plan = approved_run(stamp)

        def publishing_run(run_id):
            need(isinstance(run_id, str) and run_id.isascii() and run_id.isdigit(), "MODULE_APPROVAL_DRIFT")
            if run_id == original.name:
                return original
            recovery_plan = read(self.path.parent / run_id / "plan")
            run, _ = approved_run(recovery_plan["planSha256"])
            need(run.name == run_id, "MODULE_APPROVAL_DRIFT")
            return run

        def publish(body, receipt, returning):
            pointer = self.path.parent / ("module-" + self.req["module"] + ".ready")
            current = read(pointer) if pointer.exists() else None
            origin = receipt.get("releaseRun")
            run = publishing_run(origin)
            phase = "migrate" if "migrationSha256" in receipt else "apply"
            if phase == "migrate":
                stage = read(run / "apply.result")
                need(read(self.path.parent / ("module-migrate-" + receipt["migrationSha256"])) == read(run / "migrate.review"),
                     "MODULE_APPROVAL_DRIFT")
                need(stage["migrationSha256"] == receipt["migrationSha256"] == read(run / "migrate.review")["request"]["digest"]
                     and "migrate" in read(run / "approvals"), "MODULE_APPROVAL_DRIFT")
            need(body == plan, "MODULE_PARENT_DRIFT")
            target = run / (phase + ".result")
            unlock_failure = None
            if target.exists():
                published = read(target)
                if published != receipt:
                    reason = published.get("reason")
                    need(not returning and phase == "apply" and run.name == origin and
                         isinstance(reason, str) and reason.startswith("RELEASE_IO_OR_INPUT_ERROR/") and
                         published == dict(receipt, status="HELD", reason=reason), "MODULE_RECEIPT_DRIFT")
                    unlock_failure = published
            tip = {"run": run.name, "phase": phase, "planSha256": stamp}
            if current and current["planSha256"] == stamp and current["run"] != origin:
                # A recovery apply can republish an already durable READY from the original run.
                publisher = publishing_run(current["run"])
                need(current["phase"] == "apply" and read(publisher / "apply.result") == receipt,
                     "MODULE_RECEIPT_DRIFT")
                tip = current
            if current != tip:
                need(current is None or not returning and int(current["run"]) < int(run.name), "MODULE_RECEIPT_DRIFT")
            if "receiptSigning" in self.profile:
                directory = Path(self.profile["journal"]) / stamp
                operation.confirm(directory, "ready-before-signing.json", receipt)
                module_receipt.attest(self.profile["receiptSigning"], directory, issue=True)
            if unlock_failure:
                operation.confirm(run, "apply.unlock-failure", unlock_failure)
                save(target, receipt, replace=True)
            else:
                operation.confirm(run, target.name, receipt)
            if current != tip:
                save(pointer, tip, replace=True)

        def published_receipt():
            pointer = self.path.parent / ("module-" + self.req["module"] + ".ready")
            tip = read(pointer) if pointer.is_file() else {}
            run = publishing_run(tip["run"]) if tip.get("planSha256") == stamp else original
            for phase in ("migrate", "apply"):
                path = run / (phase + ".result")
                if path.is_file():
                    result = read(path)
                    if result.get("status") == "READY":
                        return result
            return None

        return operation.reviewed.return_run(self.profile, stamp, self.runtime, publication=publish,
                                             approved_plan=plan, published_receipt=published_receipt)
