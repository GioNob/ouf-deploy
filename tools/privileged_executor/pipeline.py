"""Three protected calls. Root records the expected next digest before returning it to Actions."""
import copy
from contextlib import ExitStack
import http.client
import hashlib
from pathlib import Path
import time
from urllib.parse import quote

from ingress import verified
from mandate import Held, digest, intent, need
from queue_inventory import Queue, permit, review_rows
from runbooks import Books, stop
from semantic import Engine, allocated_profile, prepare, profile_template, signal_once
from semantic_identity_v25 import semantic_observe, semantic_profile
from store import Journal, read, save, trusted
from successor_image import admit, migration_review


def until(fn, seconds, code):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            return fn()
        except Held as error:
            last = str(error)
            time.sleep(.25)
        except (ValueError, OSError, RuntimeError, http.client.HTTPException):
            time.sleep(.25)
    # Public diagnosis: only the last public code of the inner check, never data.
    raise Held(code + "/" + last if last else code)


class Cutover:
    def __init__(self, cfg, root, req, source_get=None):
        self.cfg, self.root, self.req = cfg, root, req
        self.source_get = source_get
        self.path = root / req["run"]
        self.log = Journal(self.path)
        self.books = Books(cfg, self.path)
        self.queue = Queue(cfg["queue"], cfg["socket"])
        self.engine = Engine(cfg["socket"])
        self.forward = req["direction"] == "forward"
        self.name = cfg["originalProfile"]["containerName"]

    def record(self, file):
        return read(self.path / file)

    def supervisor(self, version):
        return read(Path(self.cfg["installRoot"]) / "versions" / str(version) / "supervisor/configuration.json")

    def owner(self, direction):
        return read(self.root / direction)["run"]

    def original(self):
        return read(self.root / self.owner("forward") / "plan")

    def current_version(self):
        directory = Path(self.cfg["installRoot"]) / "authorization"
        names = {p.name for p in directory.iterdir()}
        n = len(names) // 2
        need(n in (27, 28) and names == {f"{i}.{suffix}" for i in range(1, n+1)
             for suffix in ("json", "signature.json")}, "HEAD_RECONCILIATION_REQUIRED")
        return n

    def authority(self):
        directory = Path(self.cfg["installRoot"]) / "authorization"
        return digest({p.name: hashlib.sha256(trusted(p, private=True).read_bytes()).hexdigest()
                       for p in directory.iterdir()})

    def resume_gated(self, version):
        direction = self.req["direction"]
        origin = self.root / self.owner(direction)
        original = read(origin / "plan")
        previous = self.root / self.owner(direction + "-stage")
        need(original["profileSha256"] == digest(self.cfg) and original["head"] == version
             and not (self.forward and (self.root / "return").exists())
             and (origin / "start-gate.receipt").exists() and not (previous / "start.claim").exists(),
             "GATED_RESUME_UNPROVEN")
        if (previous / "issue.claim").exists():
            need(read(previous / "issue-no-effect")["plan"] == read(previous / "issue.claim")["plan"],
                 "PARTIAL_ISSUANCE_REQUIRES_RECONCILIATION")
        cid = read(origin / ("create.receipt" if self.forward else "reconnect.receipt"))["result"]
        target = allocated_profile(original, cid) if self.forward else original["original"]
        sup = self.supervisor(version)
        self.closed(sup)
        generation = self.engine.process(cid, target, "GATE_WAITING")
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], rows)
        return {**original, "intent": intent(self.req), "queue": rows, "resume": {
            "origin": origin.name, "previous": previous.name, "cid": cid, "target": target,
            "generation": generation, "epoch": self.observe(cid, target, sup)}}

    def initial(self):
        version = self.current_version()
        direction = self.req["direction"]
        prior = None
        if (self.root / direction).exists():
            prior = self.owner(direction)
            if not (self.root / prior / "stop-no-effect").is_file():
                return self.resume_gated(version)
        if self.forward:
            need(version == 27, "EXPECTED_SOURCE_HEAD")
            profile = semantic_profile(self.cfg["originalProfile"])
            old = self.engine.inspect(self.name)
            spec = self.cfg.get("successorImage")
            request, target = prepare(old, profile, spec["ci"]["imageId"] if spec is not None else None)
            if "successorImage" not in self.cfg:
                self.image_binding(request, profile)
            self.ready(old["Id"], profile, self.engine.process(old["Id"], profile, "APPLICATION_RUNNING"))
            probe_preflight = self.probe_preflight(version, old["Id"])
            nets = {k: v["NetworkID"] for k, v in old["NetworkSettings"]["Networks"].items()}
            frame = {"old": old["Id"], "request": request, "networks": nets, "original": profile,
                     "probePreflight": probe_preflight, "template": profile_template(old), "target": target, "source": old["Id"], "previous": profile}
            need(self.engine.inspect(self.cfg["retainedName"], True) is None, "RETAINED_NAME_IN_USE")
            if "successorImage" in self.cfg:
                frame["successorImage"] = admit(self.cfg, self.log, self.source_get)
                self.image_binding(request, target)
        else:
            first = self.original()
            source = read(self.root / self.owner("forward") / "create.receipt")["result"]
            retained = self.engine.inspect(first["old"])
            need(retained["Id"] == first["old"] and retained["Name"] == "/" + self.cfg["retainedName"]
                 and retained["Image"] == first["original"]["image"] and not retained["State"]["Running"]
                 and not retained["NetworkSettings"]["Networks"], "RETAINED_CID_DRIFT")
            need(self.engine.inspect(self.cfg["failedName"], True) is None, "RETURN_NAME_IN_USE")
            frame = {**{k: first[k] for k in ("request", "networks", "old", "original")},
                     "source": source, "previous": allocated_profile(first, source), "target": first["original"]}
            if "successorImage" in first:
                frame["request"] = {**first["request"], "Image": first["template"]["Config"]["Image"]}
        sequence = 28 if self.forward else (29 if version == 28 else 27)
        reconciliation = None
        installed = version
        if not self.forward and version == 28:
            origin = self.root / self.owner("forward-stage")
            if not (origin / "upgrade.receipt").exists():
                need(not (origin / "upgrade.claim").exists(), "PARTIAL_UPGRADE_REQUIRES_RECONCILIATION")
                signed = read(origin / "issue.receipt")["result"]
                reconciliation = Books(self.cfg, origin).call("upgrade", version)
                need(reconciliation["versionBefore"] == 27 and reconciliation["versionAfter"] == version
                     and reconciliation["authorization"]["sha256"] == signed["payloadSha256"]
                     and reconciliation["compositionInputHashes"]["semanticProfile"] == digest(frame["previous"]),
                     "RETURN_UPGRADE_DRIFT")
                installed = 27
        sup = self.supervisor(installed)
        need(sup["coordinator"]["journalPath"] == self.cfg["leaseJournal"]
             and sup["semanticIngress"]["commands"]["socket"] == self.cfg["socket"], "INSTALLATION_BINDING")
        kind = "start" if read(sup["statusPath"])["state"] == "WAITING" else "stop"
        need(not self.forward or kind == "stop", "FORWARD_REQUIRES_ACTIVE")
        # A return before issue may have a waiting successor that the v27 start plan
        # cannot admit. Use the signed stop receipt and live closure in that case.
        staged27 = not self.forward and installed == 27 and kind == "start"
        if staged27:
            stopped = read(self.root / self.owner("forward") / "stop.receipt")["result"]
            need(stopped["lastObservation"]["authorization"]["sequence"] == installed
                 and (reconciliation is not None or self.authority() == first["authority"]), "STOP_RECEIPT_REQUIRED")
            r3 = None
        else:
            r3 = self.books.call(kind, version)
            observation = r3["observation"]
            need(r3["installRoot"] == self.cfg["installRoot"] and
                 set(self.cfg["roleCids"]) == {v["cid"] for v in observation["candidates"].values()} and
                 set(self.cfg["roleTables"]) == {v["tableName"] for v in observation["tables"].values()},
                 "R3_INSTALLATION_DRIFT")
        self.observe(frame["source"], frame["previous"], sup)
        if kind == "start":
            self.closed(sup)
        else:
            until(lambda: self.check_verified(sup, frame["previous"], frame["source"], version),
                  30, "INITIAL_INGRESS_HELD")
        for op in ("start", "probe", *(("issue", "upgrade") if sequence != version else ())):
            self.books.binding(op, sequence)
        rows = self.queue.snapshot()
        need(self.req["queue"] != "empty" or not rows, "QUEUE_NOT_EMPTY")
        return {**frame, "prior": prior, "intent": intent(self.req), "profileSha256": digest(self.cfg), "head": version,
                "sequence": sequence, "installed": installed, "reconcileUpgrade": reconciliation,
                "authority": self.authority(), "stop": r3 if kind == "stop" else None, "queue": rows,
                "sourceEpoch": self.observe(frame["source"], frame["previous"], sup)}

    def probe_preflight(self, version, cid):
        home = Journal(self.path / "probe-preflight").path
        plan = Books(self.cfg, home).call("probe", version)
        need(plan["observation"]["semantic"]["containerId"] == cid and plan["secretsRead"] == 0,
             "PROBE_PREFLIGHT_SCOPE")
        return plan["planSha256"]

    def image_binding(self, request, profile):
        current = self.engine.call("GET", "images/" + quote(request["Image"], safe="") + "/json")
        need(current["Id"] == profile["image"], "IMAGE_REFERENCE_DRIFT")

    def observe(self, cid, profile, sup):
        obs, _ = semantic_observe(profile, sup["semanticIngress"]["commands"])
        need(obs["containerId"] == cid, "OBSERVED_CID_DRIFT")
        return obs

    def closed(self, sup):
        from semantic_identity_v25 import semantic_command
        import json
        lease = read(sup["coordinator"]["journalPath"])
        need(lease["state"] == "QUIESCED" and lease["leaseAuthorized"] is False
             and read(sup["statusPath"])["state"] == "WAITING", "QUIESCENCE_REQUIRED")
        tables = json.loads(semantic_command(sup["coordinator"]["nftBinding"],
                            ["-j", "list", "tables"]))["nftables"]
        names = set(self.cfg["roleTables"])
        need(len(names) == 2 and sup["semanticIngress"]["table"] in names
             and not any(r.get("table", {}).get("name") in names for r in tables), "ROLE_TABLES_PRESENT")
        for cid in self.cfg["roleCids"]:
            row = self.engine.inspect(cid)
            need(row["Id"] == cid and row["State"]["Status"] == "exited"
                 and row["State"]["Pid"] == 0, "COHORT_NOT_STOPPED")

    def prepare_stage(self, plan):
        version = plan["head"]
        need(version == self.current_version() and plan["authority"] == self.authority()
             and plan["profileSha256"] == digest(self.cfg), "PLAN_DRIFT")
        direction = self.req["direction"]
        if "resume" in plan:
            current = self.resume_gated(version)
            need(current == plan, "GATED_PLAN_DRIFT")
            staged = plan["resume"]
            save(self.root / (direction + "-stage"), {"run": self.req["run"]}, replace=True)
            return self.issuance_stage(plan, staged["cid"], staged["target"], self.supervisor(version))
        sup = self.supervisor(plan["installed"])
        need(self.observe(plan["source"], plan["previous"], sup) == plan["sourceEpoch"], "SOURCE_EPOCH_DRIFT")
        if self.forward:
            image = plan.get("successorImage")
            request, target = prepare(self.engine.inspect(plan["old"]), plan["original"],
                                      image["ci"]["imageId"] if image else None)
            need(request == plan["request"] and target == plan["target"], "SUCCESSOR_PLAN_DRIFT")
            self.image_binding(request, target)
        name = self.cfg["retainedName" if self.forward else "failedName"]
        need(self.engine.inspect(name, True) is None, "RETENTION_NAME_DRIFT")
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], plan["queue"])
        replace = plan["prior"] is not None
        if replace:
            need(self.owner(direction) == plan["prior"] and (self.root / plan["prior"] / "stop-no-effect").is_file(),
                 "STOP_CLAIM_DRIFT")
        save(self.root / direction, {"run": self.req["run"], "plan": digest(plan)}, replace=replace)
        save(self.root / (direction + "-stage"), {"run": self.req["run"]}, replace=replace)
        if plan["stop"]:
            def record(n, row):
                save(self.path / f"stop-retry-{n}", row)
            try:
                self.log.effect("stop", plan["stop"], lambda: stop(self.books, version, plan["stop"], record))
            except Held as error:
                if str(error) in ("STOP_RETRY_LIMIT", "STOP_REQUIRES_NEW_REVIEW", "RENEWAL_TIMEOUT"):
                    save(self.path / "stop-no-effect", {"plan": digest(plan), "reason": str(error)})
                raise
        self.closed(sup)
        if plan["reconcileUpgrade"]:
            book = Books(self.cfg, self.root / self.owner("forward-stage"))
            upgrade = plan["reconcileUpgrade"]
            self.log.effect("reconcile-upgrade", upgrade,
                            lambda: book.call("upgrade", version, upgrade["planSha256"]))
            sup = self.supervisor(version)
            self.closed(sup)
        need(self.observe(plan["source"], plan["previous"], sup) == plan["sourceEpoch"], "SOURCE_EPOCH_DRIFT")
        self.log.effect("detach", {"parent": digest(plan), "cid": plan["source"]},
            lambda: self.engine.detach(plan["source"], self.cfg["retainedName" if self.forward else "failedName"],
                                       plan["networks"]))
        if self.forward:
            cid = self.log.effect("create", {"request": digest(plan["request"]), "parent": digest(plan)},
                lambda: self.engine.create(self.name, plan["request"], plan["target"]["image"]))
        else:
            cid = self.log.effect("reconnect", {"parent": digest(plan), "old": plan["old"]},
                lambda: self.engine.reconnect(plan["old"], self.name,
                    plan["request"]["NetworkingConfig"]["EndpointsConfig"], plan["networks"]))
        launch = copy.deepcopy(plan["request"])
        if not self.forward:
            launch["Env"] = ["OUF_DISCOVERY_WORKER_ENABLED=false" if v == "OUF_DISCOVERY_WORKER_ENABLED=true"
                             else v for v in launch["Env"]]
        self.log.effect("start-gate", {"cid": cid, "parent": digest(plan)},
                        lambda: self.engine.start_gate(cid, self.name, launch, plan["target"]["image"]))
        target = allocated_profile(plan, cid) if self.forward else plan["original"]
        return self.issuance_stage(plan, cid, target, sup)

    def issuance_stage(self, plan, cid, target, sup):
        seq, version = plan["sequence"], plan["head"]
        generation = until(lambda: self.engine.process(cid, target, "GATE_WAITING"), 15, "GATE_HELD")
        epoch = self.observe(cid, target, sup)
        need(epoch == self.observe(cid, target, sup), "GATED_EPOCH_DRIFT")
        issue = None
        if seq != version:
            issue = self.books.call("issue", seq)
            need(issue["previousHead"]["sequence"] == version and issue["payload"]["sequence"] == seq
                 and issue["payload"]["supersedes"] == issue["previousHead"]["sha256"]
                 and issue["compositionInputHashes"]["semanticProfile"] == digest(target)
                 and issue["privateKeysRead"] == 0, "ISSUANCE_SCOPE_DRIFT")
        return {"cid": cid, "profile": target, "generation": generation, "epoch": epoch,
                "issue": issue, "parent": digest(plan)}

    def finish(self, plan, stage):
        version, seq, cid = plan["head"], plan["sequence"], stage["cid"]
        profile, generation = stage["profile"], stage["generation"]
        need(self.owner(self.req["direction"] + "-stage") == self.req["run"] and
             (not self.forward or not (self.root / "return").exists()), "TRANSACTION_SUPERSEDED")
        need(self.current_version() == version and self.engine.process(cid, profile, "GATE_WAITING") == generation
             and self.observe(cid, profile, self.supervisor(version)) == stage["epoch"], "SIGNING_EPOCH_DRIFT")
        self.closed(self.supervisor(version))
        if stage["issue"]:
            # The existing issuer revalidates its frozen input bundle, mandate and head under lock.
            stamp = stage["issue"]["planSha256"]
            signed = self.log.effect("issue", {"plan": stamp, "parent": digest(stage)},
                                     lambda: self.books.call("issue", seq, stamp))
            upgrade = self.books.call("upgrade", seq)
            need(upgrade["versionBefore"] == version and upgrade["versionAfter"] == seq
                 and upgrade["authorization"]["sha256"] == signed["payloadSha256"]
                 and upgrade["compositionInputHashes"] == stage["issue"]["compositionInputHashes"],
                 "UPGRADE_SCOPE_DRIFT")
            self.apply_book("upgrade", seq, upgrade, digest(stage))
        sup = self.supervisor(seq)
        need(sup["semanticIngress"]["profile"] == profile, "START_PROFILE_DRIFT")
        chain = self.authority()
        start = self.books.call("start", seq)
        self.apply_book("start", seq, start, digest(stage))
        try:
            permit(self.queue.snapshot(), self.req["queue"], plan["queue"])
            # PostgreSQL on the local Engine shares the host realtime clock.
            time_floor = time.time_ns() // 1000
            with ExitStack() as ingress:
                deadline = until(lambda: ingress.enter_context(verified(sup, profile, cid, seq)),
                                 30, "GATE_RELEASE_HELD")
                need(self.authority() == chain, "RELEASE_HEAD_DRIFT")
                permit(self.queue.snapshot(deadline=deadline), self.req["queue"], plan["queue"])
                signal_once(self.engine, self.log, cid, profile, generation, deadline)
            until(lambda: self.ready(cid, profile, generation), 120, "READINESS_HELD")
            probe = self.books.call("probe", seq)
            need(probe["observation"]["semantic"]["containerId"] == cid, "PROBE_CID_DRIFT")
            self.apply_book("probe", seq, probe, digest(stage))
            need(self.authority() == chain, "FINAL_HEAD_DRIFT")
            self.ready(cid, profile, generation)
            until(lambda: self.check_verified(sup, profile, cid, seq), 30, "FINAL_READBACK_HELD")
        except Exception:
            cleanup = self.books.call("stop", seq)
            need(cleanup["observation"]["authorization"] == start["observation"]["authorization"]
                 and cleanup["observation"]["configurationSha256"] == start["observation"]["configurationSha256"],
                 "FAILURE_STOP_SCOPE_DRIFT")
            self.log.effect("failure-stop", cleanup, lambda: stop(self.books, seq, cleanup,
                            lambda i, p: save(self.path / f"failure-stop-retry-{i}", p)))
            self.closed(sup)
            raise
        return {"ingress": "VERIFIED", "readiness": "UP", "probe": "C_PROBE_PASSED", "worker": "on" if self.forward else "off",
                "proofSince": time_floor}

    @staticmethod
    def check_verified(sup, profile, cid, seq):
        with verified(sup, profile, cid, seq):
            return True

    def apply_book(self, op, seq, plan, parent):
        return self.log.effect(op, {"parent": parent, "plan": plan}, lambda: self.books.call(op, seq, plan["planSha256"]))

    def ready(self, cid, profile, generation):
        need(self.engine.process(cid, profile, "APPLICATION_RUNNING") == generation, "JAVA_PID_ONE_REQUIRED")
        conn = http.client.HTTPConnection(profile["ipv4"], self.cfg["readinessPort"], timeout=2)
        try:
            import json
            conn.request("GET", "/actuator/health/readiness")
            response = conn.getresponse()
            need(response.status == 200 and json.loads(response.read(8193))["status"] == "UP", "READINESS_HELD")
        finally:
            conn.close()
        need(self.engine.process(cid, profile, "APPLICATION_RUNNING") == generation, "READINESS_EPOCH_DRIFT")

    def execute(self, review):
        phase = self.req["phase"]
        def accept():
            save(self.path / (phase + ".review"), {"request": self.req, "review": review})
        if phase == "plan":
            accept()
            plan = self.initial()
            save(self.path / "plan", plan)
            response = {"digest": digest(plan), "queueCount": len(plan["queue"]), "queueDigest": digest(plan["queue"]),
                        "queue": review_rows(plan["queue"])}
            if "successorImage" in plan:
                image = plan["successorImage"]
                response["imageId"] = image["ci"]["imageId"]
                response["zipSha256"] = image["ci"]["zipSha256"]
                response["inventorySha256"] = digest(image["migrations"])
            return response
        plan = self.record("plan")
        need(plan["intent"] == intent(self.req) and plan["profileSha256"] == digest(self.cfg)
             and self.record("plan.review")["request"]["digest"] == intent(self.req), "PARENT_MANDATE_DRIFT")
        if phase == "proof":
            result = self.record("result")
            need(self.forward and result["worker"] == "on" and self.req["digest"] == digest(result)
                 and self.owner("forward-stage") == self.req["run"] and not (self.root / "return").exists(),
                 "WORKER_PROOF_SCOPE")
            need("proof" in self.cfg["queue"], "WORKER_PROOF_PROFILE_REQUIRED")
            accept()
            proof = self.queue.worker(result["proofSince"])
            save(self.path / "worker-proof", proof)
            return {"digest": digest(proof), "proof": proof["state"]}
        if phase == "apply":
            need(self.req["digest"] == digest(plan), "APPROVED_PLAN_DRIFT")
            accept()
            stage = self.prepare_stage(plan)
            save(self.path / "stage", stage)
            migration = migration_review(plan, stage)
            if migration:
                new = plan["successorImage"]["newMigrations"]
                return {"digest": migration, "migrationCount": len(new), "migrationsSha256": digest(new),
                        "imageId": stage["profile"]["image"]}
            return {"digest": stage["issue"]["planSha256"] if stage["issue"] else digest(stage)}
        stage = self.record("stage")
        need(self.record("apply.review")["request"]["digest"] == stage["parent"] == digest(plan),
             "APPROVED_ISSUANCE_DRIFT")
        signing = stage["issue"]["planSha256"] if stage["issue"] else digest(stage)
        migration = migration_review(plan, stage)
        if phase == "migrate":
            need(migration and self.req["digest"] == migration, "APPROVED_MIGRATION_DRIFT")
            accept()
            return {"digest": signing}
        need(phase == "sign" and self.req["digest"] == signing, "APPROVED_ISSUANCE_DRIFT")
        if migration:
            need((self.path / "migrate.review").is_file() and
                 self.record("migrate.review")["request"] == {**self.req, "phase": "migrate", "digest": migration},
                 "MIGRATION_REVIEW_REQUIRED")
        accept()
        result = self.finish(plan, stage)
        save(self.path / "result", result)
        return {"digest": digest(result), "ingress": result["ingress"], "readiness": result["readiness"],
                "worker": result["worker"]}
