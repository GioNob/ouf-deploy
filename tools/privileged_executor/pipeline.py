"""Three protected calls. Root records the expected next digest before returning it to Actions."""
from contextlib import ExitStack
import http.client
import hashlib
from pathlib import Path
import time
from urllib.parse import quote

from ingress import verified
from mandate import Held, digest, hex64, intent, need
from queue_inventory import Queue, permit, review_rows
from runbooks import Books, SUCCESS, SUPPORTED_HEADS, stop
from semantic import Engine, allocated_profile, configuration, never_started, prepare, profile_template, signal_once
from semantic_identity_v25 import semantic_observe, semantic_profile
import store
from store import Journal, read, save, trusted
from successor_image import admit, inventory, migration_review


INGRESS_PAUSE = 2.0


def until(fn, seconds, code, pause=.25):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            return fn()
        except Held as error:
            last = str(error)
            time.sleep(pause)
        except (ValueError, OSError, RuntimeError, http.client.HTTPException):
            time.sleep(pause)
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
        self.next_release = req.get("release") == "next"
        self.source_head = 28 if self.next_release else 27
        self.name = cfg["originalProfile"]["containerName"]

    @property
    def retained_name(self):
        return self.cfg["retainedName"] + ("-v28" if self.next_release else "")

    def record(self, file):
        return read(self.path / file)

    def supervisor(self, version):
        return read(Path(self.cfg["installRoot"]) / "versions" / str(version) / "supervisor/configuration.json")

    def completed_forward(self):
        need((self.root / "completed-forward").is_file(), "COMPLETED_FORWARD_REQUIRED")
        pointer = read(self.root / "completed-forward")
        archive = read(self.root / pointer["run"] / "closed-forward")
        need(digest(archive) == pointer["archive"], "CLOSURE_POINTER_DRIFT")
        return archive

    def pointer(self, key):
        path = self.root / key
        if key in ("forward", "forward-stage") and not path.exists():
            other = "forward-stage" if key == "forward" else "forward"
            need(not (self.root / other).exists(), "INCOMPLETE_FORWARD_PUBLICATION")
            return self.completed_forward()["pointers"][key]
        return read(path)

    def owner(self, direction):
        return self.pointer(direction)["run"]

    def original(self):
        return read(self.root / self.owner("forward") / "plan")

    def forward_creation(self):
        plan = self.original()
        return self.root / plan.get("createdFrom", plan.get("beforeCreate", self.owner("forward")))

    def issuing_run(self, run):
        plan = read(self.root / run / "plan")
        return self.root / plan.get("committedFrom", run)

    def bind_return(self):
        for op in SUCCESS:
            self.books.binding(op, self.source_head + 2)

    def prepare_image(self, old, profile, image):
        if image is None:
            return prepare(old, profile, worker_enabled=self.next_release)
        iid = image["ci"]["imageId"]
        inspected = self.engine.call("GET", "images/" + quote(iid, safe="") + "/json")
        need(inspected["Id"] == iid, "IMAGE_REFERENCE_DRIFT")
        return prepare(old, profile, iid, inspected["Config"], worker_enabled=self.next_release)

    def retained(self, first):
        row = self.engine.inspect(first["old"])
        config = dict(row["Config"])
        config.pop("MacAddress", None)
        need(row["Id"] == first["old"] and row["Name"] == "/" + self.retained_name
             and row["Image"] == first["original"]["image"] and config == first["template"]["Config"]
             and row["State"]["Status"] == "exited" and row["State"]["Running"] is False
             and row["State"]["Pid"] == 0 and not row["NetworkSettings"]["Networks"], "RETAINED_CID_DRIFT")

    def interrupted_creation(self, version):
        """Reconstruct the reviewed create from its original immutable journal."""
        owner = self.owner("forward")
        origin = self.forward_creation()
        first = read(origin / "plan")
        active = self.original()
        need(read(self.root / "forward") == {"run": owner, "plan": digest(active)}
             and self.owner("forward-stage") in (owner, active.get("interrupted", owner))
             and not (self.root / owner / "start-gate.receipt").exists()
             and not (origin / "start-gate.receipt").exists()
             and (not self.forward or not (self.root / "return").exists())
             and version == first["head"] == first["installed"] == self.source_head
             and self.authority() == first["authority"], "CREATED_RESUME_UNPROVEN")
        original_commit = read(origin / "plan.review")["request"]["commit"]
        # Installing the fix changes the executor commit. All other installed
        # profile fields must still reproduce the original private digest.
        need(first["profileSha256"] in (digest(self.cfg), digest({**self.cfg, "commit": original_commit})),
             "CREATED_PROFILE_DRIFT")
        parent = digest(first)
        stopped = self.book_result(origin, "stop", first["stop"])
        need(stopped["lastObservation"]["authorization"]["sequence"] == version
             and stopped["lastObservation"]["authorization"]["decision"] == "OPERATE"
             and self.effect_result(origin, "detach", {"parent": parent, "cid": first["old"]}) == first["old"],
             "STOP_RECEIPT_REQUIRED")
        cid = self.effect_result(origin, "create", {"request": digest(first["request"]), "parent": parent})
        need(hex64(cid) and cid != first["old"], "CREATE_CID_REQUIRED")
        for directory, plan in ((origin, first), (self.root / owner, active)):
            claim = directory / "start-gate.claim"
            if claim.exists():
                need(read(claim) == {"cid": cid, "parent": digest(plan)}, "START_GATE_CLAIM_DRIFT")
        sup = self.supervisor(version)
        need(sup["coordinator"]["journalPath"] == self.cfg["leaseJournal"]
             and sup["semanticIngress"]["commands"]["socket"] == self.cfg["socket"], "INSTALLATION_BINDING")
        self.closed(sup)
        self.retained(first)
        row = self.engine.inspect(cid)
        need(row["Id"] == cid and row["Name"] == "/" + self.name and row["Image"] == first["target"]["image"]
             and never_started(row["State"]), "NEVER_STARTED_REQUIRED")
        return origin, first, row

    @staticmethod
    def effect_result(origin, name, claim):
        receipt = origin / (name + ".receipt")
        need(receipt.is_file(), "INTERRUPTED_RECEIPT_REQUIRED")
        row = read(receipt)
        need(read(origin / (name + ".claim")) == claim and row["planSha256"] == digest(claim),
             "CREATED_RECEIPT_DRIFT")
        return row["result"]

    def book_result(self, origin, op, claim):
        if (origin / (op + ".receipt")).is_file():
            return self.effect_result(origin, op, claim)
        # The pinned runbook may have durably published its own result before
        # our process could write a receipt. Never repeat the claimed apply.
        need((origin / (op + ".claim")).is_file() and read(origin / (op + ".claim")) == claim,
             "INTERRUPTED_RECEIPT_REQUIRED")
        proposal = claim if op == "stop" else claim["plan"]
        if op == "stop":
            for retry in (1, 2):
                if (origin / f"stop-retry-{retry}").is_file():
                    proposal = read(origin / f"stop-retry-{retry}")
        result = Path(proposal["outputDirectory"]) / "result.json"
        need(result.is_file(), "RUNBOOK_OUTCOME_REQUIRES_RECONCILIATION")
        row = read(result)
        need(row["planSha256"] == proposal["planSha256"] and row["status"] == SUCCESS[op],
             "RUNBOOK_RESULT_DRIFT")
        return row

    def before_create(self, version, origin):
        first = read(origin / "plan")
        pointer = self.pointer("forward")
        need(pointer["plan"] == digest(self.original()) and first["head"] == version == self.source_head
             and first["authority"] == self.authority() and first["profileSha256"] == digest(self.cfg)
             and not (self.root / "return").exists() and not (origin / "create.claim").exists(),
             "CREATE_OUTCOME_REQUIRES_RECONCILIATION")
        stopped = self.book_result(origin, "stop", first["stop"])
        need(stopped["lastObservation"]["authorization"] == first["stop"]["observation"]["authorization"],
             "STOP_RECEIPT_REQUIRED")
        self.closed(self.supervisor(version))
        cid = first["old"]
        old = self.engine.inspect(cid)
        frozen = first["template"]
        frame = profile_template(old)
        remaining = frame.pop("NetworkSettings")["Networks"]
        need(frame == {k: v for k, v in frozen.items() if k != "NetworkSettings"}
             and old["Image"] == first["original"]["image"] and old["Id"] == cid
             and old["Name"] in ("/" + self.name, "/" + self.retained_name)
             and all(k in first["networks"] and v["NetworkID"] == first["networks"][k]
                     and v["IPAMConfig"] == frozen["NetworkSettings"]["Networks"][k]["IPAMConfig"]
                     for k, v in remaining.items()), "PRE_CREATE_FRAME_DRIFT")
        parked = old["Name"] == "/" + self.retained_name
        if parked:
            self.retained(first)
            need(self.engine.inspect(self.name, True) is None, "CREATE_NAME_IN_USE")
        else:
            need(self.engine.inspect(self.retained_name, True) is None, "RETAINED_NAME_IN_USE")
        claim = {"parent": digest(first), "cid": cid}
        if (origin / "detach.claim").exists():
            need(read(origin / "detach.claim") == claim, "DETACH_CLAIM_DRIFT")
        if (origin / "detach.receipt").exists():
            need(parked and self.effect_result(origin, "detach", claim) == cid, "DETACH_RECEIPT_DRIFT")
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], rows)
        plan = {**first, "beforeCreate": origin.name, "interrupted": pointer["run"],
                "parked": parked, "remainingNetworks": {k: first["networks"][k] for k in remaining},
                "queue": rows, "intent": intent(self.req)}
        if not self.forward:
            plan.pop("successorImage", None)
            plan.update(request=self.return_request(first), target=first["original"], sequence=version)
        return plan

    def stage_before_create(self, plan, sup):
        origin = self.root / plan["beforeCreate"]
        first = read(origin / "plan")
        need(self.before_create(plan["head"], origin) == plan, "PRE_CREATE_PLAN_DRIFT")
        cid = first["old"]
        claim = {"parent": digest(first), "cid": cid}
        journal = Journal(origin)
        if not (origin / "detach.claim").exists():
            save(origin / "detach.claim", claim)
        if not plan["parked"]:
            self.log.effect("complete-detach", {"parent": digest(plan), "cid": cid},
                            lambda: self.engine.detach(cid, self.retained_name, plan["remainingNetworks"]))
        self.retained(first)
        if not (origin / "detach.receipt").exists():
            save(origin / "detach.receipt", {"planSha256": digest(claim), "result": cid,
                                             "observedBy": self.req["run"]})
        self.publish(plan, replace=self.forward)
        if self.forward:
            cid = journal.effect("create", {"request": digest(first["request"]), "parent": digest(first)},
                                 lambda: self.engine.create(self.name, first["request"], first["target"]["image"]))
        return self.launch_stage(plan, cid, sup)

    def created_plan(self, version):
        origin = self.forward_creation()
        if self.next_release and not (origin / "create.receipt").is_file():
            return self.before_create(version, origin)
        origin, first, row = self.interrupted_creation(version)
        cid = row["Id"]
        if self.forward:
            baseline = {**first["template"], "Name": "/" + self.name, "Image": first["original"]["image"]}
            request, target = self.prepare_image(baseline, first["original"], first.get("successorImage"))
            if "successorImage" not in first:
                self.image_binding(request, target)
            self.engine.stopped_gate(cid, self.name, request, target["image"])
            nets = row["NetworkSettings"]["Networks"]
            endpoints = request["NetworkingConfig"]["EndpointsConfig"]
            need(nets.keys() == endpoints.keys() and all(
                nets[k].get("NetworkID") in (None, "", first["networks"][k])
                and all(nets[k].get(f) == ep.get(f) for f in ("IPAMConfig", "DriverOpts", "Links"))
                and set(ep.get("Aliases") or []) <= set(nets[k].get("Aliases") or []) <=
                    set(ep.get("Aliases") or []) | {self.name, cid[:12]}
                for k, ep in endpoints.items()), "CREATED_NETWORK_DRIFT")
        else:
            request = self.return_request(first)
            target = first["original"]
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], rows)
        frame = {k: first[k] for k in ("old", "original", "networks", "template", "head", "authority", "installed")}
        if self.forward and "successorImage" in first:
            frame["successorImage"] = first["successorImage"]
        sequence = version + 1 if self.forward else version
        for op in ("start", "probe", *(("issue", "upgrade") if self.forward else ())):
            self.books.binding(op, sequence)
        return {**frame, "request": request, "target": target, "source": cid,
                "createdFrom": origin.name, "interrupted": self.owner("forward"), "originPlan": digest(first),
                "sequence": sequence, "queue": rows, "intent": intent(self.req), "profileSha256": digest(self.cfg)}

    @staticmethod
    def return_request(first):
        return {**first["template"]["Config"], "HostConfig": first["template"]["HostConfig"],
                "NetworkingConfig": first["request"]["NetworkingConfig"]}

    def close_forward(self):
        # forward-stage is retired last and anchors recovery after partial archival.
        if not (self.root / "forward-stage").exists() or (self.root / "return").exists():
            return
        stage = self.root / self.owner("forward-stage")
        if not (stage / "result").exists():
            return
        path = stage / "closed-forward"
        keys = ("forward", "forward-stage")
        if not path.exists():
            pointers = {key: read(self.root / key) for key in keys}
            origin = self.original()
            plan, staged, result = (read(stage / key) for key in ("plan", "stage", "result"))
            cid = read(self.forward_creation() / "create.receipt")["result"]
            need(pointers["forward"]["plan"] == digest(origin) and staged["parent"] == digest(plan)
                 and plan["sequence"] == origin["sequence"] == origin["head"] + 1
                 and staged["cid"] == cid and staged["profile"] == allocated_profile(origin, cid)
                 and result["worker"] == "on" and result["readiness"] == "UP"
                 and result["ingress"] == "VERIFIED" and result["probe"] == "C_PROBE_PASSED",
                 "FORWARD_COMPLETION_UNPROVEN")
            save(path, {"pointers": pointers, "result": digest(result), "head": plan["sequence"]})
        archive = read(path)
        need(archive["result"] == digest(read(stage / "result")), "CLOSURE_RESULT_DRIFT")
        self.retire(stage, archive, keys, "completed-forward")

    def retire(self, stage, archive, keys, marker):
        pointers = archive["pointers"]
        need(set(pointers) == set(keys) and all(not (self.root / key).exists()
             or read(self.root / key) == pointers[key] for key in keys), "CLOSURE_POINTER_DRIFT")
        save(self.root / marker, {"run": stage.name, "archive": digest(archive)}, replace=True)
        for key in keys:
            pointer = self.root / key
            if pointer.exists():
                pointer.unlink()
                store.sync_dir(self.root)

    def close_return(self):
        # The last pointer retired is the recovery anchor for partial archival.
        if not (self.root / "return-stage").exists():
            return
        stage = self.root / self.owner("return-stage")
        if not (stage / "result").exists():
            return
        path = stage / "closed-transaction"
        if not path.exists():
            pointers = {key: self.pointer(key) for key in ("forward", "forward-stage", "return", "return-stage")}
            for key in ("forward", "return"):
                need(pointers[key]["plan"] == digest(read(self.root / pointers[key]["run"] / "plan")),
                     "CLOSURE_PLAN_DRIFT")
            plan = read(stage / "plan")
            staged = read(stage / "stage")
            result = read(stage / "result")
            creation = self.forward_creation()
            if "beforeCreate" in plan:
                need(not (creation / "create.claim").exists() and plan["source"] == plan["old"],
                     "CREATE_OUTCOME_REQUIRES_RECONCILIATION")
            else:
                need(read(creation / "create.receipt")["result"] == plan["source"], "RETURN_SOURCE_DRIFT")
            need(result["worker"] == ("on" if self.original()["head"] == 28 else "off")
                 and result["readiness"] == "UP" and result["ingress"] == "VERIFIED"
                 and staged["cid"] == plan["old"] and staged["parent"] == digest(plan),
                 "RETURN_COMPLETION_UNPROVEN")
            saved_cid = None if "createdFrom" in plan or "beforeCreate" in plan else plan["source"]
            save(path, {"pointers": pointers, "result": digest(result), "failedCid": saved_cid})
        archive = read(path)
        need(archive["result"] == digest(read(stage / "result")), "CLOSURE_RESULT_DRIFT")
        completed = self.root / "completed-forward"
        if completed.exists() and self.completed_forward()["pointers"]["forward"] == archive["pointers"]["forward"]:
            completed.unlink()
            store.sync_dir(self.root)
        self.retire(stage, archive, ("forward", "forward-stage", "return", "return-stage"), "last-closed")

    def archived_failure(self):
        row = self.engine.inspect(self.cfg["failedName"], True)
        if row is None:
            return None
        need((self.root / "last-closed").exists(), "RETURN_NAME_IN_USE")
        last = read(self.root / "last-closed")
        archive = read(self.root / last["run"] / "closed-transaction")
        need(digest(archive) == last["archive"] and row["Id"] == archive["failedCid"]
             and row["Name"] == "/" + self.cfg["failedName"] and row["State"]["Status"] == "exited"
             and row["State"]["Pid"] == 0 and row["State"]["Running"] is False
             and not row["NetworkSettings"]["Networks"], "ARCHIVED_CID_DRIFT")
        return row["Id"]

    def current_version(self):
        directory = Path(self.cfg["installRoot"]) / "authorization"
        names = {p.name for p in directory.iterdir()}
        n = len(names) // 2
        need(n in SUPPORTED_HEADS and names == {f"{i}.{suffix}" for i in range(1, n+1)
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
        receipt = self.forward_creation() / "create.receipt" if self.forward else origin / "reconnect.receipt"
        cid = read(receipt)["result"]
        target = allocated_profile(original, cid) if self.forward else original["original"]
        sup = self.supervisor(version)
        self.closed(sup)
        generation = self.engine.process(cid, target, "GATE_WAITING")
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], rows)
        return {**original, "intent": intent(self.req), "queue": rows, "resume": {
            "origin": origin.name, "previous": previous.name, "cid": cid, "target": target,
            "generation": generation, "epoch": self.observe(cid, target, sup)}}

    def restore_plan(self, version):
        owner = self.owner("return")
        active = read(self.root / owner / "plan")
        origin = self.root / active.get("returnFrom", owner)
        first = read(origin / "plan")
        need(self.pointer("return") == {"run": owner, "plan": digest(active)}
             and version == first["head"] and version in (self.source_head, self.source_head + 1)
             and first["sequence"] == (version if version == self.source_head else version + 1)
             and self.authority() == first["authority"] and first["profileSha256"] == digest(self.cfg),
             "RETURN_STAGE_DRIFT")
        self.closed(self.supervisor(version))
        forward = self.original()
        cid = first["old"]
        old = self.engine.inspect(cid)
        template = profile_template(old)
        nets = template.pop("NetworkSettings")["Networks"]
        need(cid == forward["old"] == old["Id"] and old["Image"] == first["original"]["image"]
             and template == {k: v for k, v in forward["template"].items() if k != "NetworkSettings"}
             and old["Name"] in ("/" + self.retained_name, "/" + self.name)
             and old["State"]["Status"] == "exited" and not old["State"]["Running"] and old["State"]["Pid"] == 0
             and self.partial_networks(nets, first), "RETURN_PREDECESSOR_DRIFT")
        parked = old["Name"] == "/" + self.retained_name
        need(not parked or not nets, "RETAINED_CID_DRIFT")
        source = first["source"]
        candidate = None
        if source != cid:
            need(read(self.forward_creation() / "create.receipt")["result"] == source, "RETURN_SOURCE_DRIFT")
            row = self.engine.inspect(source, True)
            if row is None:
                need("createdFrom" in first and any((directory / "remove-created.claim").is_file()
                     for directory in (origin, self.root / owner)), "CREATE_CID_REQUIRED")
            else:
                request = forward["request"]
                config = dict(row["Config"])
                config.pop("MacAddress", None)
                if config["Hostname"] == source[:12] and not request["Hostname"]:
                    config["Hostname"] = ""
                networks = row["NetworkSettings"]["Networks"]
                need(row["Id"] == source and row["Image"] == forward["target"]["image"]
                     and config == configuration(request) and self.partial_networks(networks, forward)
                     and row["Name"] in ("/" + self.name, "/" + self.cfg["failedName"]), "RETURN_SOURCE_DRIFT")
                failed = row["Name"] == "/" + self.cfg["failedName"]
                need(not failed or (not networks and row["State"]["Status"] == "exited"
                     and not row["State"]["Running"] and row["State"]["Pid"] == 0), "RETURN_SOURCE_DRIFT")
                if "createdFrom" in first:
                    need(never_started(row["State"]) and not failed, "NEVER_STARTED_REQUIRED")
                candidate = {"failed": failed, "remaining": {k: first["networks"][k] for k in networks},
                             "state": row["State"]}
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], rows)
        return {**first, "returnFrom": origin.name, "returnOwner": owner, "candidate": candidate,
                "rename": parked, "missing": sorted(set(first["networks"]) - set(nets)),
                "intent": intent(self.req), "queue": rows}

    @staticmethod
    def partial_networks(networks, plan):
        endpoints = plan["request"]["NetworkingConfig"]["EndpointsConfig"]
        return all(k in plan["networks"] and v["NetworkID"] == plan["networks"][k]
                   and v.get("IPAMConfig") == endpoints[k].get("IPAMConfig") for k, v in networks.items())

    def restore_stage(self, plan, sup):
        need(self.restore_plan(plan["head"]) == plan, "RETURN_RECOVERY_DRIFT")
        source, cid = plan["source"], plan["old"]
        candidate = plan["candidate"]
        self.publish(plan, replace=True)
        if candidate and not candidate["failed"]:
            if "createdFrom" in plan:
                self.log.effect("remove-created", {"parent": digest(plan), "cid": source},
                                lambda: self.engine.remove_stopped(source, self.name, created=True))
            else:
                self.log.effect("detach", {"parent": digest(plan), "cid": source},
                                lambda: self.engine.detach(source, self.cfg["failedName"], candidate["remaining"]))
        endpoints = plan["request"]["NetworkingConfig"]["EndpointsConfig"]
        self.log.effect("reconnect", {"parent": digest(plan), "old": cid},
                        lambda: self.engine.reconnect_missing(cid, self.name, endpoints, plan["networks"],
                                                              rename=plan["rename"], missing=plan["missing"]))
        return self.start_stage(plan, cid, sup)

    def approved_issue(self, directory, stage, version):
        issue = stage["issue"]
        stamp = issue["planSha256"]
        need(issue["payload"]["sequence"] == version and read(directory / "sign.review")["request"]["digest"] == stamp
             and read(directory / "issue.claim") == {"parent": digest(stage), "plan": stamp}, "SIGNED_STAGE_DRIFT")
        head = Path(self.cfg["installRoot"]) / "authorization" / f"{version}.json"
        need(hashlib.sha256(trusted(head, private=True).read_bytes()).hexdigest() == issue["payloadSha256"],
             "SIGNED_PAYLOAD_DRIFT")
        return issue

    def committed_plan(self):
        # The stage owner keeps all one-shot claims across recovery dispatches.
        directory = self.root / self.owner(self.req["direction"] + "-stage")
        first, stage = (read(directory / key) for key in ("plan", "stage"))
        version = self.current_version()
        issued = stage["issue"] is not None
        before = self.source_head + int(not self.forward and issued)
        need(version == first["sequence"] == before + int(issued) and first["head"] == before
             and first["profileSha256"] == digest(self.cfg) and stage["parent"] == digest(first),
             "COMMITTED_STAGE_DRIFT")
        if self.forward:
            need(issued and not (self.root / "return").exists()
                 and stage["cid"] == read(self.forward_creation() / "create.receipt")["result"], "SIGNED_STAGE_DRIFT")
        else:
            receipt = read(self.root / self.owner("return") / "reconnect.receipt")
            need(stage["cid"] == first["old"] == self.original()["old"] == receipt["result"], "RETURN_STAGE_DRIFT")
        if issued:
            self.approved_issue(directory, stage, version)
        else:
            reviewed = read(directory / "sign.review")["request"]["digest"]
            need(reviewed == digest(stage) and self.authority() == first["authority"], "RETURN_STAGE_DRIFT")
        checkpoint = {}
        for op in ("issue", "upgrade", "start", "signal", "probe", "failure-stop"):
            for suffix in ("claim", "receipt"):
                path = directory / (op + "." + suffix)
                if path.exists():
                    checkpoint[path.name] = digest(read(path))
        for op in ("upgrade", "start", "probe"):
            if op + ".claim" in checkpoint:
                claim = read(directory / (op + ".claim"))
                need(claim["parent"] == digest(stage), "COMMITTED_STAGE_DRIFT")
                self.book_result(directory, op, claim)
        installed = first["sequence"] if "upgrade.claim" in checkpoint else first["head"]
        sup = self.supervisor(installed)
        state = read(sup["statusPath"])["state"]
        need(state in ("WAITING", "ACTIVE") and self.observe(stage["cid"], stage["profile"], sup) == stage["epoch"],
             "SIGNED_EPOCH_DRIFT")
        if state == "WAITING":
            self.closed(sup)
        kind = "APPLICATION_RUNNING" if "signal.claim" in checkpoint else "GATE_WAITING"
        need(self.engine.process(stage["cid"], stage["profile"], kind) == stage["generation"],
             "SIGNED_PROCESS_DRIFT")
        if "signal.claim" in checkpoint:
            need(read(directory / "signal.claim") == stage["generation"], "SIGNAL_GENERATION_DRIFT")
        rows = first["queue"]
        if "signal.claim" not in checkpoint:
            rows = self.queue.snapshot()
            permit(rows, self.req["queue"], rows)
        return {**first, "intent": intent(self.req), "committedFrom": directory.name,
                "authority": self.authority(), "queue": rows, "checkpoint": checkpoint, "r3State": state}

    def stop_unattempted(self, run):
        if not self.next_release:
            return False
        path = self.root / run
        plan = read(path / "plan")
        if not self.forward and (not plan.get("stop") or plan["head"] != self.source_head + 1
                                 or plan["sequence"] != self.source_head + 2 or "returnFrom" in plan):
            return False
        return (self.pointer(self.req["direction"]) == {"run": run, "plan": digest(plan)}
                and not any((path / key).exists() for key in
                            ("stop.claim", "detach.claim", "create.claim", "reconnect.claim", "start-gate.claim"))
                and (not self.forward or not (self.root / "return").exists())
                and "beforeCreate" not in plan and "createdFrom" not in plan)

    def initial(self):
        self.close_return()
        self.close_forward()
        version = self.current_version()
        direction = self.req["direction"]
        if self.next_release and (self.forward or version > self.source_head):
            self.bind_return()
        if (self.root / "forward").exists():
            need(self.original()["head"] == self.source_head, "ACTIVE_RELEASE_MISMATCH")
        prior = None
        if (self.root / direction).exists():
            prior = self.owner(direction)
            if self.next_release:
                if self.forward and version == self.source_head + 1:
                    return self.committed_plan()
                if not self.forward and not self.stop_unattempted(prior):
                    if not (self.root / prior / "start-gate.receipt").exists():
                        return self.restore_plan(version)
                    if version == self.source_head + 2 or (self.root / self.owner("return-stage") / "start.claim").exists():
                        return self.committed_plan()
            if not (self.root / prior / "stop-no-effect").is_file() and not self.stop_unattempted(prior):
                if self.forward and not (self.root / prior / "start-gate.receipt").exists():
                    return self.created_plan(version)
                return self.resume_gated(version)
        if self.forward:
            need(version == self.source_head, "EXPECTED_SOURCE_HEAD")
            profile = semantic_profile(self.cfg["originalProfile"])
            old = self.engine.inspect(self.name)
            spec = self.cfg.get("successorImage")
            if self.next_release:
                archive = self.completed_forward()
                previous = read(self.root / archive["pointers"]["forward-stage"]["run"] / "stage")
                profile = semantic_profile(self.supervisor(version)["semanticIngress"]["profile"])
                source_plan = read(self.root / archive["pointers"]["forward"]["run"] / "plan")
                spec = self.cfg.get("nextSuccessorImage")
                need(archive["head"] == version and previous["profile"] == profile and spec
                     and previous["cid"] == old["Id"]
                     and spec["ci"]["imageId"] != profile["image"], "NEXT_RELEASE_BASELINE_DRIFT")
                need("successorImage" in source_plan and
                     inventory(spec["predecessorMigrations"]) == inventory(source_plan["successorImage"]["migrations"]),
                     "PREDECESSOR_MIGRATIONS_CHANGED")
            request, target = prepare(old, profile, worker_enabled=self.next_release)
            if spec is None:
                self.image_binding(request, profile)
            self.ready(old["Id"], profile, self.engine.process(old["Id"], profile, "APPLICATION_RUNNING"))
            probe_preflight = self.probe_preflight(version, old["Id"])
            nets = {k: v["NetworkID"] for k, v in old["NetworkSettings"]["Networks"].items()}
            frame = {"old": old["Id"], "request": request, "networks": nets, "original": profile,
                     "probePreflight": probe_preflight, "template": profile_template(old), "target": target, "source": old["Id"], "previous": profile}
            if self.next_release:
                frame["retainedName"] = self.retained_name
            need(self.engine.inspect(self.retained_name, True) is None, "RETAINED_NAME_IN_USE")
            frame["archivedFailure"] = self.archived_failure()
            if spec is not None:
                image = admit({**self.cfg, "successorImage": spec}, self.log, self.source_get)
                frame["successorImage"] = image
                frame["request"], frame["target"] = self.prepare_image(old, profile, image)
        else:
            need((self.root / "forward").is_file() or (self.root / "completed-forward").is_file(), "ACTIVE_FORWARD_REQUIRED")
            first = self.original()
            need(first["head"] == self.source_head, "ACTIVE_RELEASE_MISMATCH")
            need(version in (self.source_head, self.source_head + 1), "RETURN_HEAD_DRIFT")
            need(self.engine.inspect(self.cfg["failedName"], True) is None, "RETURN_NAME_IN_USE")
            if not (self.root / self.owner("forward") / "start-gate.receipt").exists():
                return self.created_plan(version)
            source = read(self.forward_creation() / "create.receipt")["result"]
            self.retained(first)
            frame = {**{k: first[k] for k in ("request", "networks", "old", "original")},
                     "source": source, "previous": allocated_profile(first, source), "target": first["original"]}
            frame["forwardOwner"] = self.pointer("forward")
            frame["request"] = self.return_request(first)
        sequence = version + 1 if self.forward or version != self.source_head else version
        reconciliation = None
        installed = version
        if not self.forward and version != self.source_head:
            origin = self.issuing_run(self.owner("forward-stage"))
            if not (origin / "upgrade.receipt").exists() and (origin / "upgrade.claim").exists():
                claim = read(origin / "upgrade.claim")
                need(claim["parent"] == digest(read(origin / "stage")), "COMMITTED_STAGE_DRIFT")
                self.book_result(origin, "upgrade", claim)
            elif not (origin / "upgrade.receipt").exists():
                issue = self.approved_issue(origin, read(origin / "stage"), version)
                reconciliation = Books(self.cfg, origin).call("upgrade", version)
                need(reconciliation["versionBefore"] == self.source_head and reconciliation["versionAfter"] == version
                     and reconciliation["authorization"]["sha256"] == issue["payloadSha256"]
                     and reconciliation["compositionInputHashes"]["semanticProfile"] == digest(frame["previous"]),
                     "RETURN_UPGRADE_DRIFT")
                installed = self.source_head
        sup = self.supervisor(installed)
        need(sup["coordinator"]["journalPath"] == self.cfg["leaseJournal"]
             and sup["semanticIngress"]["commands"]["socket"] == self.cfg["socket"], "INSTALLATION_BINDING")
        kind = "start" if read(sup["statusPath"])["state"] == "WAITING" else "stop"
        need(not self.forward or kind == "stop", "FORWARD_REQUIRES_ACTIVE")
        # The waiting candidate can differ from the signed source profile before issuance.
        staged_source = not self.forward and installed == self.source_head and kind == "start"
        if staged_source:
            creation = self.forward_creation()
            stopped = self.book_result(creation, "stop", read(creation / "plan")["stop"])
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
            # Ingress checks hold the R3 common lock: leave the supervisor room for its tick.
            until(lambda: self.check_verified(sup, frame["previous"], frame["source"], version),
                  60, "INITIAL_INGRESS_HELD", pause=INGRESS_PAUSE)
        for op in ("start", "probe", *(("issue", "upgrade") if sequence != version else ())):
            self.books.binding(op, sequence)
        rows = self.queue.snapshot()
        need(self.req["queue"] != "empty" or not rows, "QUEUE_NOT_EMPTY")
        return {**frame, "prior": prior, "intent": intent(self.req), "profileSha256": digest(self.cfg), "head": version,
                "sequence": sequence, "installed": installed, "reconcileUpgrade": reconciliation,
                "authority": self.authority(), "stop": r3 if kind == "stop" else None, "queue": rows,
                "sourceEpoch": self.observe(frame["source"], frame["previous"], sup)}

    def source_probe(self, books):
        if self.next_release:
            archive = self.completed_forward()
            need(archive["head"] == self.source_head, "PROBE_SOURCE_HEAD_DRIFT")
            books.probe_source = self.issuing_run(archive["pointers"]["forward-stage"]["run"])
        return books

    def probe_preflight(self, version, cid):
        home = Journal(self.path / "probe-preflight").path
        plan = self.source_probe(Books(self.cfg, home)).call("probe", version)
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
        if "committedFrom" in plan:
            need(self.committed_plan() == plan, "SIGNED_PLAN_DRIFT")
            stage = read(self.root / plan["committedFrom"] / "stage")
            return {**stage, "parent": digest(plan), "issue": None}
        version = plan["head"]
        need(version == self.current_version() and plan["authority"] == self.authority()
             and plan["profileSha256"] == digest(self.cfg), "PLAN_DRIFT")
        direction = self.req["direction"]
        if "forwardOwner" in plan:
            need(self.pointer("forward") == plan["forwardOwner"], "TRANSACTION_SUPERSEDED")
        if "resume" in plan:
            current = self.resume_gated(version)
            need(current == plan, "GATED_PLAN_DRIFT")
            staged = plan["resume"]
            save(self.root / (direction + "-stage"), {"run": self.req["run"]}, replace=True)
            return self.issuance_stage(plan, staged["cid"], staged["target"], self.supervisor(version))
        sup = self.supervisor(plan["installed"])
        if "returnFrom" in plan:
            return self.restore_stage(plan, sup)
        if "beforeCreate" in plan:
            return self.stage_before_create(plan, sup)
        if "createdFrom" in plan:
            need(self.created_plan(version) == plan, "CREATED_PLAN_DRIFT")
            cid = plan["source"]
            if self.forward:
                self.log.effect("reuse", {"cid": cid, "origin": plan["createdFrom"], "plan": digest(plan)},
                                lambda: cid)
            else:
                need(self.engine.inspect(self.cfg["failedName"], True) is None, "RETURN_NAME_IN_USE")
            self.publish(plan, replace=self.forward)
            if not self.forward:
                self.log.effect("remove-created", {"cid": cid, "parent": digest(plan)},
                                lambda: self.engine.remove_stopped(cid, self.name, created=True))
            return self.launch_stage(plan, cid, sup)
        need(self.observe(plan["source"], plan["previous"], sup) == plan["sourceEpoch"], "SOURCE_EPOCH_DRIFT")
        if self.forward:
            need(not (self.root / "return").exists(), "TRANSACTION_SUPERSEDED")
            image = plan.get("successorImage")
            request, target = self.prepare_image(self.engine.inspect(plan["old"]), plan["original"], image)
            need(request == plan["request"] and target == plan["target"], "SUCCESSOR_PLAN_DRIFT")
            if image is None:
                self.image_binding(request, target)
        name = (self.retained_name if self.forward else self.cfg["failedName"])
        need(self.engine.inspect(name, True) is None, "RETENTION_NAME_DRIFT")
        rows = self.queue.snapshot()
        permit(rows, self.req["queue"], plan["queue"])
        replace = plan["prior"] is not None
        if replace:
            need(self.owner(direction) == plan["prior"] and ((self.root / plan["prior"] / "stop-no-effect").is_file()
                 or self.stop_unattempted(plan["prior"])),
                 "STOP_CLAIM_DRIFT")
        else:
            need(not (self.root / direction).exists(), "TRANSACTION_SUPERSEDED")
        if self.forward:
            failed = self.archived_failure()
            need(failed == plan.get("archivedFailure"), "ARCHIVED_CID_DRIFT")
            if failed:
                self.log.effect("remove-archived", {"cid": failed, "parent": digest(plan)},
                                lambda: self.engine.remove_stopped(failed, self.cfg["failedName"]))
        else:
            self.retained(self.original())
        self.publish(plan, replace)
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
            book = Books(self.cfg, self.issuing_run(self.owner("forward-stage")))
            upgrade = plan["reconcileUpgrade"]
            self.log.effect("reconcile-upgrade", upgrade,
                            lambda: book.call("upgrade", version, upgrade["planSha256"]))
            sup = self.supervisor(version)
            self.closed(sup)
        need(self.observe(plan["source"], plan["previous"], sup) == plan["sourceEpoch"], "SOURCE_EPOCH_DRIFT")
        self.log.effect("detach", {"parent": digest(plan), "cid": plan["source"]},
            lambda: self.engine.detach(plan["source"], (self.retained_name if self.forward else self.cfg["failedName"]),
                                       plan["networks"]))
        if self.forward:
            cid = self.log.effect("create", {"request": digest(plan["request"]), "parent": digest(plan)},
                lambda: self.engine.create(self.name, plan["request"], plan["target"]["image"]))
        else:
            cid = plan["old"]
        return self.launch_stage(plan, cid, sup)

    def publish(self, plan, replace):
        direction = self.req["direction"]
        for key, pointer in ((direction, {"run": self.req["run"], "plan": digest(plan)}),
                             (direction + "-stage", {"run": self.req["run"]})):
            save(self.root / key, pointer, replace=replace)
            need(read(self.root / key) == pointer, "OWNER_PUBLICATION_DRIFT")

    def launch_stage(self, plan, cid, sup):
        if not self.forward:
            cid = self.log.effect("reconnect", {"parent": digest(plan), "old": plan["old"]},
                lambda: self.engine.reconnect(plan["old"], self.name,
                    plan["request"]["NetworkingConfig"]["EndpointsConfig"], plan["networks"]))
        return self.start_stage(plan, cid, sup)

    def start_stage(self, plan, cid, sup):
        self.log.effect("start-gate", {"cid": cid, "parent": digest(plan)},
                        lambda: self.engine.start_gate(cid, self.name, plan["request"], plan["target"]["image"]))
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
        if "committedFrom" in plan:
            need(self.committed_plan() == plan, "SIGNED_PLAN_DRIFT")
            original = self.root / plan["committedFrom"]
            frozen = read(original / "stage")
            return self.finish_issued(plan, frozen, Journal(original), Books(self.cfg, original), recovering=True)
        version, seq, cid = plan["head"], plan["sequence"], stage["cid"]
        profile, generation = stage["profile"], stage["generation"]
        need(self.owner(self.req["direction"] + "-stage") == self.req["run"] and
             (not self.forward or not (self.root / "return").exists()), "TRANSACTION_SUPERSEDED")
        need(self.current_version() == version and self.engine.process(cid, profile, "GATE_WAITING") == generation
             and self.observe(cid, profile, self.supervisor(version)) == stage["epoch"], "SIGNING_EPOCH_DRIFT")
        self.closed(self.supervisor(version))
        if stage["issue"]:
            if self.next_release and self.forward:
                self.bind_return()
            # The existing issuer revalidates its frozen input bundle, mandate and head under lock.
            stamp = stage["issue"]["planSha256"]
            signed = self.log.effect("issue", {"plan": stamp, "parent": digest(stage)},
                                     lambda: self.books.call("issue", seq, stamp))
            need(signed["payloadSha256"] == stage["issue"]["payloadSha256"], "SIGNED_PAYLOAD_DRIFT")
        return self.finish_issued(plan, stage, self.log, self.books)

    def finish_issued(self, plan, stage, log, issuing_books, *, recovering=False):
        seq, cid = plan["sequence"], stage["cid"]
        profile, generation = stage["profile"], stage["generation"]
        parent = digest(stage)

        def applied(op, books, check):
            claim = log.path / (op + ".claim")
            if claim.exists():
                saved = read(claim)
                need(saved["parent"] == parent, "COMMITTED_STAGE_DRIFT")
                check(saved["plan"])
                self.book_result(log.path, op, saved)
                return saved["plan"]
            proposal = books.call(op, seq)
            check(proposal)
            log.effect(op, {"parent": parent, "plan": proposal},
                       lambda: books.call(op, seq, proposal["planSha256"]))
            return proposal

        if stage["issue"]:
            def upgrade_scope(upgrade):
                need(upgrade["versionBefore"] == plan["head"] and upgrade["versionAfter"] == seq
                     and upgrade["authorization"]["sha256"] == stage["issue"]["payloadSha256"]
                     and upgrade["compositionInputHashes"] == stage["issue"]["compositionInputHashes"],
                     "UPGRADE_SCOPE_DRIFT")
            if not (log.path / "upgrade.claim").exists():
                self.closed(self.supervisor(plan["head"]))
            applied("upgrade", issuing_books, upgrade_scope)
        sup = self.supervisor(seq)
        need(sup["semanticIngress"]["profile"] == profile, "START_PROFILE_DRIFT")
        if recovering or stage["issue"]:
            self.books.probe_source = log.path
        chain = self.authority()
        if not (log.path / "start.claim").exists():
            self.closed(sup)
        start = applied("start", self.books, lambda row: need(
            row["observation"]["authorization"]["sequence"] == seq, "START_HEAD_DRIFT"))
        if recovering and "start.claim" in plan["checkpoint"] and plan["r3State"] == "WAITING":
            # The reviewed readback proves that a previously started cohort is now closed.
            if (log.path / "failure-stop.claim").exists():
                self.effect_result(log.path, "failure-stop", read(log.path / "failure-stop.claim"))
            self.closed(sup)
            start = self.books.call("start", seq)
            self.apply_book("start", seq, start, digest(plan))
        sent = recovering and (log.path / "signal.claim").exists()
        try:
            if sent:
                need(read(log.path / "signal.claim") == generation, "SIGNAL_GENERATION_DRIFT")
                time_floor = read(log.path / "proof-since")
            else:
                permit(self.queue.snapshot(), self.req["queue"], plan["queue"])
                # PostgreSQL on the local Engine shares the host realtime clock.
                time_floor = time.time_ns() // 1000
                if self.next_release:
                    save(log.path / "proof-since", time_floor, replace=True)
                with ExitStack() as ingress:
                    deadline = until(lambda: ingress.enter_context(verified(sup, profile, cid, seq)),
                                     60, "GATE_RELEASE_HELD", pause=INGRESS_PAUSE)
                    need(self.authority() == chain, "RELEASE_HEAD_DRIFT")
                    permit(self.queue.snapshot(deadline=deadline), self.req["queue"], plan["queue"])
                    signal_once(self.engine, log, cid, profile, generation, deadline)
            until(lambda: self.ready(cid, profile, generation), 120, "READINESS_HELD")
            if self.next_release and not self.forward and stage["issue"] is None:
                self.source_probe(self.books)
            applied("probe", self.books, lambda row: need(
                row["observation"]["semantic"]["containerId"] == cid, "PROBE_CID_DRIFT"))
            need(self.authority() == chain, "FINAL_HEAD_DRIFT")
            self.ready(cid, profile, generation)
            until(lambda: self.check_verified(sup, profile, cid, seq), 60, "FINAL_READBACK_HELD",
                  pause=INGRESS_PAUSE)
        except Exception:
            cleanup = self.books.call("stop", seq)
            need(cleanup["observation"]["authorization"] == start["observation"]["authorization"]
                 and cleanup["observation"]["configurationSha256"] == start["observation"]["configurationSha256"],
                 "FAILURE_STOP_SCOPE_DRIFT")
            self.log.effect("failure-stop", cleanup, lambda: stop(self.books, seq, cleanup,
                            lambda i, p: save(self.path / f"failure-stop-retry-{i}", p)))
            self.closed(sup)
            raise
        return {"ingress": "VERIFIED", "readiness": "UP", "probe": "C_PROBE_PASSED", "worker": "on" if self.forward or self.next_release else "off",
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
            if self.forward and self.next_release:
                response["returnAfterIssue"] = "available"
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
            if self.next_release and self.forward:
                self.bind_return()
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
        if "committedFrom" in plan:
            save(self.root / (self.req["direction"] + "-stage"), {"run": self.req["run"]}, replace=True)
        if self.forward:
            self.close_forward()
        else:
            self.close_return()
        return {"digest": digest(result), "ingress": result["ingress"], "readiness": result["readiness"],
                "worker": result["worker"]}
