"""Plan and execute the ordered levels against a narrowly scoped Docker interface."""
from contextlib import ExitStack
from datetime import datetime, timezone
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import socket
import sys
import time
import uuid

from .docker import GateHeld
from . import identity
from .profile import Held, canonical, require, sha, unique


def stamp():
    return datetime.now(timezone.utc).isoformat()


def persist(directory, filename, value):
    fd = os.open(Path(directory) / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    if sys.platform == "linux":
        fd = os.open(directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def receipt(directory, report):
    report["finishedAt"] = stamp()
    token = (uuid.UUID(report["bootId"]) if report["mode"] == "boot" and report["status"] == "SUCCEEDED"
             else uuid.uuid4())
    filename = f"{report['mode']}-{token.hex}.json"
    persist(directory, filename, report)
    return filename


def claim_boot(directory, boot_id):
    require(isinstance(boot_id, str) and str(uuid.UUID(boot_id)) == boot_id, "BOOT_ID_INVALID")
    try:
        persist(directory, f"boot-{boot_id}.marker", {"bootId": boot_id})
    except FileExistsError:
        raise Held("BOOT_ALREADY_ATTEMPTED") from None


def tcp_ready(address, port, timeout):
    if address:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(timeout)
            try:
                return probe.connect_ex((address, port)) == 0
            except OSError:
                return False
    return False


def http_ready(probe):
    conn = http.client.HTTPConnection(probe["address"], probe["port"], timeout=probe["timeoutSeconds"])
    try:
        conn.request("GET", probe["path"])
        response = conn.getresponse()
        if response.status not in probe["acceptStatus"]:
            return False
        if "jsonStatus" not in probe:
            return True
        body = response.read(65537)
        if len(body) > 65536:
            return False
        payload = json.loads(body, object_pairs_hook=unique)
        return isinstance(payload, dict) and payload.get("status") == probe["jsonStatus"]
    except (OSError, http.client.HTTPException, ValueError, RecursionError, Held):
        return False
    finally:
        conn.close()


def probe_in_namespace(pid, probe):
    try:
        with (Path("/proc") / str(pid) / "ns/net").open("rb", buffering=0) as namespace:
            os.setns(namespace.fileno(), os.CLONE_NEWNET)
        up = http_ready(probe)
    except OSError:
        up = False
    raise SystemExit(0 if up else 1)


def application_ready(pid, probe, timeout):
    # Only the child enters the network namespace. Bound the entire HTTP exchange,
    # including a slow stream of response bytes, by the remaining monotonic budget.
    deadline = time.monotonic() + timeout
    child = multiprocessing.get_context("fork").Process(target=probe_in_namespace, args=(pid, probe))
    child.start()
    try:
        child.join(max(0, deadline - time.monotonic()))
        return child.exitcode == 0
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()


class Controller:
    def __init__(self, cfg, profile_hash, docker, *, source_hash=None, clock=time.monotonic, sleep=time.sleep, tcp=tcp_ready):
        self.cfg = cfg
        self.profile_hash = profile_hash
        self.source_hash = source_hash
        self.docker = docker
        self.clock = clock
        self.sleep = sleep
        self.tcp = tcp
        self.members = {member["containerName"]: member for level in cfg["levels"]
                        for member in level["containers"]}

    def plan(self, action):
        self.gates = {}
        require(action in ("start", "stop"), "ACTION_INVALID")
        excluded = set(self.cfg["governedElsewhere"])
        names = self.members.keys() | excluded
        rows = self.docker.inventory(names)
        selected = {}
        reasons = []
        addresses = {}
        for row in rows:
            name = row["name"]
            if name in names:
                if name in selected:
                    reasons.append(["AMBIGUOUS_NAME", name])
                selected[name] = row
                if name in excluded:
                    if action == "stop" and row["running"]:
                        reasons.append(["GOVERNED_CONTAINER_RUNNING", name])
                else:
                    if row["status"] not in ("created", "exited", "running", "restarting"):
                        reasons.append(["UNSUPPORTED_STATE", name])
                    for net, ips in row["networks"].items():
                        for ip in ips.values():
                            if ip:
                                addresses.setdefault((net, ip), set()).add(name)
        for name in names - selected.keys():
            reasons.append(["MISSING_CONTAINER", name])
        for row in rows:
            if row["name"] not in names and row["running"]:
                for net, ips in row["networks"].items():
                    for target in addresses.get((net, ips["live"]), ()):
                        reasons.append(["IPV4_CONFLICT", target, row["name"]])
        steps = []
        levels = list(enumerate(self.cfg["levels"], 1))
        for index, level in levels if action == "start" else reversed(levels):
            for member in level["containers"]:
                name = member["containerName"]
                target = selected.get(name)
                op = "missing" if target is None else action
                if target and target["running"] == (action == "start"):
                    op = "skip"
                step = dict(level=index, levelTimeoutSeconds=level["timeoutSeconds"], containerName=name,
                            exists=target is not None, readiness=member["readiness"], operation=op, observation=target)
                gate = member.get("gate", {})
                if gate and (action == "start" or "identity" in gate):
                    if "identity" in gate:
                        source = gate["identity"]
                        context = step["release"] = dict(owner=source.get("module", source["source"]))
                        try:
                            gate = identity.resolve(gate, name, target, self.docker, context)
                        except Held as error:
                            if isinstance(error, identity.OpenTransaction):
                                context["residual"] = error.residue
                            reasons.append([str(error), name])
                            steps.append(step)
                            continue
                    self.gates[name] = gate
                    step["expectedImageId"] = gate["imageId"]
                    if action == "start":
                        step["gateOperation"] = "verify_and_signal" if op == "start" else "verify_application"
                steps.append(step)
        return dict(schema="ouf.platform-restart-plan.v1", profileSha256=self.profile_hash, action=action,
                    steps=steps, governedElsewhere={n: selected.get(n) for n in sorted(excluded)},
                    reasons=sorted(reasons, key=lambda r: (r[0] != "RELEASE_TRANSACTION_OPEN", r)))

    def observe(self, step, deadline):
        expected = step["observation"]
        row = self.docker.inspect(expected["cid"], deadline)
        require(row["name"] == step["containerName"] and row["cid"] == expected["cid"], "TARGET_CHANGED")
        require(row["status"] in ("created", "exited", "running", "restarting"), "UNSUPPORTED_STATE")
        require(self.clock() < deadline, "LEVEL_TIMEOUT")
        return row

    def ready(self, row, probe, deadline, stability):
        if not row["running"] or row["restarting"] or row["status"] != "running":
            stability.pop(row["cid"], None)
            return False
        if probe["type"] == "healthy":
            return row["health"] == "healthy"
        if probe["type"] == "tcp":
            address = row["networks"].get(probe["network"], {}).get("live")
            remaining = deadline - self.clock()
            return remaining > 0 and self.tcp(address, probe["port"], min(probe["timeoutSeconds"], remaining))
        # A continuous observation window for one Docker start generation.
        prior = stability.get(row["cid"])
        if prior is None or prior[0] != row["startedAt"]:
            stability[row["cid"]] = (row["startedAt"], self.clock())
        return self.clock() - stability[row["cid"]][1] >= probe["stableSeconds"]

    def open_gate(self, step, member, operation, deadline, event):
        gate = self.gates[step["containerName"]]
        generation, state = self.docker.gate_state(step, gate, deadline)
        since, _ = generation
        previous = step["observation"]["startedAt"]
        if (operation == "skip") != (since == previous):
            raise GateHeld("GENERATION_CHANGED")
        if state == "application":
            if operation != "skip":
                raise GateHeld("UNEXPECTED_GATE_RELEASE")
            event["gate"] = "already_open"
            return generation
        if operation == "skip":
            # A running shell may belong to an upgrade that has yet to migrate.
            raise GateHeld("GATE_START_NOT_OWNED")
        while state == "arming":
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise GateHeld("HANDLER_NOT_ARMED")
            self.sleep(min(0.05, remaining))
            observed, state = self.docker.gate_state(step, gate, deadline)
            if observed != generation:
                raise GateHeld("GENERATION_CHANGED")
        if state != "armed":
            raise GateHeld("UNEXPECTED_GATE_RELEASE")
        if self.clock() >= deadline:
            raise GateHeld("GATE_VERIFICATION_TIMEOUT")
        cid = step["observation"]["cid"]
        event["gate"] = "signal_unconfirmed"
        try:
            self.docker.command("kill", "--signal=USR1", cid, deadline=deadline)
        except Held:
            raise GateHeld("SIGNAL_UNCONFIRMED") from None
        event["gate"] = "signal_issued"
        return generation

    def gated_ready(self, step, member, generation, deadline):
        require(self.clock() < deadline, "READINESS_NOT_UP")
        try:
            observed, state = self.docker.gate_state(step, self.gates[step["containerName"]], deadline)
        except GateHeld as error:
            if self.clock() >= deadline or error.detail in {
                "RUNNING_GENERATION_UNVERIFIED", "PID1_COMMAND_MISMATCH", "PROCESS_UNAVAILABLE"
            }:
                return False
            raise
        if observed != generation:
            raise GateHeld("GENERATION_CHANGED")
        remaining = deadline - self.clock()
        probe = member["readiness"]
        if state != "application" or remaining <= 0:
            return False
        if not application_ready(generation[1], probe, min(remaining, probe["timeoutSeconds"])):
            return False
        require(self.clock() < deadline, "READINESS_NOT_UP")
        try:
            confirmed = self.docker.gate_state(step, self.gates[step["containerName"]], deadline)
        except GateHeld:
            require(self.clock() < deadline, "READINESS_NOT_UP")
            raise
        if confirmed != (generation, "application"):
            raise GateHeld("GENERATION_CHANGED")
        require(self.clock() < deadline, "READINESS_NOT_UP")
        return True

    def check_gate_deadlines(self, deadlines, report):
        for name, limit in deadlines.items():
            if self.clock() >= limit:
                report["container"] = name
                raise Held("READINESS_NOT_UP")

    def level(self, action, steps, report, generations, gate_deadlines):
        number = steps[0]["level"]
        deadline = self.clock() + self.cfg["levels"][number - 1]["timeoutSeconds"]
        stability = {}
        for step in steps:
            self.check_gate_deadlines(gate_deadlines, report)
            name = step["containerName"]
            report["container"] = name
            row = self.observe(step, deadline)
            # Health can progress between barriers. The authorized identity,
            # generation and requested lifecycle transition must still match.
            require(all(row[k] == step["observation"][k] for k in
                        ("startedAt", "running", "status", "restartPolicy", "networks")), "TARGET_CHANGED")
            operation = "skip" if row["running"] == (action == "start") else action
            event = dict(at=stamp(), container=name, level=number, operation=operation, outcome="pending")
            report["events"].append(event)
            member = self.members[name]
            if action == "start" and "gate" in member:
                if row["status"] == "created":
                    raise GateHeld("FIRST_START_REQUIRES_UPGRADE_OWNER")
                if name in generations:
                    if operation != "skip" or row["startedAt"] != generations[name][0]:
                        raise GateHeld("GENERATION_CHANGED")
                else:
                    gate_deadlines.setdefault(name, min(deadline, self.clock() + member["readiness"]["budgetSeconds"]))
            if operation != "skip":
                try:
                    if action == "stop":
                        for excluded in report["plan"]["governedElsewhere"].values():
                            peer = self.docker.inspect(excluded["cid"], deadline)
                            require(peer["name"] == excluded["name"], "GOVERNED_CONTAINER_CHANGED")
                            require(not peer["running"], "GOVERNED_CONTAINER_RUNNING")
                    self.docker.change(action, row["cid"], gate_deadlines.get(name, deadline))
                except Held as error:
                    event.update(outcome="unconfirmed", reason=str(error))
                    raise
            event["outcome"] = "issued" if operation != "skip" else "skipped"
            if name in gate_deadlines and name not in generations:
                generations[name] = self.open_gate(step, member, operation, gate_deadlines[name], event)
            if action == "stop":
                require(not self.observe(step, deadline)["running"], "STOP_UNCONFIRMED")
                event["outcome"] = "stopped" if operation != "skip" else "skipped"
        if action == "stop":
            return
        while True:
            waiting = []
            for step in steps:
                self.check_gate_deadlines(gate_deadlines, report)
                name = step["containerName"]
                report["container"] = name
                member = self.members[name]
                if name in generations:
                    limit = gate_deadlines.get(name, deadline)
                    ready = self.gated_ready(step, member, generations[name], limit)
                    if ready and name in gate_deadlines:
                        del gate_deadlines[name]
                        report["events"].append(dict(at=stamp(), level=number, container=name,
                                                     operation="readiness", pid1=self.gates[name]["command"][0], outcome="UP"))
                    else:
                        require(self.clock() < limit, "READINESS_NOT_UP")
                else:
                    row = self.observe(step, deadline)
                    ready = self.ready(row, member["readiness"], deadline, stability)
                if not ready:
                    waiting.append(name)
            if not waiting and self.clock() < deadline:
                return
            report["container"] = waiting[0] if waiting else steps[-1]["containerName"]
            remaining = min([deadline, *gate_deadlines.values()]) - self.clock()
            if remaining > 0:
                self.sleep(min(0.25, remaining))
            for name in waiting:
                if name in generations and self.clock() >= gate_deadlines.get(name, deadline):
                    report["container"] = name
                    raise Held("READINESS_NOT_UP")
            require(self.clock() < deadline, "READINESS_TIMEOUT")

    def execute(self, plan, report, boot):
        action = plan["action"]
        levels = list(dict.fromkeys(s["level"] for s in plan["steps"]))
        for number in levels:
            steps = [s for s in plan["steps"] if s["level"] == number]
            report["level"] = number
            delays = self.cfg["bootRetryDelaysSeconds"] if boot else []
            generations = {}
            gate_deadlines = {}
            for attempt in range(len(delays) + 1):
                try:
                    if attempt:
                        self.check_gate_deadlines(gate_deadlines, report)
                        current = self.plan(action)
                        require(not current["reasons"], "RETRY_PLAN_DENIED")
                        for old, new in zip(plan["steps"], current["steps"], strict=True):
                            require(old["observation"]["cid"] == new["observation"]["cid"], "TARGET_CHANGED")
                        steps = [s for s in current["steps"] if s["level"] == number]
                    self.level(action, steps, report, generations, gate_deadlines)
                except Held as error:
                    report["events"].append(dict(at=stamp(), level=number, attempt=attempt + 1,
                                                 container=report["container"], reason=str(error)))
                    if str(error) not in {
                        "READINESS_TIMEOUT", "LEVEL_TIMEOUT", "DOCKER_TIMEOUT", "DOCKER_COMMAND_FAILED"
                    }:
                        raise
                    self.check_gate_deadlines(gate_deadlines, report)
                    if attempt == len(delays):
                        raise
                    delay = delays[attempt]
                    if gate_deadlines:
                        delay = min(delay, min(gate_deadlines.values()) - self.clock())
                    self.sleep(max(0, delay))
                else:
                    report["events"].append(dict(at=stamp(), level=number, outcome="verified"))
                    break

    def run(self, mode, action, requested=None, boot_id=None):
        require(mode in ("boot", "plan", "apply"), "MODE_INVALID")
        is_boot = mode == "boot"
        require(not is_boot or action == "start", "BOOT_START_ONLY")
        report = dict(schema="ouf.platform-restart-receipt.v1", mode=mode, action=action,
                      profileSha256=self.profile_hash, sourceSha256=self.source_hash, startedAt=stamp(), status="HELD", events=[],
                      level=None, container=None)
        locks = ExitStack()
        try:
            if is_boot:
                report["bootId"] = boot_id
                claim_boot(self.cfg["receipts"], boot_id)
            sources = [m["gate"]["identity"] for m in self.members.values() if "identity" in m.get("gate", {})]
            try:
                locks.enter_context(identity.release_locks(sources))
            except identity.OpenTransaction as error:
                report.update(owners=sorted({s.get("module", s["source"]) for s in sources}),
                              residual=error.residue)
                raise
            plan = self.plan(action)
            report["plan"] = plan
            digest = sha(canonical(plan))
            report["planSha256"] = digest
            if is_boot:
                report["planReceipt"] = receipt(self.cfg["receipts"], {
                    **report, "mode": "boot-plan", "status": "HELD" if plan["reasons"] else "PLAN_READY"})
            if plan["reasons"]:
                reason, name, *_ = plan["reasons"][0]
                report["container"] = name
                report["level"] = next((s["level"] for s in plan["steps"] if s["containerName"] == name), None)
                raise Held(reason)
            if mode != "plan":
                if is_boot:
                    requested = digest
                    require(sha(canonical(self.plan(action))) == requested, "PLAN_CHANGED")
                require(digest == requested, "PLAN_CHANGED")
                self.execute(plan, report, is_boot)
            report["status"] = "PLAN_READY" if mode == "plan" else "SUCCEEDED"
        except Held as error:
            report["reason"] = str(error)
            if isinstance(error, GateHeld):
                report["gateReason"] = error.detail
        except (ValueError, OSError):
            report["reason"] = "OBSERVATION_OR_IO_FAILED"
        finally:
            locks.close()
        if is_boot and report.get("reason") not in (None, "BOOT_ALREADY_ATTEMPTED"):
            incident(self.cfg["incidents"], report)
        filename = receipt(self.cfg["receipts"], report)
        return {**report, "receipt": filename}


def incident(directory, report):
    entry = dict(schema="ouf.platform-restart-incident.v1", code="PLATFORM_BOOT_START_FAILED",
                 at=stamp(), level=report["level"], container=report["container"], reason=report["reason"])
    print("<3>" + canonical(entry).decode(), file=sys.stderr, flush=True)
    persist(directory, f"incident-{uuid.uuid4().hex}.json", entry)
