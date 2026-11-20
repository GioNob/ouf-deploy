"""Plan and execute the ordered levels against a narrowly scoped Docker interface."""
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import sys
import time
import uuid

from .profile import Held, canonical, require, sha


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
    filename = f"{report['mode']}-{uuid.uuid4().hex}.json"
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


class Controller:
    def __init__(self, cfg, profile_hash, docker, *, source_hash=None, clock=time.monotonic, sleep=time.sleep, tcp=tcp_ready):
        self.cfg = cfg
        self.profile_hash = profile_hash
        self.source_hash = source_hash
        self.docker = docker
        self.clock = clock
        self.sleep = sleep
        self.tcp = tcp
        self.members = {member["containerName"]: member["readiness"] for level in cfg["levels"]
                        for member in level["containers"]}

    def plan(self, action):
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
                steps.append(dict(level=index, levelTimeoutSeconds=level["timeoutSeconds"], containerName=name,
                                  exists=target is not None, readiness=member["readiness"], operation=op, observation=target))
        return dict(schema="ouf.platform-restart-plan.v1", profileSha256=self.profile_hash, action=action,
                    steps=steps, governedElsewhere={n: selected.get(n) for n in sorted(excluded)},
                    reasons=sorted(reasons))

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

    def level(self, action, steps, report):
        number = steps[0]["level"]
        deadline = self.clock() + self.cfg["levels"][number - 1]["timeoutSeconds"]
        stability = {}
        for step in steps:
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
            if operation != "skip":
                try:
                    if action == "stop":
                        for excluded in report["plan"]["governedElsewhere"].values():
                            peer = self.docker.inspect(excluded["cid"], deadline)
                            require(peer["name"] == excluded["name"], "GOVERNED_CONTAINER_CHANGED")
                            require(not peer["running"], "GOVERNED_CONTAINER_RUNNING")
                    self.docker.change(action, row["cid"], deadline)
                except Held as error:
                    event.update(outcome="unconfirmed", reason=str(error))
                    raise
            event["outcome"] = "issued" if operation != "skip" else "skipped"
            if action == "stop":
                require(not self.observe(step, deadline)["running"], "STOP_UNCONFIRMED")
                event["outcome"] = "stopped" if operation != "skip" else "skipped"
        if action == "stop":
            return
        while True:
            waiting = []
            for step in steps:
                name = step["containerName"]
                report["container"] = name
                row = self.observe(step, deadline)
                if not self.ready(row, self.members[name], deadline, stability):
                    waiting.append(name)
            if not waiting and self.clock() < deadline:
                return
            report["container"] = waiting[0] if waiting else steps[-1]["containerName"]
            remaining = deadline - self.clock()
            require(remaining > 0, "READINESS_TIMEOUT")
            self.sleep(min(0.25, remaining))
            require(self.clock() < deadline, "READINESS_TIMEOUT")

    def execute(self, plan, report, boot):
        action = plan["action"]
        levels = list(dict.fromkeys(s["level"] for s in plan["steps"]))
        for number in levels:
            steps = [s for s in plan["steps"] if s["level"] == number]
            report["level"] = number
            delays = self.cfg["bootRetryDelaysSeconds"] if boot else []
            for attempt in range(len(delays) + 1):
                try:
                    if attempt:
                        current = self.plan(action)
                        require(not current["reasons"], "RETRY_PLAN_DENIED")
                        for old, new in zip(plan["steps"], current["steps"], strict=True):
                            require(old["observation"]["cid"] == new["observation"]["cid"], "TARGET_CHANGED")
                        steps = [s for s in current["steps"] if s["level"] == number]
                    self.level(action, steps, report)
                except Held as error:
                    report["events"].append(dict(at=stamp(), level=number, attempt=attempt + 1,
                                                 container=report["container"], reason=str(error)))
                    if attempt == len(delays) or str(error) not in {
                        "READINESS_TIMEOUT", "LEVEL_TIMEOUT", "DOCKER_TIMEOUT", "DOCKER_COMMAND_FAILED"
                    }:
                        raise
                    self.sleep(delays[attempt])
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
        try:
            if is_boot:
                claim_boot(self.cfg["receipts"], boot_id)
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
        except (ValueError, OSError):
            report["reason"] = "OBSERVATION_OR_IO_FAILED"
        if is_boot and report.get("reason") not in (None, "BOOT_ALREADY_ATTEMPTED"):
            incident(self.cfg["incidents"], report)
        filename = receipt(self.cfg["receipts"], report)
        return {**report, "receipt": filename}


def incident(directory, report):
    entry = dict(schema="ouf.platform-restart-incident.v1", code="PLATFORM_BOOT_START_FAILED",
                 at=stamp(), level=report["level"], container=report["container"], reason=report["reason"])
    print("<3>" + canonical(entry).decode(), file=sys.stderr, flush=True)
    persist(directory, f"incident-{uuid.uuid4().hex}.json", entry)
