"""Engine API 1.44, exact worker delta and a generation-bound release."""
import copy
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import time
from urllib.parse import quote

from gated_creation_plan import ENTRY
from gated_process_observation import GatedProcessObservation
from semantic_identity_v25 import semantic_configuration
from mandate import canonical, hex64, need

WORKER = "OUF_DISCOVERY_WORKER_ENABLED"
PROVIDER = "OUF_SCHEMA_GOV_ENABLED"


def merge_image(cfg, image):
    """Docker daemon merge for a Linux container (API 1.44), request wins."""
    need(isinstance(image, dict), "IMAGE_CONFIG_REQUIRED")
    for field in ("User", "WorkingDir", "StopSignal"):
        if not cfg.get(field) and image.get(field):
            cfg[field] = image[field]
    for field in ("Labels", "Volumes", "ExposedPorts"):
        if image.get(field):
            cfg[field] = {**image[field], **(cfg.get(field) or {})}
    if not cfg.get("Labels") and "Labels" in image:
        cfg["Labels"] = copy.deepcopy(image["Labels"])
    if image.get("Env"):
        env = cfg.get("Env") or []
        keys = {entry.partition("=")[0] for entry in env}
        cfg["Env"] = env + [entry for entry in image["Env"] if entry.partition("=")[0] not in keys]
    if not cfg.get("Entrypoint"):
        if not cfg.get("Cmd") and image.get("Cmd"):
            cfg["Cmd"] = list(image["Cmd"])
        if cfg.get("Entrypoint") is None and image.get("Entrypoint"):
            cfg["Entrypoint"] = list(image["Entrypoint"])
    health = image.get("Healthcheck")
    if health is not None:
        if cfg.get("Healthcheck") is None:
            cfg["Healthcheck"] = copy.deepcopy(health)
        else:
            for key in ("Test", "Interval", "Timeout", "Retries", "StartPeriod", "StartInterval"):
                if not cfg["Healthcheck"].get(key) and health.get(key):
                    cfg["Healthcheck"][key] = copy.deepcopy(health[key])


def configuration(request):
    return {k: v for k, v in request.items() if k not in ("HostConfig", "NetworkingConfig")}


def prepare(old, profile, successor_image=None, image_config=None):
    cfg, host = copy.deepcopy(old["Config"]), copy.deepcopy(old["HostConfig"])
    need(old["Image"] == profile["image"] and semantic_configuration(old) == profile["configurationSha256"]
         and old["Name"] == "/" + profile["containerName"], "BASELINE_DRIFT")
    env = cfg["Env"]
    keys = [v.split("=", 1)[0] for v in env]
    need(len(keys) == len(set(keys)) and WORKER+"=false" in env and PROVIDER+"=true" in env,
         "WORKER_BASELINE")
    need(cfg["Entrypoint"] == ENTRY and cfg["Cmd"] == ["java", "-XX:MaxRAMPercentage=75", "-jar",
         "/app/application.jar"] and cfg["User"] == "10001:10001" and not host["AutoRemove"]
         and host["RestartPolicy"]["Name"] == "no" and not host["Privileged"], "GATED_BASELINE")
    expected = copy.deepcopy(old)
    cfg["Env"][keys.index(WORKER)] = WORKER + "=true"
    if successor_image is not None:
        # The request always carries the gate Entrypoint, so the daemon ignores the image's own.
        merge_image(cfg, image_config)
        cfg["Image"] = successor_image
        profile = {**profile, "image": successor_image}
    expected["Config"] = copy.deepcopy(cfg)
    cfg.pop("MacAddress", None)
    if cfg["Hostname"] == old["Id"][:12]:
        cfg["Hostname"] = ""
    endpoints = {}
    for net, ep in old["NetworkSettings"]["Networks"].items():
        ipam = ep.get("IPAMConfig") or {}
        need(ep["IPAddress"] and ipam.get("IPv4Address") == ep["IPAddress"] and
             (not ep.get("GlobalIPv6Address") or ipam.get("IPv6Address") == ep["GlobalIPv6Address"]),
             "STATIC_ADDRESS_REQUIRED")
        endpoints[net] = {k: ep[k] for k in ("IPAMConfig", "Aliases", "DriverOpts", "Links")
                          if ep.get(k) is not None}
        need(not ep.get("GwPriority"), "ENGINE_API_FRAME")
    declared = {m["Target"]: (m["Type"], m.get("Source")) for m in host.get("Mounts") or []}
    for binding in host.get("Binds") or []:
        parts = binding.split(":")
        need(len(parts) in (2, 3), "EXPLICIT_MOUNT_REQUIRED")
        declared[parts[1]] = ("bind" if parts[0].startswith("/") else "volume", parts[0])
    need(endpoints and not host.get("VolumesFrom"), "EXPLICIT_BINDINGS_REQUIRED")
    need(set(cfg.get("Volumes") or {}) <= set(declared), "EXPLICIT_MOUNT_REQUIRED")
    for m in old["Mounts"]:
        src = m["Name"] if m["Type"] == "volume" else m["Source"]
        need(m["Type"] in ("volume", "bind") and declared.get(m["Destination"]) == (m["Type"], src),
             "EXPLICIT_MOUNT_REQUIRED")
    request = {**cfg, "HostConfig": host, "NetworkingConfig": {"EndpointsConfig": endpoints}}
    return request, {**profile, "configurationSha256": semantic_configuration(expected)}


def profile_template(old):
    # Retain only the creation-time fields consumed by the existing R3 hash.
    # The new CID is allocated after review. API 1.44 adds its short alias.
    nets = {}
    for name, ep in old["NetworkSettings"]["Networks"].items():
        nets[name] = {k: ep.get(k) for k in ("NetworkID", "IPAMConfig", "IPAddress", "GlobalIPv6Address",
                      "Links", "DriverOpts", "GwPriority", "Aliases", "DNSNames")}
    cfg = dict(old["Config"])
    cfg.pop("MacAddress", None)
    return {**{k: old[k] for k in ("Id", "HostConfig", "Mounts", "Path", "Args")},
            "Config": cfg, "NetworkSettings": {"Networks": nets}}


def allocated_profile(plan, cid):
    need(hex64(cid) and cid != plan["old"], "CREATE_CID_REQUIRED")
    expected = copy.deepcopy(plan["template"])
    need(expected["Id"] == plan["old"], "TEMPLATE_CID_DRIFT")
    expected["Id"] = cid
    cfg = expected["Config"] = configuration(plan["request"])
    cfg.pop("MacAddress", None)
    if cfg["Hostname"] == "":
        cfg["Hostname"] = cid[:12]
    for ep in expected["NetworkSettings"]["Networks"].values():
        if plan["old"][:12] in (ep["Aliases"] or []):
            ep["Aliases"] = sorted(set(ep["Aliases"]) | {cid[:12]})
        if ep["DNSNames"]:
            names = set(ep["DNSNames"])
            if plan["old"][:12] not in (ep["Aliases"] or []):
                names.discard(plan["old"][:12])
            ep["DNSNames"] = sorted(names | {cid[:12]})
    return {**plan["target"], "configurationSha256": semantic_configuration(expected)}


def never_started(state):
    return (state["Status"] == "created" and state["Pid"] == 0 and state["Running"] is False
            and state["StartedAt"] == "0001-01-01T00:00:00Z")


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host_path)


class Engine:
    def __init__(self, path):
        self.path = path

    def call(self, method, resource, body=None, *, absent=False):
        conn = UnixHTTP("localhost", timeout=45)
        conn.host_path = self.path
        try:
            conn.request(method, "/v1.44/" + resource, None if body is None else canonical(body),
                         {"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read(2**20+1)
            if absent and response.status == 404:
                return None
            need(200 <= response.status < 300 and len(raw) <= 2**20, "ENGINE_OPERATION_HELD")
            return json.loads(raw) if raw.strip() else None
        finally:
            conn.close()

    def inspect(self, name, absent=False):
        return self.call("GET", "containers/" + quote(name, safe="") + "/json", absent=absent)

    def detach(self, cid, name, networks):
        row = self.inspect(cid)
        need(row["Id"] == cid and set(row["NetworkSettings"]["Networks"]) == set(networks), "DETACH_FRAME")
        if row["State"]["Running"]:
            self.call("POST", f"containers/{cid}/stop?t=30")
        row = self.inspect(cid)
        need(row["State"]["Pid"] == 0 and not row["State"]["Running"], "STOP_UNPROVEN")
        for net in networks.values():
            self.call("POST", "networks/" + net + "/disconnect", {"Container": cid, "Force": False})
        need(self.inspect(cid)["NetworkSettings"]["Networks"] == {}, "DETACH_UNPROVEN")
        self.call("POST", f"containers/{cid}/rename?name=" + quote(name, safe=""))
        need(self.inspect(name)["Id"] == cid, "RENAME_UNPROVEN")
        return cid

    def create(self, name, request, image):
        need(self.inspect(name, True) is None and
             self.call("GET", "images/" + quote(request["Image"], safe="") + "/json")["Id"] == image,
             "CREATE_TARGET_DRIFT")
        result = self.call("POST", "containers/create?name=" + quote(name, safe=""), request)
        need(hex64(result["Id"]) and not result.get("Warnings"), "CREATE_RECEIPT_UNPROVEN")
        return result["Id"]

    def reconnect(self, cid, name, endpoints, networks):
        row = self.inspect(cid)
        need(row["Id"] == cid and not row["State"]["Running"] and not row["NetworkSettings"]["Networks"]
             and self.inspect(name, True) is None, "RETURN_CID_UNPROVEN")
        self.call("POST", f"containers/{cid}/rename?name=" + quote(name, safe=""))
        for net, endpoint in endpoints.items():
            self.call("POST", "networks/" + networks[net] + "/connect",
                      {"Container": cid, "EndpointConfig": endpoint})
        return cid

    def stopped_gate(self, cid, name, request, image):
        row = self.inspect(cid)
        cfg = dict(row["Config"])
        cfg.pop("MacAddress", None)
        if cfg["Hostname"] == cid[:12] and request["Hostname"] == "":
            cfg["Hostname"] = ""
        expected = configuration(request)
        need(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == image
             and row["State"]["Pid"] == 0 and not row["State"]["Running"] and cfg == expected
             and row["Config"]["Entrypoint"] == ENTRY, "STOPPED_GATE_FRAME_DRIFT")
        host = dict(row["HostConfig"])
        # API 1.44 represents the cgroup-v2 default as false until start.
        if host.get("OomKillDisable") is False and request["HostConfig"].get("OomKillDisable") is None:
            host["OomKillDisable"] = None
        need(host == request["HostConfig"], "STOPPED_HOST_FRAME_DRIFT")
        return row

    def start_gate(self, cid, name, request, image):
        self.stopped_gate(cid, name, request, image)
        return self.call("POST", f"containers/{cid}/start")

    def remove_stopped(self, cid, name, *, created=False):
        row = self.inspect(cid)
        need(hex64(cid) and row["Id"] == cid and row["Name"] == "/" + name
             and row["State"]["Status"] in ("created", "exited") and row["State"]["Pid"] == 0
             and row["State"]["Running"] is False, "REMOVE_CID_DRIFT")
        if created:
            need(never_started(row["State"]), "NEVER_STARTED_REQUIRED")
        self.call("DELETE", f"containers/{cid}")
        need(self.inspect(cid, True) is None and self.inspect(name, True) is None, "REMOVE_UNPROVEN")
        return cid

    def process(self, cid, profile, kind):
        row = self.inspect(cid)
        need(row["Id"] == cid and row["Name"] == "/" + profile["containerName"]
             and row["Image"] == profile["image"] and semantic_configuration(row) == profile["configurationSha256"]
             and row["State"]["Running"] and not row["State"]["Paused"] and not row["State"]["Restarting"],
             "SEMANTIC_FRAME_DRIFT")
        pid = row["State"]["Pid"]
        status = (Path("/proc") / str(pid) / "status").read_text()
        nspid, = [s for s in status.splitlines() if s.startswith("NSpid:")]
        need(nspid.split()[-1] == "1", "NAMESPACE_PID_ONE_REQUIRED")
        observed = GatedProcessObservation(row["Config"]).observe(pid)
        need(observed["processKind"] == kind, "PROCESS_KIND_UNPROVEN")
        return {"cid": cid, "image": row["Image"], "startedAt": row["State"]["StartedAt"],
                **observed["generation"]}


def signal_once(engine, journal, cid, profile, generation, deadline=None):
    # Pin the kernel process before the last observation. Recording intent before
    # sending makes an interrupted system call non-repeatable, even on runner loss.
    fd = os.pidfd_open(generation["pid"])
    try:
        need(engine.process(cid, profile, "GATE_WAITING") == generation, "GATE_GENERATION_DRIFT")
        def send():
            need(deadline is None or time.monotonic() < deadline, "INGRESS_WINDOW_EXPIRED")
            signal.pidfd_send_signal(fd, signal.SIGUSR1)
            return {"sent": 1}
        return journal.effect("signal", generation, send)
    finally:
        os.close(fd)
