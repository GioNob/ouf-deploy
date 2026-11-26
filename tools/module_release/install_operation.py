"""First installation. All callers that mutate hold the exclusive A2 executor lock."""
from copy import deepcopy
import hashlib
import ipaddress
from pathlib import Path
import tempfile
from urllib.parse import quote

from . import frame_spec, operation
from .contract import Held, SHA, digest, matches, package, require
from .frame import baseline, configuration, merge_image, snapshot as release_snapshot
from .install_contract import validate
from .operation import confirm, never_started, park, read, ready_status, reason, record, sync_dir


def canonical_mounts(doc):
    """Docker may list the same mounts in another order: compare them sorted by destination."""
    return sorted(doc["Mounts"], key=lambda m: m["Destination"])


def snapshot(doc):
    """Generation digest for module-install: the release snapshot over canonically ordered mounts.

    Used for the gate generation, the resume checks, the receipt and the `.installed` pointer
    (module_operation reads it as `install.snapshot`)."""
    return release_snapshot(dict(doc, Mounts=canonical_mounts(doc)))


LABEL = "ouf.install.plan"
# The digest field cannot include itself. Commit the entire request with a
# fixed-width zero slot, then substitute the approved digest in that slot only.
EMPTY_LABEL = "0" * 64


def engine(profile):
    # A future release may change the launch command. Installation always
    # proves the unmodified gate.command against the installed process.
    return operation.Docker({k: v for k, v in profile.items() if k != "candidate"})


def network_inventory(p, rt, own=None):
    result = {}
    for name in p["networks"]:
        net = rt.api("GET", "/networks/" + quote(name, safe=""), missing=True)
        require(net and net["Name"] == name and matches(SHA, net["Id"]) and net["Driver"] not in ("host", "null"),
                "NETWORK_UNAVAILABLE")
        ips = {ep["IPv4Address"].split("/")[0] for cid, ep in (net.get("Containers") or {}).items() if cid != own}
        subnets = [ipaddress.ip_network(s["Subnet"]) for s in net["IPAM"]["Config"] if s.get("Subnet")]
        address = ipaddress.IPv4Address(p["networks"][name]["ipv4"])
        require(any(address in s and address not in (s.network_address, s.broadcast_address)
                    for s in subnets if s.version == 4), "IPV4_OUTSIDE_NETWORK")
        for subnet in net["IPAM"]["Config"]:
            ips.add(subnet.get("Gateway"))
            ips.update((subnet.get("AuxiliaryAddresses") or {}).values())
        result[name] = {"NetworkID": net["Id"], "ips": ips, "aliases": set()}
    # Network inspect lacks DNS aliases and stopped containers' reservations.
    for row in rt.api("GET", "/containers/json?all=1"):
        if row["Id"] == own:
            continue
        doc = rt.inspect(row["Id"])
        for name, ep in doc["NetworkSettings"]["Networks"].items():
            if name in result:
                result[name]["ips"].update((ep.get("IPAddress"), (ep.get("IPAMConfig") or {}).get("IPv4Address")))
                result[name]["aliases"].update(ep.get("Aliases") or ())
                result[name]["aliases"].update(ep.get("DNSNames") or ())
                result[name]["aliases"].add(doc["Name"].lstrip("/"))
    require(all(p["container"].lower() not in {a.lower() for a in net["aliases"]} for net in result.values()),
            "ALIAS_UNAVAILABLE")
    return result


def summary(p):
    section = frame_spec.install_section(p["install"])
    ready = p["readiness"]
    return {"imageId": p["ci"]["imageId"], "container": p["container"], "networks": p["networks"],
            "binds": [{k: row[k] for k in ("target", "mode", "sha256") if k in row} for row in section["binds"]],
            "tmpfs": section["tmpfs"], "user": section["user"], "env": [row["name"] for row in section["env"]],
            "readiness": {key: ready[key] for key in ("port", "path", "acceptStatus", "jsonStatus", "attempts")
                          if key in ready}, "tls": "tls" in ready}


def ownership(p, rt, stamp):
    candidate = rt.inspect(p["container"], missing=True)
    require(candidate and matches(SHA, candidate["Id"]) and candidate["Name"] == "/" + p["container"]
            and (candidate["Config"].get("Labels") or {}).get(LABEL) == stamp
            and candidate["Image"] == p["ci"]["imageId"], "CREATE_UNCERTAIN")
    return candidate


def observe(p, rt, *, resume=None, archive=None, verified_package=None):
    validate(p)
    parent = Path(p["journal"])
    require(not (parent / (p["module"] + ".lock")).exists(), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
    history = []
    for claim in sorted(parent.glob("*/install-intent.json")):
        if claim.parent.name == resume or read(claim.parent, claim.name)["module"] != p["module"]:
            continue
        if (claim.parent / "parked.json").exists():
            history.append(digest(read(claim.parent, "parked.json")))
        elif not (claim.parent / "receipt.json").exists() or (claim.parent / "park-intent.json").exists():
            raise Held("INSTALL_CREATION_PENDING")
        elif rt.inspect(p["container"], missing=True) is None:
            raise Held("INSTALLED_SERVICE_MISSING")
    if resume:
        own = ownership(p, rt, resume)["Id"]
    else:
        require(rt.inspect(p["container"], missing=True) is None, "SERVICE_EXISTS")
        own = None
    require(rt.inspect(p["install"]["failedName"], missing=True) is None, "CUSTODY_NAME_OCCUPIED")
    if verified_package is None:
        defaults = {}
        artifact = package(p, archive, image_defaults=defaults)
    else:
        artifact, defaults = verified_package
    live = network_inventory(p, rt, own)
    facts = {"imageId": p["ci"]["imageId"], "Config": defaults, "networks": live}
    section = p["install"]
    body, custody = frame_spec.create_with_custody(p, facts, EMPTY_LABEL)
    plan = {"operation": "module-install", "module": p["module"], "profileSha256": digest(p),
            "ci": p["ci"], "artifact": artifact, "review": summary(p),
            "preconditions": {"absent": [p["container"], section["failedName"]], "pending": False,
                              "bindingsFree": True, "bindCustody": custody,
                              "previousIsolations": history,
                              "networks": {n: {"NetworkID": ep["NetworkID"]} for n, ep in live.items()}},
            "requestSha256": digest(body)}
    return plan, body, defaults


def plan(p, runtime=None, *, resume=None):
    try:
        rt = runtime or engine(p)
        if resume is not None:
            require(matches(SHA, resume), "PLAN_DIGEST_REQUIRED")
            root = Path(p["journal"]) / resume
            require((root / "install-intent.json").is_file() and not (root / "park-intent.json").exists()
                    and not (root / "failure.json").exists(), "INSTALL_RESUME_UNAVAILABLE")
        body, req, defaults = observe(p, rt, resume=resume)
        stamp = hashlib.sha256(frame_spec.canonical(body)).hexdigest()
        if resume:
            require(stamp == resume and read(root, "plan.json") == body, "PLAN_CHANGED")
            cid = ownership(p, rt, resume)["Id"]
            req["Labels"][LABEL] = stamp
            doc = verify_creation(p, rt, root, body, req, defaults, cid)
            if (root / "receipt.json").exists():
                require(snapshot(doc) == read(root, "receipt.json")["frameSha256"], "INSTALL_RECEIPT_DRIFT")
        return {"status": "PLANNED", "planSha256": stamp, "plan": body}
    except Exception as exc:
        return {"status": "HELD", "reason": reason(exc)}


# Linux Engine API 1.44 serializes omitted CREATE settings as typed Go zero
# values, and materializes a small set of daemon defaults. Keep these closed:
# an unknown field (even zero) requires review before we adopt its frame.
HOST_DEFAULTS = {
    **dict.fromkeys(("CpuShares Memory NanoCpus BlkioWeight CpuPeriod CpuQuota CpuRealtimePeriod "
                     "CpuRealtimeRuntime MemoryReservation MemorySwap KernelMemory KernelMemoryTCP "
                     "OomScoreAdj CpuCount CpuPercent IOMaximumIOps IOMaximumBandwidth").split(), (0,)),
    **dict.fromkeys("Privileged AutoRemove PublishAllPorts".split(), (False,)),
    **dict.fromkeys(("ContainerIDFile VolumeDriver Cgroup PidMode UTSMode UsernsMode Isolation CgroupParent "
                     "CpusetCpus CpusetMems").split(), ("",)),
    **dict.fromkeys(("Binds VolumesFrom CapAdd CapDrop Dns DnsOptions DnsSearch ExtraHosts Links "
                     "BlkioWeightDevice BlkioDeviceReadBps BlkioDeviceWriteBps BlkioDeviceReadIOps "
                     "BlkioDeviceWriteIOps Devices DeviceCgroupRules DeviceRequests Ulimits SecurityOpt").split(),
                    (None, [])),
    **dict.fromkeys("PortBindings StorageOpt Sysctls Annotations".split(), (None, {})),
    "MemorySwappiness": (None,), "PidsLimit": (None, 0), "OomKillDisable": (None, False),
    "Init": (None, False), "ConsoleSize": ([0, 0],), "IpcMode": ("", "private"),
    "Runtime": ("", "runc"), "CgroupnsMode": ("", "private"), "ShmSize": (64 << 20,),
    "LogConfig": ({"Type": "json-file", "Config": {}},),
    "MaskedPaths": (None, sorted(("/proc/acpi /proc/asound /proc/interrupts /proc/kcore /proc/keys "
                           "/proc/latency_stats /proc/sched_debug /proc/scsi /proc/timer_list "
                           "/proc/timer_stats /sys/devices/virtual/powercap /sys/firmware").split()),),
    "ReadonlyPaths": (None, sorted("/proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger".split())),
}


def compare_fields(actual, expected, defaults, code):
    """An explicit request wins. Only named Engine defaults may appear in addition."""
    for key in actual.keys() | expected.keys():
        if key in expected:
            require(key in actual and actual[key] == expected[key]
                    and type(actual[key]) is type(expected[key]), code)
        else:
            require(any(type(actual[key]) is type(value) and actual[key] == value
                        for value in defaults.get(key, ())), code)


def verify_frame(p, doc, req, defaults, networks, cid, *, parking=False):
    cfg = dict(doc["Config"])
    cfg.pop("MacAddress", None)
    expected = deepcopy({k: v for k, v in req.items() if k not in ("HostConfig", "NetworkingConfig")})
    merge_image(expected, defaults)
    names = {"/" + p["container"]}
    if parking:
        names.add("/" + p["install"]["failedName"])
    require(doc["Id"] == cid and doc["Name"] in names and doc["Image"] == req["Image"]
            and [doc["Path"], *doc["Args"]] == req["Entrypoint"] + req["Cmd"], "INSTALL_IDENTITY_CHANGED")
    if cfg.get("Env") is None:
        cfg["Env"] = []
    compare_fields(cfg, expected, {
        "Hostname": (cid[:12],), "Domainname": ("",), "WorkingDir": ("", "/"), "StopSignal": ("",),
        "Healthcheck": (None,), "StopTimeout": (None,), "Shell": (None, []), "OnBuild": (None, []),
        "Volumes": (None, {}), "ExposedPorts": (None, {}),
        **dict.fromkeys("AttachStdin AttachStdout AttachStderr Tty OpenStdin StdinOnce ArgsEscaped NetworkDisabled".split(),
                        (False,)),
    }, "INSTALL_CONFIG_CHANGED")
    host, want = dict(doc["HostConfig"]), dict(req["HostConfig"])
    for field, empty in (("Mounts", []), ("GroupAdd", []), ("Tmpfs", {})):
        if host.get(field) is None:
            host[field] = empty
    for field in ("MaskedPaths", "ReadonlyPaths"):
        if isinstance(host.get(field), list):
            host[field] = sorted(host[field])
    compare_fields(host.pop("RestartPolicy"), want.pop("RestartPolicy"), {"MaximumRetryCount": (0,)},
                   "INSTALL_HOST_CONFIG_CHANGED")
    requested = sorted(want.pop("Mounts"), key=lambda m: m["Target"])
    observed = sorted(host.pop("Mounts"), key=lambda m: m["Target"])
    require(len(requested) == len(observed), "INSTALL_HOST_MOUNTS_CHANGED")
    for mount, binding in zip(observed, requested):
        compare_fields({"ReadOnly": False, **mount}, binding, {"BindOptions": (None, {})}, "INSTALL_HOST_MOUNTS_CHANGED")
    compare_fields(host, want, HOST_DEFAULTS, "INSTALL_HOST_CONFIG_CHANGED")
    realized = sorted(doc["Mounts"], key=lambda m: m["Destination"])
    require(len(requested) == len(realized), "INSTALL_MOUNTS_CHANGED")
    for mount, binding in zip(realized, requested):
        compare_fields(mount, {"Type": "bind", "Source": binding["Source"], "Destination": binding["Target"],
                               "RW": not binding["ReadOnly"]},
                       {"Mode": ("", "ro" if binding["ReadOnly"] else "rw"), "Propagation": ("rprivate",)},
                       "INSTALL_MOUNTS_CHANGED")
    ports = doc["NetworkSettings"].get("Ports") or {}
    require(ports.keys() <= (expected.get("ExposedPorts") or {}).keys()
            and all(value in (None, []) for value in ports.values()),
            "INSTALL_HOST_CONFIG_CHANGED")
    actual = doc["NetworkSettings"]["Networks"]
    require(req["NetworkingConfig"]["EndpointsConfig"].keys() == networks.keys() and
            (actual.keys() <= networks.keys() if parking else actual.keys() == networks.keys()), "NETWORK_SET_CHANGED")
    for name, ep in actual.items():
        binding = req["NetworkingConfig"]["EndpointsConfig"][name]
        expected_names = set(binding["Aliases"])
        dns_names = set(ep.get("DNSNames") or [])
        ip = binding["IPAMConfig"]["IPv4Address"]
        # These are Engine observations of the attachment. All requestable
        # endpoint settings below have an expected value from CREATE or a zero default.
        allocated = {"EndpointID", "Gateway", "IPPrefixLen", "IPv6Gateway", "GlobalIPv6Address",
                     "GlobalIPv6PrefixLen", "MacAddress"}
        require(ep.keys() <= allocated | {"NetworkID", "IPAddress", "Aliases", "DNSNames", "IPAMConfig",
                                          "Links", "DriverOpts", "GwPriority"}
                and ep["IPAMConfig"] == binding["IPAMConfig"]
                and set(ep.get("Aliases") or ()) in (expected_names, expected_names | {cid[:12]})
                and dns_names <= expected_names | {cid[:12], doc["Name"].lstrip("/")}
                and ep.get("IPAddress", "") in ("", ip)
                and not ep.get("Links") and not ep.get("DriverOpts") and not ep.get("GwPriority")
                and ep["NetworkID"] in ("", networks[name]["NetworkID"]), "ENDPOINT_DELTA")
        if doc["State"]["Running"]:
            require(ep["NetworkID"] == networks[name]["NetworkID"] and ep["IPAddress"] == ip,
                    "ENDPOINT_DELTA")


class GateFailure(Held):
    """Only a failed gate or readiness on an attested generation can initiate park."""
    def __init__(self, reason_code, generation):
        super().__init__(reason_code)
        self.generation = generation


def park_proof(doc):
    # Docker releases its live network allocations on exit. verify_frame checks
    # the remaining attachments against CREATE, including addresses and aliases.
    network = {k: v for k, v in doc["NetworkSettings"].items() if k not in
               ("Networks", "Ports", "SandboxID", "SandboxKey", "EndpointID", "MacAddress")}
    return {"cid": doc["Id"], "frameSha256": snapshot(doc),
            "epoch": {"startedAt": doc["State"]["StartedAt"], "restartCount": doc["RestartCount"]},
            "stableFrameSha256": digest([doc["Image"], configuration(doc), doc["HostConfig"],
                                         canonical_mounts(doc), doc["Path"], doc["Args"], network])}


def same_stopped_run(doc, observed, approved):
    state = doc["State"]
    return (state["Running"] is False and state["Pid"] == 0 and (state["Status"] == "exited" or never_started(doc))
            and all(observed[k] == approved.get(k) for k in ("cid", "epoch", "stableFrameSha256")))


def finish(p, rt, root, req, defaults, networks, cid):
    def checked():
        doc = rt.inspect(cid)
        verify_frame(p, doc, req, defaults, networks, cid)
        return doc

    doc = checked()
    if never_started(doc):
        require(not any((root / name).exists() for name in ("generation.json", "signal.json")), "GENERATION_CHANGED")
        confirm(root, "start-intent.json", {"cid": cid})
        rt.start(cid)
        doc = checked()
    require(read(root, "start-intent.json") == {"cid": cid} and doc["State"]["Running"]
            and doc["State"]["Pid"] > 0 and doc["RestartCount"] == 0, "GATE_NOT_RUNNING")
    proof = park_proof(doc)
    generation = proof["frameSha256"]
    signal = {"cid": cid, "generation": generation}
    confirm(root, "generation.json", signal)
    confirm(root, "gate-run.json", proof)

    def live():
        current = checked()
        require(snapshot(current) == generation and read(root, "generation.json") == signal, "GENERATION_CHANGED")
        return current

    if (root / "signal.json").exists():
        require(read(root, "signal.json") == signal, "SIGNAL_GENERATION_CHANGED")
    else:
        for _ in range(p["readiness"]["attempts"]):
            if rt.process(live(), gated=True):
                break
            rt.pause()
        else:
            raise GateFailure("GATE_NOT_PROVEN", generation)
        record(root, "signal.json", signal)
        require(rt.process(live(), gated=True), "GATE_CHANGED")
        try:
            rt.signal(cid)
        except Exception as exc:
            record(root, "signal-failure.json", {"reason": reason(exc)})
    for _ in range(p["readiness"]["attempts"]):
        status = ready_status(rt, live(), p["readiness"])
        if status:
            doc = live()
            baseline(p, doc, predecessor_image=req["Image"])
            return {"operation": "module-install", "status": "READY", "cid": cid, "imageId": req["Image"],
                    "frameSha256": generation, "planSha256": root.name, "readyHttp": status}
        rt.pause()
    raise GateFailure("READINESS_NOT_UP", generation)


def install_claim(p, req, stamp):
    return {"module": p["module"], "requestSha256": digest(req), "planSha256": stamp}


def verify_creation(p, rt, root, body, req, defaults, cid):
    require(read(root, "install-intent.json") == install_claim(p, req, root.name), "INSTALL_INTENT_CHANGED")
    doc = rt.inspect(cid)
    verify_frame(p, doc, req, defaults, body["preconditions"]["networks"], cid)
    if (root / "created.json").exists():
        require(read(root, "created.json") == {"cid": cid}, "CREATE_UNCERTAIN")
    else:
        require(never_started(doc) and not (root / "start-intent.json").exists(), "CREATE_UNCERTAIN")
    if (root / "generation.json").exists() or (root / "signal.json").exists():
        binding = {"cid": cid, "generation": snapshot(doc)}
        require(read(root, "generation.json") == binding, "GENERATION_CHANGED")
        if (root / "signal.json").exists():
            require(read(root, "signal.json") == binding, "SIGNAL_GENERATION_CHANGED")
    return doc


def approved_create(p, root, body, defaults):
    """Reconstruct from the approved plan without requiring free names or reopening a writable bind."""
    image = p["ci"]["imageId"]
    nets = {name: {**net, "aliases": [], "ips": []} for name, net in body["preconditions"]["networks"].items()}
    req = frame_spec.create_request(p, {"imageId": image, "Config": defaults, "networks": nets}, EMPTY_LABEL)
    require(digest(req) == body["requestSha256"], "INSTALL_REQUEST_CHANGED")
    req["Labels"][LABEL] = root.name
    require(read(root, "install-intent.json") == install_claim(p, req, root.name), "INSTALL_INTENT_CHANGED")
    return req


class InstallParkRuntime:
    """Check the very reads that park uses to decide stop, disconnect and rename."""
    def __init__(self, rt, check):
        self.runtime = rt
        self.check = check
        self.first = True
        self.stop = rt.stop
        self.disconnect = rt.disconnect
        self.rename = rt.rename

    def inspect(self, cid):
        doc = self.runtime.inspect(cid)
        self.check(doc, self.first)
        self.first = False
        return doc


def isolate(p, rt, root, body, req, defaults, cid, *, failure=None):
    failed = p["install"]["failedName"]
    networks = body["preconditions"]["networks"]
    continuing = (root / "park-intent.json").exists()
    require(read(root, "created.json") == {"cid": cid}
            and read(root, "install-intent.json") == install_claim(p, req, root.name), "PARK_IDENTITY_CHANGED")
    doc = rt.inspect(cid)
    verify_frame(p, doc, req, defaults, networks, cid, parking=continuing)
    for name in (p["container"], failed):
        owner = rt.inspect(name, missing=True)
        require(owner is None or owner["Id"] == cid, "CUSTODY_NAME_OCCUPIED")
    observed = park_proof(doc)
    if continuing:
        claim = read(root, "park-intent.json")
        require(claim["cid"] == cid and (observed["frameSha256"] == claim["frameSha256"]
                or same_stopped_run(doc, observed, claim)),
                "PARK_GENERATION_CHANGED")
    else:
        claim = observed
        if not never_started(doc):
            require(read(root, "start-intent.json") == {"cid": cid}, "GENERATION_CHANGED")
            if doc["State"]["Running"]:
                require(doc["State"]["Pid"] > 0 and doc["RestartCount"] == 0, "GENERATION_CHANGED")
            else:
                require(failure is None and (root / "signal.json").exists()
                        and (root / "gate-run.json").exists(), "GENERATION_CHANGED")
                claim = read(root, "gate-run.json")
                require(same_stopped_run(doc, observed, claim), "GENERATION_CHANGED")
    binding = {"cid": cid, "generation": claim["frameSha256"]}
    if failure is not None:
        require(not continuing and binding["generation"] == failure.generation, "GENERATION_CHANGED")
    if failure is not None or any((root / f).exists() for f in ("generation.json", "signal.json", "receipt.json")):
        require(read(root, "generation.json") == binding, "GENERATION_CHANGED")
    if (root / "signal.json").exists():
        require(read(root, "signal.json") == binding, "SIGNAL_GENERATION_CHANGED")
    if (root / "receipt.json").exists():
        require(read(root, "receipt.json")["frameSha256"] == binding["generation"], "GENERATION_CHANGED")
    if not continuing:
        if failure is not None:
            confirm(root, "failure.json", {"reason": reason(failure)})
        record(root, "park-intent.json", claim)

    def check(current, first):
        verify_frame(p, current, req, defaults, networks, cid, parking=continuing or not first)
        proof = park_proof(current)
        if first:
            require(proof == observed and current["State"]["Running"] == doc["State"]["Running"]
                    and current["State"]["Status"] == doc["State"]["Status"], "PARK_GENERATION_CHANGED")
        else:
            require(same_stopped_run(current, proof, observed), "PARK_GENERATION_CHANGED")

    # Engine mutations address a CID and have no atomic generation precondition.
    park(InstallParkRuntime(rt, check), cid, failed, networks)
    result = {"status": "ROLLED_BACK", "cid": cid, "planSha256": root.name}
    confirm(root, "parked.json", result)
    return result


def apply(p, stamp, runtime=None):
    try:
        require(matches(SHA, stamp), "PLAN_DIGEST_REQUIRED")
        validate(p)
        rt = runtime or engine(p)
        root = Path(p["journal"]) / stamp
        if (root / "plan.json").exists():
            saved = read(root, "plan.json")
            require(digest(saved) == stamp and saved["profileSha256"] == digest(p), "PLAN_CHANGED")
            defaults = {}
            require(package(p, image_defaults=defaults) == saved["artifact"], "ARTIFACT_CHANGED")
            if (root / "receipt.json").exists():
                receipt = read(root, "receipt.json")
                req = approved_create(p, root, saved, defaults)
                binding = {"cid": receipt["cid"], "generation": receipt["frameSha256"]}
                require(receipt["planSha256"] == stamp and receipt["cid"] == read(root, "created.json")["cid"]
                        and read(root, "generation.json") == read(root, "signal.json") == binding
                        and receipt["imageId"] == p["ci"]["imageId"] and receipt["status"] == "READY",
                        "INSTALL_RECEIPT_DRIFT")
                if not (root / "park-intent.json").exists():
                    verify_creation(p, rt, root, saved, req, defaults, receipt["cid"])
                return receipt
            if (root / "park-intent.json").exists() or (root / "failure.json").exists():
                raise Held("INSTALL_PARKED_OR_RETURNING")
        pending = (root / "install-intent.json").exists()
        with tempfile.TemporaryFile(dir=p["journal"]) as archive:
            body, req, defaults = observe(p, rt, resume=stamp if pending else None, archive=archive)
            require(digest(body) == stamp, "PLAN_CHANGED")
            req["Labels"][LABEL] = stamp
            claim = install_claim(p, req, stamp)
            if pending:
                require(read(root, "install-intent.json") == claim, "INSTALL_INTENT_CHANGED")
                cid = ownership(p, rt, stamp)["Id"]
            else:
                archive.seek(0)
                rt.load(archive, body["artifact"])
                frame_spec.check_image_volumes(rt.image_defaults(req["Image"]).get("Volumes"), p)
                current, _, _ = observe(p, rt, verified_package=(body["artifact"], defaults))
                require(current == body, "PLAN_CHANGED")
                root.mkdir(mode=0o700, exist_ok=True)
                sync_dir(root.parent)
                confirm(root, "plan.json", body)
                record(root, "install-intent.json", claim)
                try:
                    cid = rt.create(p["container"], req)
                except Exception:
                    raise Held("CREATE_UNCERTAIN") from None
            require(matches(SHA, cid), "CREATE_UNCERTAIN")
            verify_creation(p, rt, root, body, req, defaults, cid)
            confirm(root, "created.json", {"cid": cid})
        try:
            result = finish(p, rt, root, req, defaults, body["preconditions"]["networks"], cid)
        except GateFailure as exc:
            isolate(p, rt, root, body, req, defaults, cid, failure=exc)
            return {"status": "HELD", "reason": reason(exc), "rollback": "ROLLED_BACK", "planSha256": stamp}
        record(root, "receipt.json", result)
        return result
    except Exception as exc:
        return {"status": "HELD", "reason": reason(exc)}


def rollback(p, stamp, runtime=None):
    try:
        require(matches(SHA, stamp), "PLAN_DIGEST_REQUIRED")
        rt = runtime or engine(p)
        root = Path(p["journal"]) / stamp
        require(not (root.parent / (p["module"] + ".lock")).exists(), "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        require((root / "install-intent.json").is_file(), "NO_INSTALL_TO_RETURN")
        body = read(root, "plan.json")
        require(body["operation"] == "module-install" and digest(body) == stamp
                and body["profileSha256"] == digest(p), "PLAN_CHANGED")
        require((root / "created.json").exists(), "CREATE_UNCERTAIN")
        cid = read(root, "created.json")["cid"]
        require(matches(SHA, cid), "CREATE_UNCERTAIN")
        if (root / "parked.json").exists():
            return read(root, "parked.json")
        defaults = rt.image_defaults(p["ci"]["imageId"])
        req = approved_create(p, root, body, defaults)
        return isolate(p, rt, root, body, req, defaults, cid)
    except Exception as exc:
        return {"status": "HELD", "reason": reason(exc)}


from .contract import validate_profile_options

_engine = engine
_plan = plan
_apply = apply
_rollback = rollback


def engine(profile):
    validate_profile_options(profile)
    return _engine(profile)


def plan(p, runtime=None, *, resume=None):
    try:
        validate_profile_options(p)
    except Held as exc:
        return {"status": "HELD", "reason": reason(exc)}
    return _plan(p, runtime, resume=resume)


def apply(p, stamp, runtime=None):
    try:
        validate_profile_options(p)
    except Held as exc:
        return {"status": "HELD", "reason": reason(exc)}
    return _apply(p, stamp, runtime)


def rollback(p, stamp, runtime=None):
    try:
        validate_profile_options(p)
    except Held as exc:
        return {"status": "HELD", "reason": reason(exc)}
    return _rollback(p, stamp, runtime)
