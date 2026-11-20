"""Translate Docker inspect into a create request and check the realized configuration."""

from copy import deepcopy

from .contract import ENTRY, SHA, digest, matches, require


def aliases(ep, cid):
    return sorted(set(ep.get("Aliases") or ()) - {cid[:12]})


def endpoint(ep):
    ipam = dict(ep.get("IPAMConfig") or {}, IPv4Address=ep["IPAddress"])
    if ep.get("GlobalIPv6Address"):
        ipam["IPv6Address"] = ep["GlobalIPv6Address"]
    result = {"IPAMConfig": ipam, "Aliases": list(ep.get("Aliases") or [])}
    for key in ("DriverOpts", "Links", "GwPriority"):
        if ep.get(key):
            result[key] = ep[key]
    return result


def configuration(doc):
    cfg = deepcopy(doc["Config"])
    cfg.pop("MacAddress", None)
    return cfg


def baseline(p, old):
    host = old["HostConfig"]
    require(matches(SHA, old["Id"]) and old["Image"] == p["oldImage"]
            and old["Name"] == "/" + p["container"] and old["State"]["Running"], "PREDECESSOR_CHANGED")
    require(old["Config"]["Entrypoint"] == ENTRY and old["Config"]["Cmd"] == p["gate"]["command"]
            and [old["Path"], *old["Args"]] == ENTRY + p["gate"]["command"], "KNOWN_GATE_REQUIRED")
    require(not host["AutoRemove"] and host["RestartPolicy"]["Name"] == "no"
            and not host.get("VolumesFrom") and not host.get("PublishAllPorts"), "UNSUPPORTED_RETENTION_POLICY")
    # Anonymous volumes would be allocated afresh by CREATE.
    require(all(m["Type"] == "bind" for m in old["Mounts"]), "EXPLICIT_BIND_MOUNTS_REQUIRED")
    nets = old["NetworkSettings"]["Networks"]
    require(set(nets) == set(p["networks"]), "NETWORK_SET_CHANGED")
    for name, expected in p["networks"].items():
        ep = nets[name]
        require(matches(SHA, ep["NetworkID"]) and ep["IPAddress"] == expected["ipv4"]
                and aliases(ep, old["Id"]) == sorted(expected["aliases"]), "NETWORK_BINDING_CHANGED")


def image_configuration(old, image, labels):
    cfg = configuration(old)
    cfg["Image"] = image
    if labels:
        cfg["Labels"] = {**(cfg.get("Labels") or {}), **labels}
    return cfg


def provenance_labels(profile):
    return {key: profile["ci"][field] for key, field in profile.get("provenanceLabels", {}).items()}


def request(old, image, labels=None):
    cfg = image_configuration(old, image, labels)
    cfg["HostConfig"] = deepcopy(old["HostConfig"])
    if cfg["HostConfig"].get("OomKillDisable") is None:
        cfg["HostConfig"]["OomKillDisable"] = False
    cfg["NetworkingConfig"] = {"EndpointsConfig": {
        name: endpoint(ep) for name, ep in old["NetworkSettings"]["Networks"].items()}}
    return cfg


def epoch(doc):
    return [doc["Id"], doc["State"]["StartedAt"], doc["State"]["Pid"], doc["RestartCount"]]


def check_body(old, doc, image, config_image, *, created=False, labels=None):
    cfg = image_configuration(old, config_image, labels)
    host = dict(old["HostConfig"])
    if created and host.get("OomKillDisable") is None:
        host["OomKillDisable"] = False
    mounts = lambda d: sorted(d["Mounts"], key=lambda m: m["Destination"])
    require(digest(configuration(doc)) == digest(cfg) and doc["Image"] == image
            and digest(doc["HostConfig"]) == digest(host) and mounts(doc) == mounts(old)
            and (doc["Path"], doc["Args"]) == (old["Path"], old["Args"]), "CONFIGURATION_DELTA")


def check_created_networks(old, doc):
    before = old["NetworkSettings"]["Networks"]
    now = doc["NetworkSettings"]["Networks"]
    require(set(now) == set(before), "NETWORK_SET_CHANGED")
    for name, ep in before.items():
        cfg = endpoint(ep)
        actual = now[name]
        names = set(cfg["Aliases"])
        require(actual.get("NetworkID") in ("", ep["NetworkID"])
                and actual.get("IPAMConfig") == cfg["IPAMConfig"]
                and set(actual.get("Aliases") or ()) in (names, names | {doc["Id"][:12]})
                and all(actual.get(k) == cfg[k] for k in ("DriverOpts", "Links", "GwPriority") if k in cfg),
                "ENDPOINT_DELTA")


def check_live_networks(old, doc):
    # Sandbox and attachment identifiers belong to a generation. All other
    # top-level network settings (including published ports) must match.
    allocated = {"Networks", "SandboxID", "SandboxKey", "EndpointID", "MacAddress"}
    def settings(container):
        return {k: v for k, v in container["NetworkSettings"].items() if k not in allocated}
    require(digest(settings(old)) == digest(settings(doc)), "NETWORK_CONFIGURATION_DELTA")
    before, now = (v["NetworkSettings"]["Networks"] for v in (old, doc))
    require(set(before) == set(now), "NETWORK_SET_CHANGED")
    for name, ep in before.items():
        actual = dict(now[name])
        expected = dict(ep)
        for fields in (actual, expected):
            fields.pop("MacAddress", None)
            fields.pop("EndpointID", None)
        for key in ("Aliases", "DNSNames"):
            observed = set(actual.get(key) or ())
            prior = set(expected.get(key) or ())
            if key == "DNSNames" and old["Id"][:12] not in (ep.get("Aliases") or ()):
                # Docker replaces the generated DNS name on a new CID.
                if old["Id"] != doc["Id"] and old["Id"][:12] not in observed:
                    prior.discard(old["Id"][:12])
            require(observed in (prior, prior | {doc["Id"][:12]}), "ENDPOINT_DELTA")
            actual.pop(key, None)
            expected.pop(key, None)
        # A previously dynamic address is requested explicitly on reattachment.
        if actual["IPAMConfig"] != expected["IPAMConfig"]:
            expected["IPAMConfig"] = endpoint(ep)["IPAMConfig"]
        require(digest(actual) == digest(expected), "ENDPOINT_DELTA")


def snapshot(old):
    nets = deepcopy(old["NetworkSettings"])
    nets.pop("MacAddress", None)
    for ep in nets["Networks"].values():
        ep.pop("MacAddress", None)
    return digest([old["Name"], old["Image"], configuration(old), old["HostConfig"], old["Mounts"],
                   old["Path"], old["Args"], nets, epoch(old)])
