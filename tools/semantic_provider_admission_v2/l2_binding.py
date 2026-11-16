"""Epoch-local L2 observations of successor interface and MAC placeholders.

Signed IPs, bridges, NIC order and complete peer declarations remain authority.
The historical admission libraries receive copies; signed bytes are never rewritten.
"""
import copy
import json
import os
from pathlib import Path
import re

from tools.semantic_provider_operation import authorization
from .consumption_v2 import generation as valid_generation, require

L2_LIVE_MAC = "02:00:00:00:00:00"
SCHEMA = "ouf.semantic-provider-l2-binding.v1"
NIC_FIELDS = {"interface", "bridge", "mac", "ipv4", "workloadRef", "bindingRef"}
LIVE_FIELDS = {"childIfindex", "hostIfindex", "hostInterface"}
IFNAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")


def live_interface(index):
    return "l2live" + str(index)


def interface_name(value):
    require(type(value) is str and IFNAME.fullmatch(value), "L2_INTERFACE_INVALID")
    return value


def live_mac(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value)
            and not int(value[:2], 16) & 1
            and value not in ("00:00:00:00:00:00", L2_LIVE_MAC), "L2_MAC_INVALID")
    return value


def enabled(document):
    if type(document) is dict:
        return document.get("mac") == L2_LIVE_MAC or any(enabled(v) for v in document.values())
    return type(document) is list and any(enabled(v) for v in document)


def effective(signed_doc, observations, *, container_id=None):
    """Replace only the two explicit placeholders, preserving every signed field."""
    if container_id is None and len(observations) == 1:
        container_id = next(iter(observations))
    def visit(value, cid):
        if type(value) is list:
            return [visit(v, cid) for v in value]
        if type(value) is not dict:
            return value
        cid = value.get("containerId", cid)
        result = copy.deepcopy(value)
        if "networkBindings" in value:
            row = observations.get(cid)
            if row is None:
                require(not enabled(value["networkBindings"]), "L2_OBSERVATION_REQUIRED")
            else:
                require(row["containerId"] == cid, "L2_SIGNED_FIELD_DRIFT")
                approved, actual = value["networkBindings"], row["bindings"]
                require(len(approved) == len(actual), "L2_SIGNED_FIELD_DRIFT")
                for index, (signed, observed) in enumerate(zip(approved, actual)):
                    require(set(signed) in (NIC_FIELDS, NIC_FIELDS | {"leaseGuard"})
                            and set(observed) == set(signed) | LIVE_FIELDS
                            and all(observed.get(k) == v for k, v in signed.items()
                                    if not (k == "mac" and v == L2_LIVE_MAC
                                            or k == "interface" and v == live_interface(index))),
                            "L2_SIGNED_FIELD_DRIFT")
                    live_mac(observed["mac"])
                    interface_name(observed["interface"])
                result["networkBindings"] = [{**n, "interface": a["interface"], "mac": a["mac"]}
                                             for n, a in zip(approved, actual)]
        for key in value.keys() - {"networkBindings"}:
            result[key] = visit(value[key], cid)
        return result
    result = visit(signed_doc, container_id)
    require(not enabled(result), "L2_OBSERVATION_REQUIRED")
    return result


def observe(cid, generation, runtime_binding, commands, budget, *, network_bindings,
            run=None, generation_reader=None):
    """Two bounded reads of the process netns and reciprocal host veths.

    runtime_binding includes the approved runtime root. Command execution and
    process generation are source-bound in production; callbacks allow offline tests.
    """
    if run is None:
        from tools.semantic_provider_node_observation import NodeObservation
        run = NodeObservation({}, budget).run
    if generation_reader is None:
        from tools.semantic_provider_preexec_native import NativeBackend
        generation_reader = lambda pid: NativeBackend.generation(None, pid)
    from tools.semantic_provider_deployment_producer import program
    valid_generation(generation)
    require(type(network_bindings) is list and 1 <= len(network_bindings) <= 32, "L2_INTERFACE_INVALID")
    approved_ips = {n["ipv4"] for n in network_bindings}
    require(len(approved_ips) == len(network_bindings), "L2_IPV4_DUPLICATE")
    runtime = {k: runtime_binding[k] for k in ("path", "sha256")}

    def state():
        budget.check()
        row = json.loads(run(runtime, ["--root", runtime_binding["root"], "state", cid], 16384))
        require(row.get("id") == cid and row.get("status") in ("created", "running")
                and row.get("pid") == generation["pid"], "L2_BINDING_CHANGED")
        require(generation_reader(generation["pid"]) == generation, "L2_BINDING_CHANGED")
        return row

    def links():
        budget.check()
        # nsenter executes ip itself: verify its binding before and after too.
        program(commands["ip"], budget)
        children = json.loads(run(commands["nsenter"], ["--net=/proc/" + str(generation["pid"]) + "/ns/net",
                              commands["ip"]["path"], "-j", "addr", "show"], 131072))
        program(commands["ip"], budget)
        require(type(children) is list and len(children) <= 33, "L2_INTERFACE_INVALID")
        children = [n for n in children if n.get("ifname") != "lo"]
        addresses = []
        for child in children:
            interface_name(child.get("ifname"))
            addresses.extend(a["local"] for a in child.get("addr_info", []) if a.get("family") == "inet")
        require(len(addresses) == len(set(addresses)), "L2_IPV4_DUPLICATE")
        require(all(ip in approved_ips for ip in addresses), "L2_UNAPPROVED_INTERFACE")
        require(len(children) <= len(network_bindings), "L2_UNAPPROVED_INTERFACE")
        require(len({n["ifname"] for n in children}) == len(children), "L2_INTERFACE_AMBIGUOUS")
        hosts = json.loads(run(commands["ip"], ["-j", "link", "show"], 131072))
        require(type(hosts) is list and len(hosts) <= 1024, "L2_HOST_LINK_INVALID")
        result = []
        used_children, used_hosts = set(), set()
        for position, nic in enumerate(network_bindings):
            found = [n for n in children if any(a.get("family") == "inet" and a.get("local") == nic["ipv4"]
                                              for a in n.get("addr_info", []))]
            if not found:
                continue # Check every present NIC for drift before waiting.
            require(len(found) == 1, "L2_INTERFACE_AMBIGUOUS")
            child = found[0]
            addresses = [a["local"] for a in child.get("addr_info", []) if a.get("family") == "inet"]
            require(bool(addresses), "PEER_ADDRESSES_NOT_READY")
            require(addresses == [nic["ipv4"]], "L2_IP_DRIFT")
            require(not any(a.get("family") == "inet6" for a in child.get("addr_info", [])), "L2_IPV6_UNAPPROVED")
            mac = live_mac(child.get("address"))
            require(nic["mac"] in (L2_LIVE_MAC, mac)
                    and nic["interface"] in (live_interface(position), child["ifname"]), "L2_SIGNED_FIELD_DRIFT")
            index, child_index = child.get("link_index"), child.get("ifindex")
            require(type(index) is int and index > 1 and type(child_index) is int and child_index > 1,
                    "L2_HOST_INDEX_INVALID")
            require(child_index not in used_children and index not in used_hosts, "L2_INTERFACE_AMBIGUOUS")
            used_children.add(child_index)
            used_hosts.add(index)
            found = [h for h in hosts if h.get("ifindex") == index]
            # link_netnsid is relative to the observer's netns, not an ifindex.
            # Never replace the host lookup or reciprocal bridge proof with it.
            require(len(found) == 1, "L2_HOST_LINK_INVALID")
            host = found[0]
            require(host.get("link_index") == child_index and host.get("master") == nic["bridge"]
                    and type(host.get("ifname")) is str
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", host["ifname"]),
                    "L2_RECIPROCAL_BRIDGE_DRIFT")
            result.append({**nic, "interface": child["ifname"], "mac": mac, "childIfindex": child_index,
                           "hostIfindex": index, "hostInterface": host["ifname"]})
        require(len(result) == len(network_bindings), "PEER_INTERFACE_MISSING")
        return result

    before = state()
    first, second = links(), links()
    require(first == second and state() == before, "L2_BINDING_CHANGED")
    budget.check()
    return {"containerId": cid, "generation": copy.deepcopy(generation), "bindings": first}


def cohort(signed_doc, cid, runtime_binding, commands, budget, *, run=None):
    """Observe candidate and all CREATED_CANDIDATE peers, before v1 MAC checks."""
    from tools.semantic_provider_peer_bindings import declarations
    from tools.semantic_provider_preexec_native import NativeBackend
    from tools.semantic_provider_node_observation import NodeObservation
    run = run or NodeObservation({}, budget).run
    expectations = [{"containerId": cid, "networkBindings": signed_doc["networkBindings"]},
                    *declarations(signed_doc["transport"], cid)]
    observations = {}
    runtime = {k: runtime_binding[k] for k in ("path", "sha256")}
    for expected in expectations:
        row = json.loads(run(runtime, ["--root", runtime_binding["root"], "state", expected["containerId"]], 16384))
        require(row.get("id") == expected["containerId"] and row.get("status") in ("created", "running")
                and type(row.get("pid")) is int and row["pid"] > 1, "L2_BINDING_CHANGED")
        gen = NativeBackend.generation(None, row["pid"])
        observations[expected["containerId"]] = observe(expected["containerId"], gen, runtime_binding,
            commands, budget, network_bindings=expected["networkBindings"], run=run)
    # Close the cohort interval: no member may change while another is read.
    for row in observations.values():
        require(NativeBackend.generation(None, row["generation"]["pid"]) == row["generation"], "L2_BINDING_CHANGED")
    return observations


def write_exclusive(epoch_root, observations):
    raw = authorization.canonical({"schema": SCHEMA, "containers": observations})
    require(len(raw) <= 131072, "L2_BINDING_UNBOUNDED")
    path = Path(epoch_root) / "l2-binding.json"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise authorization.OperationDenied("L2_BINDING_EXISTS") from None
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return authorization.sha(raw)


def check(epoch_root, observations):
    from .broker_v2 import private
    try:
        raw = private(Path(epoch_root) / "l2-binding.json")
    except FileNotFoundError:
        raise authorization.OperationDenied("L2_OBSERVATION_REQUIRED") from None
    require(authorization.decode(raw) == {"schema": SCHEMA, "containers": observations}, "L2_BINDING_CHANGED")
    return observations


def bound(signed_doc, cid, epoch_root, runtime_binding, commands, budget, *, run=None):
    """Reobserve a v4 document and require the immutable epoch binding."""
    if not enabled(signed_doc):
        return copy.deepcopy(signed_doc)
    try:
        observations = cohort(signed_doc, cid, runtime_binding, commands, budget, run=run)
    except authorization.OperationDenied as error:
        if str(error).startswith("L2_") or str(error) in (
                "PEER_INTERFACES_NOT_READY", "PEER_INTERFACE_MISSING", "PEER_ADDRESSES_NOT_READY"):
            raise authorization.OperationDenied("L2_BINDING_CHANGED") from None
        raise
    check(epoch_root, observations)
    return effective(signed_doc, observations, container_id=cid)
