"""Single APISIX generation, reached on its private loopback through a pinned netns."""
from contextlib import contextmanager
import ctypes
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket

from gateway_bundle import ID, KINDS, LIMIT, matches
from mandate import Held, canonical, need
from module_release.docker import Docker
from store import trusted


def switch_namespace(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    clone_newnet = 0x40000000  # Linux CLONE_NEWNET, also on Python versions before os.setns
    need(libc.setns(fd, clone_newnet) == 0, "GATEWAY_NETWORK_NAMESPACE")


def generation(engine, container):
    doc = engine.inspect(container)
    state = doc["State"]
    need(state["Running"] is True and state["Pid"] > 0, "GATEWAY_NOT_RUNNING")
    return {"cid": doc["Id"], "started": state["StartedAt"], "pid": state["Pid"]}


DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII | re.I)
SEMANTIC_BINDING = "services.bindings.ouf-semantic-registry"


def upstream_error(code, resource):
    error = Held(code)
    error.public_context = f"resource={resource['kind']}/{resource['id']}"
    return error


def dns_host(value, resource):
    if isinstance(value, str):
        name = value.removesuffix(".")
        if len(name) <= 253 and all(DNS_LABEL.fullmatch(label) for label in name.split(".")):
            try:
                # Also reject IPv4 spellings accepted by libc, e.g. 127.1.
                socket.inet_aton(name)
            except OSError:
                return name.lower()
    raise upstream_error("GATEWAY_UPSTREAM_LITERAL_IP", resource)


def shared_endpoints(engine, gateway_cid):
    gateway = engine.inspect(gateway_cid)
    networks = {ep["NetworkID"] for ep in gateway["NetworkSettings"]["Networks"].values() if ep["NetworkID"]}
    owners = {}
    for summary in engine.api("GET", "/containers/json"):
        if not any(ep["NetworkID"] in networks for ep in summary["NetworkSettings"]["Networks"].values()):
            continue
        peer = engine.inspect(summary["Id"])
        if peer["State"]["Running"] is not True:
            continue
        for ep in peer["NetworkSettings"]["Networks"].values():
            if ep["NetworkID"] in networks:
                names = [peer["Name"].removeprefix("/"), *(ep.get("Aliases") or []), *(ep.get("DNSNames") or [])]
                for name in names:
                    owners.setdefault(name.lower(), {}).setdefault(peer["Id"], {})[ep["NetworkID"]] = ep["IPAddress"]
    return owners


def check_semantic_owner(engine, name, candidates, resource):
    active = engine.inspect(name, missing=True) if name else None
    if (not active or active["Name"] != "/" + name or active["State"]["Running"] is not True
            or active["Id"] not in candidates):
        raise upstream_error("GATEWAY_UPSTREAM_MISMATCH", resource)
    endpoints = {ep["NetworkID"]: ep for ep in active["NetworkSettings"]["Networks"].values()}
    for network, ipv4 in candidates[active["Id"]].items():
        endpoint = endpoints.get(network, {})
        reserved = (endpoint.get("IPAMConfig") or {}).get("IPv4Address")
        if not ipv4 or ipv4 != reserved or ipv4 != endpoint.get("IPAddress"):
            raise upstream_error("GATEWAY_UPSTREAM_MISMATCH", resource)


def node_hosts(resource):
    body = resource["body"]
    upstream = body if resource["kind"] == "upstreams" else body.get("upstream", {})
    if not isinstance(upstream, dict):
        raise upstream_error("GATEWAY_UPSTREAM_LITERAL_IP", resource)
    nodes = upstream.get("nodes", [])
    if isinstance(nodes, dict):
        # APISIX also accepts a map keyed by host:port.
        for address in nodes:
            host, port_separator, _ = address.rpartition(":")
            yield dns_host(host if port_separator else address, resource)
    elif isinstance(nodes, list):
        for node in nodes:
            yield dns_host(node.get("host") if isinstance(node, dict) else None, resource)
    else:
        raise upstream_error("GATEWAY_UPSTREAM_LITERAL_IP", resource)


def check_upstreams(profile, semantic_profile, identity, resources):
    local, external = {}, set()
    for resource in resources:
        for host in node_hosts(resource):
            if "." in host:
                external.add((resource["kind"], resource["id"]))
            else:
                local.setdefault(host, resource)
    if not local:
        return external

    engine = Docker(profile)
    owners = shared_endpoints(engine, identity["cid"])
    semantic = profile["values"].get(SEMANTIC_BINDING)
    for host, resource in local.items():
        candidates = owners.get(host, {})
        if not candidates:
            raise upstream_error("GATEWAY_UPSTREAM_UNRESOLVED", resource)
        if len(candidates) != 1:
            raise upstream_error("GATEWAY_UPSTREAM_AMBIGUOUS", resource)
        if isinstance(semantic, str) and host == semantic.removesuffix(".").lower():
            check_semantic_owner(engine, semantic_profile.get("containerName"), candidates, resource)
    return external


@contextmanager
def connect(profile):
    engine = Docker(profile)
    identity = generation(engine, profile["container"])
    key = trusted(profile["keyFile"], private=True).read_text(encoding="ascii").rstrip("\r\n")
    need(key and key.isascii() and key.isprintable(), "GATEWAY_ADMIN_KEY")
    host = ipaddress.ip_address(profile["host"])
    need(host.is_loopback, "GATEWAY_ADMIN_LOOPBACK")
    proc = Path("/proc", str(identity["pid"]), "ns/net")
    with open_namespace(proc) as target, open_namespace("/proc/self/ns/net") as original:
        def guard():
            need(generation(engine, profile["container"]) == identity, "GATEWAY_GENERATION_CHANGED")

        guard()
        ns = os.fstat(target)
        switch_namespace(target)
        try:
            admin = Admin(str(host), profile["port"], profile["adminPath"], key, guard)
            yield admin, dict(identity, netns=[ns.st_dev, ns.st_ino])
        finally:
            switch_namespace(original)


@contextmanager
def open_namespace(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        yield fd
    finally:
        os.close(fd)


class AdminRequestError(Held):
    def __init__(self, status):
        super().__init__("GATEWAY_ADMIN_REQUEST")
        self.status = status


class Admin:
    def __init__(self, host, port, base, key, guard):
        self.host, self.port, self.base = host, port, base
        self.key, self.guard = key, guard

    def _request(self, method, path, body=None):
        self.guard()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.request(method, path, None if body is None else canonical(body),
                         {"X-API-KEY": self.key, "Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read(LIMIT + 1)
            self.guard()
            need(len(data) <= LIMIT, "GATEWAY_ADMIN_RESPONSE")
            return response.status, data
        finally:
            conn.close()

    def request(self, method, row, body=None):
        kind, ident = row["kind"], row["id"]
        need(kind in KINDS and matches(ID, ident) and ident not in (".", ".."), "GATEWAY_RESOURCE_PATH")
        status, data = self._request(method, f"{self.base}/{kind}/{ident}", body)
        if method == "GET" and status == 404:
            error = json.loads(data)
            message = error.get("error_msg", error.get("message"))
            need(isinstance(message, str) and message.lower() == "key not found", "GATEWAY_ADMIN_NOT_FOUND")
            return None
        if status not in ((200, 201) if method == "PUT" else (200,)):
            raise AdminRequestError(status)
        if method == "DELETE":
            return None
        doc = json.loads(data)
        need(doc["key"].endswith(f"/{kind}/{ident}") and type(doc["value"]) is dict, "GATEWAY_ADMIN_RESOURCE")
        value = doc["value"].copy()
        need(str(value.pop("id", ident)) == ident, "GATEWAY_ADMIN_ID")
        for field in ("create_time", "update_time"):
            value.pop(field, None)
        return value

    def list_routes(self):
        status, data = self._request("GET", f"{self.base}/routes")
        if status != 200:
            raise AdminRequestError(status)
        code = "GATEWAY_ADMIN_RESOURCE"
        try:
            doc = json.loads(data)
        except (ValueError, RecursionError):
            raise Held(code) from None
        need(type(doc) is dict and type(doc.get("list")) is list and type(doc.get("total")) is int
             and doc["total"] == len(doc["list"]), code)
        routes = {}
        for entry in doc["list"]:
            need(type(entry) is dict and isinstance(entry.get("key"), str) and type(entry.get("value")) is dict,
                 code)
            collection, _, ident = entry["key"].rpartition("/")
            # The key includes the store prefix, which may differ between installations.
            need(collection.startswith("/") and collection.endswith("/routes")
                 and matches(ID, ident) and ident not in (".", "..")
                 and ident not in routes, code)
            value = entry["value"]
            value_id = value.get("id", ident)
            need(type(value_id) in (str, int) and str(value_id) == ident, code)
            routes[ident] = value
        return routes

    def get(self, row):
        return self.request("GET", row)

    def write(self, row, body):
        if body is None:
            return self.request("DELETE", row)
        return self.request("PUT", row, body)
