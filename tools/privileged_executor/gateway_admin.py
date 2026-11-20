"""Single APISIX generation, reached on its private loopback through a pinned netns."""
from contextlib import contextmanager
import ctypes
import http.client
import ipaddress
import json
import os
from pathlib import Path

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

    def request(self, method, row, body=None):
        kind, ident = row["kind"], row["id"]
        need(kind in KINDS and matches(ID, ident) and ident not in (".", ".."), "GATEWAY_RESOURCE_PATH")
        path = f"{self.base}/{kind}/{ident}"
        self.guard()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.request(method, path, None if body is None else canonical(body),
                         {"X-API-KEY": self.key, "Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read(LIMIT + 1)
            self.guard()
            need(len(data) <= LIMIT, "GATEWAY_ADMIN_RESPONSE")
            if method == "GET" and response.status == 404:
                error = json.loads(data)
                message = error.get("error_msg", error.get("message"))
                need(isinstance(message, str) and message.lower() == "key not found", "GATEWAY_ADMIN_NOT_FOUND")
                return None
            if response.status not in ((200, 201) if method == "PUT" else (200,)):
                raise AdminRequestError(response.status)
            if method == "DELETE":
                return None
            doc = json.loads(data)
            need(doc["key"].endswith(f"/{kind}/{ident}") and type(doc["value"]) is dict, "GATEWAY_ADMIN_RESOURCE")
            value = doc["value"].copy()
            need(str(value.pop("id", ident)) == ident, "GATEWAY_ADMIN_ID")
            for field in ("create_time", "update_time"):
                value.pop(field, None)
            return value
        finally:
            conn.close()

    def get(self, row):
        return self.request("GET", row)

    def write(self, row, body):
        if body is None:
            return self.request("DELETE", row)
        return self.request("PUT", row, body)
