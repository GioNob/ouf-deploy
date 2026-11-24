"""Provider sintetico con finestra fissa per rotta e guasti temporizzati."""

import ipaddress
import math
import re
import socket
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer

from .manifest import canonical, digest


class Provider:
    def __init__(self, provider, capacity, emit, clock=time.monotonic):
        self.config = provider
        self.capacity = capacity
        self.emit = emit
        self.clock = clock
        self.origin = clock()
        self.lock = threading.Lock()
        self.bucket = None
        self.count = Counter()
        self.active = self.serial = 0

    def begin(self, route, method):
        with self.lock:
            now = self.clock()
            elapsed = now - self.origin
            window = self.capacity["windowSeconds"]
            bucket = math.floor(elapsed / window)
            if bucket != self.bucket:
                self.bucket = bucket
                self.count.clear()
            delay = retry = 0
            status, effect = 200, "ok"
            if route == "other" or method != "GET":
                status, effect = (404 if route == "other" else 405), "rejected"
            else:
                self.count[route] += 1
                delay = self.config["latencyMs"][route]
                if self.count[route] > self.capacity["count"]:
                    status, effect = 429, "quota"
                    retry = max(1, math.ceil((bucket + 1) * window - elapsed))
                else:
                    for fault in self.config["outages"]:
                        age = elapsed - fault["startSeconds"]
                        if 0 <= age < fault["durationSeconds"] and fault["route"] in (route, "both"):
                            effect = fault["effect"]
                            status = {"upstream429": 429, "close": 0, "timeout": 0,
                                      "503": 503, "late": 200}[effect]
                            delay += fault["delayMs"]
                            retry = fault["retryAfterSeconds"]
                            break
            self.serial += 1
            self.active += 1
            event = dict(kind="arrival", t=now, utc=datetime.now(timezone.utc).isoformat(),
                         seq=self.serial, route=route, inFlight=self.active)
            self.emit(event)
            return event, status, effect, delay / 1000, retry

    def finish(self, arrival, status, effect):
        with self.lock:
            now = self.clock()
            self.active -= 1
            self.emit(dict(arrival, kind="arrivalEnd", end=now, latency=now-arrival["t"],
                           code=status, outcome=effect))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # La diagnostica standard include la request line.

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self.serve_request
        raise AttributeError(name)

    def serve_request(self):
        provider = self.server.provider
        path = self.path.partition("?")[0]
        if path == self.server.search_path:
            route = "search"
        elif path == self.server.fetch_path or path.startswith(self.server.fetch_path + "/"):
            route = "fetch"
        else:
            route = "other"
        arrival, status, effect, delay, retry = provider.begin(route, self.command)
        try:
            if delay:
                time.sleep(delay)
            if status == 0:
                self.close_connection = True
                return
            if status == 200:
                key = digest(canonical([provider.config["seed"], self.path]))
                if route == "search":
                    payload = {"results": [{"id": key, "href": f"{self.server.fetch_path}/{key}"}]}
                else:
                    resource = path.rsplit("/", 1)[-1]
                    resource_id = resource if re.fullmatch("[a-f0-9]{64}", resource) else key
                    payload = {"id": resource_id, "label": "Risorsa sintetica"}
            else:
                payload = {"outcome": effect}
            raw = canonical(payload)
            self.send_response(status)
            if status in (429, 503):
                self.send_header("Retry-After", str(retry))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()
        except (ConnectionError, TimeoutError):
            effect = "disconnected"
        finally:
            provider.finish(arrival, status, effect)


class Server(ThreadingHTTPServer):
    daemon_threads = False

    def server_bind(self):
        # HTTPServer normalmente esegue una risoluzione inversa del nome.
        TCPServer.server_bind(self)

    def get_request(self):
        connection, client = super().get_request()
        connection.settimeout(10)
        return connection, client

    def handle_error(self, request, client_address):
        # Non inviare l'indirizzo del peer allo stderr.
        pass


def server(address, port, provider, search_path="/search", fetch_path="/fetch"):
    """Il bind accetta un indirizzo numerico o localhost. Nessuna risoluzione di rete."""
    host = str(ipaddress.ip_address("127.0.0.1" if address == "localhost" else address))
    if not all(p.startswith("/") and not any(c in p for c in "?#\r\n")
               for p in (search_path, fetch_path)) or search_path == fetch_path:
        raise ValueError("INVALID_ROUTES")

    class BoundServer(Server):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    httpd = BoundServer((host, port), Handler)
    httpd.provider = provider
    httpd.search_path = search_path
    httpd.fetch_path = fetch_path
    return httpd
