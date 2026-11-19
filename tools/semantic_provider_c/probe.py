"""D-049. No lifecycle, policy, lease or nft mutations; no response bodies in evidence."""
import base64
from contextlib import closing, contextmanager
import errno
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import select
import signal
import socket
import ssl
import stat
import struct
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

from tools.semantic_provider_r3 import install_common as I, operate as R

SCHEMA = "ouf.semantic-provider-c-probe.v1"
# The adapter admits only the Semantic owner's search grammar (ouf-api-gateway
# tools/semantic_provider_boundary.py: PREFIX + HEAD + pattern + MIDDLE + intent + TAIL).
# P2 uses the CLASS pattern with a fixed intent, sent as the Semantic's form body.
SEARCH_INTENT = "persona"
QUERY = ("PREFIX owl: <http://www.w3.org/2002/07/owl#>\n"
         "PREFIX skos: <http://www.w3.org/2004/02/skos/core#>\n"
         "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n"
         "SELECT DISTINCT ?resource ?label WHERE { ?resource a owl:Class ."
         " OPTIONAL { ?resource rdfs:label|skos:prefLabel ?label }"
         " FILTER(CONTAINS(LCASE(STR(COALESCE(?label,?resource))),LCASE(\"" + SEARCH_INTENT + "\")))"
         " } ORDER BY ?resource LIMIT 50")
SEARCH_BODY = urlencode({"query": QUERY, "format": "application/sparql-results+json"}).encode("ascii")
FORM = "application/x-www-form-urlencoded"
MAX_HTTP, REQUEST_SECONDS, TOTAL_SECONDS = 12, 10, 900
MAX_BODY = 2 * 1024 * 1024
CASES = ("P1", "P2", "P3", "N1", "N2", "N3", "N4", "N5", "N6", "N7")
ENV_NAMES = ("GATEWAY_BASE_URL", "SEARCH_PATH", "FETCH_PATH", "TOKEN_ENDPOINT",
             "CLIENT_ID", "WORKLOAD_SCOPE", "CLIENT_SECRET_FILE")
require, canonical, sha = I.require, I.canonical, I.sha


def preconditions(observation):
    require(set(observation["candidates"]) == set(R.ROLES)
            and all(R.running(v) for v in observation["candidates"].values())
            and R.active(observation)
            and observation["lease"] == {"state": "LEASE_READY", "leaseAuthorized": True}
            and set(observation["tables"]) == set(R.ROLES)
            and all(t[f] is True for t in observation["tables"].values() for f in ("inet", "bridge")),
            "C_R3_PRECONDITIONS_UNSATISFIED")


def installed(args, observation, reader):
    """Same installed runtime loader as operate; link A2 peer to accepted R3 bytes."""
    S = I.native_switch()
    root = I.V.absolute(args.install_root)
    wrapper = S.custody(args.wrapper, 0o755)[0]
    require(sha(wrapper) == args.wrapper_sha256, "C_R3_BINDING_DRIFT")
    code_root = I.wrapper_code_root(root, wrapper)
    source = code_root / "source" / I.C.RUNTIME
    runtime_raw = S.custody(source, 0o600)[0]
    # Same closed set as operate: delivered runtime or its deterministic v16 overlay.
    require(sha(runtime_raw) in I.installed_runtime_hashes(), "C_R3_BINDING_DRIFT")
    runtime = I.compiled(runtime_raw, source, "c_probe_runtime", sha(runtime_raw))
    cfg, raw = runtime.load_configuration(code_root / "runtime-configuration.json")
    runtime.verify_files(cfg)
    require(sha(raw) == observation["configurationSha256"], "C_R3_BINDING_DRIFT")
    auth, _ = runtime.operation_modules(cfg)
    heads = [runtime.authorization_head(cfg, raw, cid, auth) for cid in sorted(cfg["candidates"])]
    require(heads[0] == heads[1] and {k: heads[0][k] for k in ("sha256", "sequence", "decision")}
            == observation["authorization"], "C_R3_BINDING_DRIFT")
    index = I.C.document(reader.read(args.inputs, args.inputs_sha256))
    require(index["schema"] == "ouf.semantic-provider-r3-inputs.v1"
            # Any R3 version index: the probe needs only these v1 inputs, each re-bound
            # to the signed head (acceptance) or to the accepted A2 files below.
            and I.C.DATA_INPUTS <= set(index["files"]), "C_R3_INPUTS_UNPROVEN")
    accepted_raw = reader.bound(index["files"]["acceptance"])
    require(sha(accepted_raw) == heads[0]["authorization"]["acceptanceSha256"], "C_R3_ACCEPTANCE_DRIFT")
    accepted = I.C.ACCEPT.decode_manifest(accepted_raw)
    documents = {}
    for name, field in (("semanticPeer", "semanticPeer"), ("a2Manifest", "manifest")):
        bound = index["files"][name]
        require(bound["sha256"] == accepted["preparationA"]["files"][field]["sha256"],
                "C_R3_ACCEPTANCE_DRIFT")
        documents[name] = I.C.document(reader.bound(bound))
    peer, manifest = documents["semanticPeer"], documents["a2Manifest"]
    require(manifest["manifest"]["semanticPeer"] == peer
            and manifest["planSha256"] == accepted["preparationA"]["planSha256"], "C_R3_PEER_UNPROVEN")
    # Installed, hash-bound preparer supplies the IP executable, not host PATH.
    cid = observation["candidates"]["southbound"]["cid"]
    broker = I.C.document(runtime.bound_bytes(cfg["admissionConfigurations"][cid]))
    template = I.C.document(runtime.bound_bytes(broker["preparerTemplate"]))
    ip_binding = (template["commands"]["ip"], template["commandHashes"]["ip"])
    transport = I.C.document(runtime.bound_bytes(broker["transportBinding"]))
    return peer, ip_binding, transport


def semantic(args, peer, ip_binding, inspector=None):
    """Reuse P/A's complete generation, endpoint and reciprocal bridge check twice."""
    code = "C_SEMANTIC_IDENTITY_DRIFT"
    try:
        if inspector is None:
            path = I.ROOT / "scripts/prepare-semantic-provider-installation.py"
            inspector = I.compiled(path.read_bytes(), path, "c_probe_peer_checks", sha(path.read_bytes()))
        cid, proof = peer["containerId"], peer["generation"]
        rows = R.decode(R.docker(args, "inspect", cid))
        require(len(rows) == 1, code)
        row = rows[0]
        require(row["Id"] == cid and row["State"]["Running"] is True
                and row["State"]["Status"] == "running" and row["State"]["Pid"] == proof["pid"]
                and row["State"]["StartedAt"] == peer["startedAt"] and row["Image"] == peer["image"], code)
        class Reader:
            def command_json(self, executable, *argv):
                require(executable == ip_binding[0], code)
                return R.decode(R.command(*ip_binding, list(argv), args.timeout_seconds))
        for _ in range(2):
            inspector.verify_peer(Reader(), ip_binding[0], peer, row)
        return row
    except Exception:
        raise I.A.OperationDenied(code) from None


def configuration(row):
    env = {}
    for item in row["Config"]["Env"]:
        key, sep, value = item.partition("=")
        if key.startswith("OUF_SCHEMA_GOV_") and key[15:] in ENV_NAMES:
            require(sep and key[15:] not in env and 0 < len(value) <= 2048,
                    "C_SEMANTIC_CONFIGURATION_UNPROVEN")
            env[key[15:]] = value
    require(set(env) == set(ENV_NAMES), "C_SEMANTIC_CONFIGURATION_UNPROVEN")
    for name in ("SEARCH_PATH", "FETCH_PATH"):
        require(re.fullmatch(r"/[A-Za-z0-9_/-]{1,255}", env[name]), "C_ROUTE_UNPROVEN")
    path = PurePosixPath(env["CLIENT_SECRET_FILE"])
    require(path.is_absolute() and ".." not in path.parts and str(path) == env["CLIENT_SECRET_FILE"],
            "C_SECRET_PATH_UNPROVEN")
    require(all(re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,512}", env[k]) for k in ("CLIENT_ID", "WORKLOAD_SCOPE")),
            "C_SEMANTIC_CONFIGURATION_UNPROVEN")
    return env


def endpoint(value, schemes):
    parsed = urlsplit(value)
    require(parsed.scheme in schemes and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment, "C_ENDPOINT_UNPROVEN")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    require(1 <= port <= 65535, "C_ENDPOINT_UNPROVEN")
    return parsed, port


def targets(profile, env, peer, transport):
    require(profile["schema"] == "ouf.semantic-provider-installation.v1", "C_INSTALLATION_PROFILE_UNPROVEN")
    base, port = endpoint(env["GATEWAY_BASE_URL"], {"https"})
    require(base.path in ("", "/") and port == profile["ports"]["southbound"], "C_ENDPOINT_PROFILE_DRIFT")
    networks = profile["roles"]["southbound"]["networks"]
    # Docker repeats the container name and aliases on every network of the southbound
    # (backend, egress, internal): only the network shared with the Semantic is the path
    # the R3 ingress admits.
    shared = set(profile["roles"]["semantic"]["networks"])
    matches = [(name, ep) for name, ep in networks.items()
               if name in shared and (base.hostname in ep["aliases"] or base.hostname in ep["dnsNames"])]
    require(len(matches) == 1, "C_SOUTHBOUND_ALIAS_UNPROVEN")
    network, south = matches[0]
    semantic_net = profile["roles"]["semantic"]["networks"][network]
    require(semantic_net["ipv4"] == peer["binding"]["ipv4"]
            and profile["networks"][network]["bridge"] == peer["binding"]["bridge"], "C_ENDPOINT_PROFILE_DRIFT")
    flows = transport["transport"]
    ingress = [f for f in flows if f["source"] == semantic_net["ipv4"] and f["destination"] == south["ipv4"]
               and f["port"] == port and f["peerIngress"] == {"kind": "BRIDGE_PORT", "ifindex": peer["binding"]["hostIfindex"]}]
    require(len(ingress) == 1, "C_ENDPOINT_PROFILE_DRIFT")
    adapter_ips = {ep["ipv4"] for ep in profile["roles"]["adapter"]["networks"].values()}
    relay = [f for f in flows if f["source"] in {ep["ipv4"] for ep in networks.values()}
             and f["destination"] in adapter_ips and f["port"] == profile["ports"]["adapter"]]
    require(len(relay) == 1, "C_ADAPTER_ENDPOINT_UNPROVEN")
    token, token_port = endpoint(env["TOKEN_ENDPOINT"], {"http", "https"})
    # The network shared by Semantic/southbound is proved via R3, not guessed from host routing.
    adapter_host = profile["roles"]["adapter"]["containerName"]
    require(any(ep["ipv4"] == relay[0]["destination"] and adapter_host in ep["dnsNames"]
                for ep in profile["roles"]["adapter"]["networks"].values()), "C_ADAPTER_ENDPOINT_UNPROVEN")
    return {"southboundHost": base.hostname, "southboundAddress": south["ipv4"], "southboundPort": port,
            "adapterHost": adapter_host,
            "adapterAddress": relay[0]["destination"], "adapterPort": profile["ports"]["adapter"],
            "backendSubnets": profile["networks"][network]["subnets"], "backendNetwork": network,
            "tokenHost": token.hostname, "tokenPort": token_port, "tokenTls": token.scheme == "https",
            "tokenPath": token.path or "/",
            # D-053: P3 fetches only inside the operator-declared namespaces (hash-bound profile).
            "namespacePrefixes": declared_namespaces(profile)}


def declared_namespaces(profile):
    rows = profile.get("providerNamespaces")
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict
            and type(rows[0].get("namespacePrefixes")) is list and rows[0]["namespacePrefixes"]
            and all(type(p) is str and p.startswith(("https://", "http://")) and p.endswith(("/", "#"))
                    for p in rows[0]["namespacePrefixes"]), "C_PROVIDER_NAMESPACES_UNPROVEN")
    return list(rows[0]["namespacePrefixes"])


def proc_read(pid, filename, maximum):
    """Walk relative to the container root; no path-component symlinks or disk copies."""
    parts = PurePosixPath(filename).parts
    require(parts[0] == "/" and ".." not in parts, "C_CONTAINER_FILE_UNPROVEN")
    fd = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        with os.fdopen(os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "C_CONTAINER_FILE_UNPROVEN")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
                    "C_CONTAINER_FILE_CHANGED")
            return raw
    finally:
        os.close(fd)


PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")


def pem_certificates(raw):
    """Merged trust bundles may carry non-ASCII comment headers; keep only PEM blocks."""
    blocks = PEM_CERTIFICATE.findall(raw)
    require(1 <= len(blocks) <= 1024, "C_SOUTHBOUND_TLS_UNPROVEN")
    return b"\n".join(blocks).decode("ascii") + "\n"


def resolver(raw):
    servers = [line.split()[1] for line in raw.decode("ascii", errors="replace").splitlines()
               if line.split() and line.split()[0] == "nameserver" and len(line.split()) >= 2]
    require(bool(servers), "C_CONTAINER_RESOLVER_UNPROVEN")
    return str(ipaddress.ip_address(servers[0]))


SETTLE_ATTEMPTS, SETTLE_PAUSE_SECONDS = 6, 5


def r3_settled(args, *, output_exists=False, deadline=None, sleep=time.sleep):
    """A lease renewal briefly publishes LEASE_UPDATING; wait it out (bounded) instead of failing."""
    for attempt in range(SETTLE_ATTEMPTS):
        r3 = R.observe(args, output_exists=output_exists, deadline=deadline)
        if r3["lease"]["state"] != "LEASE_UPDATING":
            return r3
        if attempt + 1 < SETTLE_ATTEMPTS:
            sleep(SETTLE_PAUSE_SECONDS)
    return r3


def r3_stable(r3):
    """Fields that must not change around the probe. The supervisor reason and the rolling
    activation counter change legitimately with renewals and are excluded from comparisons
    and from the plan digest; state, epochs, unit, lease and tables stay exact."""
    supervisor = {k: r3["supervisor"][k] for k in ("unit", "state", "epochs", "authorizationSequence")}
    return {**r3, "supervisor": supervisor}


def observation(args, *, output_exists=False, deadline=None):
    r3 = r3_settled(args, output_exists=output_exists, deadline=deadline)
    preconditions(r3)
    reader = I.Reader()
    peer, ip_binding, transport = installed(args, r3, reader)
    row = semantic(args, peer, ip_binding)
    env = configuration(row)
    profile = I.C.document(reader.read(args.installation_profile, args.installation_profile_sha256))
    target = targets(profile, env, peer, transport)
    ca = reader.read(args.southbound_ca, args.southbound_ca_sha256)
    try:
        ssl.create_default_context(cadata=pem_certificates(ca))
    except Exception:
        raise I.A.OperationDenied("C_SOUTHBOUND_TLS_UNPROVEN") from None
    resolv = proc_read(peer["generation"]["pid"], "/etc/resolv.conf", 65536)
    state = {"r3": r3_stable(r3), "semantic": {"containerId": peer["containerId"], "generation": peer["generation"],
             "bootId": peer["bootId"]}, "configuration": env, "targets": target,
             "resolver": {"nameserver": resolver(resolv), "sha256": sha(resolv)}, "inputHashes": reader.hashes}
    reader.verify()
    require(configuration(semantic(args, peer, ip_binding)) == env, "C_SEMANTIC_CONFIGURATION_DRIFT")
    again = r3_settled(args, output_exists=output_exists, deadline=deadline)
    require(r3_stable(again) == state["r3"], "C_R3_OBSERVATION_DRIFT")
    return state, ca


def proposal(args, state):
    return I.digest_plan({"schema": SCHEMA, "observation": state, "outputDirectory": args.output_directory,
        "bindings": {k: v for k, v in vars(args).items() if k not in ("plan", "apply", "plan_sha256")},
        "querySha256": sha(QUERY.encode()), "limits": {"southboundHttp": MAX_HTTP,
        "requestSeconds": REQUEST_SECONDS, "totalSeconds": TOTAL_SECONDS, "pauseSeconds": 1}, "secretsRead": 0})


class Budget:
    def __init__(self, deadline, clock=time.monotonic, sleep=time.sleep):
        self.deadline, self.clock, self.sleep = deadline, clock, sleep
        self.last = None
        self.southbound_http = 0

    def remaining(self):
        remaining = self.deadline - self.clock()
        require(remaining > 0, "C_TOTAL_TIMEOUT")
        return min(REQUEST_SECONDS, remaining)

    def wait(self, seconds):
        end = self.clock() + max(0, seconds)
        require(end < self.deadline, "C_TOTAL_TIMEOUT")
        while self.clock() < end:
            self.sleep(min(1, end - self.clock()))

    def begin(self, southbound=False):
        if self.last is not None:
            self.wait(max(0, self.last + 1 - self.clock()))
        self.remaining()
        if southbound:
            require(self.southbound_http < MAX_HTTP, "C_SOUTHBOUND_REQUEST_LIMIT")
            self.southbound_http += 1

    def finish(self):
        self.last = self.clock()


def dns_name(raw, offset):
    """Skip one bounded DNS name (including a compression pointer)."""
    for _ in range(128):
        require(offset < len(raw), "C_DNS_UNPROVEN")
        size = raw[offset]
        if size & 0xc0 == 0xc0:
            require(offset + 1 < len(raw), "C_DNS_UNPROVEN")
            return offset + 2
        require(size <= 63, "C_DNS_UNPROVEN")
        offset += 1
        if not size:
            return offset
        offset += size
    require(False, "C_DNS_UNPROVEN")


def resolve(host, nameserver, budget):
    """A query directly to container nameserver. Never calls host getaddrinfo."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    labels = host.rstrip(".").encode("idna").split(b".")
    require(all(0 < len(v) <= 63 for v in labels), "C_DNS_UNPROVEN")
    question = b"".join(bytes([len(v)]) + v for v in labels) + b"\0" + struct.pack("!HH", 1, 1)
    ident = os.urandom(2)
    query = ident + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0) + question
    family = socket.AF_INET6 if ipaddress.ip_address(nameserver).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(budget.remaining())
        sock.connect((nameserver, 53))
        sock.send(query)
        raw = sock.recv(65535)
    require(len(raw) >= 12 and raw[:2] == ident, "C_DNS_UNPROVEN")
    flags, qd, an, _, _ = struct.unpack("!HHHHH", raw[2:12])
    require(flags & 0x8000 and not flags & 0x020f and qd == 1 and an <= 128
            and raw[12:12 + len(question)] == question, "C_DNS_UNPROVEN")
    offset, addresses = 12 + len(question), []
    for _ in range(an):
        offset = dns_name(raw, offset)
        require(offset + 10 <= len(raw), "C_DNS_UNPROVEN")
        kind, cls, _, length = struct.unpack("!HHIH", raw[offset:offset + 10])
        offset += 10
        require(offset + length <= len(raw), "C_DNS_UNPROVEN")
        if (kind, cls, length) == (1, 1, 4):
            addresses.append(str(ipaddress.ip_address(raw[offset:offset + 4])))
        offset += length
    require(bool(addresses), "C_DNS_UNPROVEN")
    return sorted(set(addresses))


def metadata(status=None, outcome="HTTP", body=b"", duration=0):
    return {"httpStatus": status, "outcome": outcome, "durationSeconds": round(duration, 6),
            "bodySha256": sha(body), "bodyLength": len(body)}


class Transport:
    def __init__(self, nameserver, ca, budget):
        self.nameserver, self.budget = nameserver, budget
        self.south_context = ssl.create_default_context(cadata=pem_certificates(ca))
        self.token_context = ssl.create_default_context()

    def addresses(self, host):
        return resolve(host, self.nameserver, self.budget)

    def connect(self, address, port, context=None, sni=None, deadline=None):
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        deadline = deadline or time.monotonic() + self.budget.remaining()
        def remaining():
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError()
            return min(seconds, self.budget.remaining())
        try:
            sock.settimeout(remaining())
            sock.connect((address, port))
            if context:
                sock.settimeout(remaining())
                sock = context.wrap_socket(sock, server_hostname=sni)
            return sock
        except BaseException:
            sock.close()
            raise

    def tls(self, target):
        start = time.monotonic()
        try:
            with self.connect(target["southboundAddress"], target["southboundPort"],
                              self.south_context, target["southboundHost"], start + self.budget.remaining()):
                return metadata(outcome="TLS_VERIFIED", duration=time.monotonic() - start)
        except Exception:
            raise I.A.OperationDenied("C_SOUTHBOUND_TLS_UNPROVEN") from None

    def request(self, address, port, host, method, path, body=b"", token=None,
                *, context=None, sni=None, southbound=False, content_type="application/sparql-query"):
        self.budget.begin(southbound)
        start = time.monotonic()
        data = b""
        status = None
        connected = False
        timed_out = threading.Event()
        try:
            # connect() and socket use one absolute deadline, including trickling bodies.
            deadline = start + self.budget.remaining()
            with closing(http.client.HTTPConnection(host, port, timeout=self.budget.remaining())) as conn:
                conn.sock = self.connect(address, port, context, sni, deadline)
                connected = True
                active_socket = conn.sock
                def interrupt():
                    timed_out.set()
                    try:
                        active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                timer = threading.Timer(max(.001, deadline - time.monotonic()), interrupt)
                timer.daemon = True
                timer.start()
                headers = {"Host": f"{host}:{port}", "Connection": "close", "Accept": "application/sparql-results+json, application/json",
                           "Content-Type": content_type}
                if token is not None:
                    headers["Authorization"] = "Bearer " + token
                conn.sock.settimeout(max(.001, deadline - time.monotonic()))
                conn.request(method, path, body=body, headers=headers)
                conn.sock.settimeout(max(.001, deadline - time.monotonic()))
                response = conn.getresponse()
                status = response.status
                while True:
                    require(time.monotonic() < deadline, "C_REQUEST_TIMEOUT")
                    # read1 avoids an unbounded sequence of per-recv socket timeouts.
                    if response.fp is not None:
                        response.fp.raw._sock.settimeout(max(.001, deadline - time.monotonic()))
                    chunk = response.read1(min(65536, MAX_BODY + 1 - len(data)))
                    if not chunk:
                        break
                    data += chunk
                    require(len(data) <= MAX_BODY, "C_BODY_LIMIT")
                require(response.length in (None, 0), "C_BODY_INCOMPLETE")
                require(not timed_out.is_set() and time.monotonic() < deadline, "C_REQUEST_TIMEOUT")
                result = {**metadata(response.status, body=data, duration=time.monotonic() - start),
                          "connectionEstablished": True}
                return result, data
        except ssl.SSLError:
            outcome = "TLS_FAILED"
        except (TimeoutError, socket.timeout):
            outcome = "TIMEOUT"
        except OSError as error:
            outcome = {errno.ECONNREFUSED: "REFUSED", errno.ENETUNREACH: "UNREACHABLE",
                       errno.EHOSTUNREACH: "UNREACHABLE"}.get(error.errno, "IO_FAILED")
        except Exception:
            outcome = "REQUEST_FAILED"
        finally:
            if "timer" in locals():
                timer.cancel()
            self.budget.finish()
        if timed_out.is_set():
            outcome = "TIMEOUT"
        return {**metadata(status, outcome=outcome, body=data, duration=time.monotonic() - start),
                "connectionEstablished": connected}, b""


def expected(case, result):
    status, outcome = result.get("httpStatus"), result.get("outcome")
    if case == "N4" and outcome == "SKIPPED":
        return result.get("reason") == "EXPIRES_IN_GT_600"
    if case == "N6" and outcome in ("TIMEOUT", "UNREACHABLE", "REFUSED"):
        return not result.get("connectionEstablished", False)
    if case == "N7" and outcome == "TLS_FAILED":
        return True
    if outcome != "HTTP":
        return False
    if case == "P1":
        return status == 200 and result.get("bearer") is True and result.get("scopeGranted") is True
    if case == "P2":
        return status == 200 and result.get("rows", 0) >= 1 and result.get("firstUriValid") is True
    if case == "P3":
        return status == 200
    if case == "N4":
        # Expired token: openid-connect tolerates clock skew (~120 s), so at exp+5 s the
        # strict admission Lua (claims.exp <= now) denies with 403; either is a denial.
        return status in (401, 403)
    if case in ("N1", "N2", "N3"):
        return status == 401
    if case == "N5":
        return status in (400, 404)
    if case == "N6":
        return status == 403
    if case == "N7":
        return status is not None and 400 <= status <= 499
    return False


def parse_token(raw, env):
    value = R.decode(raw)
    token = value["access_token"]
    require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)
            and len(token) <= 32768, "C_P1_INVALID_TOKEN")
    payload = R.decode(base64.urlsafe_b64decode(token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)))
    expires = value["expires_in"]
    require(type(expires) in (int, float) and math.isfinite(expires) and expires > 0
            and type(payload["exp"]) in (int, float) and math.isfinite(payload["exp"]), "C_P1_INVALID_EXPIRY")
    granted = value.get("scope", payload.get("scope", ""))
    require(type(granted) is str, "C_P1_INVALID_SCOPE")
    return token, payload["exp"], expires, {"bearer": str(value.get("token_type", "")).lower() == "bearer",
            "scopeGranted": set(env["WORKLOAD_SCOPE"].split()) <= set(granted.split())}


def first_uri(raw, prefixes=None):
    """First valid result URI; with prefixes, the first one inside a declared namespace."""
    value = R.decode(raw)
    rows = value["results"]["bindings"]
    require(type(rows) is list and 1 <= len(rows) <= 50, "C_P2_ROWS_UNPROVEN")
    uris = []
    for row in rows:
        item = row["resource"]
        uri = item["value"]
        require(item["type"] == "uri" and type(uri) is str and len(uri) <= 8192
                and urlsplit(uri).scheme and not any(ord(ch) < 32 for ch in uri), "C_P2_URI_UNPROVEN")
        uris.append(uri)
    if prefixes is None:
        return uris[0], len(rows)
    inside = [u for u in uris if any(u.startswith(p) and len(u) > len(p) for p in prefixes)]
    require(inside, "C_P3_DECLARED_NAMESPACE_URI_ABSENT")
    return inside[0], len(rows)


def suite(state, ca, deadline, secret_reader=proc_read, transport_factory=Transport, wall=time.time, identity_check=None):
    budget = Budget(deadline)
    target, env = state["targets"], state["configuration"]
    transport = transport_factory(state["resolver"]["nameserver"], ca, budget)
    results = {"cases": {}, "secretsRead": 0, "southboundHttpRequests": 0}
    cases = results["cases"]
    check = identity_check or (lambda: None)
    try:
        check()
        require(transport.addresses(target["southboundHost"]) == [target["southboundAddress"]], "C_SOUTHBOUND_DNS_DRIFT")
        results["tlsPreflight"] = transport.tls(target)
        token_ips = transport.addresses(target["tokenHost"])
        if not target["tokenTls"]:
            require(all(any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in target["backendSubnets"])
                        for ip in token_ips), "C_TOKEN_HTTP_OUTSIDE_BACKEND")
        results["tokenTransport"] = {"tls": target["tokenTls"], "systemTrustStore": target["tokenTls"],
                                     "containerResolver": True, "httpBackendOnly": not target["tokenTls"]}
        check()
        secret = secret_reader(state["semantic"]["generation"]["pid"], env["CLIENT_SECRET_FILE"], 65536)
        results["secretsRead"] = 1
        check()
        form = urlencode({"grant_type": "client_credentials", "client_id": env["CLIENT_ID"],
                          "client_secret": secret.decode("utf-8").rstrip("\r\n"), "scope": env["WORKLOAD_SCOPE"]}).encode()
        del secret
        p1, raw = transport.request(token_ips[0], target["tokenPort"], target["tokenHost"], "POST", target["tokenPath"],
            form, context=transport.token_context if target["tokenTls"] else None,
            sni=target["tokenHost"], content_type="application/x-www-form-urlencoded")
        del form
        cases["P1"] = p1
        require(p1["httpStatus"] == 200, "C_P1_FAILED")
        token, exp, expires, fields = parse_token(raw, env)
        del raw
        p1.update(fields)
        require(expected("P1", p1), "C_P1_FAILED")

        def south(case, method="POST", path=None, bearer=token, sni=None):
            check()
            record, body = transport.request(target["southboundAddress"], target["southboundPort"],
                target["southboundHost"], method, path or env["SEARCH_PATH"], SEARCH_BODY if method == "POST" else b"",
                bearer, context=transport.south_context, sni=sni or target["southboundHost"], southbound=True,
                content_type=FORM)
            cases[case] = record
            return body

        raw = south("P2")
        require(cases["P2"]["httpStatus"] == 200, "C_P2_FAILED")
        uri, rows = first_uri(raw, target["namespacePrefixes"])
        del raw
        cases["P2"].update(rows=rows, firstUriValid=True)
        south("P3", "GET", env["FETCH_PATH"] + "?" + urlencode({"uri": uri}))
        south("N1", bearer=None)
        header, payload, signature = token.split(".")
        altered = ("A" if signature[0] != "A" else "B") + signature[1:]
        south("N2", bearer=".".join((header, payload, altered)))
        south("N3", bearer=token[:len(token) // 2])
        south("N5", "GET")
        check()
        n6, _ = transport.request(target["adapterAddress"], target["adapterPort"], target["adapterHost"],
            "POST", env["SEARCH_PATH"], SEARCH_BODY, context=transport.south_context,
            sni=target["adapterHost"], content_type=FORM)
        cases["N6"] = n6
        south("N7", bearer=None, sni="c-probe-invalid.invalid")
        if expires > 600:
            cases["N4"] = {**metadata(outcome="SKIPPED"), "reason": "EXPIRES_IN_GT_600"}
        else:
            while wall() < exp + 5:
                budget.wait(min(1, exp + 5 - wall()))
            south("N4")
    except Exception as error:
        results.update(reason=I.public(error), held=not cases)
    finally:
        results["southboundHttpRequests"] = budget.southbound_http
        for case in CASES:
            if case not in cases:
                cases[case] = metadata(outcome="NOT_RUN")
            cases[case]["passed"] = expected(case, cases[case])
        results["failedCases"] = [case for case in CASES if not cases[case]["passed"]]
    return results


def check_process(proof, boot):
    code = "C_SEMANTIC_IDENTITY_DRIFT"
    try:
        proc = Path("/proc", str(proof["pid"]))
        def ticks():
            with (proc / "stat").open("rb") as stream:
                raw = stream.read(8193)
            require(len(raw) <= 8192 and raw.startswith(f"{proof['pid']} (".encode()), code)
            return int(raw.rsplit(b") ", 1)[1].split()[19])
        before = ticks()
        ns = (proc / "ns/net").stat()
        require(before == ticks() == proof["startTicks"]
                and (ns.st_dev, ns.st_ino) == (proof["namespaceDevice"], proof["namespaceInode"])
                and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot, code)
    except Exception:
        raise I.A.OperationDenied(code) from None


def child_probe(state, ca, deadline):
    """Fork once. Only the child enters the pinned netns and reads the secret."""
    pid = state["semantic"]["generation"]["pid"]
    netfd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    proof = state["semantic"]["generation"]
    try:
        require((os.fstat(netfd).st_dev, os.fstat(netfd).st_ino) ==
                (proof["namespaceDevice"], proof["namespaceInode"]), "C_SEMANTIC_IDENTITY_DRIFT")
        readfd, writefd = os.pipe()
        try:
            child = os.fork()
        except BaseException:
            os.close(readfd)
            os.close(writefd)
            raise
    except BaseException:
        os.close(netfd)
        raise
    if child == 0:
        os.close(readfd)
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            def expired(*_):
                raise I.A.OperationDenied("C_TOTAL_TIMEOUT")
            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic()))
            check = lambda: check_process(proof, state["semantic"]["bootId"])
            check()
            os.setns(netfd, 0)
            require(os.stat("/proc/self/ns/net").st_ino == proof["namespaceInode"], "C_SEMANTIC_IDENTITY_DRIFT")
            result = suite(state, ca, deadline, identity_check=check)
        except Exception as error:
            result = {"held": True, "reason": I.public(error), "secretsRead": 0,
                      "southboundHttpRequests": 0, "cases": {}, "failedCases": list(CASES)}
        try:
            data = canonical(result)
            while data:
                data = data[os.write(writefd, data):]
        finally:
            os._exit(0)
    os.close(writefd)
    os.close(netfd)
    raw = bytearray()
    reaped = False
    try:
        while True:
            require(time.monotonic() < deadline, "C_TOTAL_TIMEOUT")
            readable, _, _ = select.select([readfd], [], [], min(1, deadline - time.monotonic()))
            if readable:
                chunk = os.read(readfd, 65536)
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= 131072, "C_CHILD_OUTPUT_UNBOUNDED")
        _, status = os.waitpid(child, 0)
        reaped = True
        require(status == 0, "C_CHILD_FAILED")
        return R.decode(raw)
    finally:
        os.close(readfd)
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def apply(args, plan, report, observe=None, run=None, deadline=None):
    observe, run = observe or observation, run or child_probe
    deadline = deadline or time.monotonic() + TOTAL_SECONDS
    require(args.plan_sha256 == plan["planSha256"], "C_PLAN_DIGEST_CHANGED")
    before, ca = observe(args, deadline=deadline)
    require(proposal(args, before) == plan, "C_PLAN_DIGEST_CHANGED")
    output = Path(args.output_directory)
    I.mkdir_once(output, report)
    report["outputCreated"] = True
    report["planSha256"] = plan["planSha256"]
    I.write_once(output / "probe-claim.json", canonical(plan), report)
    report["before"] = before
    try:
        report.update(run(before, ca, deadline - 60))  # reserve readback within the same 15 minutes
    except Exception as error:
        report.update(reason=I.public(error), failedCases=list(CASES))
    try:
        after, _ = observe(args, output_exists=True, deadline=deadline)
        report["after"] = after
        report["r3Unchanged"] = before == after
    except Exception as error:
        report.update(r3Unchanged=False, readbackReason=I.public(error))
    report["status"] = ("HELD" if report.get("held") and report["r3Unchanged"] else
                        "C_PROBE_PASSED" if not report.get("failedCases") and report["r3Unchanged"] else "C_PROBE_FAILED")


def arguments(argv):
    parser = I.Arguments(description="D-049: sonda JWT/TLS governata, senza lifecycle")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    for name in ("install-root", "wrapper", "wrapper-sha256", "docker", "docker-sha256", "docker-socket",
                 "systemctl", "systemctl-sha256", "nft", "nft-sha256", "output-directory", "inputs", "inputs-sha256",
                 "installation-profile", "installation-profile-sha256", "southbound-ca", "southbound-ca-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    args.timeout_seconds = 10
    require(args.apply == (args.plan_sha256 is not None), "INVALID_ARGUMENTS")
    require(all(I.V.hashed(v) for k, v in vars(args).items() if k.endswith("sha256") and v is not None), "INVALID_ARGUMENTS")
    path = PurePosixPath(args.output_directory)
    require(str(path.parent) == "/etc/ouf/deploy-snapshots"
            and re.fullmatch(r"semantic-provider-c-probe-[0-9]{8}T[0-9]{6}Z", path.name), "C_EXCLUSIVE_EVIDENCE_PATH_REQUIRED")
    require(re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", args.docker_socket), "INVALID_ARGUMENTS")
    return args


@contextmanager
def deadline_guard(deadline):
    """Hard process deadline also covers DNS, header trickling and native readback."""
    def expired(*_):
        raise I.A.OperationDenied("C_TOTAL_TIMEOUT")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic()))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main(argv=None):
    report = {"schema": SCHEMA, "status": "HELD", "secretsRead": 0, "southboundHttpRequests": 0,
              "containerLifecycleOperations": 0, "nftWrites": 0, "doNotRerunApply": False}
    args = None
    try:
        args = arguments(argv)
        require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "ROOT_CUSTODY_REQUIRED")
        require(sys.flags.isolated and sys.flags.dont_write_bytecode, "ISOLATED_PYTHON_REQUIRED")
        os.umask(0o077)
        deadline = time.monotonic() + TOTAL_SECONDS
        if args.apply and os.path.lexists(args.output_directory):
            report["doNotRerunApply"] = True
        with deadline_guard(deadline), I.module_scope():
            state, _ = observation(args, deadline=deadline)
            plan = proposal(args, state)
            if args.plan:
                report.update(plan, status="PLAN_READY")
            else:
                apply(args, plan, report, deadline=deadline)
    except Exception as error:
        report.update(status="C_PROBE_FAILED" if report.get("outputCreated") else "HELD", reason=I.public(error))
    if report.get("outputCreated"):
        try:
            I.write_once(Path(args.output_directory) / "result.json", canonical(report), report)
        except Exception:
            report.update(status="C_PROBE_FAILED", diagnosisSaved=False)
    print(canonical(report).decode("ascii"), flush=True)
    return int(report["status"] not in ("PLAN_READY", "C_PROBE_PASSED"))
