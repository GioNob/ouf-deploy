"""Closed projection and byte-preserving rewrite of the D-052 route source."""

import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit


TRAILER = b"#END\n"
UNPROVEN = "R3_EGRESS_CONFIG_UNPROVEN"
FLOW_FIELDS = ("purpose", "source", "destination", "protocol", "port")
MAX_BYTES = 131072


class Held(RuntimeError):
    pass


def require(condition, code=UNPROVEN):
    if not condition:
        raise Held(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode(raw):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "DUPLICATE_JSON_FIELD")
        return result

    def finite(value):
        number = float(value)
        require(math.isfinite(number), "NONFINITE_JSON_VALUE")
        return number

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_float=finite,
                          parse_constant=lambda _: require(False, "NONFINITE_JSON_VALUE"))
    except (UnicodeError, ValueError, RecursionError):
        raise Held("INVALID_JSON") from None


def fields(value, allowed, required=()):
    require(type(value) is dict and set(required) <= value.keys() <= set(allowed))


def hostname(value):
    require(type(value) is str and len(value) <= 253)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        require(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in value.rstrip(".").split(".")))
    return value


def port(value):
    require(type(value) is int and 1 <= value <= 65535)
    return value


def endpoint(value, *, url=False):
    require(type(value) is str and value and not any(c.isspace() or ord(c) < 32 for c in value))
    try:
        parsed = urlsplit(value if url else "//" + value)
        require(parsed.username is None and parsed.password is None and parsed.hostname is not None)
        number = parsed.port
    except ValueError:
        raise Held(UNPROVEN) from None
    host = hostname(parsed.hostname)
    if url:
        require(parsed.scheme in {"http", "https"} and not parsed.fragment)
        return {"host": host, "port": port(number if number is not None else
                                           {"http": 80, "https": 443}[parsed.scheme])}
    require(not (parsed.path or parsed.query or parsed.fragment) and number is not None)
    require(value == (f"[{host}]:{number}" if ":" in host else f"{host}:{number}"))
    return {"host": host, "port": port(number)}


def upstream_projection(value):
    required = {"scheme", "nodes", "upstream_host", "pass_host"}
    fields(value, required | {"type", "timeout", "retries", "retry_timeout"}, required)
    require(value["scheme"] in ("http", "https") and value["pass_host"] in ("pass", "node", "rewrite")
            and value.get("type", "roundrobin") == "roundrobin")
    nodes = value["nodes"]
    require(type(nodes) is dict and bool(nodes))
    for node, weight in nodes.items():
        endpoint(node)
        require(type(weight) is int and weight > 0)
    result = {key: value[key] for key in required}
    hostname(value["upstream_host"])
    if "timeout" in value:
        timeouts = value["timeout"]
        fields(timeouts, {"connect", "send", "read"})
        require(all(type(item) in (int, float) and item > 0 for item in timeouts.values()))
        result["timeout"] = timeouts
    for key in ("retries", "retry_timeout"):
        if key in value:
            require(type(value[key]) in (int, float) and value[key] >= 0)
    return result


def oidc_projection(value):
    required = {"discovery", "ssl_verify", "bearer_only"}
    fields(value, required | {"issuer", "client_id", "client_secret", "scope", "required_scopes",
                              "use_jwks", "unauth_action", "realm", "timeout",
                              "token_signing_alg_values_expected", "set_access_token_header",
                              "set_id_token_header", "set_userinfo_header",
                              "access_token_in_authorization_header"}, required)
    require(all(type(value[key]) is bool for key in ("ssl_verify", "bearer_only")))
    result = {key: value[key] for key in ("ssl_verify", "bearer_only")}
    for key in ("discovery", "issuer"):
        if key in value:
            result[key] = endpoint(value[key], url=True)
    return result


def route_projection(route):
    required = {"uri", "methods", "upstream", "plugins"}
    fields(route, required | {"id", "name", "desc", "status", "priority", "host", "hosts"}, required)
    require(type(route["uri"]) is str and re.fullmatch(r"/[A-Za-z0-9_./~:@*-]*", route["uri"]))
    methods = route["methods"]
    require(type(methods) is list and methods and all(
        type(method) is str and method in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        for method in methods))
    plugins = route["plugins"]
    fields(plugins, {"openid-connect", "limit-count", "request-validation"}, {"openid-connect"})
    if "limit-count" in plugins:
        limit = plugins["limit-count"]
        fields(limit, {"count", "time_window", "key_type", "key", "policy", "rejected_code",
                       "rejected_msg", "show_limit_quota_header", "allow_degradation"})
        require(limit.get("policy", "local") == "local")
    if "request-validation" in plugins:
        fields(plugins["request-validation"], {"header_schema", "body_schema", "rejected_code", "rejected_msg"})
    return {"uri": route["uri"], "methods": methods, "upstream": upstream_projection(route["upstream"]),
            "openid-connect": oidc_projection(plugins["openid-connect"])}


def parse_routes(raw):
    require(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n" + TRAILER), "INVALID_ROUTES_TRAILER")
    document = decode(raw[:-len(TRAILER)])
    fields(document, {"routes", "ssls"}, {"routes"})
    require(type(document["routes"]) is list and bool(document["routes"]))
    if "ssls" in document:
        require(type(document["ssls"]) is list)
        for ssl in document["ssls"]:
            fields(ssl, {"id", "snis", "type", "status", "cert", "key", "certs", "keys"})
    return document


def project(path, raw):
    """The sole public view. Never return parsed secret-bearing objects."""
    document = parse_routes(raw)
    return {"source": str(path), "sha256": sha(raw), "bytes": len(raw),
            "routes": [route_projection(route) for route in document["routes"]]}


def one(rows, field, value):
    require(type(rows) is list and all(type(row) is dict for row in rows))
    matches = [row for row in rows if row.get(field) == value]
    require(len(matches) == 1, "DECLARED_ROUTE_FLOW_UNPROVEN")
    return matches[0]


def declared_destination(southbound, adapter, coordinator):
    """Read the declaration and independently corroborate both endpoints and g2."""
    south, peer = southbound["candidate"], adapter["candidate"]
    outbound = one(south["networkBindings"], "bindingRef", "southbound-internal")
    inbound = one(peer["networkBindings"], "bindingRef", "adapter-internal")
    flow = one(south["transport"], "purpose", "GATEWAY_ADAPTER")
    kernel = coordinator["kernel"]
    require(type(kernel.get("generation")) is int and kernel["generation"] == 2
            and kernel.get("providerFlowMatch") == "ORIGINAL_TUPLE", "DECLARED_ROUTE_FLOW_UNPROVEN")
    static = one(kernel["staticFlows"], "purpose", "GATEWAY_ADAPTER")
    ingress = flow["peerIngress"]
    require(flow["protocol"] == "tcp" and flow["source"] == outbound["ipv4"]
            and flow["destination"] == inbound["ipv4"] and outbound["bridge"] == inbound["bridge"]
            and ingress["kind"] == "CREATED_CANDIDATE" and ingress["bindingRef"] == inbound["bindingRef"]
            and ingress["declaration"]["containerId"] == peer["containerId"]
            and one(ingress["declaration"]["networkBindings"], "bindingRef", "adapter-internal") == inbound
            and canonical({key: flow[key] for key in FLOW_FIELDS}) ==
                canonical({key: static[key] for key in FLOW_FIELDS}), "DECLARED_ROUTE_FLOW_UNPROVEN")
    require(str(ipaddress.IPv4Address(flow["source"])) == flow["source"], "DECLARED_ROUTE_FLOW_UNPROVEN")
    destination = str(ipaddress.IPv4Address(flow["destination"]))
    require(destination == flow["destination"] and destination != flow["source"], "DECLARED_ROUTE_FLOW_UNPROVEN")
    return {"destination": destination, "port": port(flow["port"])}


def regenerate(path, raw, expected_sha256, target, *, expected_routes=2):
    require(sha(raw) == expected_sha256, "ROUTES_SHA256_MISMATCH")
    document = parse_routes(raw)
    require(canonical(document) + b"\n" + TRAILER == raw, "ROUTES_BYTE_IDENTITY_UNPROVEN")
    before = project(path, raw)
    changes = []
    # No adapter name in code: every route must address one TLS peer by name, with the
    # node host equal to upstream_host (the verified TLS identity); all share that name.
    hosts = set()
    for index, route in enumerate(document["routes"]):
        projected = before["routes"][index]
        upstream = route["upstream"]
        require(upstream["scheme"] == "https" and upstream["pass_host"] == "rewrite"
                and len(upstream["nodes"]) == 1 and next(iter(upstream["nodes"].values())) == 1,
                "ADAPTER_ROUTE_SET_UNPROVEN")
        host = endpoint(next(iter(upstream["nodes"])))["host"]
        require(host == upstream["upstream_host"], "ADAPTER_ROUTE_SET_UNPROVEN")
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        require(not literal, "ADAPTER_ROUTE_SET_UNPROVEN")
        hosts.add(host)
        # The new port comes only from the flow, even if the old node differs.
        nodes = {f"{target['destination']}:{target['port']}": 1}
        changes.append({"path": f"/routes/{index}/upstream/nodes",
                        "before": projected["upstream"]["nodes"], "after": nodes})
        upstream["nodes"] = nodes
    require(len(changes) == expected_routes and len(hosts) == 1, "ADAPTER_ROUTE_SET_UNPROVEN")
    updated = canonical(document) + b"\n" + TRAILER
    return updated, changes, before, project(path, updated)
