"""D-052.2 checks over the closed, public routes projection and bound recipes."""
import ipaddress
from pathlib import PurePosixPath
import re

from tools.semantic_provider_operation.authorization import require


CONFIG = 'R3_EGRESS_CONFIG_UNPROVEN'
TLS = 'R3_UPSTREAM_TLS_IDENTITY_MISMATCH'
UPSTREAM = 'R3_UPSTREAM_FLOW_MISMATCH'
NETWORK = 'R3_EGRESS_NETWORK_MISMATCH'
MISSING = 'R3_EGRESS_FLOW_MISSING'
AMBIGUOUS = 'R3_EGRESS_FLOW_AMBIGUOUS'
ROUTE_TARGET = '/run/ouf-semantic-provider/historical-apisix.yaml'
ROUTE_INPUT = 'southbound/routesProjection'
SHA256 = re.compile(r'[0-9a-f]{64}')
DNS_LABEL = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}


def dns_name(name):
    # A wildcard SAN is a DNS entry, but membership never expands wildcards.
    return (type(name) is str and len(name) <= 253
            and all(DNS_LABEL.fullmatch(label) for label in name.removeprefix('*.').rstrip('.').split('.')))


def source_entry(recipe, *, certificate=False):
    code = TLS if certificate else CONFIG
    rows = recipe.get('sources')
    require(type(rows) is list and all(type(row) is dict for row in rows), code)
    if certificate:
        matches = [row for row in rows if type(row.get('source')) is str
                   and PurePosixPath(row['source']).name == 'server.crt']
    else:
        matches = [row for row in rows if row.get('target') == ROUTE_TARGET]
    require(len(matches) == 1, code)
    entry = matches[0]
    require(type(entry.get('source')) is str and type(entry.get('sha256')) is str
            and SHA256.fullmatch(entry['sha256']) and entry.get('readOnly') is True
            and all(type(entry.get(key)) is int and entry[key] >= 0 for key in ('uid', 'gid', 'mode'))
            and entry['mode'] <= 0o777 and type(entry.get('maxBytes')) is int
            and 0 < entry['maxBytes'] <= 1048576, code)
    return entry


def shape(value, required, optional=()):
    require(type(value) is dict, CONFIG)
    require(value.keys() <= set(required) | set(optional), MISSING)
    require(set(required) <= value.keys(), CONFIG)


def bind_projection(data, route_module):
    """Verify the public shape and its source bindings before compiling the recipes."""
    projection = data[ROUTE_INPUT]
    shape(projection, ('source', 'sha256', 'bytes', 'routes'), ('adapterTlsIdentity',))
    launch = source_entry(data['southbound/launch'])
    policy = source_entry(data['southbound/policy'])
    require(launch == policy and (projection['source'], projection['sha256']) ==
            (policy['source'], policy['sha256']) and type(projection['bytes']) is int
            and 0 < projection['bytes'] <= min(route_module.MAX_BYTES, policy['maxBytes']), CONFIG)
    cert = source_entry(data['adapter/launch'], certificate=True)
    cert_policy = source_entry(data['adapter/policy'], certificate=True)
    tls = projection.get('adapterTlsIdentity')
    require(type(tls) is dict and set(tls) == {'certificateSha256', 'dnsNames'}
            and cert == cert_policy and tls['certificateSha256'] == cert['sha256'], TLS)
    names = tls['dnsNames']
    require(type(names) is list and names and all(dns_name(name) for name in names)
            and names == sorted(set(names)), TLS)
    require(type(projection['routes']) is list and projection['routes'], CONFIG)
    for route in projection['routes']:
        shape(route, ('uri', 'methods', 'upstream', 'openid-connect'), ('serverless',))
        require(type(route.get('serverless', [])) is list, CONFIG)
        # Serverless Lua is no egress: the D-052 projection admits only a closed module
        # set without network/subrequest primitives and exposes just function hashes.
        for item in route.get('serverless', []):
            require(type(item) is dict and set(item) == {'plugin', 'phase', 'functionSha256'}
                    and item['plugin'] in ('serverless-pre-function', 'serverless-post-function')
                    and item['phase'] in ('rewrite', 'access')
                    and type(item['functionSha256']) is list and item['functionSha256']
                    and all(type(h) is str and SHA256.fullmatch(h) for h in item['functionSha256']), CONFIG)
        require(type(route['uri']) is str and re.fullmatch(r'/[A-Za-z0-9_./~:@*-]*', route['uri'])
                and type(route['methods']) is list and route['methods']
                and all(type(method) is str and method in HTTP_METHODS for method in route['methods']), CONFIG)
        upstream, oidc = route['upstream'], route['openid-connect']
        shape(upstream, ('scheme', 'nodes', 'upstream_host', 'pass_host'), ('timeout',))
        require(dns_name(upstream['upstream_host']) and not upstream['upstream_host'].startswith('*.'), TLS)
        shape(oidc, ('discovery', 'ssl_verify', 'bearer_only'), ('issuer',))
        require(type(oidc['ssl_verify']) is type(oidc['bearer_only']) is bool, CONFIG)
        for key in ('discovery', 'issuer'):
            if key in oidc:
                shape(oidc[key], ('host', 'port'))
                require(type(oidc[key]['port']) is int, NETWORK)
        # Reuse the D-052 upstream schema, including node, timeout and host syntax.
        try:
            route_module.upstream_projection(upstream)
        except route_module.Held:
            require(False, UPSTREAM)
    return projection


def check_routes(projection, south, adapter, kernel, identity, route_module):
    flows = [flow for flow in south['transport'] if flow.get('purpose') == 'GATEWAY_ADAPTER'
             and flow.get('protocol') == 'tcp']
    require(flows, MISSING)
    require(len(flows) == 1, AMBIGUOUS)
    flow = flows[0]
    static = [row for row in kernel['staticFlows']
              if all(key in flow and row.get(key) == flow[key] for key in route_module.FLOW_FIELDS)]
    require(static, MISSING)
    require(len(static) == 1, AMBIGUOUS)
    adapter_ips = {nic['ipv4'] for nic in adapter['networkBindings']}
    internal = [nic for nic in adapter['networkBindings'] if nic['bindingRef'] == 'adapter-internal'
                and 'leaseGuard' not in nic and nic['ipv4'] == flow['destination']]
    require(len(internal) == 1 and any(nic['bindingRef'] == 'southbound-internal'
            and nic['ipv4'] == flow['source'] and nic['bridge'] == internal[0]['bridge']
            for nic in south['networkBindings']), UPSTREAM)
    ingress = flow.get('peerIngress', {})
    require(ingress.get('kind') == 'CREATED_CANDIDATE' and ingress.get('bindingRef') == internal[0]['bindingRef'], UPSTREAM)
    host, port = flow['destination'], flow['port']
    require(type(port) is int and 1 <= port <= 65535, UPSTREAM)
    node = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    try:
        issuer_host, issuer_port = identity.issuer_endpoint(kernel, south)
    except identity.Denied:
        require(False, NETWORK)
    issuer = {'host': issuer_host, 'port': issuer_port}
    tls_hosts = set()
    for route in projection['routes']:
        upstream, oidc = route['upstream'], route['openid-connect']
        for address in upstream['nodes']:
            peer = route_module.endpoint(address)['host']
            # A different address of this adapter (or a name) is an upstream
            # mismatch. A literal outside the adapter's bindings has no route flow.
            try:
                ipaddress.ip_address(peer)
            except ValueError:
                continue
            require(peer in adapter_ips, MISSING)
        require(set(upstream['nodes']) == {node}, UPSTREAM)
        require(upstream['scheme'] == 'https' and upstream['pass_host'] == 'rewrite', TLS)
        tls_hosts.add(upstream['upstream_host'])
        require(oidc['discovery'] == issuer and oidc.get('issuer', issuer) == issuer, NETWORK)
    require(len(tls_hosts) == 1 and tls_hosts <= set(projection['adapterTlsIdentity']['dnsNames']), TLS)
    return issuer_port


def check_identity_flow(candidate, port):
    flows = [flow for flow in candidate['transport'] if flow['purpose'] == 'IDENTITY']
    require(len(flows) == 1 and flows[0]['protocol'] == 'tcp' and flows[0]['port'] == port, NETWORK)
