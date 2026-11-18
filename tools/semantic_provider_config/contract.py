"""Closed D-053 adapter configuration and installation declaration."""
import ipaddress
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from tools.semantic_provider_routes.routes import canonical, decode, hostname, require, sha


PROFILE_PATH = '/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json'
DECLARATION = 'providerNamespaces'
TARGET = '/run/ouf-semantic-provider/adapter.json'
METADATA = (10006, 10006, 0o600)
MAX_BYTES = 1048576  # B1's mounted-source byte limit
SHA256 = re.compile(r'[0-9a-f]{64}')
REF = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}')
SCHEMA = 'ADAPTER_CONFIGURATION_SCHEMA_INVALID'
ENDPOINT = 'ADAPTER_CONFIGURATION_ENDPOINT_INVALID'
NAMESPACES = 'PROVIDER_NAMESPACE_DECLARATION_INVALID'
TOP = set('listenAddress listenPort maxWorkers requestTimeoutSeconds searchPath fetchPath provider admission '
          'receiptKeyFile tlsCertificateFile tlsPrivateKeyFile'.split())
PROVIDER = set('endpoint namespace_prefixes allowed_cidrs max_request_bytes max_response_bytes '
               'max_intent_chars timeout_seconds ca_file'.split())
ADMISSION = set('installation issuer audience workload scope tenants'.split())


def shape(value, fields, code):
    require(type(value) is dict and value.keys() == set(fields), code)


def clean(value):
    return type(value) is str and bool(value) and not any(
        c.isspace() or ord(c) < 32 or ord(c) == 127 or c == '\\' for c in value)


def absolute(value):
    if not clean(value) or not value.startswith('/') or value.startswith('//'):
        return False
    path = PurePosixPath(value)
    return path.as_posix() == value and '..' not in path.parts and value != '/'


def url(value, schemes, code, *, fragment=False):
    require(clean(value) and '?' not in value and
            ('#' not in value or fragment and value.endswith('#') and value.count('#') == 1), code)
    try:
        parsed = urlsplit(value)
        require(parsed.scheme in schemes and parsed.hostname is not None and
                parsed.username is None and parsed.password is None and not parsed.netloc.endswith(':'), code)
        port = parsed.port
        require(port is None or 1 <= port <= 65535, code)
        host = hostname(parsed.hostname)
        authority = f'[{host}]' if ':' in host else host
        require(re.fullmatch(re.escape(authority) + r'(?::[0-9]+)?', parsed.netloc, re.IGNORECASE), code)
    except (ValueError, RuntimeError):
        require(False, code)
    return parsed


def endpoint(value):
    parsed = url(value, {'https'}, ENDPOINT)
    require(parsed.path.startswith('/'), ENDPOINT)
    return {'host': parsed.hostname, 'port': 443 if parsed.port is None else parsed.port, 'path': parsed.path}


def prefixes(values, *, declaration=False):
    require(type(values) is list and (values or not declaration), NAMESPACES)
    for value in values:
        url(value, {'http', 'https'}, NAMESPACES, fragment=True)
        require(value.endswith(('/', '#')), NAMESPACES)
    require(len(values) == len(set(values)), NAMESPACES)
    return values


def declaration(profile):
    require(type(profile) is dict and profile.get('schema') == 'ouf.semantic-provider-installation.v1', NAMESPACES)
    rows = profile.get(DECLARATION)
    # This installation declares the one adapter provider. IAM is a separate egress.
    require(type(rows) is list and len(rows) == 1, NAMESPACES)
    row = rows[0]
    shape(row, ('endpointRef', 'namespacePrefixes'), NAMESPACES)
    require(type(row['endpointRef']) is str and REF.fullmatch(row['endpointRef']), NAMESPACES)
    prefixes(row['namespacePrefixes'], declaration=True)
    return row


def config(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, SCHEMA)
    value = decode(raw)
    require(canonical(value) + b'\n' == raw, 'ADAPTER_CONFIGURATION_CANONICAL_LF_REQUIRED')
    shape(value, TOP, SCHEMA)
    provider, admission = value['provider'], value['admission']
    shape(provider, PROVIDER, SCHEMA)
    shape(admission, ADMISSION, SCHEMA)
    require(clean(value['listenAddress']) and all(type(value[key]) is int and value[key] > 0
            for key in ('listenPort', 'maxWorkers', 'requestTimeoutSeconds')) and value['listenPort'] <= 65535
            and all(absolute(value[key]) for key in ('searchPath', 'fetchPath', 'receiptKeyFile',
                                                     'tlsCertificateFile', 'tlsPrivateKeyFile'))
            and absolute(provider['ca_file'])
            and all(type(provider[key]) is int and provider[key] > 0
                    for key in ('max_request_bytes', 'max_response_bytes', 'max_intent_chars', 'timeout_seconds'))
            and all(clean(admission[key]) for key in ADMISSION - {'tenants'})
            and type(admission['tenants']) is list and all(clean(item) for item in admission['tenants']), SCHEMA)
    endpoint(provider['endpoint'])
    prefixes(provider['namespace_prefixes'])
    cidrs = provider['allowed_cidrs']
    require(type(cidrs) is list and all(type(item) is str for item in cidrs), SCHEMA)
    try:
        require(all('/' in item and ipaddress.ip_network(item) for item in cidrs), SCHEMA)
    except ValueError:
        require(False, SCHEMA)
    return value


def project(source, raw):
    require(absolute(source) and PurePosixPath(source).name == 'adapter.json', SCHEMA)
    provider = config(raw)['provider']
    return {'source': source, 'sha256': sha(raw), 'bytes': len(raw),
            'provider': {'endpoint': endpoint(provider['endpoint']), 'allowed_cidrs': provider['allowed_cidrs'],
                         'namespace_prefixes': provider['namespace_prefixes']}}


def regenerate(source, raw, profile):
    before = project(source, raw)
    value = config(raw)
    old = value['provider']['namespace_prefixes']
    new = declaration(profile)['namespacePrefixes']
    require(old != new, 'ADAPTER_NAMESPACE_DELTA_REQUIRED')
    value['provider']['namespace_prefixes'] = new
    updated = canonical(value) + b'\n'
    after = project(source, updated)
    value['provider']['namespace_prefixes'] = old
    require(canonical(value) + b'\n' == raw, 'ADAPTER_NAMESPACE_DELTA_UNPROVEN')
    return updated, [{'path': '/provider/namespace_prefixes', 'before': old, 'after': new}], before, after


def source_entry(recipe, check=require, code=SCHEMA):
    rows = recipe.get('sources')
    check(type(rows) is list and all(type(row) is dict for row in rows), code)
    matches = [row for row in rows if row.get('target') == TARGET or
               type(row.get('source')) is str and PurePosixPath(row['source']).name == 'adapter.json']
    check(len(matches) == 1, code)
    row = matches[0]
    check(row.keys() == {'source', 'target', 'sha256', 'readOnly', 'uid', 'gid', 'mode', 'maxBytes'}
          and row['target'] == TARGET and absolute(row['source']) and PurePosixPath(row['source']).name == 'adapter.json'
          and type(row['sha256']) is str and SHA256.fullmatch(row['sha256']) and row['readOnly'] is True
          and all(type(row[k]) is int for k in ('uid', 'gid', 'mode', 'maxBytes'))
          and (row['uid'], row['gid'], row['mode']) == METADATA and 0 < row['maxBytes'] <= MAX_BYTES, code)
    return row
