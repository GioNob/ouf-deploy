#!/usr/bin/env python3
"""R-033. Swap an immutable MCP image on an unchanged schema 14."""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import zipfile


BASE = Path(__file__).resolve().parents[1]
STATE = Path('/etc/ouf/deploy-snapshots/mcp-image-swap-r033')


def helper(name, relative):
    spec = importlib.util.spec_from_file_location(name, BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lifecycle = helper('lifecycle', 'scripts/upgrade-semantic-application-20261108.py')
mcp = helper('mcp', 'scripts/upgrade-mcp-analysis-20261108.py')
contract = helper('contract', 'scripts/read-discovery-contract-20261108.py')
inventory = helper('inventory', 'scripts/read-analysis-discovery-runtime-20261107.py')
APP = mcp.APP
ENTRY = mcp.ENTRY
SERVICE = '/ouf-mcp'
REVISION = 'org.opencontainers.image.revision'
SOURCE = 'ouf.mcp.analysis-source'
HEX = '[0-9a-f]{64}'
IMAGE = 'sha256:' + HEX
FILES = ('MCP_FINGERPRINT_KEY_FILE', 'MCP_OIDC_CLIENT_SECRET_FILE',
         'MCP_REPROCESSING_KEY_PROFILE_FILE', 'MCP_REPROCESSING_PERMIT_FILE',
         'MCP_REPROCESSING_EXISTING_POLICY_FILE')
SQL = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL timezone='UTC';
SELECT json_build_object('databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'tables',to_regclass('ouf_mcp.profile_analysis') IS NOT NULL
     AND to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL,
 'history',(SELECT json_agg(json_build_array(version,checksum,applied_at) ORDER BY version)
              FROM ouf_mcp.schema_migration));
ROLLBACK;"""


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return sha(encoded(value))


def check_candidate(c):
    need(set(c) == {'runId', 'artifactId', 'sourceCommit', 'publisherCommit', 'sourceTree', 'publisherTree',
                    'zipSha256', 'archiveSha256', 'binarySha256', 'capabilitiesSha256', 'imageId'},
         'CANDIDATE_FIELDS_CHANGED')
    for key in ('runId', 'artifactId'):
        need(type(c[key]) is int and c[key] > 0, 'CI_ID_REQUIRED')
    for key in ('sourceCommit', 'publisherCommit', 'sourceTree', 'publisherTree'):
        need(re.fullmatch('[0-9a-f]{40}', c[key]), 'CI_COMMIT_OR_TREE_INVALID')
    need(c['publisherTree'] == c['sourceTree'], 'DIFFERENT_PUBLISHER_TREE')
    for key in ('zipSha256', 'archiveSha256', 'binarySha256', 'capabilitiesSha256'):
        need(re.fullmatch(HEX, c[key]), 'CANDIDATE_DIGEST_REQUIRED')
    need(re.fullmatch(IMAGE, c['imageId']), 'ENGINE_IMAGE_ID_REQUIRED')


def package(path, c, store):
    """Verify all five publisher payloads and the single tagged OCI graph before load."""
    check_candidate(c)
    need(path.stat().st_size <= 64 << 20, 'ZIP_TOO_LARGE')
    raw = path.read_bytes()
    need(sha(raw) == c['zipSha256'], 'ZIP_CHANGED')
    names = {'image.tar.gz', 'image-id.txt', 'image-config.json', 'source-commit.txt', 'capabilities.json'}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(sorted(z.namelist()) == sorted(names | {'SHA256SUMS'}), 'ZIP_MEMBERS_CHANGED')
        need(sum(item.file_size for item in z.infolist()) <= 64 << 20, 'PAYLOAD_TOO_LARGE')
        files = {name: z.read(name) for name in names}
        sums = z.read('SHA256SUMS').decode('ascii').splitlines()
    need(sorted(sums) == sorted(sha(data) + '  ' + name for name, data in files.items()),
         'PUBLISHER_CHECKSUMS_CHANGED')
    archive = files['image.tar.gz']
    need(sha(archive) == c['archiveSha256'] and sha(files['capabilities.json']) == c['capabilitiesSha256']
         and files['source-commit.txt'].decode().strip() == c['publisherCommit'], 'CI_PAYLOAD_CHANGED')
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as gz:
        expanded = gz.read((160 << 20) + 1)
    need(len(expanded) <= 160 << 20, 'IMAGE_TOO_LARGE')
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as tar:
        members = tar.getmembers()
        need(len(members) <= 512 and len({m.name for m in members}) == len(members)
             and all((m.isfile() or m.isdir()) and re.fullmatch('[a-zA-Z0-9_./-]+', m.name)
                     and '..' not in m.name.split('/') and not m.name.startswith('/') for m in members),
             'INVALID_IMAGE_MEMBERS')

        def read(name):
            member = tar.getmember(name)
            need(member.isfile(), 'REGULAR_IMAGE_MEMBER_REQUIRED')
            return tar.extractfile(member).read()

        def blob(descriptor):
            ident = descriptor['digest']
            need(re.fullmatch(IMAGE, ident), 'INVALID_OCI_DESCRIPTOR')
            raw = read('blobs/sha256/' + ident[7:])
            need(len(raw) == descriptor['size'] and sha(raw) == ident[7:], 'OCI_BLOB_CHANGED')
            return raw

        index, = json.loads(read('index.json'))['manifests']
        manifest = json.loads(blob(index))
        native_id, config_id = index['digest'], manifest['config']['digest']
        config = json.loads(blob(manifest['config']))
        for layer in manifest['layers']:
            blob(layer)
        legacy, = json.loads(read('manifest.json'))
        need(legacy['Config'] == 'blobs/sha256/' + config_id[7:] and legacy['Layers'] ==
             ['blobs/sha256/' + layer['digest'][7:] for layer in manifest['layers']]
             and legacy['RepoTags'] in (['ouf-mcp:ci'], ['docker.io/library/ouf-mcp:ci'])
             and index.get('annotations', {}).get('io.containerd.image.name') in
             (None, 'docker.io/library/ouf-mcp:ci') and
             index.get('annotations', {}).get('org.opencontainers.image.ref.name') in (None, 'ci', 'ouf-mcp:ci'),
             'SINGLE_MCP_IMAGE_REQUIRED')
    producer_id = files['image-id.txt'].decode().strip()
    inspected, = json.loads(files['image-config.json'])
    need(store in ('classic', 'containerd') and c['imageId'] == (native_id if store == 'containerd' else config_id)
         and producer_id == inspected['Id'] and producer_id in (config_id, native_id)
         and config['os'] == 'linux' and config['architecture'] == 'amd64', 'ARCHIVED_ID_CHANGED')
    defaults = config['config']
    need(defaults['Entrypoint'] == APP[:1] and defaults['Cmd'] == APP[1:]
         and defaults['User'] == '10005:10005' and defaults['WorkingDir'] == '/app'
         and all(inspected['Config'].get(k) == v for k, v in defaults.items() if v)
         and (defaults.get('Labels') or {}).get(REVISION, c['publisherCommit']) == c['publisherCommit'],
         'ARCHIVED_DEFAULTS_CHANGED')
    return archive, defaults


def without_mac(fields):
    return {key: value for key, value in fields.items() if key != 'MacAddress'}


def frame(doc):
    result = dict(inventory.frame(doc), Name=doc['Name'], RestartCount=doc['RestartCount'])
    result['Config'] = without_mac(doc['Config'])
    settings = without_mac(doc['NetworkSettings'])
    settings['Networks'] = {net: without_mac(ep) for net, ep in settings['Networks'].items()}
    result['NetworkSettings'] = settings
    return result


class RestoredFrameChanged(RuntimeError):
    def __init__(self, differences):
        super().__init__('RESTORED_FRAME_CHANGED')
        self.differences = differences


def verify_restored_frame(old, gated, *, reconnected=False):
    """Verify the predecessor's identity and functional bindings before release."""
    differences = {}

    def describe(path, before, after, key):
        change = {'before': type(before[key]).__name__ if key in before else 'absent',
                  'after': type(after[key]).__name__ if key in after else 'absent'}
        if isinstance(before.get(key), list) and isinstance(after.get(key), list):
            change['orderOnly'] = sorted(map(encoded, before[key])) == sorted(map(encoded, after[key]))
        differences[path] = change

    for key in ('Id', 'Image', 'Name', 'Path', 'Args', 'Config', 'HostConfig'):
        expected, actual = old[key], gated[key]
        if key == 'Config':
            expected, actual = without_mac(expected), without_mac(actual)
        if encoded(expected) == encoded(actual):
            continue
        if key in ('Config', 'HostConfig'):
            # These direct keys belong to the Engine schema. Stop before
            # user-controlled maps (labels, driver options, ports, etc.).
            for field in sorted(expected.keys() | actual.keys()):
                if (field not in expected or field not in actual or
                        encoded(expected[field]) != encoded(actual[field])):
                    describe(key + '.' + field, old[key], actual, field)
        else:
            describe(key, old, gated, key)
    if encoded(lifecycle.mounts(old)) != encoded(lifecycle.mounts(gated)):
        describe('Mounts', old, gated, 'Mounts')

    bindings = endpoint_matches(old, gated, reconnected=reconnected)
    for field, matches in bindings.items():
        if not matches:
            differences['NetworkSettings.' + field] = {'matchesOriginal': False}

    if differences:
        if 'HostConfig.NetworkMode' in differences:
            name, endpoint_before = next(iter(old['NetworkSettings']['Networks'].items()))
            for side, doc in [('before', old), ('after', gated)]:
                mode = doc['HostConfig'].get('NetworkMode')
                differences['HostConfig.NetworkMode'][side + 'MatchesName'] = mode == name
                differences['HostConfig.NetworkMode'][side + 'MatchesId'] = mode == endpoint_before['NetworkID']
        raise RestoredFrameChanged(differences)


class Runtime(lifecycle.Engine):
    def store(self):
        info = self.api('GET', '/info')
        if ['driver-type', 'io.containerd.snapshotter.v1'] in (info.get('DriverStatus') or []):
            return 'containerd'
        need(info['Driver'] == 'overlay2', 'UNQUALIFIED_IMAGE_STORE')
        return 'classic'

    def database(self, doc, pgid):
        need(re.fullmatch(HEX, pgid), 'POSTGRES_CID_REQUIRED')
        pg = self.inspect(pgid)
        need(pg['Id'] == pgid and pg['State']['Running'], 'POSTGRES_CHANGED')
        user, db = contract.db_binding(doc, pg, 'mcp', inventory)
        p = subprocess.run((*mcp.DOCKER, 'exec', '-i', pgid, 'psql', '-XwqAt', '-v', 'ON_ERROR_STOP=1',
                            '-h', '/var/run/postgresql', '-U', user, '-d', db),
                           input=SQL.encode(), capture_output=True, timeout=12)
        need(p.returncode == 0 and len(p.stdout) <= 32768, 'DATABASE_READ_FAILED')
        return json.loads(p.stdout)

    def process(self, doc, gated):
        pid = doc['State']['Pid']
        need(doc['State']['Running'] and pid > 0 and not doc['State']['Paused']
             and not doc['State']['Restarting'], 'PROCESS_NOT_RUNNING')
        proc = Path('/proc', str(pid))
        args = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        need(args == (ENTRY + APP if gated else APP), 'PROCESS_CHANGED')
        binary = lifecycle.file_sha(proc / 'root' / APP[0][1:])
        if gated:
            import signal
            mask = re.search(r'^SigCgt:\s*([0-9a-fA-F]+)$', (proc / 'status').read_text(), re.M)
            need(mask and int(mask[1], 16) & (1 << (signal.SIGUSR1 - 1)), 'GATE_TRAP_NOT_READY')
        else:
            need(lifecycle.file_sha(proc / 'exe') == binary, 'RUNNING_BINARY_CHANGED')
        env = inventory.environment(doc)
        bindings = {}
        for key in FILES:
            _, meta = contract.mount_file(doc, env[key])
            need(meta.get('sameAsHostSource'), 'MOUNTED_FILE_BINDING_CHANGED')
            st = (proc / 'root' / env[key][1:]).stat()
            bindings[key] = [meta, st.st_dev, st.st_ino, st.st_ctime_ns, st.st_size]
        return binary, digest(bindings)

    ready = staticmethod(mcp.readiness)

    def load(self, archive):
        p = subprocess.run((*mcp.DOCKER, 'load'), input=archive, capture_output=True, timeout=120)
        need(p.returncode == 0, 'IMAGE_IMPORT_FAILED')


def database_sha(value):
    rows = value['history']
    need(value['tables'] is True and isinstance(rows, list) and len(rows) == 14 and
         all(len(row) == 3 and row[0] == i and re.fullmatch(HEX, row[1]) and row[2]
             for i, row in enumerate(rows, 1)), 'EXACT_SCHEMA_14_REQUIRED')
    return digest(value)


def observe(rt, pgid):
    old = rt.inspect(SERVICE[1:])
    need(old['Name'] == SERVICE and re.fullmatch(HEX, old['Id']) and re.fullmatch(IMAGE, old['Image']),
         'EXPECTED_SERVICE_REQUIRED')
    need(old['Config']['Entrypoint'] == ENTRY and old['Config']['Cmd'] == APP
         and [old['Path'], *old['Args']] == ENTRY + APP, 'PREDECESSOR_RESTART_GATE_REQUIRED')
    need(len(old['NetworkSettings']['Networks']) == 1, 'SINGLE_BACKEND_REQUIRED')
    binary, bindings = rt.process(old, False)
    history = database_sha(rt.database(old, pgid))
    need(rt.ready(old), 'PREDECESSOR_NOT_READY')
    need(frame(old) == frame(rt.inspect(old['Id'])), 'FRAME_CHANGED_DURING_READ')
    return old, {'cid': old['Id'], 'imageId': old['Image'], 'frameSha256': digest(frame(old)),
                 'binarySha256': binary, 'bindingsSha256': bindings, 'postgresCid': pgid,
                 'databaseSha256': history, 'schema': 14, 'readyHttp': 204}


def image_config(rt, image_id):
    img = rt.api('GET', '/images/' + image_id + '/json')
    need(img['Id'] == image_id, 'IMAGE_ID_CHANGED')
    return img['Config']


def plan(rt, inputs, defaults):
    need(set(inputs) == {'candidate', 'snapshot', 'expectedOldImageId'}, 'INPUT_FIELDS_CHANGED')
    c, photo = inputs['candidate'], inputs['snapshot']
    check_candidate(c)
    old, actual = observe(rt, photo['postgresCid'])
    need(actual == photo, 'SNAPSHOT_CHANGED')
    need(old['Image'] == inputs['expectedOldImageId'], 'UNEXPECTED_PREDECESSOR_IMAGE')
    need(old['Image'] != c['imageId'], 'DISTINCT_CANDIDATE_REQUIRED')
    # Compare image-owned defaults that Docker can merge into CREATE. Inspect
    # also contains empty compatibility fields absent in an OCI config.
    original = image_config(rt, old['Image'])
    for key in (set(original) | set(defaults)) - {'MacAddress'}:
        a, b = original.get(key), defaults.get(key)
        if key == 'Labels':
            a, b = ({k: v for k, v in (labels or {}).items() if k not in (REVISION, SOURCE)}
                    for labels in (a, b))
        need(a == b or ((key not in original or key not in defaults) and not a and not b),
             'UNRELATED_IMAGE_DEFAULT_CHANGE')
    # The shared request builder indexes the legacy endpoint field. Supply its
    # optional input on a copy and strip both MAC fields before hashing or use.
    builder_input = copy.deepcopy(old)
    for endpoint in builder_input['NetworkSettings']['Networks'].values():
        endpoint.setdefault('MacAddress', None)
    req = mcp.request(builder_input, c['imageId'])
    req.pop('MacAddress', None)
    for endpoint in req['NetworkingConfig']['EndpointsConfig'].values():
        endpoint.pop('MacAddress', None)
    req['Labels'] = dict(old['Config'].get('Labels') or {}, **{REVISION: c['publisherCommit'], SOURCE: c['sourceCommit']})
    host = old['HostConfig']
    need(not host.get('PublishAllPorts') and all(str(binding.get('HostPort') or '').isdigit()
         and int(binding['HostPort']) > 0 for bindings in (host.get('PortBindings') or {}).values()
         for binding in (bindings or [])), 'DYNAMIC_HOST_PORT_UNSUPPORTED')
    net, ep = next(iter(old['NetworkSettings']['Networks'].items()))
    need(re.fullmatch('[a-zA-Z0-9_.-]+', net) and re.fullmatch(HEX, ep['NetworkID']), 'NETWORK_ID_REQUIRED')
    need(not ep.get('GwPriority'), 'UNSUPPORTED_GATEWAY_PRIORITY')
    ipam = ep.get('IPAMConfig') or {}
    need(all(not ipam.get(key) or ipam[key] == ep[field] for key, field in
             [('IPv4Address', 'IPAddress'), ('IPv6Address', 'GlobalIPv6Address')]), 'ENDPOINT_IPAM_CHANGED')
    original_frame = frame(old)
    body = {'version': 1, 'api': '1.44', 'inputs': inputs, 'requestSha256': digest(req),
            'controllerSha256': lifecycle.file_sha(__file__),
            'oldSectionSha256': {k: digest(original_frame[k]) for k in ('Config', 'HostConfig', 'Mounts', 'NetworkSettings')},
            'custodyTag': 'ouf-mcp-r033-custody:' + old['Id'],
            'retainedName': SERVICE + '-before-r033-' + old['Id'][:12],
            'isolatedName': SERVICE + '-failed-r033-' + old['Id'][:12]}
    vacant(rt, body)
    need(all(body['custodyTag'] not in (img.get('RepoTags') or [])
             for img in rt.api('GET', '/images/json?all=1')), 'CUSTODY_TAG_OCCUPIED')
    return old, req, body


def vacant(rt, body):
    names = {name for row in rt.api('GET', '/containers/json?all=1') for name in row['Names']}
    need(not names.intersection((body['retainedName'], body['isolatedName'])), 'CUSTODY_NAME_OCCUPIED')


def stopped_frame(old, doc, name):
    for key in ('Id', 'Image', 'Path', 'Args', 'HostConfig'):
        need(encoded(old[key]) == encoded(doc[key]), 'STOPPED_FRAME_CHANGED')
    need(doc['Name'] == name and encoded(without_mac(old['Config'])) == encoded(without_mac(doc['Config'])),
         'STOPPED_FRAME_CHANGED')
    need(encoded(lifecycle.mounts(old)) == encoded(lifecycle.mounts(doc)) and doc['State']['Pid'] == 0
         and doc['State']['Running'] is False and doc['State']['StartedAt'] == old['State']['StartedAt'],
         'STOPPED_BINDINGS_CHANGED')


def retained(old, actual, name):
    stopped_frame(old, actual, name)
    need(actual['NetworkSettings']['Networks'] == {}, 'RETAINED_ENDPOINT_PRESENT')


def stopped(old, doc):
    stopped_frame(old, doc, old['Name'])
    need(all(endpoint_matches(old, doc, active=False).values()), 'STOPPED_BINDINGS_CHANGED')


def endpoint_matches(old, doc, *, reconnected=False, active=True):
    net, prior = next(iter(old['NetworkSettings']['Networks'].items()))
    networks = doc['NetworkSettings']['Networks']
    actual = networks.get(net, {})
    aliases = set(prior.get('Aliases') or [])
    if reconnected:
        aliases.add(doc['Id'][:12])
    matches = {
        'Networks': set(networks) == {net},
        'Ports': doc['NetworkSettings'].get('Ports') == old['NetworkSettings'].get('Ports'),
        'NetworkID': actual.get('NetworkID') == prior['NetworkID'],
        'IPAddress': actual.get('IPAddress') == prior['IPAddress'],
        'Aliases': set(actual.get('Aliases') or []) == aliases,
    }
    ipam = prior.get('IPAMConfig')
    if reconnected:
        # CREATE and CONNECT explicitly request the original live addresses,
        # including when Docker originally assigned them dynamically.
        ipam = dict(ipam or {}, IPv4Address=prior['IPAddress'])
        if prior.get('GlobalIPv6Address'):
            ipam['IPv6Address'] = prior['GlobalIPv6Address']
    matches['IPAMConfig'] = actual.get('IPAMConfig') == ipam
    for field in ('GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'IPPrefixLen', 'Gateway', 'IPv6Gateway',
                  'Links', 'DriverOpts', 'GwPriority'):
        matches[field] = encoded(actual.get(field)) == encoded(prior.get(field))
    if prior.get('DNSNames') or actual.get('DNSNames'):
        names = set(prior.get('DNSNames') or [])
        if reconnected:
            names.add(doc['Id'][:12])
        matches['DNSNames'] = set(actual.get('DNSNames') or []) == names
    # Before START and after STOP, Engine can report cleared live allocations.
    # Check configured addresses and aliases even with no live endpoint.
    if not active and not actual.get('EndpointID') and not actual.get('IPAddress'):
        for field in ('NetworkID', 'IPAddress', 'GlobalIPv6Address', 'Gateway', 'IPv6Gateway'):
            if actual.get(field) == '':
                matches[field] = True
        for field in ('GlobalIPv6PrefixLen', 'IPPrefixLen'):
            if actual.get(field) == 0:
                matches[field] = True
        if not doc['NetworkSettings'].get('Ports'):
            matches['Ports'] = True
        if not actual.get('DNSNames'):
            matches['DNSNames'] = True
    # EndpointID identifies an attachment, so it can change across CONNECT.
    # The same-generation frame still compares it exactly.
    handled = matches.keys() | {'EndpointID', 'MacAddress'}
    matches['EndpointSettings'] = encoded({k: v for k, v in actual.items() if k not in handled}) == encoded(
        {k: v for k, v in prior.items() if k not in handled})
    return matches


def verify_new(old, req, doc, started, cid):
    need(doc['Id'] == cid and doc['Name'] == SERVICE and [doc['Path'], *doc['Args']] == ENTRY + APP,
         'CANDIDATE_IDENTITY_CHANGED')
    config = {k: v for k, v in req.items() if k not in ('HostConfig', 'NetworkingConfig')}
    need(encoded(without_mac(doc['Config'])) == encoded(config), 'REPLACEMENT_CONFIG_CHANGED')
    host = dict(req['HostConfig'])
    if started and old['HostConfig'].get('OomKillDisable') is None and host.get('OomKillDisable') is False:
        host['OomKillDisable'] = None
    need(doc['Image'] == req['Image'] and encoded(doc['HostConfig']) == encoded(host)
         and encoded(lifecycle.mounts(doc)) == encoded(lifecycle.mounts(old)), 'REPLACEMENT_IMAGE_HOST_MOUNTS_CHANGED')
    need(doc['State']['Running'] is started, 'REPLACEMENT_RUNNING_STATE_CHANGED')
    bindings = endpoint_matches(old, doc, reconnected=True, active=started)
    need(all(bindings.values()), 'ENDPOINT_BINDINGS_CHANGED')


def put(path, value):
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    sync_directory(path.parent)


def sync_directory(path):
    if os.name == 'posix':
        fd = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def effect(rt, journal, step, path, payload=None):
    put(journal / (step + '.intent'), {'action': step})
    result = rt.api('POST', path, payload)
    put(journal / (step + '.done'), result)
    return result


def release(rt, journal, doc, binary, photo):
    cid = doc['Id']
    for attempt in range(20):
        try:
            proof = rt.process(doc, True)
            break
        except RuntimeError as exc:
            if str(exc) != 'GATE_TRAP_NOT_READY' or attempt == 19:
                raise
            time.sleep(0.1)
    need(proof == (binary, photo['bindingsSha256']), 'GATED_BINARY_OR_BINDINGS_CHANGED')
    need(database_sha(rt.database(doc, photo['postgresCid'])) == photo['databaseSha256'], 'DATABASE_CHANGED')
    need(frame(doc) == frame(rt.inspect(cid)), 'GATE_FRAME_CHANGED')
    effect(rt, journal, 'release', '/containers/' + cid + '/kill?signal=USR1')
    for _ in range(60):
        live = rt.inspect(cid)
        need(live['State']['Running'] and live['State']['StartedAt'] == doc['State']['StartedAt'],
             'SERVER_GENERATION_CHANGED')
        if rt.ready(live):
            need(rt.process(live, False) == (binary, photo['bindingsSha256']), 'SERVER_BINARY_OR_BINDINGS_CHANGED')
            need(database_sha(rt.database(live, photo['postgresCid'])) == photo['databaseSha256'], 'DATABASE_CHANGED')
            need(frame(live) == frame(rt.inspect(cid)), 'FRAME_CHANGED_DURING_ACCEPTANCE')
            return live
        time.sleep(1)
    raise RuntimeError('READINESS_TIMEOUT')


def apply(rt, state, inputs, archive, defaults, approved):
    old, req, body = plan(rt, inputs, defaults)
    need(digest(body) == approved, 'PLAN_CHANGED')
    need(sha(archive) == inputs['candidate']['archiveSha256'], 'ARCHIVE_CHANGED')
    cid = old['Id']
    journal = state / ('attempt-' + cid)
    journal.mkdir(mode=0o700)
    sync_directory(state)
    put(journal / 'plan.json', body)
    put(journal / 'old.private.json', old)
    put(journal / 'request.private.json', req)
    c = inputs['candidate']
    effect(rt, journal, 'protect-image', '/images/' + old['Image'] + '/tag?repo=ouf-mcp-r033-custody&tag=' + cid)
    need(rt.api('GET', '/images/' + body['custodyTag'] + '/json')['Id'] == old['Image'], 'PREDECESSOR_IMAGE_LOST')
    put(journal / 'load.intent', {'archiveSha256': sha(archive)})
    rt.load(archive)
    need(rt.api('GET', '/images/ouf-mcp:ci/json')['Id'] == req['Image'], 'LOADED_TAG_ID_CHANGED')
    need(rt.api('GET', '/images/' + body['custodyTag'] + '/json')['Id'] == old['Image'], 'PREDECESSOR_IMAGE_LOST')
    image_config(rt, req['Image'])
    put(journal / 'load.done', {'imageId': req['Image']})
    vacant(rt, body)
    _, fresh = observe(rt, inputs['snapshot']['postgresCid'])
    need(fresh == inputs['snapshot'], 'PRE_STOP_FRAME_CHANGED')
    effect(rt, journal, 'stop', '/containers/' + cid + '/stop?t=20')
    stopped(old, rt.inspect(cid))
    net = next(iter(old['NetworkSettings']['Networks'].values()))['NetworkID']
    effect(rt, journal, 'detach', '/networks/' + net + '/disconnect', {'Container': cid, 'Force': False})
    retained(old, rt.inspect(cid), SERVICE)
    effect(rt, journal, 'retain', '/containers/' + cid + '/rename?name=' + body['retainedName'][1:])
    retained(old, rt.inspect(cid), body['retainedName'])
    new = effect(rt, journal, 'create', '/containers/create?name=ouf-mcp', req)['Id']
    need(re.fullmatch(HEX, new) and new != cid, 'INVALID_CREATED_ID')
    verify_new(old, req, rt.inspect(new), False, new)
    effect(rt, journal, 'start', '/containers/' + new + '/start')
    gated = rt.inspect(new)
    verify_new(old, req, gated, True, new)
    put(journal / 'gated.private.json', gated)
    live = release(rt, journal, gated, c['binarySha256'], fresh)
    need(frame(live) == frame(gated), 'CANDIDATE_FRAME_CHANGED_AFTER_RELEASE')
    verify_new(old, req, live, True, new)
    retained(old, rt.inspect(cid), body['retainedName'])
    receipt = {'status': 'READY', 'planSha256': approved, 'candidate': c, 'cid': new, 'imageId': live['Image'],
               'binarySha256': c['binarySha256'], 'retainedCid': cid, 'schema': 14, 'readyHttp': 204,
               'databaseSha256': fresh['databaseSha256'], 'bindingsSha256': fresh['bindingsSha256']}
    put(journal / 'receipt.json', receipt)
    return receipt


def read(path):
    return json.loads(path.read_bytes())


def rollback(rt, journal, approved):
    body = read(journal / 'plan.json')
    need(digest(body) == approved and (journal / 'stop.intent').exists(), 'APPLIED_PLAN_REQUIRED')
    need(body['controllerSha256'] == lifecycle.file_sha(__file__), 'CONTROLLER_CHANGED')
    photo = body['inputs']['snapshot']
    old = read(journal / 'old.private.json')
    req = read(journal / 'request.private.json')
    cid = old['Id']
    need(digest(frame(old)) == photo['frameSha256'] and digest(req) == body['requestSha256']
         and cid == photo['cid'], 'PRIVATE_JOURNAL_CHANGED')
    current = rt.inspect(cid)
    net, ep = next(iter(old['NetworkSettings']['Networks'].items()))
    attached = bool(current['NetworkSettings']['Networks'])
    if attached:
        stopped(old, current)
    else:
        need((journal / 'detach.intent').exists() and current['Name'] in (SERVICE, body['retainedName']),
             'RETAINED_PHASE_CHANGED')
        retained(old, current, current['Name'])
    new = None
    if (journal / 'create.intent').exists():
        # Lost CREATE response is ambiguous. Never adopt a container by name.
        need((journal / 'create.done').exists(), 'RECONCILE_CREATE_OUTCOME')
        new = read(journal / 'create.done')['Id']
        candidate = rt.inspect(new)
        need(current['Name'] == body['retainedName'] and not attached and candidate['Name'] == SERVICE
             and candidate['Id'] == new and candidate['Image'] == req['Image'] and cid != new,
             'IMMEDIATE_SUCCESSOR_REQUIRED')
        need(rt.inspect('ouf-mcp')['Id'] == new, 'SERVICE_OWNER_CHANGED')
        if (journal / 'gated.private.json').exists():
            generation = read(journal / 'gated.private.json')
            need(candidate['State']['StartedAt'] == generation['State']['StartedAt'], 'SUCCESSOR_GENERATION_CHANGED')
            if candidate['State']['Running']:
                verify_new(old, req, candidate, True, new)
            else:
                stopped(generation, candidate)
        else:
            need(not candidate['State']['Running'] and not (journal / 'start.intent').exists(),
                 'RECONCILE_GATE_START')
            verify_new(old, req, candidate, False, new)

    need(database_sha(rt.database(old, photo['postgresCid'])) == photo['databaseSha256'], 'DATABASE_CHANGED')
    rb = journal / 'rollback'
    rb.mkdir(mode=0o700)
    sync_directory(journal)
    if new:
        if candidate['State']['Running']:
            effect(rt, rb, 'stop', '/containers/' + new + '/stop?t=20')
            stopped(candidate, rt.inspect(new))
        effect(rt, rb, 'detach', '/networks/' + ep['NetworkID'] + '/disconnect', {'Container': new, 'Force': False})
        effect(rt, rb, 'isolate', '/containers/' + new + '/rename?name=' + body['isolatedName'][1:])
        isolated = rt.inspect(new)
        need(isolated['Id'] == new and isolated['Name'] == body['isolatedName']
             and isolated['State']['Pid'] == 0 and not isolated['State']['Running']
             and isolated['NetworkSettings']['Networks'] == {}, 'CANDIDATE_NOT_ISOLATED')
    if current['Name'] != SERVICE:
        effect(rt, rb, 'restore-name', '/containers/' + cid + '/rename?name=ouf-mcp')
    if not attached:
        retained(old, rt.inspect(cid), SERVICE)
        effect(rt, rb, 'connect', '/networks/' + ep['NetworkID'] + '/connect',
               {'Container': cid, 'EndpointConfig': req['NetworkingConfig']['EndpointsConfig'][net]})
    effect(rt, rb, 'start', '/containers/' + cid + '/start')
    gated = rt.inspect(cid)
    verify_restored_frame(old, gated, reconnected=not attached)
    live = release(rt, rb, gated, photo['binarySha256'], photo)
    need(frame(live) == frame(gated), 'RESTORED_FRAME_CHANGED_AFTER_RELEASE')
    receipt = {'status': 'ROLLED_BACK', 'planSha256': approved, 'cid': cid, 'imageId': live['Image'],
               'binarySha256': photo['binarySha256'], 'isolatedCid': new, 'schema': 14, 'readyHttp': 204,
               'databaseSha256': photo['databaseSha256'], 'bindingsSha256': photo['bindingsSha256']}
    put(rb / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    sub.add_parser('snapshot').add_argument('postgres_cid')
    sub.add_parser('plan')
    for name in ('apply', 'rollback'):
        sub.add_parser(name).add_argument('plan_sha256')
    args = parser.parse_args()
    need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
    import fcntl
    os.environ['DOCKER_API_VERSION'] = '1.44'
    os.umask(0o077)
    rt = Runtime()
    # Lock the shared state directory across every plan/CID, including rollback.
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.mode == 'snapshot':
            return observe(rt, args.postgres_cid)[1]
        if args.mode != 'plan':
            need(re.fullmatch(HEX, args.plan_sha256), 'PLAN_DIGEST_REQUIRED')
        if args.mode == 'rollback':
            matches = [p.parent for p in STATE.glob('attempt-*/plan.json') if digest(read(p)) == args.plan_sha256]
            need(len(matches) == 1, 'EXACTLY_ONE_JOURNAL_REQUIRED')
            return rollback(rt, matches[0], args.plan_sha256)
        inputs = read(STATE / 'inputs.json')
        check_candidate(inputs['candidate'])
        archive, defaults = package(STATE / ('candidate-' + str(inputs['candidate']['artifactId']) + '.zip'),
                                    inputs['candidate'], rt.store())
        if args.mode == 'plan':
            _, _, body = plan(rt, inputs, defaults)
            return {'status': 'PLANNED', 'planSha256': digest(body), 'plan': body}
        return apply(rt, STATE, inputs, archive, defaults, args.plan_sha256)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True), flush=True)
    except Exception as exc:
        reason = str(exc)
        print(json.dumps({'status': 'HELD', 'reason': reason if re.fullmatch('[A-Z0-9_]+', reason)
                          else type(exc).__name__}), flush=True)
        sys.exit(1)
