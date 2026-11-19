#!/usr/bin/env python3
"""Inspect current Semantic policy binding and make one authenticated policy GET.

Uses the pinned runtime helper only for read-only retained configuration checks.
No token issuance, receipt signing, policy installation or business request.
"""
import base64
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import signal
import ssl
import stat
import time
from urllib.parse import urlsplit

RUNTIME_SHA = 'b3acd99dd437ebb454a5ba5550dd20fe222f3b1dc9de839627af21dabe77563b'
POLICY_PATH = '/internal/capabilities/v1/authorization/policy-bundle/active'
POLICY61_HASH = '47e7ae3cbfddbeb5f98f3be35774d6db861d026550b2b2bdf72d77d0ae142fca'
FIELDS = ('ouf.authorization.registry-url', 'ouf.authorization.registry-token-file',
          'ouf.authorization.bundle-file', 'ouf.authorization.bundle-version',
          'ouf.authorization.refresh-seconds', 'ouf.authorization.max-staleness-seconds',
          'ouf.semantic.delegation.key-file', 'ouf.semantic.delegation.workload',
          'ouf.iam.issuer', 'ouf.iam.audience')

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_KEY')
        result[key] = value
    return result

def canonical(key):
    return re.sub('[._-]', '', key).lower()

def declarations(doc):
    env = unique(row.split('=', 1) for row in doc['Config'].get('Env') or [])
    found = {key: [] for key in FIELDS}
    def add(key, value, origin):
        for target in FIELDS:
            if canonical(key) == canonical(target):
                need(isinstance(value, (str, int)) and not isinstance(value, bool), 'PROPERTY_SHAPE_INVALID')
                found[target].append((str(value), origin))
    for key, value in env.items():
        add(key, value, 'ENV')
    def flatten(value, prefix=''):
        need(isinstance(value, dict), 'SPRING_JSON_OBJECT_REQUIRED')
        for key, child in value.items():
            name = prefix + key
            if isinstance(child, dict):
                flatten(child, name + '.')
            elif child is not None:
                add(name, child, 'SPRING_APPLICATION_JSON')
    if env.get('SPRING_APPLICATION_JSON'):
        need(len(env['SPRING_APPLICATION_JSON']) <= 1024*1024, 'SPRING_JSON_TOO_LARGE')
        flatten(json.loads(env['SPRING_APPLICATION_JSON'], object_pairs_hook=unique))
    args = list(doc['Config'].get('Entrypoint') or []) + list(doc['Config'].get('Cmd') or [])
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'JAVA_OPTS'):
        args.extend(shlex.split(env.get(key, '')))
    for arg in args:
        if arg.startswith(('-D', '--')) and '=' in arg:
            key, value = arg[2:].split('=', 1)
            add(key, value, 'DECLARED_ARGUMENT')
    # Do not guess precedence when declarations conflict.
    need(all(len({value for value, _ in rows}) <= 1 for rows in found.values()),
         'CONFLICTING_SELECTED_PROPERTY_DECLARATIONS')
    values = {key: rows[0][0] if rows else None for key, rows in found.items()}
    summary = {'scope': 'DECLARATIONS_NOT_EFFECTIVE_SPRING_CONFIGURATION',
               'declaredProperties': {key: sorted({origin for _, origin in rows})
                                      for key, rows in found.items() if rows},
               'springConfigImportPresent': bool(env.get('SPRING_CONFIG_IMPORT')),
               'externalConfigLocationPresent': any(env.get(k) for k in
                   ('SPRING_CONFIG_LOCATION', 'SPRING_CONFIG_ADDITIONAL_LOCATION')),
               'staticBundleFileDeclared': bool(values['ouf.authorization.bundle-file']),
               'runtimeLoadedPolicyRead': False}
    for name in ('bundle-version', 'refresh-seconds', 'max-staleness-seconds'):
        value = values['ouf.authorization.' + name]
        if value is not None:
            need(re.fullmatch('[0-9]{1,10}', value), 'SELECTED_NUMBER_INVALID')
            summary[name] = int(value)
    summary['delegationKeyFileDeclared'] = bool(values['ouf.semantic.delegation.key-file'])
    summary['delegationWorkloadDeclared'] = bool(values['ouf.semantic.delegation.workload'])
    summary['iamIssuerAndAudienceDeclared'] = bool(values['ouf.iam.issuer'] and values['ouf.iam.audience'])
    return values, summary

def mounted_read(doc, target, maximum):
    need(isinstance(target, str) and re.fullmatch('/[A-Za-z0-9_./-]+', target)
         and str(Path(target)) == target and '..' not in Path(target).parts,
         'EXACT_MOUNTED_FILE_PATH_REQUIRED')
    mounts = [m for m in doc['Mounts'] if target == m['Destination'] or
              target.startswith(m['Destination'].rstrip('/') + '/')]
    mounts.sort(key=lambda m: len(m['Destination']), reverse=True)
    need(mounts and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is False,
         'READ_ONLY_BIND_REQUIRED')
    mount = mounts[0]
    descriptors = []
    try:
        parent = os.open('/proc/' + str(doc['State']['Pid']) + '/root', os.O_PATH | os.O_DIRECTORY)
        descriptors.append(parent)
        parts = Path(target).parts[1:]
        for part in parts[:-1]:
            parent = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        frame = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and frame(before) == frame(after)
             == frame(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)), 'MOUNTED_FILE_CHANGED')
        host_path = mount['Source'] + target[len(mount['Destination']):]
        try:
            host = os.stat(host_path, follow_symlinks=False)
            same = (host.st_dev, host.st_ino) == (before.st_dev, before.st_ino)
        except FileNotFoundError:
            same = False
        return raw, {'readOnlyMount': True, 'readFromApplicationMountView': True,
                     'sameFileAsCurrentHostSource': same, 'uid': before.st_uid,
                     'gid': before.st_gid, 'modeOctal': format(stat.S_IMODE(before.st_mode), '04o')}
    finally:
        for fd in reversed(descriptors):
            os.close(fd)

def token_metadata(raw, now):
    token = raw.decode('ascii').strip()
    need(len(token) <= 16384 and re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token),
         'JWT_TOKEN_SHAPE_INVALID')
    payload = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)), object_pairs_hook=unique)
    exp = claims.get('exp')
    need(type(exp) is int and 0 <= exp <= 253402300799, 'JWT_EXPIRY_REQUIRED')
    nbf = claims.get('nbf')
    need(nbf is None or type(nbf) is int, 'JWT_NOT_BEFORE_INVALID')
    return token, {'expiredAtRead': now >= exp, 'expiryEpoch': exp,
                   'expiryUtc': datetime.datetime.fromtimestamp(exp, datetime.timezone.utc).isoformat(),
                   'notYetValidAtRead': nbf is not None and now < nbf,
                   'signatureVerifiedLocally': False, 'claimsAreMetadataOnly': True}

def endpoint(value):
    need(isinstance(value, str) and len(value) <= 2048, 'POLICY_URL_REQUIRED')
    url = urlsplit(value)
    need(url.scheme == 'https' and url.hostname and not url.username and not url.password
         and not url.query and not url.fragment and url.path == POLICY_PATH
         and url.port in (None, 443), 'EXPECTED_HTTPS_POLICY_ENDPOINT_REQUIRED')
    return url

def policy_summary(status, raw):
    result = {'httpStatus': status, 'activePolicyResponseRead': False,
              'hostTransportOnly': True, 'applicationJvmTransportTested': False,
              'applicationLoadedPolicyProven': False, 'policyInstalledByReader': False}
    if status != 200:
        return result
    doc = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(doc, dict) and set(doc) <= {'bundleId', 'bundleVersion', 'activatedAt', 'bundle', 'contentHash'},
         'ACTIVE_POLICY_ENVELOPE_INVALID')
    bundle = doc['bundle']
    need(isinstance(bundle, dict) and type(doc['bundleVersion']) is int, 'ACTIVE_BUNDLE_INVALID')
    caps, grants = bundle['capabilities'], bundle['grants']
    need(isinstance(caps, list) and isinstance(grants, list) and len(caps) <= 10000 and len(grants) <= 10000,
         'ACTIVE_POLICY_CARDINALITY_LIMIT')
    result.update(activePolicyResponseRead=True, bundleVersion=doc['bundleVersion'],
                  bundleIsOufLabAuthorization=doc['bundleId'] == 'ouf-lab-authorization',
                  returnedHashMatchesObservedPolicy61=doc['contentHash'] == POLICY61_HASH,
                  semanticSearchDeclared=any(c.get('capabilityId') == 'ouf.semantic.search' for c in caps),
                  configuredSemanticSearchGrantCount=sum(g.get('capabilityId') == 'ouf.semantic.search' for g in grants))
    return result

def policy_get(url, token):
    conn = http.client.HTTPSConnection(url.hostname, 443, timeout=8, context=ssl.create_default_context())
    try:
        conn.request('GET', url.path, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        response = conn.getresponse()
        if response.status != 200:
            return policy_summary(response.status, b'')
        raw = response.read(5*1024*1024 + 65537)
        need(len(raw) <= 5*1024*1024 + 65536, 'POLICY_RESPONSE_LIMIT')
        return policy_summary(response.status, raw)
    finally:
        conn.close()

def runtime_helper():
    supplied = globals().get('RUNTIME_READER')
    if supplied is not None:
        return supplied
    raw = Path(__file__).with_name('ouf-runtime-20261107.py').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == RUNTIME_SHA, 'RUNTIME_HELPER_HASH_MISMATCH')
    namespace = {'__name__': 'retained_runtime_reader'}
    exec(compile(raw, 'retained_runtime_reader', 'exec'), namespace)
    return namespace

def execute(report, runtime):
    checks = {}
    bound, docs = runtime['retained_semantic'](checks)
    doc = docs[bound['semantic']]
    report['retainedConfigurationVerified'] = checks['semanticConfigurationCheck']['matches']
    report['otherRoleConfigurationMismatches'] = checks['retainedConfigurationMismatches']
    report['process'] = runtime['semantic_process'](doc)['processKind']
    need(report['process'] == 'APPLICATION_RUNNING', 'SEMANTIC_JAVA_REQUIRED')
    values, report['configuration'] = declarations(doc)
    url = endpoint(values['ouf.authorization.registry-url'])
    token_file = values['ouf.authorization.registry-token-file']
    need(token_file, 'EXPLICIT_REGISTRY_TOKEN_FILE_REQUIRED')
    raw, report['tokenMount'] = mounted_read(doc, token_file, 65536)
    token, report['tokenMetadata'] = token_metadata(raw, time.time())
    key_file = values['ouf.semantic.delegation.key-file']
    if key_file:
        key, report['delegationKeyMount'] = mounted_read(doc, key_file, 4096)
        report['delegationKeyFormatValid'] = bool(re.fullmatch(b'[0-9a-fA-F]{64}', key.strip()))
    report['receiptVerificationTested'] = False
    report['policyGetAttempts'] = 1
    try:
        report['policyGet'] = policy_get(url, token)
    except (OSError, http.client.HTTPException) as exc:
        report['policyGet'] = {'completed': False, 'errorClass': type(exc).__name__,
                               'hostTransportOnly': True, 'applicationJvmTransportTested': False}
    after = runtime['inspect'](doc['Id'])[doc['Id']]
    same = all(after[key] == doc[key] for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings'))
    same = same and all(after['State'][key] == doc['State'][key] for key in ('Pid', 'StartedAt', 'Running', 'Restarting'))
    need(same, 'SEMANTIC_RUNTIME_CHANGED_DURING_READ')
    report.update(status='SEMANTIC_POLICY_READ_COMPLETE', runtimeUnchangedDuringRead=True)

def main():
    report = {'schema': 'ouf.current-semantic-policy-read.v1', 'status': 'READ_INCOMPLETE',
              'credentialValuesEmitted': False, 'serviceConfigurationChanged': False,
              'serviceStops': 0, 'tokenRequests': 0, 'permissionChanges': 0,
              'databaseQueriesIssuedByScript': 0, 'businessRequestsIssued': 0, 's3Requests': 0,
              'policyGetAttempts': 0, 'applicationLoadedPolicyProven': False}
    signal.alarm(90)
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        with open('/run/lock/ouf-runtime-e2e.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            execute(report, runtime_helper())
    except Exception as exc:
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,120}', str(exc)) else type(exc).__name__
    report['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'SEMANTIC_POLICY_READ_COMPLETE' else 1

if __name__ == '__main__':
    raise SystemExit(main())
