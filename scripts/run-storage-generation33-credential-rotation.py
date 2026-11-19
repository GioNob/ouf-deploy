#!/usr/bin/env python3
"""Public fixture S3 keys: old -> overlap -> new -> restart, on exact OCI33.

Controlled gateway replacements, stable TLS/policy/data. No target credentials,
hot reload, zero downtime or production secret-custody qualification.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from urllib.parse import quote, urlencode
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location('credential_tls33', ROOT / 'scripts/run-storage-generation33-tls-rotation.py')
tls_rotation = importlib.util.module_from_spec(spec); spec.loader.exec_module(tls_rotation)
labs, require, binding = tls_rotation.labs, tls_rotation.require, tls_rotation.binding
LOCK_SHA, COHORT_SHA = tls_rotation.LOCK_SHA, tls_rotation.COHORT_SHA
COHORT_ARTIFACT_ID = tls_rotation.COHORT_ARTIFACT_ID
COHORT_ARCHIVE_SHA, COHORT_ARCHIVE_BYTES = tls_rotation.COHORT_ARCHIVE_SHA, tls_rotation.COHORT_ARCHIVE_BYTES
NEW = ('ouf-fixture-prefix-next', 'public-next-prefix-fixture-not-production')
KEY = 'staging/credential-rotation.bin'
NEW_KEY = 'staging/new-credential-proof.bin'
BODY = b'OUF unchanged object across credential rotation\x00\xff\n'
NEW_BODY = b'OUF one write with the new fixture key\x00\xff\n'
MIME = 'application/octet-stream'
STAGES = ('old', 'overlap', 'new', 'restarted')
NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}


def sha(raw): return hashlib.sha256(raw).hexdigest()


def config_for(module, stage):
    require(stage in STAGES, 'KNOWN_CREDENTIAL_STAGE_REQUIRED')
    result = module.fixture_config()
    keys = [module.APP] if stage == 'old' else [module.APP, NEW] if stage == 'overlap' else [NEW]
    result['identities'][1]['credentials'] = [{'accessKey': k, 'secretKey': s} for k, s in keys]
    return result


def expected_objects(stage):
    return {KEY: BODY, **({NEW_KEY: NEW_BODY} if stage in ('new', 'restarted') else {})}


def request(module, tls, credentials, method, key='', body=b'', query=None):
    require(method in ('GET', 'HEAD', 'PUT', 'DELETE'), 'BOUNDED_METHOD_REQUIRED')
    path = '/' + module.BUCKET + ('/' + quote(key, safe='/~') if key else '')
    query = urlencode(sorted((query or {}).items()), quote_via=quote, safe='~')
    context = ssl.create_default_context(cafile=str(tls / 'ca.pem'))
    connection = http.client.HTTPSConnection('localhost', 18333, timeout=10, context=context)
    try:
        connection.connect()
        peer = sha(connection.sock.getpeercert(binary_form=True))
        expected = sha(ssl.PEM_cert_to_DER_cert((tls / 'server.pem').read_text()))
        require(peer == expected, 'UNCHANGED_TLS_IDENTITY_REQUIRED')
        headers = module.signed_headers(method, path, query, body, credentials)
        headers['content-type'] = MIME
        connection.request(method, path + ('?' + query if query else ''), body=body, headers=headers)
        response = connection.getresponse(); payload = response.read(16385)
        require(len(payload) <= 16384, 'BOUNDED_RESPONSE_REQUIRED')
        return {'status': response.status, 'body': payload,
                'headers': {k.lower(): v for k, v in response.getheaders()}, 'peerSha256': peer}
    finally:
        connection.close()


def read_objects(module, tls, credentials, bodies, requester=request):
    listing = requester(module, tls, credentials, 'GET', query={'list-type': '2', 'prefix': 'staging/', 'max-keys': '3'})
    require(listing['status'] == 200, 'LIST_SUCCESS_REQUIRED')
    tree = ET.fromstring(listing['body'])
    require(tree.tag == '{' + NS['s'] + '}ListBucketResult'
            and tree.findtext('s:IsTruncated', namespaces=NS) == 'false'
            and tree.find('s:NextContinuationToken', NS) is None
            and sorted(x.text for x in tree.findall('s:Contents/s:Key', NS)) == sorted(bodies),
            'EXACT_COMPLETE_OBJECT_LIST_REQUIRED')
    result = {}
    for key, body in sorted(bodies.items()):
        for method in ('GET', 'HEAD'):
            response = requester(module, tls, credentials, method, key)
            require(response['status'] == 200 and response['body'] == (body if method == 'GET' else b''),
                    'EXACT_OBJECT_BODY_REQUIRED')
            require(response['headers'].get('content-length') == str(len(body))
                    and response['headers'].get('content-type') == MIME, 'EXACT_OBJECT_METADATA_REQUIRED')
            require(response['peerSha256'] == listing['peerSha256'], 'STABLE_TLS_PEER_REQUIRED')
        result[key] = {'sha256': sha(body), 'bytes': len(body), 'mime': MIME}
    return {'objects': result, 'listedKeys': sorted(bodies), 'peerSha256': listing['peerSha256']}


def denial(module, tls, credentials, method, key, code, requester=request, **kwargs):
    response = requester(module, tls, credentials, method, key, **kwargs)
    require(response['status'] == 403, 'EXPLICIT_403_REQUIRED')
    if method == 'HEAD':
        require(response['body'] == b'' and code is None, 'HEAD_STATUS_ONLY_REQUIRED')
    else:
        require(ET.fromstring(response['body']).findtext('Code') == code, 'EXACT_S3_DENIAL_CODE_REQUIRED')
    return {'method': method, 'key': key, 'status': 403, 'code': code,
            'peerSha256': response['peerSha256'], 'attempts': 1}


def verify_stage(module, tls, stage, requester=request):
    require(stage in STAGES, 'KNOWN_CREDENTIAL_STAGE_REQUIRED')
    reads = {}; denied = []; writes = 0
    old, new = module.APP, NEW
    if stage == 'new':
        before = read_objects(module, tls, new, {KEY: BODY}, requester)
    else:
        before = None
    if stage in ('new', 'restarted'):
        for method, key, extra in [('GET', KEY, {}), ('HEAD', KEY, {}),
                ('GET', '', {'query': {'list-type': '2', 'prefix': 'staging/'}}),
                ('PUT', KEY, {'body': b'forbidden overwrite'}),
                ('PUT', 'staging/retired-key-must-not-create.bin', {'body': b'forbidden new object'}),
                ('DELETE', KEY, {})]:
            denied.append({'identity': 'retired', **denial(module, tls, old, method, key,
                None if method == 'HEAD' else 'InvalidAccessKeyId', requester, **extra)})
        for method, key in [('PUT', 'outside-prefix.bin'), ('DELETE', KEY)]:
            denied.append({'identity': 'new-scope', **denial(module, tls, new, method, key,
                'AccessDenied', requester, **({'body': b'forbidden scope'} if method == 'PUT' else {}))})
        denied.append({'identity': 'new-wrong-secret', **denial(module, tls, (new[0], 'public-wrong-fixture-secret'),
            'GET', KEY, 'SignatureDoesNotMatch', requester)})
        if stage == 'new':
            response = requester(module, tls, new, 'PUT', NEW_KEY, body=NEW_BODY)
            require(response['status'] == 200, 'NEW_KEY_SINGLE_PUT_REQUIRED'); writes = 1
        reads['new'] = read_objects(module, tls, new, expected_objects(stage), requester)
    else:
        reads['old'] = read_objects(module, tls, old, {KEY: BODY}, requester)
        if stage == 'overlap': reads['new'] = read_objects(module, tls, new, {KEY: BODY}, requester)
        else:
            denied.append({'identity': 'not-yet-issued', **denial(module, tls, new, 'GET', KEY,
                'InvalidAccessKeyId', requester)})
    peer = next(iter(reads.values()))['peerSha256']
    require(all(x['peerSha256'] == peer for x in [*reads.values(), *denied])
            and (before is None or before['peerSha256'] == peer), 'STABLE_TLS_PEER_REQUIRED')
    return {'stage': stage, 'reads': reads, 'beforeWriteRead': before, 'denied': denied,
            'successfulObjectPuts': writes, 'mutatingRequestRetries': 0}


def client(module, config, action):
    if action == 'ready': return module.client('ready', config / 'tls')
    require(action in STAGES, 'KNOWN_CREDENTIAL_STAGE_REQUIRED')
    if action == 'old':
        for credentials, key, body in [(module.OWNER, '', b''), (module.APP, KEY, BODY)]:
            require(request(module, config / 'tls', credentials, 'PUT', key, body)['status'] == 200,
                    'ONE_TIME_SEED_REQUIRED')
    result = verify_stage(module, config / 'tls', action)
    if action == 'old': result['successfulObjectPuts'] = 1; result['bucketCreates'] = 1
    return result


def replacement_argv(lab, image_id, stage):
    require(stage in ('overlap', 'new', 'restarted'), 'REPLACEMENT_STAGE_REQUIRED')
    args = tls_rotation.replacement_argv(lab, image_id)
    return [lab.prefix + '-s3-' + stage if value == lab.prefix + '-s3-next' else
            value.replace('/config/tls-next/', '/config/tls/') for value in args]


def validate_replacement(before, after, lab, image_id):
    require(len(before) == len(after) == 4
            and [x['Id'] for x in before[:-1]] == [x['Id'] for x in after[:-1]], 'RETAINED_STORAGE_IDS_REQUIRED')
    require(before[-1]['Id'] != after[-1]['Id'] and len({x['Id'] for x in before + after}) == 5,
            'DISTINCT_GATEWAY_REQUIRED')
    require(all(a['State']['StartedAt'] == b['State']['StartedAt'] and a['RestartCount'] == b['RestartCount'] == 0
                for a, b in zip(before[:-1], after[:-1])), 'STORAGE_MUST_NOT_RESTART')
    require(all(x['State']['Running'] and not x['State']['OOMKilled'] and x['Image'] == image_id for x in after),
            'LIVE_EXACT_IMAGE_REQUIRED')
    item = after[-1]; host = item['HostConfig']; mounts = {m['Destination']: m for m in item['Mounts']}
    require(item['Config']['User'] == '65532:65532' and host['ReadonlyRootfs'] and host['CapDrop'] == ['ALL']
            and not host['PortBindings'] and host['NetworkMode'] in
            {'container:' + after[0]['Id'], 'container:' + lab.prefix + '-master'}, 'GATEWAY_ISOLATION_REQUIRED')
    require(mounts['/data']['Source'] == str(lab.data / 's3') and mounts['/config']['Source'] == str(lab.data / 'config')
            and mounts['/config']['RW'] is False, 'EXACT_EXISTING_ROOTS_REQUIRED')
    for flag in ('-config=/config/s3.json', '-key.file=/config/tls/server.key', '-cert.file=/config/tls/server.pem'):
        require(flag in item['Config']['Cmd'], 'UNCHANGED_TLS_AND_CONFIG_PATH_REQUIRED')


def replace_gateway(module, lab, old_name, stage):
    retained = [lab.prefix + '-' + role for role in ('master', 'volume', 'filer')]
    before = json.loads(module.command(['docker', 'inspect', *retained, old_name]))
    require(len(before) == 4 and all(x['State']['Running'] for x in before), 'FOUR_LIVE_ROLES_REQUIRED')
    module.write_json(lab.evidence / (stage + '-before-containers.json'), before)
    module.command(['docker', 'stop', '--time', '30', old_name], timeout=40)
    old = json.loads(module.command(['docker', 'inspect', old_name]))[0]
    module.write_json(lab.evidence / (stage + '-retired-gateway.json'), old)
    require(old['Id'] == before[-1]['Id'] and not old['State']['Running'] and old['State']['ExitCode'] == 0
            and not old['State']['OOMKilled'], 'OLD_GATEWAY_CLEAN_STOP_REQUIRED')
    log = subprocess.run(['docker', 'logs', old_name], check=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, timeout=30)
    (lab.evidence / (stage + '-retired-gateway.log')).write_bytes(log.stdout)
    module.command(['docker', 'rm', old_name]); lab.names.remove(old_name)
    config = lab.data / 'config/s3.json'
    module.command(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', str(config)])
    module.write_json(config, config_for(module, stage))
    module.command(['sudo', '-n', 'chown', '65532:65532', str(config)])
    # Public fixture credentials only; actual loaded config retained for readback.
    (lab.evidence / (stage + '-fixture-config.json')).write_bytes(config.read_bytes())
    module.command(replacement_argv(lab, module.cold.IMAGE_ID, stage))
    new_name = lab.prefix + '-s3-' + stage; lab.names.append(new_name)
    after = json.loads(module.command(['docker', 'inspect', *retained, new_name]))
    validate_replacement(before, after, lab, module.cold.IMAGE_ID)
    module.write_json(lab.evidence / (stage + '-after-containers.json'), after)
    lab.client('ready', stage + '-ready')
    return new_name


def run(archive, work, receipt):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() != 0, 'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not work.exists() and not work.is_symlink(), 'FRESH_WORK_REQUIRED')
    bound = binding(receipt); module = tls_rotation.configure(bound); cold = module.cold
    work.mkdir(parents=True); evidence = work / 'evidence'; evidence.mkdir(); lab = None
    class CredentialLab(module.Lab):
        def client(self, action, output=None):
            argv = ['sudo', '-n', 'nsenter', '-t', self.pid, '-n', sys.executable, '-I', '-B', '-S',
                    str(ENTRYPOINT), 'client', action, str(self.data / 'config'), str(receipt)]
            try: result = json.loads(module.command(argv, timeout=150))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                (evidence / ((output or action) + '-stderr.log')).write_text(cold.bounded_diagnostic(error.stderr, 'CREDENTIAL_CLIENT_FAILED'))
                raise RuntimeError('CREDENTIAL_CLIENT_FAILED:' + action) from error
            module.write_json(evidence / ((output or action) + '.json'), result); return result
    try:
        module.write_json(evidence / 'exact-image.json', cold.prepare_image(archive, work))
        data = work / 'fixture'
        for role in ('master', 'volume', 'filer', 's3', 'config'): (data / role).mkdir(parents=True)
        module.write_json(data / 'config/s3.json', config_for(module, 'old'))
        (evidence / 'old-fixture-config.json').write_bytes((data / 'config/s3.json').read_bytes())
        tls = module.certificates(data / 'config')
        for name in ('ca.pem', 'server.pem'): (evidence / name).write_bytes((tls / name).read_bytes())
        peer = sha(ssl.PEM_cert_to_DER_cert((tls / 'server.pem').read_text()))
        module.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(data)])
        lab = CredentialLab('ouf-keys33-' + str(os.getpid()), data, evidence); lab.start()
        stages = [lab.client('old')]; current = lab.prefix + '-s3'
        for stage in ('overlap', 'new', 'restarted'):
            current = replace_gateway(module, lab, current, stage)
            stages.append(lab.client(stage))
        seed = {'sha256': sha(BODY), 'bytes': len(BODY), 'mime': MIME}
        require(all(read['objects'][KEY] == seed and read['peerSha256'] == peer
                    for stage in stages for read in stage['reads'].values()), 'ORIGINAL_OBJECT_AND_TLS_MUST_SURVIVE')
        require(stages[2]['reads'] == stages[3]['reads'] and stages[2]['denied'] == stages[3]['denied'],
                'RESTART_MUST_PRESERVE_KEYS_POLICY_AND_OBJECTS')
        require([s['successfulObjectPuts'] for s in stages] == [1, 0, 1, 0], 'EXACTLY_TWO_OBJECT_PUTS_NO_RESEED')
        lab.stop()
        stopped = [json.loads(p.read_bytes()) for p in evidence.glob('*-stopped.json')]
        require(len(stopped) == 4 and all(not x['Running'] and x['ExitCode'] == 0 and not x['OOMKilled'] for x in stopped),
                'FOUR_FINAL_CLEAN_STOPS_REQUIRED')
        module.write_json(evidence / 'receipt.json', {
            'schema': 'ouf.storage-generation33-credential-rotation.v1', 'status': 'SYNTHETIC_S3_CREDENTIAL_ROTATION_PASS',
            'generation': 33, 'candidateLockSha256': LOCK_SHA, 'cohortReceiptSha256': COHORT_SHA,
            'ociManifestDigest': bound['lock']['image']['manifestDigest'], 'binarySha256': labs.binding_api.BINARY_SHA,
            'stages': list(STAGES), 'gatewayReplacements': 3, 'distinctContainerCount': 7, 'cleanContainerStops': 7,
            'maximumConcurrentContainers': 4, 'storageRolesRestarted': False, 'simultaneousS3Gateways': 1,
            'deniedRequests': sum(len(s['denied']) for s in stages), 'successfulObjectPuts': 2, 'bucketCreates': 1,
            'mutatingRequestRetries': 0, 'originalObject': seed, 'finalObjects': stages[-1]['reads']['new']['objects'],
            'peerCertificateSha256': peer, 'oldKeyRejectedAfterRestart': True, 'newKeyWriteReadVerified': True,
            'policyUnchanged': True, 'fixtureCredentialsOnly': True, 'privateKeysUploaded': False,
            'hotReloadQualified': False, 'zeroDowntimeQualified': False, 'productionSecretCustodyQualified': False,
            'targetOperations': 0, 'releaseAdmitted': False, 'runtimeAuthorityIssued': False,
            'gatesClosed': 0, 'acceptanceTestsPassed': 0})
    except Exception as error:
        module.write_json(evidence / 'failure.json', {'status': 'SYNTHETIC_S3_CREDENTIAL_ROTATION_FAILED',
            'failureClass': type(error).__name__, 'safeReason': str(error)[:512]
            if isinstance(error, (ValueError, RuntimeError)) else 'COMMAND_OR_IO_FAILED', 'targetOperations': 0})
        raise
    finally:
        if lab and lab.names: lab.stop(strict=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='operation', required=True)
    runner = sub.add_parser('run')
    for name in ('archive', 'work', 'receipt'): runner.add_argument(name, type=Path)
    child = sub.add_parser('client'); child.add_argument('action', choices=('ready', *STAGES))
    child.add_argument('config', type=Path); child.add_argument('receipt', type=Path)
    args = parser.parse_args()
    if args.operation == 'run': run(args.archive.resolve(), args.work.absolute(), args.receipt.resolve())
    else: print(json.dumps(client(tls_rotation.configure(binding(args.receipt)), args.config, args.action)))


if __name__ == '__main__': main()
