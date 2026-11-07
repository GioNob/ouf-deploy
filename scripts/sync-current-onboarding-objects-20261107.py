#!/usr/bin/env python3
"""Copy missing current Onboarding objects to SeaweedFS; never overwrite or switch bindings."""
import datetime
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import parse_qsl, quote
from xml.etree import ElementTree as ET

ROOT = Path('/var/lib/ouf-storage-migration')
PLAN = ROOT / 'cold-host-bound-20261107-v1/plan.private.json'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
APP_IMAGE = 'sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51'
SEA_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
BUCKET = 'ouf-managed-files'
BINDINGS = ROOT / 'seaweedfs/staging-oci33-20261107-v1/application-s3-v1'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
METADATA = {'content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires'}
DEADLINE = 0


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path, maximum=1048576):
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    need(len(value) <= maximum, 'INPUT_TOO_LARGE')
    return value


def inspect(ref):
    p = subprocess.run((*DOCKER, 'container', 'inspect', ref), capture_output=True, timeout=15)
    need(p.returncode == 0 and len(p.stdout) <= 1048576, 'DOCKER_INSPECT_FAILED')
    rows = json.loads(p.stdout)
    need(len(rows) == 1, 'CONTAINER_NOT_UNIQUE')
    return rows[0]


def signed(method, path, host, auth, body, extra, stamp):
    # Same SigV4 canonicalization used by the successful retained-data rehearsal.
    uri, _, query = path.partition('?')
    params = sorted((quote(k, safe='-_.~'), quote(v, safe='-_.~'))
                    for k, v in parse_qsl(query, keep_blank_values=True))
    query = '&'.join(f'{k}={v}' for k, v in params)
    payload = digest(body)
    headers = dict(extra, host=host)
    headers.update({'x-amz-content-sha256': payload, 'x-amz-date': stamp})
    names = sorted(headers)
    selected = ';'.join(names)
    lines = ''.join(f'{k}:{" ".join(headers[k].split())}\n' for k in names)
    canonical = '\n'.join((method, uri, query, lines, selected, payload))
    key, secret = auth
    day = stamp[:8]
    scope = f'{day}/us-east-1/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, digest(canonical.encode())))
    signing = ('AWS4' + secret).encode()
    for component in (day, 'us-east-1', 's3', 'aws4_request'):
        signing = hmac.digest(signing, component.encode(), 'sha256')
    signature = hmac.digest(signing, message.encode(), 'sha256').hex()
    headers['authorization'] = f'AWS4-HMAC-SHA256 Credential={key}/{scope},SignedHeaders={selected},Signature={signature}'
    return uri + ('?' + query if query else ''), headers


class S3:
    def __init__(self, address, hostname, port, auth, ca=None):
        self.address, self.hostname, self.port, self.auth = address, hostname, port, auth
        self.context = ssl.create_default_context(cafile=str(ca)) if ca else None
        self.calls = 0

    def request(self, method, path, body=b'', extra=None, maximum=10*1024*1024):
        need(time.monotonic() < DEADLINE, 'COPY_DEADLINE')
        uri, headers = signed(method, path, f'{self.hostname}:{self.port}', self.auth, body, extra or {},
                              datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        outer = self
        class Connection(http.client.HTTPConnection):
            def connect(self):
                raw = socket.create_connection((outer.address, outer.port), timeout=self.timeout)
                try:
                    self.sock = outer.context.wrap_socket(raw, server_hostname=outer.hostname) if outer.context else raw
                except BaseException:
                    raw.close()
                    raise
        connection = Connection(self.hostname, self.port, timeout=min(15, max(1, DEADLINE-time.monotonic())))
        self.calls += 1
        try:
            connection.request(method, uri, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(maximum + 1)
            need(len(data) <= maximum, 'S3_RESPONSE_TOO_LARGE')
            return response.status, data, response.getheaders()
        finally:
            connection.close()


def provider_code(body):
    match = re.search(rb'<Code>([A-Za-z][A-Za-z0-9_-]{0,79})</Code>', body[:65536])
    return match.group(1).decode() if match else None


def success(response, report):
    status, body, headers = response
    if status != 200:
        report.update(lastS3HttpStatus=status, lastS3Code=provider_code(body))
        raise RuntimeError('S3_REQUEST_NOT_SUCCESSFUL')
    return body, headers


def listing(client, report):
    raw, _ = success(client.request('GET', f'/{BUCKET}?list-type=2&max-keys=1000', maximum=1048576), report)
    root = ET.fromstring(raw)
    need(root.tag.rsplit('}', 1)[-1] == 'ListBucketResult' and root.findtext('{*}Name') == BUCKET,
         'SOURCE_LIST_SHAPE')
    need(root.findtext('{*}IsTruncated') == 'false', 'SOURCE_LIST_TRUNCATED')
    rows = []
    for item in root.findall('{*}Contents'):
        row = {name: item.findtext('{*}' + name) for name in ('Key', 'ETag', 'LastModified', 'Size')}
        row['Size'] = int(row['Size'])
        need(row['Key'] and row['Key'].startswith('managed-files/') and len(row['Key']) <= 1024
             and row['ETag'] and row['LastModified'] and 0 <= row['Size'] <= 10*1024*1024, 'SOURCE_OBJECT_SCOPE')
        rows.append(row)
    need(0 < len(rows) <= 512 and len({r['Key'] for r in rows}) == len(rows)
         and sum(r['Size'] for r in rows) <= 64*1024*1024, 'SOURCE_LIST_SIZE')
    return sorted(rows, key=lambda r: r['Key'])


def metadata(headers):
    selected = {}
    for k, value in headers:
        name = k.lower()
        need(not name.startswith(('x-amz-server-side-encryption', 'x-amz-object-lock'))
             and name != 'x-amz-website-redirect-location', 'SPECIAL_METADATA_REQUIRES_REVIEW')
        if name in METADATA or name.startswith('x-amz-meta-'):
            need(name not in selected and re.fullmatch('[a-z0-9_-]+', name)
                 and all(32 <= ord(c) < 127 for c in value), 'METADATA_REQUIRES_REVIEW')
            selected[name] = value
    return selected


def align(source, destination, rows, report, journal):
    manifest = []
    for ordinal, row in enumerate(rows, 1):
        report['currentObjectOrdinal'] = ordinal
        path = '/' + BUCKET + '/' + quote(row['Key'], safe='/-_.~')
        report['phase'] = 'READ_SOURCE_OBJECT'
        body, headers = success(source.request('GET', path, extra={'if-match': row['ETag']}), report)
        need(len(body) == row['Size'] and dict((k.lower(), v) for k, v in headers).get('etag') == row['ETag'],
             'SOURCE_OBJECT_CHANGED')
        source_meta = metadata(headers)
        body_hash = digest(body)
        report['phase'] = 'COMPARE_DESTINATION_OBJECT'
        target = destination.request('GET', path)
        if target[0] == 200:
            need(digest(target[1]) == body_hash and len(target[1]) == row['Size']
                 and metadata(target[2]) == source_meta, 'EXISTING_TARGET_OBJECT_DIFFERS')
            report['objectsAlreadyMatched'] += 1
        else:
            report.update(lastS3HttpStatus=target[0], lastS3Code=provider_code(target[1]))
            need(target[0] == 404 and provider_code(target[1]) == 'NoSuchKey', 'DESTINATION_READ_NOT_ABSENT')
            # The application target identity has no tag-administration privilege.
            # Existing historical objects are not rewritten; tagged new objects require a deliberate copy path.
            report['phase'] = 'CHECK_NEW_OBJECT_TAGS'
            tag_body, _ = success(source.request('GET', path + '?tagging', maximum=16384), report)
            tags = ET.fromstring(tag_body)
            need(tags.tag.rsplit('}', 1)[-1] == 'Tagging' and not tags.findall('{*}TagSet/{*}Tag'),
                 'NEW_TAGGED_OBJECT_REQUIRES_COPY_PATH')
            intent = {'key': row['Key'], 'sha256': body_hash, 'size': row['Size'], 'state': 'PUT_INTENT'}
            journal.write(json.dumps(intent, sort_keys=True) + '\n'); journal.flush(); os.fsync(journal.fileno())
            report['phase'] = 'PUT_MISSING_OBJECT'
            report['putAttempts'] += 1
            success(destination.request('PUT', path, body, dict(source_meta, **{'if-none-match': '*'})), report)
            actual, actual_headers = success(destination.request('GET', path), report)
            need(len(actual) == row['Size'] and digest(actual) == body_hash and metadata(actual_headers) == source_meta,
                 'COPIED_OBJECT_READBACK_DIFFERS')
            report['objectsCopiedAndVerified'] += 1
            journal.write(json.dumps(dict(intent, state='VERIFIED'), sort_keys=True) + '\n'); journal.flush()
            report.pop('lastS3HttpStatus', None)
            report.pop('lastS3Code', None)
        manifest.append({'key': row['Key'], 'size': row['Size'], 'sha256': body_hash, 'metadata': source_meta})
    return manifest


def generation(doc):
    return doc['Id'], doc['Image'], doc['State']['StartedAt'], doc['State']['Pid']


def run(report):
    global DEADLINE
    DEADLINE = time.monotonic() + 600
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    raw = read(PLAN)
    need(digest(raw) == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    roles = json.loads(raw)['roles']
    app, minio, sea = inspect(roles['onboarding']['containerId']), inspect(roles['minio']['containerId']), inspect('ouf-seaweedfs-stage')
    need(app['State']['Running'] and app['Image'] == APP_IMAGE and minio['State']['Running']
         and minio['Image'] == roles['minio']['nativeImage']
         and sea['State']['Running'] and sea['Image'] == SEA_IMAGE, 'CURRENT_RUNTIME_CHANGED')
    before = [generation(d) for d in (app, minio, sea)]
    env = dict(e.split('=', 1) for e in app['Config']['Env'] if '=' in e)
    need(env['OUF_ONBOARDING_STAGING_ENDPOINT'] == 'http://ouf-minio:9000'
         and env['OUF_ONBOARDING_STAGING_BUCKET'] == BUCKET, 'CURRENT_SOURCE_BINDING_CHANGED')
    def credential(variable):
        path = Path(env[variable])
        need(path.is_absolute() and '..' not in path.parts, 'CREDENTIAL_PATH_INVALID')
        return read(Path('/proc') / str(app['State']['Pid']) / 'root' / str(path).lstrip('/'), 4096).decode().strip()
    source_auth = tuple(credential(k) for k in ('OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE', 'OUF_ONBOARDING_STAGING_SECRET_KEY_FILE'))
    client = BINDINGS / 'clients/onboarding'
    target_env = json.loads(read(client / 'binding.private.json'))['environment']
    need(target_env['OUF_ONBOARDING_STAGING_ENDPOINT'] == 'https://ouf-seaweedfs-stage:9002'
         and target_env['OUF_ONBOARDING_STAGING_BUCKET'] == BUCKET, 'TARGET_BINDING_CHANGED')
    target_auth = tuple(read(client / name, 4096).decode().strip() for name in ('access-key', 'secret-key'))
    need(all(v and not any(c in v for c in '\r\n\x00') for v in (*source_auth, *target_auth)), 'CREDENTIAL_FILE_INVALID')
    source = S3(minio['NetworkSettings']['Networks']['ouf-backend']['IPAddress'], 'ouf-minio', 9000, source_auth)
    destination = S3(sea['NetworkSettings']['Networks']['ouf-seaweedfs-private']['IPAddress'], 'ouf-seaweedfs-stage', 9002,
                     target_auth, BINDINGS / 'config/tls/ca.pem')
    work = Path(tempfile.mkdtemp(prefix='onboarding-current-copy-', dir=ROOT))
    os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    try:
        report['phase'] = 'LIST_CURRENT_SOURCE'
        rows = listing(source, report)
        report.update(sourceObjects=len(rows), sourceBytes=sum(r['Size'] for r in rows))
        (work / 'source-before.json').write_text(json.dumps(rows, sort_keys=True) + '\n')
        with (work / 'copy-journal.jsonl').open('x') as journal:
            manifest = align(source, destination, rows, report, journal)
        report['phase'] = 'VERIFY_SOURCE_SNAPSHOT'
        need(listing(source, report) == rows, 'SOURCE_CHANGED_DURING_COPY')
        need([generation(inspect(d['Id'])) for d in (app, minio, sea)] == before, 'RUNTIME_CHANGED_DURING_COPY')
        payload = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
        (work / 'objects-verified.private.json').write_bytes(payload)
        report.update(status='CURRENT_ONBOARDING_OBJECTS_ALIGNED', phase='COMPLETE',
                      sourceSnapshotUnchanged=True, manifestSha256=digest(payload),
                      sourceStateMustBeRecheckedAtEndpointSwitch=True)
    finally:
        report.update(sourceS3Requests=source.calls, destinationS3Requests=destination.calls)


if __name__ == '__main__':
    os.umask(0o077)
    report = {'schema': 'ouf.current-onboarding-object-alignment.v1', 'status': 'INCOMPLETE',
              'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'objectsAlreadyMatched': 0, 'objectsCopiedAndVerified': 0, 'putAttempts': 0,
              'sourceObjectsModified': False, 'existingTargetObjectsOverwritten': False,
              'applicationBindingsChanged': False, 'databaseRequests': 0, 'serviceStops': 0,
              'credentialValuesEmitted': False, 'targetTagsFreshlyCompared': False}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'INCOMPLETE'
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z_]+', str(exc)) else type(exc).__name__
    report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'privateEvidenceDirectory' in report:
        (Path(report['privateEvidenceDirectory']) / 'result.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'CURRENT_ONBOARDING_OBJECTS_ALIGNED' else 1)
