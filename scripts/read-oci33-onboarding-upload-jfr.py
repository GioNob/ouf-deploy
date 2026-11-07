#!/usr/bin/env python3
"""Decode the retained Onboarding JFR recording without starting the application."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import subprocess
import sys

SCHEMA = 'ouf.storage-oci33-onboarding-upload-jfr-readback.v1'
TRACE_SCHEMA = 'ouf.storage-oci33-onboarding-upload-trace.v1'
SCOPE = Path('/var/lib/ouf-storage-migration/seaweedfs/staging-oci33-20261107-v1/'
             'onboarding-stack-v1/upload-proof-v1/instrumented-upload-v1')
IMAGE = 'sha256:2dd55525d4a6969cf59f4d5e811c5f502976211c0cb49f9ba081dab5e4806c15'
IMAGE_CONFIG = 'sha256:0a29a90a48a69a6ed757748bdac97cf029b6e7d633b6bc9a9b1d706fa00837db'
TESTED = '69b099b04f1823b127ef4af4a9c44861ff4cdc67'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
LIMIT = 96 << 20
PROVIDER_CODES = ('AccessDenied', 'SignatureDoesNotMatch', 'InvalidAccessKeyId', 'InvalidRequest',
                  'XAmzContentSHA256Mismatch', 'NotImplemented', 'MissingContentLength',
                  'InternalError', 'ServiceUnavailable', 'NoSuchBucket', 'NoSuchKey', 'BadDigest')
HINTS = {
    'tlsCertificate': r'PKIX|certificate_unknown|no subject alternative|trustAnchors|unable to find valid certification path',
    'tlsHandshake': r'handshake_failure|SSL handshake|SSL peer shut down|certificate|SSLHandshake',
    'connectionRefused': r'connection refused|failed to connect',
    'connectionReset': r'connection reset|unexpected end of stream',
    'accessDenied': r'AccessDenied|access denied',
    'signature': r'SignatureDoesNotMatch|signature.*does not match|InvalidAccessKeyId',
    'requestEncoding': r'MissingContentLength|XAmzContentSHA256Mismatch|aws-chunked|unsupported header',
    'providerInternal': r'InternalError|internal (server )?error|no writable volumes|failed to assign',
    'route': r'no route to host|network is unreachable|unknown host',
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def frame(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def file_input(path, uid, maximum, read=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
             and not before.st_mode & 0o022 and 0 < before.st_size <= maximum, 'JFR_INPUT_FILE_GUARD')
        if read:
            content = stream.read(maximum + 1)
        else:
            need(stream.read(4) == b'FLR\x00', 'JFR_RECORDING_MAGIC')
            stream.seek(0)
            checksum = hashlib.sha256()
            while block := stream.read(1 << 20):
                checksum.update(block)
            content = checksum.hexdigest()
        need(frame(before) == frame(os.fstat(stream.fileno())) == frame(path.lstat()), 'JFR_INPUT_CHANGED')
        return before, content


def summarize(doc, lower, upper, report):
    exceptions, transport, hints, codes, addresses, statuses = set(), set(), set(), set(), set(), set()
    for event in doc['recording']['events']:
        values = event.get('values') or {}
        stamp = values.get('startTime')
        if not isinstance(stamp, str):
            continue
        when = datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
        inside = lower <= when <= upper
        if event['type'] == 'jdk.TLSHandshake':
            if inside and values.get('peerPort') == 9002:
                report['s3TlsHandshakesInUploadWindow'] += 1
            continue
        if event['type'] != 'jdk.JavaExceptionThrow':
            continue
        frames = (values.get('stackTrace') or {}).get('frames') or []
        owners = [str(((f.get('method') or {}).get('type') or {}).get('name', '')).replace('/', '.')
                  for f in frames]
        sdk = any(owner.startswith(('io.minio.', 'okhttp3.', 'okio.'))
                  or owner.endswith('.MinioManagedFileStagingStore') for owner in owners)
        if sdk:
            report['s3SdkExceptionEventsInRecording'] += 1
        if not inside:
            continue
        report['exceptionEventsInUploadWindow'] += 1
        qualified = str((values.get('thrownClass') or {}).get('name', '')).replace('/', '.')
        name = qualified.rsplit('.', 1)[-1]
        safe = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', name)
        network = qualified.startswith(('java.net.', 'javax.net.ssl.'))
        if sdk:
            report['s3SdkExceptionEventsInUploadWindow'] += 1
            if safe:
                exceptions.add(name)
        if network and safe:
            transport.add(name)
        if not (sdk or network):
            continue
        message = values.get('message')
        if not isinstance(message, str):
            continue
        hints.update(label for label, pattern in HINTS.items() if re.search(pattern, message, re.I))
        codes.update(code for code in PROVIDER_CODES if re.search(r'\b' + code + r'\b', message, re.I))
        statuses.update(int(code) for code in re.findall(
            r'(?:HTTP(?:/\d\.\d)?\s+|status(?: code)?[=: ]+)(400|401|403|404|411|500|502|503|504)\b',
            message, re.I))
        if re.search(r'(?<![0-9])127\.0\.0\.1(?![0-9])', message):
            addresses.add('ipv4-loopback')
        if re.search(r'(?:/|\[|\s)(?:::1|0:0:0:0:0:0:0:1)(?:\]|%|\s|:|$)', message):
            addresses.add('ipv6-loopback')
    report.update({'s3SdkExceptionClasses': sorted(exceptions)[:24],
                   'transportExceptionClasses': sorted(transport)[:24],
                   'errorHints': sorted(hints), 'providerErrorCodes': sorted(codes),
                   'providerHttpStatusHints': sorted(statuses), 'loopbackAddressHints': sorted(addresses)})


def output_cap():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def run(report):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'ISOLATED_ROOT_REQUIRED')
    for path in (*reversed(SCOPE.parents), SCOPE, SCOPE / 'diagnostics'):
        info = path.lstat()
        uid = 10003 if path == SCOPE / 'diagnostics' else 0
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
             'JFR_INPUT_DIRECTORY_GUARD')

    _, raw = file_input(SCOPE / 'claim.private.json', 0, 8192, read=True)
    claim = json.loads(raw)
    t0, raw = file_input(SCOPE / 'upload-intent.private.json', 0, 8192, read=True)
    intent = json.loads(raw)
    t1, raw = file_input(SCOPE / 'onboarding-response.private.json', 0, 32768, read=True)
    response = json.loads(raw)
    need(claim.get('schema') == TRACE_SCHEMA and claim.get('onboardingImage') == IMAGE
         and re.fullmatch('[a-f0-9]{24}', claim.get('scopeToken', ''))
         and intent.get('idempotencyKey') == claim['scopeToken']
         and intent.get('fileId') == 'file_' + claim['scopeToken']
         and intent.get('maximumRequests') == 1 and intent.get('isolatedIdentity') is True
         and response.get('code') == 'ONB_STAGING_WRITE_FAILED'
         and 0 <= t1.st_mtime_ns - t0.st_mtime_ns <= 90_000_000_000, 'JFR_UPLOAD_WINDOW_BINDING')
    report['applicationErrorCode'] = response['code']
    report['uploadWindowMilliseconds'] = (t1.st_mtime_ns - t0.st_mtime_ns) // 1000000
    recording = SCOPE / 'diagnostics/upload.jfr'
    original, digest = file_input(recording, 10003, 64 << 20)
    report['recordingBytes'] = original.st_size
    report['recordingSha256'] = digest

    socket = Path('/run/docker.sock')
    sock = socket.stat()
    need(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o007,
         'LOCAL_DOCKER_SOCKET_REQUIRED')
    base = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent']

    def docker(*args, **kwargs):
        now = socket.stat()
        need((now.st_dev, now.st_ino, now.st_uid, now.st_mode) ==
             (sock.st_dev, sock.st_ino, sock.st_uid, sock.st_mode), 'DOCKER_SOCKET_CHANGED')
        p = subprocess.run(base + list(args), stdin=subprocess.DEVNULL, env=ENV, **kwargs)
        need(p.returncode == 0, 'DOCKER_' + args[0].upper() + '_FAILED')
        return p.stdout

    need(not docker('ps', '-q', capture_output=True, timeout=15).strip(), 'OTHER_CONTAINERS_RUNNING')
    img, = json.loads(docker('image', 'inspect', IMAGE, capture_output=True, timeout=15))
    need(img['Id'] == IMAGE and img['Config']['User'] == '10003:10003'
         and img['Config']['Labels']['org.opencontainers.image.revision'] == TESTED, 'EXACT_JFR_IMAGE_REQUIRED')
    out = SCOPE / 'decoder-readback-v1'
    out.mkdir(mode=0o700)
    token = secrets.token_hex(10)
    cid = docker('create', '--name', 'ouf-jfr-readback-' + token, '--label', 'ouf.jfr-readback=' + token,
                 '--network=none', '--pull=never', '--restart=no', '--read-only', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--memory=512m', '--cpus=2', '--pids-limit=128',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777', '--user', '10003:10003',
                 '--mount', f'type=bind,src={recording},dst=/input.jfr,readonly',
                 '--entrypoint', '/opt/java/openjdk/bin/jfr', IMAGE, 'print', '--json', '--events',
                 'jdk.JavaExceptionThrow,jdk.TLSHandshake', '--stack-depth', '48', '/input.jfr',
                 capture_output=True, timeout=15).decode().strip()
    need(re.fullmatch('[a-f0-9]{64}', cid), 'JFR_DECODER_CONTAINER_ID')
    try:
        row, = json.loads(docker('container', 'inspect', cid, capture_output=True, timeout=15))
        need(row['Id'] == cid and row['Image'] in (IMAGE, IMAGE_CONFIG)
             and row['Config']['Labels']['ouf.jfr-readback'] == token
             and row['HostConfig']['NetworkMode'] == 'none' and row['HostConfig']['ReadonlyRootfs']
             and not row['HostConfig']['PortBindings'] and not row['HostConfig']['PublishAllPorts'],
             'JFR_DECODER_ISOLATION')
        with (out / 'events.private.json').open('xb') as stream, (out / 'decoder.stderr.private').open('xb') as errors:
            try:
                docker('start', '-a', cid, stdout=stream, stderr=errors, timeout=100, preexec_fn=output_cap)
            except (ValueError, subprocess.SubprocessError):
                if errors.name and Path(errors.name).stat().st_size <= 16384:
                    retained = Path(errors.name).read_bytes()
                    patterns = {'incompleteRecording': rb'incomplete|unexpected end|finished chunk',
                                'invalidRecording': rb'not a flight recording|invalid|corrupt',
                                'memoryLimit': rb'outofmemory|cannot allocate',
                                'outputLimit': rb'file size limit|broken pipe'}
                    report['decoderHints'] = [label for label, pattern in patterns.items()
                                              if re.search(pattern, retained, re.I)]
                raise
    finally:
        docker('rm', '-f', cid, capture_output=True, timeout=15)
        report['decoderContainerRemoved'] = True
    after, current = file_input(recording, 10003, 64 << 20)
    need(frame(original) == frame(after) and digest == current, 'JFR_RECORDING_CHANGED')
    report['recordingUnchanged'] = True
    _, raw = file_input(out / 'events.private.json', 0, LIMIT, read=True)
    summarize(json.loads(raw), t0.st_mtime_ns / 1e9 - 0.25, t1.st_mtime_ns / 1e9 + 0.25, report)
    report['flightRecorderParsed'] = True
    report['status'] = 'ONBOARDING_UPLOAD_JFR_READ_BACK'
    with (out / 'result.json').open('x', encoding='utf-8') as result:
        json.dump(report, result, sort_keys=True)
        result.write('\n')


def main():
    os.umask(0o077)
    report = {'schema': SCHEMA, 'status': 'HELD', 'flightRecorderParsed': False,
              'decoderContainerRemoved': False, 'recordingUnchanged': False, 'uploadRequests': 0,
              'applicationContainersStarted': 0, 'acceptanceCreditAdded': 0,
              'exceptionEventsInUploadWindow': 0, 's3SdkExceptionEventsInUploadWindow': 0,
              's3SdkExceptionEventsInRecording': 0, 's3TlsHandshakesInUploadWindow': 0}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch(r'[A-Z][A-Z0-9_]{5,80}', reason) else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())
