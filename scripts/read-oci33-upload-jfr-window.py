#!/usr/bin/env python3
"""Classify transport exceptions from the retained POST-window JFR JSON."""
from collections import Counter
from datetime import datetime
import hashlib
import json
import mmap
import os
import re
import stat
import sys
from urllib.request import urlopen

SCHEMA = 'ouf.storage-oci33-onboarding-upload-jfr-transport.v1'
JSON_BYTES = 1780674822
WINDOW_MS = 10396
EVENT = re.compile(
    rb'"type": "jdk\.(?:JavaExceptionThrow|TLSHandshake)"'
    rb'(?:,\s+"values": \{\s+"startTime": "([^"\r\n]{1,64})")?'
)
HEADER = re.compile(rb'^\s*\{\s*"recording"\s*:\s*\{\s*"events"\s*:\s*\[')
TRAILER = re.compile(rb'\]\s*}\s*}\s*$')
TRANSPORT_CLASSES = {'java.net.ConnectException', 'java.net.SocketTimeoutException'}
LINKAGE_CLASSES = {'java.lang.ClassNotFoundException', 'java.lang.NoSuchMethodError'}
SELECTED_CLASSES = TRANSPORT_CLASSES | LINKAGE_CLASSES
LOOPBACK = re.compile(r'(?<![\w.])(?P<ipv4>127\.0\.0\.1)(?![\w.])'
                      r'|(?<![\w:])(?P<ipv6>0:0:0:0:0:0:0:1|::1)(?![\w:])')
PORT = re.compile(r'\]?(?::|\s+port[= ])9002(?!\d)', re.I)


def need(ok, code):
    if not ok:
        raise ValueError(code)


def helper():
    url = ('https://raw.githubusercontent.com/GioNob/ouf-deploy/'
           '98dd534673a2843438cab1b5da8679fd6d1db11e/scripts/read-oci33-onboarding-upload-jfr.py')
    with urlopen(url, timeout=25) as response:
        raw = response.read(19366)
    need(len(raw) == 19365 and hashlib.sha256(raw).hexdigest() ==
         '28c0232cd3005095b4c257bcbbf4ed76c9778c82bb56063689f4324b03e14b79',
         'JFR_HELPER_DIGEST')
    ns = {'__name__': 'jfr_window_helper'}
    exec(compile(raw, 'read-oci33-onboarding-upload-jfr.py', 'exec'), ns)
    ns['HINTS'].update({'connectTimeout': r'connect timed out|connection timed out',
                        'readTimeout': r'read timed out|timeout waiting for response|timeout reading',
                        'http2Stream': r'http/2 stream|stream was reset|stream reset'})
    return ns


def event_at(data, start):
    decoder = json.JSONDecoder()
    size = 16384
    while size <= 2 << 20:
        raw = data[start:start + size]
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            if exc.reason != 'unexpected end of data':
                raise
            text = raw[:exc.start].decode('utf-8')
        try:
            event, _ = decoder.raw_decode(text)
            need(isinstance(event, dict), 'JFR_SELECTED_EVENT_TYPE')
            return event
        except json.JSONDecodeError:
            if len(raw) < size:
                break
            size *= 2
    raise ValueError('JFR_SELECTED_EVENT_INCOMPLETE')


def selected(data, lower, upper, report):
    need(HEADER.match(data, 0, min(len(data), 4096)), 'JFR_JSON_HEADER_REQUIRED')
    report['retainedJsonClosed'] = bool(TRAILER.search(data[max(0, len(data) - 4096):]))
    for mark in EVENT.finditer(data):
        stamp = mark.group(1)
        if stamp is None and not report['retainedJsonClosed'] and mark.start() >= len(data) - 4096:
            report['partialTailEventSkipped'] = True
            break
        need(stamp is not None, 'JFR_EVENT_TIMESTAMP_FIELD_ORDER')
        stamp = stamp.decode('ascii')
        when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        need(when.utcoffset() is not None, 'JFR_TIMESTAMP_OFFSET_REQUIRED')
        report['eventHeadersScanned'] += 1
        if not lower <= when.timestamp() <= upper:
            continue
        report['eventHeadersInUploadWindow'] += 1
        need(report['eventHeadersInUploadWindow'] <= 20000, 'JFR_UPLOAD_WINDOW_EVENT_LIMIT')
        start = data.rfind(b'{', max(0, mark.start() - 256), mark.start())
        need(start >= 0 and not data[start + 1:mark.start()].strip(), 'JFR_EVENT_BOUNDARY_REQUIRED')
        try:
            event = event_at(data, start)
        except ValueError as exc:
            if (str(exc) == 'JFR_SELECTED_EVENT_INCOMPLETE' and not report['retainedJsonClosed']
                    and start >= len(data) - (2 << 20)):
                report['partialTailEventSkipped'] = True
                break
            raise
        need(event.get('type') in ('jdk.JavaExceptionThrow', 'jdk.TLSHandshake')
             and event.get('values', {}).get('startTime') == stamp, 'JFR_SELECTED_EVENT_BINDING')
        yield event


def timestamp(values):
    return datetime.fromisoformat(values['startTime'].replace('Z', '+00:00'))


def frames(values):
    for frame in (values.get('stackTrace') or {}).get('frames') or []:
        method = frame.get('method') or {}
        yield str((method.get('type') or {}).get('name', '')).replace('/', '.'), method.get('name')


def phase(stack):
    for owner, method in stack:
        if (owner.endswith('.Http1ExchangeCodec') and method == 'readResponseHeaders'
                or owner.endswith('.Http2Stream') and method == 'takeHeaders'):
            return 'response-headers'
        if (owner.endswith('.SSLSocketImpl') and method == 'startHandshake'
                or owner.endswith('.ConnectPlan') and method == 'connectTls'):
            return 'tls'
        if (owner == 'java.net.Socket' and method == 'connect'
                or owner.endswith('.ConnectPlan') and method == 'connectSocket'):
            return 'tcp-connect'
    return 'unclassified'


def operation(stack):
    for owner, method in stack:
        if owner.startswith('io.minio.'):
            if method in ('getRegion', 'getRegionAsync'):
                return 'region-lookup'
            if method in ('putObject', 'putObjectAsync'):
                return 'put-object-call'
    return 'unclassified'


def thread_id(values):
    key = (values.get('eventThread') or {}).get('javaThreadId')
    return key if type(key) is int and key > 0 else None


def observe_transport(event, handshakes, exceptions):
    values = event['values']
    key = thread_id(values)
    if event['type'] == 'jdk.TLSHandshake':
        if values.get('peerPort') == 9002 and key is not None:
            when = timestamp(values)
            handshakes[key] = min(handshakes.get(key, when), when)
        return

    name = str((values.get('thrownClass') or {}).get('name', '')).replace('/', '.')
    if name not in SELECTED_CLASSES:
        return
    stack = list(frames(values))
    if not any(owner.startswith(('io.minio.', 'okhttp3.', 'okio.'))
               or owner.endswith('.MinioManagedFileStagingStore') for owner, _ in stack):
        return

    message = values.get('message')
    message = message if isinstance(message, str) else ''
    endpoints = {(m.lastgroup + '-loopback', bool(PORT.match(message, m.end())))
                 for m in LOOPBACK.finditer(message)}
    family, explicit_port = next(iter(endpoints)) if len(endpoints) == 1 else ('unclassified', False)
    stage = 'linkage' if name in LINKAGE_CLASSES else phase(stack)
    label = (name.rsplit('.', 1)[-1], stage, operation(stack), family, explicit_port)
    exceptions.append((key, timestamp(values), label))


def transport_groups(handshakes, exceptions):
    grouped = Counter()
    for key, when, label in exceptions:
        previous = handshakes.get(key)
        grouped[(*label, previous is not None and previous < when)] += 1

    return [dict(exception=name, phase=stage, sdkOperation=op, loopbackAddressInMessage=family,
                 addressHasExplicitS3Port=port, afterS3TlsOnSameThread=after, count=count)
            for (name, stage, op, family, port, after), count in sorted(grouped.items())]


def run(report):
    need(os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'ISOLATED_ROOT_REQUIRED')
    h = helper()
    scope, file_input, frame = h['SCOPE'], h['file_input'], h['frame']
    for path in (*reversed(scope.parents), scope, scope / 'diagnostics'):
        info = path.lstat()
        uid = 10003 if path == scope / 'diagnostics' else 0
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
             'JFR_INPUT_DIRECTORY_GUARD')

    _, raw = file_input(scope / 'claim.private.json', 0, 8192, read=True)
    claim = json.loads(raw)
    t0, raw = file_input(scope / 'upload-intent.private.json', 0, 8192, read=True)
    intent = json.loads(raw)
    t1, raw = file_input(scope / 'onboarding-response.private.json', 0, 32768, read=True)
    response = json.loads(raw)
    elapsed = (t1.st_mtime_ns - t0.st_mtime_ns) // 1000000
    token = claim.get('scopeToken', '')
    need(claim.get('schema') == h['TRACE_SCHEMA'] and claim.get('onboardingImage') == h['IMAGE']
         and re.fullmatch('[a-f0-9]{24}', token) and intent.get('idempotencyKey') == token
         and intent.get('fileId') == 'file_' + token and intent.get('maximumRequests') == 1
         and intent.get('isolatedIdentity') is True and response.get('code') == 'ONB_STAGING_WRITE_FAILED'
         and elapsed == WINDOW_MS, 'EXACT_UPLOAD_WINDOW_BINDING')
    report['applicationErrorCode'] = response['code']
    report['uploadWindowMilliseconds'] = elapsed

    recording = scope / 'diagnostics/upload.jfr'
    original, digest = file_input(recording, 10003, 64 << 20)
    need(original.st_size == h['RECORDING_BYTES'] and digest == h['RECORDING_SHA'],
         'EXACT_RETAINED_JFR_DIGEST')
    report['recordingSha256'] = digest
    path = scope / 'diagnostics/events.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 10003 and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size == JSON_BYTES, 'EXACT_JFR_JSON_FILE_BINDING')
            report['retainedJsonBytes'] = before.st_size
            lower, upper = t0.st_mtime_ns / 1e9 - 0.25, t1.st_mtime_ns / 1e9 + 0.25
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                data.madvise(mmap.MADV_SEQUENTIAL)
                handshakes = {}
                exceptions = []

                def observe():
                    for event in selected(data, lower, upper, report):
                        observe_transport(event, handshakes, exceptions)
                        yield event

                h['summarize'](observe(), lower, upper, report)
                need((report['eventHeadersScanned'], report['eventHeadersInUploadWindow'],
                      report['exceptionEventsInUploadWindow'], report['s3SdkExceptionEventsInUploadWindow'],
                      report['s3TlsHandshakesInUploadWindow'], report['retainedJsonClosed'])
                     == (10048, 330, 329, 299, 1, True), 'PRIOR_WINDOW_READBACK_MISMATCH')
                groups = transport_groups(handshakes, exceptions)
            need(frame(before) == frame(os.fstat(stream.fileno())) == frame(path.lstat()),
                 'RETAINED_JFR_JSON_CHANGED')
            report['retainedJsonUnchanged'] = True
    finally:
        after, current = file_input(recording, 10003, 64 << 20)
        need(frame(original) == frame(after) and digest == current, 'JFR_RECORDING_CHANGED')
        report['recordingUnchanged'] = True

    report['transportGroups'] = groups
    report['flightRecorderParsed'] = True
    report['status'] = 'ONBOARDING_UPLOAD_JFR_TRANSPORT_READ_BACK'


def main():
    report = {'schema': SCHEMA, 'status': 'HELD', 'flightRecorderParsed': False, 'recordingUnchanged': False,
              'retainedJsonUnchanged': False, 'applicationContainersStarted': 0, 'uploadRequests': 0,
              'decoderContainersStarted': 0, 'acceptanceCreditAdded': 0, 'eventHeadersScanned': 0,
              'eventHeadersInUploadWindow': 0, 'exceptionEventsInUploadWindow': 0,
              's3SdkExceptionEventsInUploadWindow': 0, 's3SdkExceptionEventsInRecording': 0,
              's3TlsHandshakesInUploadWindow': 0}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'HELD'
        reason = str(exc)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]{5,80}', reason) else type(exc).__name__
    # The shared summarizer only receives events selected in the upload window.
    report.pop('s3SdkExceptionEventsInRecording')
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())
