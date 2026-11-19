#!/usr/bin/env python3
"""Bounded synthetic TLS PUT interruption; no retries or cleanup mutations."""
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import quote
import xml.etree.ElementTree as ET

KEY = 'staging/interrupted-stream.bin'
BODY_BYTES = 8 * 1024 * 1024 + 257
PREFIX_BYTES = 4 * 1024 * 1024 + 65537
CHUNK_BYTES = 4 * 1024 * 1024


def require(value, code):
    if not value: raise ValueError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def body(): return hashlib.shake_256(b'OUF OCI33 interrupted streaming PUT v1').digest(BODY_BYTES)


def send_prefix(tls, signer, ip, control):
    require(control.is_dir() and not control.is_symlink() and not any(control.iterdir()), 'FRESH_STREAM_CONTROL_REQUIRED')
    payload = body(); prefix = payload[:PREFIX_BYTES]
    require(0 < CHUNK_BYTES < len(prefix) < len(payload), 'INCOMPLETE_BODY_REQUIRED')
    context = ssl.create_default_context(cafile=str(tls / 'ca.pem'))
    connection = http.client.HTTPConnection('localhost', 18333, timeout=15)
    try:
        raw = socket.create_connection((ip, 18333), timeout=15)
        try: connection.sock = context.wrap_socket(raw, server_hostname='localhost')
        except Exception: raw.close(); raise
        connection.sock.settimeout(30)
        peer = sha(connection.sock.getpeercert(binary_form=True))
        require(peer == sha(ssl.PEM_cert_to_DER_cert((tls / 'server.pem').read_text())), 'EXACT_STREAM_TLS_PEER_REQUIRED')
        path = '/' + signer.BUCKET + '/' + quote(KEY, safe='/~')
        headers = signer.signed_headers('PUT', path, '', payload, signer.APP)
        headers.update({'content-type': 'application/octet-stream', 'content-length': str(len(payload)), 'connection': 'close'})
        connection.putrequest('PUT', path, skip_host=True, skip_accept_encoding=True)
        for key, value in headers.items(): connection.putheader(key, value)
        connection.endheaders(); connection.send(prefix)
        result = {'key': KEY, 'declaredBodyBytes': len(payload), 'declaredBodySha256': sha(payload),
            'sentBodyBytes': len(prefix), 'sentPrefixSha256': sha(prefix), 'omittedBodyBytes': len(payload)-len(prefix),
            'peerSha256': peer, 'putAttempts': 1, 'responseRead': False, 'ackObserved': False}
        (control / 'prefix-sent.tmp').write_text(json.dumps(result)+'\n')
        (control / 'prefix-sent.tmp').replace(control / 'prefix-sent.json')
        deadline = time.monotonic() + 90
        while not (control / 'abort').exists():
            require(time.monotonic() < deadline, 'STREAM_ABORT_BARRIER_BUDGET')
            time.sleep(0.1)
        marker = control / 'abort'
        require(marker.is_file() and not marker.is_symlink() and marker.read_bytes() == b'ABORT\n', 'EXACT_STREAM_ABORT_MARKER_REQUIRED')
        connection.close()
        return {**result, 'clientConnectionClosed': True, 'mutatingRetries': 0}
    finally: connection.close()


def persisted_prefix(root):
    require(root.is_dir() and not root.is_symlink(), 'REGULAR_STREAM_VOLUME_REQUIRED')
    paths = sorted(root.glob('*.dat'))
    require(0 < len(paths) <= 64 and all(p.is_file() and not p.is_symlink() for p in paths), 'BOUNDED_STREAM_DAT_FILES_REQUIRED')
    sizes = {p.name:p.stat().st_size for p in paths}
    require(sum(sizes.values()) <= 128 * 1024 * 1024 and max(sizes.values()) <= 33 * 1024 * 1024, 'STREAM_DAT_BUDGET')
    prefix = body()[:CHUNK_BYTES]; matches = []
    for path in paths:
        with path.open('rb') as source: raw = source.read(sizes[path.name])
        require(len(raw) == sizes[path.name], 'COMPLETE_OBSERVED_DAT_BYTES_REQUIRED')
        offset = raw.find(prefix)
        if offset >= 0: matches.append({'file': path.name, 'offset': offset, 'bytes': len(prefix), 'sha256': sha(prefix)})
    return {'persistedPrefixFound': bool(matches), 'matches': matches, 'datSizes': sizes,
            'observedDatBytes': sum(sizes.values()), 'expectedChunkBytes': len(prefix), 'expectedChunkSha256': sha(prefix)}


def verify_absent(signer, tls, requester, baseline_key, baseline_bytes):
    results = []; peers = set()
    for method in ('GET', 'HEAD'):
        response = requester(signer, tls, signer.APP, method, KEY)
        require(response['status'] == 404, 'INTERRUPTED_OBJECT_MUST_BE_ABSENT')
        peers.add(response['peerSha256'])
        if method == 'GET':
            require(ET.fromstring(response['body']).findtext('Code') == 'NoSuchKey', 'EXPLICIT_NO_SUCH_KEY_REQUIRED')
        else: require(response['body'] == b'', 'EMPTY_HEAD404_REQUIRED')
        results.append({'method': method, 'status': 404, 'code': 'NoSuchKey' if method == 'GET' else None})
    listing = requester(signer, tls, signer.APP, 'GET', query={'list-type':'2','prefix':'staging/','max-keys':'3'})
    require(listing['status'] == 200, 'INTERRUPTED_LIST_SUCCESS_REQUIRED')
    peers.add(listing['peerSha256']); ns={'s':'http://s3.amazonaws.com/doc/2006-03-01/'}; tree=ET.fromstring(listing['body'])
    require(tree.tag=='{'+ns['s']+'}ListBucketResult' and tree.findtext('s:IsTruncated',namespaces=ns)=='false'
            and tree.find('s:NextContinuationToken',ns) is None, 'COMPLETE_INTERRUPTED_LIST_REQUIRED')
    items=[(e.findtext('s:Key',namespaces=ns),e.findtext('s:Size',namespaces=ns)) for e in tree.findall('s:Contents',ns)]
    require(items==[(baseline_key,str(baseline_bytes))] and len(peers)==1, 'BASELINE_ONLY_LIST_AND_SAME_TLS_REQUIRED')
    return {'outcome':'ABSENT_NO_REPLAY','key':KEY,'negativeReads':results,'listedObjects':items,
            'peerSha256':peers.pop(),'mutatingRequests':0}
