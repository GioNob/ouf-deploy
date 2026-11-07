"""Focused HTTP fixture for the current-file copy command; no Docker or external service."""
import hashlib
import http.server
import importlib.util
from pathlib import Path
import sys
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit
from xml.sax.saxutils import escape

spec = importlib.util.spec_from_file_location('copy_command', Path(sys.argv[1]))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.DEADLINE = time.monotonic() + 30
source = {'managed-files/a': (b'id,label\n1,A\n', {'content-type': 'text/csv'}),
          'managed-files/b': (b'id,label\n2,B\n', {'content-type': 'text/csv', 'x-amz-meta-test': 'preserve'})}
target = {'managed-files/a': source['managed-files/a']}
tagged = set()
puts = []


def etag(body):
    return '"' + hashlib.md5(body).hexdigest() + '"'


def handler(objects, role):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body, metadata=None):
            self.send_response(status)
            for key, value in (metadata or {}).items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def check(self, body):
            assert 'Credential=fixture-' + role + '/' in self.headers['Authorization']
            assert self.headers['x-amz-content-sha256'] == hashlib.sha256(body).hexdigest()

        def do_GET(self):
            self.check(b'')
            uri = urlsplit(self.path)
            query = parse_qs(uri.query, keep_blank_values=True)
            if 'list-type' in query:
                rows = ''.join('<Contents><Key>' + escape(key) + '</Key><ETag>' + escape(etag(body))
                               + '</ETag><LastModified>2026-11-07T00:00:00Z</LastModified><Size>'
                               + str(len(body)) + '</Size></Contents>' for key, (body, _) in sorted(objects.items()))
                return self.reply(200, ('<ListBucketResult><Name>' + m.BUCKET
                    + '</Name><IsTruncated>false</IsTruncated>' + rows + '</ListBucketResult>').encode())
            key = unquote(uri.path[len('/' + m.BUCKET + '/'):])
            if key not in objects:
                return self.reply(404, b'<Error><Code>NoSuchKey</Code></Error>')
            if 'tagging' in query:
                tags = '<Tag><Key>retained</Key><Value>yes</Value></Tag>' if key in tagged else ''
                return self.reply(200, ('<Tagging><TagSet>' + tags + '</TagSet></Tagging>').encode())
            body, metadata = objects[key]
            if self.headers.get('If-Match', etag(body)) != etag(body):
                return self.reply(412, b'<Error><Code>PreconditionFailed</Code></Error>')
            return self.reply(200, body, dict(metadata, ETag=etag(body)))

        def do_PUT(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            self.check(body)
            key = unquote(urlsplit(self.path).path[len('/' + m.BUCKET + '/'):])
            assert self.headers.get('If-None-Match') == '*'
            if key in objects:
                return self.reply(412, b'<Error><Code>PreconditionFailed</Code></Error>')
            objects[key] = body, {k.lower(): v for k, v in self.headers.items()
                                 if k.lower() in m.METADATA or k.lower().startswith('x-amz-meta-')}
            puts.append(key)
            self.reply(200, b'')
    return Handler


servers = [http.server.HTTPServer(('127.0.0.1', 0), handler(objects, role))
           for objects, role in ((source, 'source'), (target, 'target'))]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
clients = [m.S3('127.0.0.1', 'localhost', server.server_port, ('fixture-' + role, 'secret'))
           for server, role in zip(servers, ('source', 'target'))]


def report():
    return {'objectsAlreadyMatched': 0, 'objectsCopiedAndVerified': 0, 'putAttempts': 0}


try:
    src, dst = clients
    r = report(); rows = m.listing(src, r)
    # The real fsync path is exercised with a private temporary journal.
    import tempfile
    def align(rows, r):
        with tempfile.TemporaryFile(mode='w+') as journal:
            return m.align(src, dst, rows, r, journal)
    manifest = align(rows, r)
    assert target == source and r['objectsAlreadyMatched'] == 1 and r['objectsCopiedAndVerified'] == 1
    assert m.listing(src, r) == rows and len(manifest) == 2
    again = report(); align(rows, again)
    assert again['objectsAlreadyMatched'] == 2 and again['putAttempts'] == 0 and len(puts) == 1
    target['managed-files/a'] = (b'different', {'content-type': 'text/csv'})
    try:
        align(rows, report()); raise AssertionError('target difference accepted')
    except RuntimeError as e:
        assert str(e) == 'EXISTING_TARGET_OBJECT_DIFFERS'
    target['managed-files/a'] = source['managed-files/a']
    del target['managed-files/b']; tagged.add('managed-files/b')
    try:
        align(rows, report()); raise AssertionError('new tags silently lost')
    except RuntimeError as e:
        assert str(e) == 'NEW_TAGGED_OBJECT_REQUIRES_COPY_PATH'
    tagged.clear(); source['managed-files/a'] = (b'changed after list', {'content-type': 'text/csv'})
    try:
        align(rows, report()); raise AssertionError('source drift accepted')
    except RuntimeError as e:
        assert str(e) == 'S3_REQUEST_NOT_SUCCESSFUL'
    assert len(puts) == 1
    print('PASS: copy missing object with body/metadata readback; reuse existing; deny overwrite, new tags, and source ETag drift.')
    print('Scope: local HTTP fixture only; VPS routes, TLS and source identity permissions are not tested here.')
finally:
    for server in servers:
        server.shutdown(); server.server_close()
