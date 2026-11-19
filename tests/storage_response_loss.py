"""Single-use loopback relay: consume a successful PUT response, expose only EOF.

Test fixture only. The diagnostic receipt never authorizes catalog reconciliation.
"""
import hashlib
import http.client
import socket
import threading


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_request(stream, path, host, body):
    lines = []
    size = 0
    while True:
        line = stream.readline(8193)
        size += len(line)
        require(size <= 8192 and line.endswith(b'\r\n'), 'BOUNDED_CRLF_HEADERS_REQUIRED')
        lines.append(line)
        if line == b'\r\n':
            break
    require(lines[0] == ('PUT ' + path + ' HTTP/1.1\r\n').encode('ascii'), 'EXACT_PUT_PATH_REQUIRED')
    headers = {}
    for line in lines[1:-1]:
        key, sep, value = line.partition(b':')
        key = key.lower()
        require(sep and key not in headers and key.strip() == key, 'UNIQUE_HEADERS_REQUIRED')
        headers[key] = value.strip()
    require(headers.get(b'host') == host.encode('ascii'), 'EXACT_HOST_REQUIRED')
    require(b'transfer-encoding' not in headers and b'expect' not in headers,
            'FIXED_LENGTH_REQUEST_REQUIRED')
    require(headers.get(b'content-length') == str(len(body)).encode(), 'EXACT_BODY_LENGTH_REQUIRED')
    actual = stream.read(len(body))
    require(actual == body, 'EXACT_BODY_REQUIRED')
    return b''.join(lines) + actual


def lose_response(path, body, headers, *, backend_port=18333):
    require(type(backend_port) is int and 0 < backend_port < 65536, 'VALID_LOOPBACK_PORT_REQUIRED')
    require(isinstance(body, bytes) and 0 < len(body) <= 4096, 'BOUNDED_FIXTURE_BODY_REQUIRED')
    require(path.startswith('/') and '\r' not in path and '\n' not in path, 'VALID_PATH_REQUIRED')
    host = headers['host']
    receipt = {'forwardedRequests': 0, 'downstreamResponseBytes': 0}
    errors = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)

    def relay():
        try:
            with listener:
                downstream, _ = listener.accept()
            with downstream:
                downstream.settimeout(5)
                with downstream.makefile('rb') as stream:
                    raw = read_request(stream, path, host, body)
                    with socket.create_connection(('127.0.0.1', backend_port), timeout=5) as upstream:
                        upstream.sendall(raw)
                        receipt['forwardedRequests'] += 1
                        with http.client.HTTPResponse(upstream) as response:
                            response.begin()
                            require(response.status == 200, 'UPSTREAM_PUT_200_REQUIRED')
                            payload = response.read(4097)
                            require(len(payload) <= 4096 and response.isclosed()
                                    and response.length in (0, None), 'COMPLETE_BOUNDED_RESPONSE_REQUIRED')
                            receipt['upstreamStatus'] = response.status
                            receipt['upstreamResponseBytes'] = len(payload)
                    # No status line, headers or body are sent to the original client.
                    downstream.shutdown(socket.SHUT_RDWR)
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=relay, name='single-put-response-loss')
    conn = http.client.HTTPConnection('127.0.0.1', listener.getsockname()[1], timeout=12)
    worker.start()
    client_error = None
    try:
        conn.request('PUT', path, body=body, headers=headers)
        conn.getresponse()
    except Exception as error:
        client_error = type(error).__name__
    finally:
        conn.close()
        worker.join(timeout=15)
        listener.close()
    require(not worker.is_alive(), 'RELAY_MUST_TERMINATE')
    if errors:
        raise RuntimeError('RESPONSE_LOSS_INJECTION_FAILED: ' + str(errors[0])) from errors[0]
    require(client_error == 'RemoteDisconnected', 'CLIENT_MUST_OBSERVE_RESPONSE_LOSS')
    require(receipt['forwardedRequests'] == 1, 'EXACTLY_ONE_FORWARDED_PUT_REQUIRED')
    return {**receipt, 'clientError': client_error, 'relayTerminated': True,
            'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
