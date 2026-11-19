"""Bound DNS fan-out across flows, address types, resolvers and overlapping rounds."""
from tools.semantic_provider_operation.authorization import require
from .dns_retransmit_overlay_v20 import DNS_TARGETS


# The tag distinguishes transport/direction. Both slack values are signed
# seconds (attempt, round). No identifier, hostname, port or address is copied.
EVENT_FIELDS = """    'dnsSend': 'resolver flow kind depth attempt signed signed',
    'dnsRecv': 'resolver flow kind depth attempt signed signed bool',
    'dnsTimeout': 'resolver flow kind depth attempt signed signed',
    'dnsTcpFallback': 'resolver flow kind depth attempt signed signed',
    'dnsTcpSend': 'resolver flow kind depth attempt signed signed',
    'dnsTcpRecv': 'resolver flow kind depth attempt signed signed',
"""
INDEX_LIMITS = "'resolver': 7, 'kind': 1, 'depth': 8, 'attempt': 3, "


COLLECT = '''def _collect(requests, resolvers, resolver_port, deadline, query, monotonic, thread_factory, timing=None):
    jobs = deque((ri, fi, ti) for fi, request in enumerate(requests) for ti in range(2)
                 for ri, resolver in enumerate(resolvers) if resolver in request[4])
    lock = threading.Lock()
    closed = False
    parts = {}

    def resolve(ri, fi, ti):
        resolver = resolvers[ri]
        _, host, _, networks, _ = requests[fi]
        qtype = (1, 28)[ti]
        negatives = [] if timing is not None else None

        def record(tag, attempt, at, attempt_slack, round_slack, *flags):
            with lock:
                if not closed and monotonic() < deadline:
                    timing.event(tag, ri, fi, ti, _trace.depth, attempt,
                                 attempt_slack, round_slack, *flags, at=at)

        def bounded(*args):
            with lock:
                if closed or monotonic() >= deadline:
                    raise DNSDenied('DNS_DEADLINE_EXPIRED')
            answer = query(*args)
            if monotonic() >= deadline:
                raise DNSDenied('DNS_DEADLINE_EXPIRED')
            return answer

        _trace.record = record if timing is not None else None
        try:
            value = resolve_type(resolver, resolver_port, host, qtype, deadline, bounded, soa_ttls=negatives)
            _addresses(value['addresses'], networks)
            return value, min(negatives) if negatives else None
        except DNSDenied as error:
            return str(error), None
        except Exception:
            return 'DNS_WORKER_INTEGRITY_UNPROVEN', None
        finally:
            del _trace.record

    def worker():
        while True:
            with lock:
                if closed or not jobs or monotonic() >= deadline:
                    return
                key = jobs.popleft()
            result = resolve(*key)
            with lock:
                if closed or monotonic() >= deadline:
                    return
                parts[key] = result

    threads = []
    try:
        with _workers_lock:
            _workers.difference_update([t for t in _workers if not t.is_alive()])
            slots = min(len(jobs), 8 - len(_workers))
            for _ in range(slots):
                thread = thread_factory(target=worker, args=(), daemon=True)
                thread.start()
                _workers.add(thread)
                threads.append(thread)
        for thread in threads:
            thread.join(max(0, deadline - monotonic()))
    finally:
        with lock:
            closed = True

    # Integrity errors in ANY completed half take precedence over missing
    # siblings, including a sibling still running when the round closed.
    for key in sorted(parts):
        value, _ = parts[key]
        if isinstance(value, str) and value not in MISSING:
            raise DNSDenied(value)
    completed = {}
    for ri, resolver in enumerate(resolvers):
        for fi, request in enumerate(requests):
            if resolver not in request[4]:
                continue
            pair = [parts.get((ri, fi, ti), ('DNS_DEADLINE_EXPIRED', None)) for ti in range(2)]
            code = next((v for v, _ in pair if isinstance(v, str)), None)
            if code is not None:
                row = {'resolver': resolver, 'code': code}
            else:
                row = {'resolver': resolver, 'port': resolver_port,
                       'types': {'A': pair[0][0], 'AAAA': pair[1][0]}}
                negatives = [ttl for _, ttl in pair if ttl is not None]
                if negatives:
                    row['_soa'] = min(negatives)
            completed[resolver, fi] = row
    return completed


'''


def apply_dns(out, source_map, edit):
    # V21 intentionally emits identical bytes for the owner and recovery aliases.
    require(len({source_map[t] for t in DNS_TARGETS}) == 1, 'R3_V22_SOURCE_CONTRACT_DRIFT')
    target = DNS_TARGETS[0]

    def change(old, new):
        edit(target, old, new)

    change('import threading', 'import threading\nfrom collections import deque')
    change('_workers = {}', '_workers = set()\n_trace = threading.local()')
    raw = out[source_map[target]].decode('ascii').replace('\r\n', '\n')
    start = 'def _collect(requests, resolvers, resolver_port, deadline, query, monotonic, thread_factory, measure=False):'
    end = 'def _observe_once('
    require(raw.count(start) == raw.count(end) == 1 and raw.index(start) < raw.index(end),
            'R3_V22_SOURCE_CONTRACT_DRIFT')
    change(raw[raw.index(start):raw.index(end)], COLLECT)
    change('thread_factory, timing is not None)\n    elapsed', 'thread_factory, timing)\n    elapsed')
    change('"""One daemon per resolver for all flows; fresh TTL retries share the budget."""',
           '"""All typed queries and fresh TTL retries share the same round deadline."""')
    change('        parsed = query(resolver', '        _trace.depth = len(chain)\n        parsed = query(resolver')
    change('def _udp_response(family, address, query, deadline):',
           '''def _exchange_event(tag, attempt, attempt_deadline, deadline, *flags):
    record = getattr(_trace, 'record', None)
    if record is not None:
        at = time.monotonic()
        record(tag, attempt, at, attempt_deadline - at, deadline - at, *flags)


def _udp_response(family, address, query, deadline, overall, attempt):''')
    change('        peer.send(query)', "        peer.send(query)\n        _exchange_event('dnsSend', attempt, deadline, overall)")
    change('            remaining()\n            # A delayed or unrelated datagram cannot satisfy this attempt.',
           """            foreign = len(raw) >= 12 and raw[:2] != query[:2]
            _exchange_event('dnsRecv', attempt, deadline, overall, foreign)
            if time.monotonic() >= overall:
                raise DNSDenied('DNS_DEADLINE_EXPIRED')""")
    change('            if len(raw) >= 12 and raw[:2] != query[:2]:', '            if foreign:')
    change('for _ in range(UDP_MAX_ATTEMPTS):', 'for number in range(1, UDP_MAX_ATTEMPTS + 1):')
    change('query, attempt_deadline)\n            except TimeoutError:',
           "query, attempt_deadline, deadline, number)\n            except TimeoutError:\n"
           "                _exchange_event('dnsTimeout', number, attempt_deadline, deadline)")
    change("        if parsed['truncated']:\n            with socket.socket",
           "        if parsed['truncated']:\n"
           "            _exchange_event('dnsTcpFallback', number, attempt_deadline, deadline)\n"
           "            with socket.socket")
    mark = "                peer.sendall(struct.pack('!H', len(query)) + query)"
    change(mark, mark + "\n                _exchange_event('dnsTcpSend', number, attempt_deadline, deadline)")
    mark = '                raw = read(length)'
    change(mark, mark + "\n                _exchange_event('dnsTcpRecv', number, attempt_deadline, deadline)")
