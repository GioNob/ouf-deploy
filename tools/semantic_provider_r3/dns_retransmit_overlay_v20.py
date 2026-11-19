"""Retry UDP timeouts in both sealed R3 v20 DNS entry points."""
from tools.semantic_provider_operation.authorization import require


DNS_TARGETS = ('tools/semantic_provider_dns.py', 'tools/semantic_lease_recovery/dns.py')
UDP_ATTEMPT_SECONDS = 1
UDP_MAX_ATTEMPTS = 3
DRIFT = 'R3_V20_DNS_SOURCE_CONTRACT_DRIFT'


def check_budget(seconds):
    require(type(UDP_ATTEMPT_SECONDS) is int and UDP_ATTEMPT_SECONDS > 0
            and type(UDP_MAX_ATTEMPTS) is int and 1 < UDP_MAX_ATTEMPTS <= 65536
            and UDP_ATTEMPT_SECONDS * UDP_MAX_ATTEMPTS <= seconds,
            'R3_V20_DNS_RETRY_BUDGET_INCOMPATIBLE')


UDP_START = '''def exchange(resolver, port, question, qtype, deadline):
    address = ipaddress.ip_address(resolver)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    ident = int.from_bytes(secrets.token_bytes(2), 'big')
    query = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0)+wire_name(question)+struct.pack('!HH', qtype, 1)
    def remaining():
        value = deadline-time.monotonic()
        if value <= 0: raise DNSDenied('DNS_DEADLINE_EXPIRED')
        return value
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as peer:
            peer.settimeout(remaining()); peer.connect((str(address), port)); peer.send(query)
            raw = peer.recv(65535)
'''

UDP_RETRY = '''def _udp_response(family, address, query, deadline):
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError
        return seconds

    with socket.socket(family, socket.SOCK_DGRAM) as peer:
        peer.settimeout(remaining())
        peer.connect(address)
        peer.settimeout(remaining())
        peer.send(query)
        while True:
            peer.settimeout(remaining())
            raw = peer.recv(65535)
            remaining()
            # A delayed or unrelated datagram cannot satisfy this attempt.
            if len(raw) >= 12 and raw[:2] != query[:2]:
                continue
            return raw


def exchange(resolver, port, question, qtype, deadline):
    address = ipaddress.ip_address(resolver)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    question_wire = wire_name(question) + struct.pack('!HH', qtype, 1)

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise DNSDenied('DNS_DEADLINE_EXPIRED')
        return seconds

    used_ids = set()
    try:
        for _ in range(UDP_MAX_ATTEMPTS):
            remaining()
            # Draw uniformly from the IDs still unused by this exchange.
            ident = secrets.randbelow(65536 - len(used_ids))
            for previous in sorted(used_ids):
                if ident < previous:
                    break
                ident += 1
            used_ids.add(ident)
            query = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + question_wire
            attempt_deadline = min(deadline, time.monotonic() + UDP_ATTEMPT_SECONDS)
            try:
                raw = _udp_response(family, (str(address), port), query, attempt_deadline)
            except TimeoutError:
                continue
            break
        else:
            remaining()
            raise DNSDenied('DNS_RESOLVER_TRANSPORT_FAILED')
'''


def sources_v20(sources, source_map):
    out = dict(sources)
    # One input blob may back the recovery module and both owner aliases.
    for path in dict.fromkeys(source_map[target] for target in DNS_TARGETS):
        raw = out[path]
        eol = b'\r\n' if b'\r\n' in raw else b'\n'

        def edit(old, new):
            nonlocal raw
            before = old.encode('ascii').replace(b'\n', eol)
            require(raw.count(before) == 1, DRIFT)
            raw = raw.replace(before, new.encode('ascii').replace(b'\n', eol))

        edit(UDP_START, f'UDP_ATTEMPT_SECONDS = {UDP_ATTEMPT_SECONDS}\n'
             f'UDP_MAX_ATTEMPTS = {UDP_MAX_ATTEMPTS}\n\n\n' + UDP_RETRY)
        edit("                peer.settimeout(remaining()); peer.connect((str(address), port)); "
             "peer.sendall(struct.pack('!H', len(query))+query)",
             "                peer.settimeout(remaining())\n"
             "                peer.connect((str(address), port))\n"
             "                peer.settimeout(remaining())\n"
             "                peer.sendall(struct.pack('!H', len(query)) + query)")
        edit('        return parsed\n    except OSError:',
             '        remaining()\n        return parsed\n    except OSError:')
        out[path] = raw
    return out
