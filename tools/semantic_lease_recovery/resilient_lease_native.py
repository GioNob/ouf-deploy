"""Real DNS/nft/journal/lock with hours simulated, disposable CI netns only.

No VPS metadata, claim or authority is imported. Recovery scope is synthetic.
Kernel expiry remains real; virtual time only advances while sets are empty.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'semantic_lease_activation'))
from test_activation_native import fixture, run, load_compiler
import activation_core as core
from bounded_recovery import Policy, Recovery, Permanent
from recovery_journal import Journal
from resilient_lease_adapter import LeaseAdapter
import dns

class Clock:
    offset = 0
    def __call__(self): return time.time() + self.offset, time.monotonic() + self.offset
    def mono(self): return time.monotonic() + self.offset
    def advance(self, seconds): self.offset += max(0, seconds)

def main():
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    source = Path(sys.argv[1]).resolve(); nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]; probe.close()
    clock = Clock(); counts = {'dns': 0}; control = {'ttl': 4, 'valid': True}; server = None
    def start_server():
        nonlocal server
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); server.bind(('127.0.0.1', port))
        def serve():
            while True:
                try: query, peer = server.recvfrom(4096)
                except OSError: return
                counts['dns'] += 1
                end = 12
                while query[end]: end += query[end] + 1
                end += 1; qtype = struct.unpack('!H', query[end:end+2])[0]
                raw = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                                      '1.1.1.1' if qtype == 1 else '2606:4700:4700::1111')
                reply = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:end+4]
                reply += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, control['ttl'], len(raw)) + raw
                server.sendto(reply, peer)
        threading.Thread(target=serve, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ouf-resilient-lease-ci-', dir='/etc') as tmp:
        root = Path(tmp); root.chmod(0o700)
        owner, _ = fixture(root, source, nft); owner['dns']['resolverPort'] = port
        retained = {name: (root/'source'/name).read_bytes() for name in owner['sourceHashes']}
        core.create(root/'old-consumed-claim', b'CI_OLD_CONSUMED_CLAIM_NOT_REPLAYED')
        def read(path, expected):
            raw = Path(path).read_bytes(); assert hashlib.sha256(raw).hexdigest() == expected; return raw
        modules, _ = core.load_installed(owner, root/'source', read)
        from nft_seconds_backend import NftBackend
        backend = NftBackend([nft], owner['kernel'], owner['expectedStructureHash'], 5, clock=clock.mono)
        c = modules['semantic_provider_lease_coordination']
        worker = modules['semantic_provider_lease_owner'].LeaseOwner(owner['kernel'], owner['dns'], backend, clock=clock.mono)
        journal = c.PrivateJournal(root/'journal.json')
        coordinator = c.Coordinator(worker, owner['binding'], lambda: c.hold_common_lock(root/'common.lock'), journal.read, journal.write)
        compiler = load_compiler(HERE/'readback_margin_compiler.py')
        original_observe = dns.observe
        def observe(*args, **kw):
            # Prove native common lease lock is free during DNS, including outage.
            fd = os.open(root/'common.lock', os.O_RDWR)
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(fd)
            return original_observe(*args, **kw)
        dns.observe = observe
        def guard():
            if not control['valid']: raise Permanent('AUTHORITY_REVOKED')
        def custody(): backend.verify_ownership(owner['kernel'])
        adapter = LeaseAdapter(coordinator, dns, compiler, guard, custody, clock.mono)
        retry_dir = root/'retry'; retry_dir.mkdir(mode=0o700)
        retry = Journal(retry_dir)
        recovery = Recovery(retry, adapter, Policy(), 'a'*64, 'b'*64, clock, lambda: .5)
        retry.initialize(recovery.initial()); beginning = clock.mono()
        row = recovery.step()
        assert row['state'] == 'RETRY_WAIT' and row['reason'] == 'DNS_UNAVAILABLE'
        outage_cycles = 1
        while clock.mono() - beginning < 4*3600:
            assert not any(backend.read_sets(owner['kernel']).values())
            assert journal.read()['state'] == 'QUIESCED' and journal.read()['leaseAuthorized'] is False
            # Budget and wait progress survive reopening the real private journal.
            assert Journal(retry_dir).read()['attempts'] == row['attempts']
            clock.advance(row['nextMonotonic'] - clock.mono())
            row = recovery.step(); outage_cycles += 1
            assert row['state'] == 'RETRY_WAIT' and row['reason'] == 'DNS_UNAVAILABLE'
        print('CI_RESILIENCE_OUTAGE=' + json.dumps({'simulatedHours': 4, 'attempts': outage_cycles,
              'setsEmptyThroughout': True, 'realTransportFailure': True, 'journalReopened': True}), flush=True)
        start_server()
        clock.advance(row['nextMonotonic'] - clock.mono())
        row = recovery.step()
        assert row['state'] == 'RETRY_WAIT' and row['reason'] == 'DNS_WINDOW_TOO_SHORT'
        assert counts['dns'] == 4 and not any(backend.read_sets(owner['kernel']).values())
        control['ttl'] = 30; clock.advance(row['nextMonotonic'] - clock.mono())
        row = recovery.step(); assert row['state'] == 'ACTIVE'
        sets = backend.read_sets(owner['kernel'])
        assert len(sets) == 4 and all(sets.values()) and all(0 < ttl <= 30 for v in sets.values() for ttl in v.values())
        assert journal.read()['state'] == 'LEASE_READY' and journal.read()['leaseAuthorized'] is True
        assert journal.read()['startAuthorized'] is False and counts['dns'] == 8
        calls = counts['dns']; recovery.step(); assert counts['dns'] == calls
        print('CI_RESILIENCE_RECOVERY=FRESH_DNS_TWO_FAMILIES_POSITIVE_NO_REPLAY COMMON_LOCK_FREE_DURING_DNS=true', flush=True)
        # A new synthetic episode demonstrates revocation while in retry wait.
        second = root/'retry2'; second.mkdir(mode=0o700); control['ttl'] = 4
        r2 = Journal(second); e2 = Recovery(r2, adapter, Policy(), 'c'*64, 'b'*64, clock, lambda: .5); r2.initialize(e2.initial())
        row = e2.step(); assert row['state'] == 'RETRY_WAIT'
        before = counts['dns']; control['valid'] = False
        row = e2.step(); assert row['state'] == 'BLOCKED' and row['reason'] == 'AUTHORITY_REVOKED'
        assert counts['dns'] == before and not any(backend.read_sets(owner['kernel']).values())
        assert (root/'old-consumed-claim').read_bytes() == b'CI_OLD_CONSUMED_CLAIM_NOT_REPLAYED'
        assert all((root/'source'/name).read_bytes() == raw for name, raw in retained.items())
        print('CI_RESILIENCE_REVOCATION=BLOCKED_WHILE_PAUSED_NO_QUERY_OLD_CLAIM_AND_SOURCES_PRESERVED TARGET_ACTIONS=0', flush=True)
        server.close()

if __name__ == '__main__': main()
