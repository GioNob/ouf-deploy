"""Real DNS + nft + private journal/flock, disposable CI netns only."""
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
sys.path.insert(0, str(HERE.parent/'semantic_lease_activation'))
from test_activation_native import fixture, run
import activation_core as core
from adaptive_supervisor import supervise


def main():
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    source = Path(sys.argv[1]).resolve()
    nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 15353)); udp.settimeout(.2)
    done = threading.Event(); counts = {'queries': 0}
    def serve():
        while not done.is_set():
            try: query, peer = udp.recvfrom(4096)
            except socket.timeout: continue
            counts['queries'] += 1
            end = 12
            while query[end]: end += query[end] + 1
            end += 1
            qtype = struct.unpack('!H', query[end:end+2])[0]
            payload = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                                      '1.1.1.1' if qtype == 1 else '2606:4700:4700::1111')
            reply = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:end+4]
            reply += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 8, len(payload)) + payload
            udp.sendto(reply, peer)
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    with tempfile.TemporaryDirectory(prefix='ouf-adaptive-ci-', dir='/etc') as tmp:
        root = Path(tmp); root.chmod(0o700)
        owner, _ = fixture(root, source, nft)
        def read(path, expected):
            raw = Path(path).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == expected
            return raw
        compiler = HERE.parent/'semantic_lease_activation/materialize_southbound_lease_refresh.py'
        modules, saved = core.load_installed(owner, root/'source', read,
            {'path': str(compiler), 'sha256': core.digest(compiler.read_bytes()),
             'originalSha256': owner['sourceHashes']['tools/materialize_southbound_lease_refresh.py']})
        c = modules['semantic_provider_lease_coordination']
        backend = modules['semantic_provider_lease_nft'].NftBackend([nft], owner['kernel'], owner['expectedStructureHash'], 5)
        worker = modules['semantic_provider_lease_owner'].LeaseOwner(owner['kernel'], owner['dns'], backend)
        journal = c.PrivateJournal(root/'journal.json')
        coordinator = c.Coordinator(worker, owner['binding'], lambda: c.hold_common_lock(root/'common.lock'), journal.read, journal.write)
        old = journal.read()
        # Synthetic NEW authority for this disposable fixture only.
        with coordinator.hold_lock():
            journal.write(old, {**old, 'state': 'LEASE_READY', 'leaseAuthorized': True})
        core.create(root/'old-consumed-claim', b'OLD_CLAIM_NOT_RESET')
        cycles = []; waits = []
        def log(message, **kw):
            if message.startswith(('SEMANTIC_COORDINATED_START=', 'SEMANTIC_COORDINATED_CYCLE=')):
                sets = backend.read_sets(owner['kernel'])
                assert len(sets) == 4 and all(sets.values())
                assert all(0 < ttl < 8 for members in sets.values() for ttl in members.values())
                cycles.append(counts['queries'])
        class Stop:
            def is_set(self): return False
            def wait(self, seconds):
                waits.append(seconds)
                assert 0 < seconds < 4, 'actual short TTL must override 15-second ceiling poll'
                if len(cycles) == 6: return True
                time.sleep(seconds); return False
        try:
            supervise(coordinator, lambda: None, 15, Stop(), log=log)
            assert len(cycles) == 6 and len(waits) == 6
            assert counts['queries'] >= 24 and all(b > a for a, b in zip(cycles, cycles[1:]))
            assert journal.read()['state'] == 'QUIESCED' and journal.read()['leaseAuthorized'] is False
            assert not any(backend.read_sets(owner['kernel']).values())
            assert (root/'old-consumed-claim').read_bytes() == b'OLD_CLAIM_NOT_RESET'
            prior = counts['queries']
            try: coordinator.fresh_start()
            except c.CoordinationDenied: pass
            else: raise AssertionError('consumed authority rearmed')
            assert counts['queries'] == prior
            assert all((root/'source'/name).read_bytes() == raw for name, raw in saved.items())
            print('ADAPTIVE_LEASE_NATIVE=PASS REAL_DNS_NFT_FLOCK=true CYCLES=6 DNS_TTL_SECONDS=8 CONFIGURED_POLL_SECONDS=15 FRESH_QUERIES_EVERY_CYCLE=true STOP_REVOKED=true REARM_DENIED=true INSTALLED_SOURCES_UNCHANGED=true TARGET_ACTIONS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            done.set(); thread.join(2); udp.close()
            for family in ('inet', 'bridge'):
                run([nft, 'delete', 'table', family, owner['kernel']['tableName']], check=False)


if __name__ == '__main__': main()
