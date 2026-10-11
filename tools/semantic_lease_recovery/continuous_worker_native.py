"""Actual systemd worker + DNS/nft; only authority/metadata are CI fixtures."""
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
import traceback
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'semantic_lease_activation'))
from test_activation_native import fixture, run, load_compiler
sys.path.insert(0, str(HERE))
import activation_core as core
from bounded_recovery import Policy, Recovery, Permanent
from recovery_journal import Journal
from continuous_supervisor import RenewingLeaseAdapter, Supervisor
import dns


class Clock:
    offset = 0
    def __call__(self): return time.time() + self.offset, time.monotonic() + self.offset
    def mono(self): return time.monotonic() + self.offset


def child(root):
    owner = json.loads((root / 'owner.json').read_bytes())
    clock = Clock()
    def read(path, expected):
        raw = Path(path).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        return raw
    modules, _ = core.load_installed(owner, root / 'source', read)
    from deadline_backend import DeadlineNftBackend
    backend = DeadlineNftBackend([owner['nft']], owner['kernel'],
                                owner['expectedStructureHash'], 5, clock=clock.mono)
    c = modules['semantic_provider_lease_coordination']
    worker = modules['semantic_provider_lease_owner'].LeaseOwner(
        owner['kernel'], owner['dns'], backend, clock=clock.mono)
    journal = c.PrivateJournal(root / 'journal.json')
    coordinator = c.Coordinator(worker, owner['binding'],
        lambda: c.hold_common_lock(root / 'common.lock'), journal.read, journal.write)
    compiler = load_compiler(HERE / 'readback_margin_compiler.py')
    original_exchange = dns.exchange
    def exchange(*args, **kw):
        for path in [root / 'common.lock', root / 'retry' / 'recovery.lock']:
            fd = os.open(path, os.O_RDWR)
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(fd)
        return original_exchange(*args, **kw)
    dns.exchange = exchange
    def guard():
        if (root / 'revoked').exists(): raise Permanent('AUTHORITY_REVOKED')
        if time.time() >= json.loads((root / 'scope.json').read_bytes())['expiresAt']:
            raise Permanent('AUTHORITY_EXPIRED')
    adapter = RenewingLeaseAdapter(coordinator, dns, compiler, guard,
        lambda: backend.verify_ownership(owner['kernel']), clock.mono)
    # Diagnostic only in this synthetic CI fixture, never in the target worker.
    for method in ('prepare', 'publish', 'prepare_renewal', 'publish_renewal'):
        original = getattr(adapter, method)
        def debug(*args, _original=original, **kw):
            try: return _original(*args, **kw)
            except (Permanent,):
                raise
            except Exception:
                traceback.print_exc()
                raise
        setattr(adapter, method, debug)
    retry = Journal(root / 'retry')
    recovery = Recovery(retry, adapter, Policy(), 'a'*64, 'b'*64, clock, lambda: .5)
    supervisor = Supervisor(recovery, coordinator, 1)
    event = threading.Event()
    core.install_signal_handlers(event)
    last = {}
    class Stop:
        def is_set(self): return event.is_set()
        def wait(self, seconds):
            for path in [root / 'common.lock', root / 'retry' / 'recovery.lock']:
                fd = os.open(path, os.O_RDWR)
                try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(fd)
            if last.get('state') == 'RETRY_WAIT':
                assert not any(backend.read_sets(owner['kernel']).values())
                assert journal.read()['state'] == 'QUIESCED'
                row = retry.read()
                clock.offset += max(0, row['nextMonotonic'] - clock.mono())
                return event.wait(.04)
            return event.wait(min(seconds, .1) if last.get('state') != 'ACTIVE' else seconds)
    def observe(row):
        last.clear(); last.update(row)
        row = {**row, 'virtualOffsetSeconds': clock.offset,
               'pid': os.getpid(), 'journalAttempts': retry.read()['attempts']}
        core.status(root, row)
        if row['state'] == 'RETRY_WAIT' and clock.offset >= 4*3600:
            (root / 'outage-four-hours').touch(exist_ok=True)
    supervisor.serve(Stop(), observe)
    return 0


def main(source):
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    port = server.getsockname()[1]
    control = {'ttl': 30, 'queries': 0}
    def serve():
        while True:
            try: query, peer = server.recvfrom(4096)
            except OSError: return
            control['queries'] += 1
            end = 12
            while query[end]: end += query[end] + 1
            end += 1
            qtype = struct.unpack('!H', query[end:end+2])[0]
            raw = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                                  '1.1.1.1' if qtype == 1 else '2606:4700:4700::1111')
            reply = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:end+4]
            reply += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, control['ttl'], len(raw)) + raw
            server.sendto(reply, peer)
    threading.Thread(target=serve, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ouf-continuous-worker-ci-', dir='/etc') as tmp:
        root = Path(tmp); root.chmod(0o700)
        owner, _ = fixture(root, source, nft)
        owner['dns']['resolverPort'] = port
        owner['nft'] = nft
        original = {name: (root/'source'/name).read_bytes() for name in owner['sourceHashes']}
        core.create(root/'owner.json', owner)
        core.create(root/'scope.json', {'expiresAt': time.time() + 180})
        core.create(root/'old-consumed-r10-claim', b'CI_ONLY_OLD_CLAIM_PRESERVED')
        retry_dir = root/'retry'; retry_dir.mkdir(mode=0o700)
        retry = Journal(retry_dir)
        recovery = Recovery(retry, None, Policy(), 'a'*64, 'b'*64,
                            lambda: (time.time(), time.monotonic()), lambda: .5)
        retry.initialize(recovery.initial())
        unit = 'ouf-ci-continuous-' + uuid.uuid4().hex[:8] + '.service'
        args = ['/usr/bin/systemd-run', '--unit=' + unit, '--service-type=exec', '--no-block',
                '--property=Restart=no', '--property=KillMode=control-group',
                '--property=NetworkNamespacePath=/proc/' + str(os.getpid()) + '/ns/net',
                str(Path(sys.executable).resolve()), '-I', '-B', str(Path(__file__).resolve()),
                '--child', str(root)]
        def wait_for(predicate, timeout=50):
            deadline = time.monotonic() + timeout
            while True:
                value = json.loads((root/'worker-status.json').read_bytes()) if (root/'worker-status.json').exists() else {}
                if predicate(value): return value
                if time.monotonic() >= deadline:
                    print(run(['/usr/bin/journalctl', '-u', unit, '--no-pager'], check=False).stdout)
                    raise RuntimeError('CI_WORKER_STAGE_TIMEOUT_' + json.dumps(value))
                time.sleep(.04)
        try:
            run(args)
            first = wait_for(lambda v: v.get('renewals', 0) >= 2)
            assert first['ready'] and first['attempts'] == 1
            control['ttl'] = 4
            paused = wait_for(lambda v: v.get('state') == 'RETRY_WAIT')
            for family in ('inet', 'bridge'):
                tables = json.loads(run([nft, '-j', 'list', 'table', family, owner['kernel']['tableName']]).stdout)
                assert not any(v.get('set', {}).get('elem') for v in tables['nftables'])
            wait_for(lambda v: (root/'outage-four-hours').exists())
            control['ttl'] = 30
            recovered = wait_for(lambda v: v.get('ready') is True and v.get('attempts', 0) > 1)
            assert recovered['pid'] == first['pid']
            assert recovered['virtualOffsetSeconds'] >= 14400
            assert recovered['incidentRef'] == first['incidentRef']
            before = recovered['renewals']
            wait_for(lambda v: v.get('renewals', 0) > before)
            print('CI_CONTINUOUS_WORKER=HEALTHY_OUTAGE_FOUR_VIRTUAL_HOURS_RECOVERY_HEALTHY SAME_PROCESS=true REAL_SYSTEMD_DNS_NFT=true LOCKS_FREE=true', flush=True)
            control['ttl'] = 4
            exhausted = wait_for(lambda v: v.get('state') == 'PAUSED_EXHAUSTED')
            assert exhausted['attempts'] > recovered['attempts']
            before = control['queries']; time.sleep(.35)
            assert control['queries'] == before
            props = run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID,NRestarts,Restart']).stdout
            assert 'ActiveState=active' in props and 'Restart=no' in props and 'NRestarts=0' in props
            (root/'revoked').touch()
            wait_for(lambda v: v.get('reason') == 'AUTHORITY_REVOKED')
            assert control['queries'] == before
            assert (root/'old-consumed-r10-claim').read_bytes() == b'CI_ONLY_OLD_CLAIM_PRESERVED'
            assert all((root/'source'/name).read_bytes() == raw for name, raw in original.items())
            # Concurrent process cannot get the invocation lock or reset budget.
            repeated = run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                            '--child', str(root)], check=False)
            assert repeated.returncode != 0 and retry.read()['attempts'] == exhausted['attempts']
            run(['/usr/bin/systemctl', 'stop', unit])
            assert json.loads((root/'journal.json').read_bytes())['state'] == 'QUIESCED'
            print('CI_CONTINUOUS_WORKER=EXHAUSTED_ALIVE_REVOKED_NO_QUERY CONCURRENT_WORKER_DENIED=true OLD_CLAIM_SOURCES_PRESERVED=true TARGET_ACTIONS=0', flush=True)
        finally:
            run(['/usr/bin/systemctl', 'stop', unit], check=False)
            run(['/usr/bin/systemctl', 'reset-failed', unit], check=False)
            for family in ('inet', 'bridge'):
                run([nft, 'delete', 'table', family, owner['kernel']['tableName']], check=False)
            server.close()


if __name__ == '__main__':
    if sys.argv[1] == '--child': sys.exit(child(Path(sys.argv[2])))
    main(Path(sys.argv[1]).resolve())
