"""Real recovery worker/DNS/nft/systemd; metadata fixture in a CI-only netns.

The production worker function runs unchanged. Only container/configuration
metadata and human authority are supplied by the disposable fixture wrapper.
No VPS authority, endpoints, keys or container lifecycle operations exist here.
"""
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
import uuid

import activation_core as core
import activate_finite_r10 as target
sys.path.append(str(Path(__file__).resolve().parent.parent/'semantic_lease_activation'))
from test_activation_native import fixture, run

HERE = Path(__file__).resolve().parent

CHILD = r'''import hashlib,json,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root))
import entry as target
owner=json.loads((root/'owner.json').read_bytes())
value=json.loads((root/'authorization.json').read_bytes())
target.SNAPSHOT_BASE=root.parent
target.APPROVAL_REF='CI_ONLY_NOT_VPS_AUTHORITY'
target.ISSUED_AT=int(time.time())-1
target.EXECUTION_EXPIRES_AT=target.ISSUED_AT+120
target.EXPECTED={}
target.FLOW_HASHES=[]
target.JOURNAL_HASH=value['expectedJournalHash']
target.UNIT=value['serviceUnit']
target.configuration=lambda reader: ({},owner)
original_load=target.load_component
def load(name,path,expected):
 module,raw=original_load(name,path,expected)
 if Path(path).name=='reader.py':
  module.GUARD=root
  module.OWNER_HASH=hashlib.sha256((root/'owner.json').read_bytes()).hexdigest()
  module.TARGETS={} # CI metadata only: no Docker or VPS cohort.
 return module,raw
target.load_component=load
sys.exit(target.worker(sys.argv[2],sys.argv[3]))
'''


def main():
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    source = Path(sys.argv[1]).resolve()
    nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 15353))
    persistent = threading.Event()
    counts = {'queries': 0, 'zeroTtl': 0}

    def serve():
        while True:
            try:
                query, peer = server.recvfrom(4096)
            except OSError:
                return
            counts['queries'] += 1
            end = 12
            labels = []
            while query[end]:
                size = query[end]
                labels.append(query[end+1:end+1+size])
                end += size+1
            end += 1
            qtype = struct.unpack('!H', query[end:end+2])[0]
            question = query[12:end+4]
            # First complete A+AAAA attempt is noncacheable; then entirely
            # fresh answers use different IPv4 values. No address carry-over.
            ttl = 0 if persistent.is_set() or counts['queries'] <= 2 else 30
            if ttl == 0:
                counts['zeroTtl'] += 1
            ipv4 = ('9.9.9.9' if ttl == 0 else '1.1.1.1') if labels[0] == b'provider' else '8.8.8.8'
            data = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                                   ipv4 if qtype == 1 else '2606:4700:4700::1111')
            answer = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question
            answer += bytes((0xc0, 0x0c)) + struct.pack('!HHIH', qtype, 1, ttl, len(data)) + data
            server.sendto(answer, peer)

    threading.Thread(target=serve, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='semantic-finite-lease-recovery-r10-', dir='/etc') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        unit = 'ouf-ci-dns-recovery-' + uuid.uuid4().hex[:8] + '.service'
        target.require_unit_absent(unit)
        owner, journal_hash = fixture(root, source, nft)
        owner['nftSha256'] = core.digest(Path(nft).read_bytes())
        core.create(root/'owner.json', owner)
        core.create(root/'coordinated-configuration.json', owner)
        core.create(root/'old-consumed-claim', b'CI_CONSUMED_CLAIM_PRESERVED')
        original = {name: (root/'source'/name).read_bytes() for name in owner['sourceHashes']}
        for name, source_path in (
                ('entry.py', HERE/'activate_finite_r10.py'),
                ('activate.py', None), ('activation_core.py', HERE/'activation_core.py'),
                ('reader.py', HERE/'reader.py'),
                ('materialize_southbound_lease_refresh.py', HERE/'materialize_southbound_lease_refresh.py'),
                ('dns.py', HERE/'dns.py'), ('nft.py', HERE/'nft_seconds_backend.py'),
                ('supervisor.py', HERE/'adaptive_supervisor.py')):
            core.create(root/name, CHILD.encode() if source_path is None else source_path.read_bytes())
        capsule = {'schema': 'ouf.provider-finite-lease-recovery-authorization.v1',
            'approvalRef': 'CI_ONLY_NOT_VPS_AUTHORITY',
            'ownerConfigurationHash': core.digest(core.encoded(owner)), 'expectedProcessGenerations': {},
            'flowHashes': [], 'expectedJournalHash': journal_hash, 'serviceUnit': unit,
            'programHashes': {name: core.digest((root/name).read_bytes()) for name in (
                'activate.py', 'activation_core.py', 'reader.py', 'materialize_southbound_lease_refresh.py', 'dns.py', 'nft.py', 'supervisor.py')},
            'leaseCompilerBinding': {'path': str(root/'materialize_southbound_lease_refresh.py'),
                'sha256': target.COMPILER_HASH, 'originalSha256': target.OLD_COMPILER_HASH},
            'dnsBinding': {'path': str(root/'dns.py'), 'sha256': target.DNS_HASH, 'originalSha256': target.OLD_DNS_HASH},
            'nftBinding': {'path':str(root/'nft.py'),'sha256':target.NFT_HASH,'originalSha256':target.OLD_NFT_HASH},
            'supervisorBinding': {'path':str(root/'supervisor.py'),'sha256':target.SUPERVISOR_HASH,'originalSha256':target.OLD_SUPERVISOR_HASH}}
        core.create(root/'authorization.json', capsule)
        capsule_hash = core.digest(core.encoded(capsule))
        args = core.service_command(root, capsule_hash, unit=unit, python=str(Path(sys.executable).resolve()))
        args.insert(1, '--property=NetworkNamespacePath=/proc/' + str(os.getpid()) + '/ns/net')
        try:
            run(args)
            deadline = time.monotonic()+50
            while not (root/'cycle-2.json').exists():
                if (root/'worker-denial.json').exists():
                    raise RuntimeError((root/'worker-denial.json').read_text())
                assert time.monotonic() < deadline, 'SECOND_CYCLE_TIMEOUT'
                time.sleep(.2)
            from importlib.util import spec_from_file_location, module_from_spec
            spec = spec_from_file_location('receipt_reader', HERE/'reader.py')
            reader = module_from_spec(spec)
            spec.loader.exec_module(reader)
            _, cycle = target.wait_for_second_cycle(reader, root, timeout=5)
            target.UNIT = unit
            assert all(target.compare(cycle, target.properties(), root).values())
            target.OLD_UNIT = unit  # Disposable service replaces only CI metadata.
            binding = {'path': '/usr/bin/systemctl',
                       'sha256': core.digest(Path('/usr/bin/systemctl').read_bytes())}
            args = ['show', unit,
                    '--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,InvocationID,ExecStart']
            props = target.service_read(reader, binding, args)
            assert b'ActiveState=active' in props and b'Restart=no' in props
            inventory = target.service_read(reader, binding,
                ['list-units', '--type=service', '--all', '--no-legend', '--no-pager'])
            assert unit.encode() in inventory
            print('FINITE_LEASE_R10_SERVICE_PROBES=PASS REAL_SYSTEMCTL=true ROOT_EXECUTABLE_HASH_VERIFIED=true', flush=True)
            assert cycle['refreshCount'] == 2 and cycle['flowAddressCounts'] == [1, 1]
            tables = {family:json.loads(run([nft,'-j','list','table',family,owner['kernel']['tableName']]).stdout)
                      for family in ('inet','bridge')}
            projection = reader.lease_projection(owner, reader.parse(reader.private(root/'journal.json')), tables)
            assert projection['journalAndMembershipConsistent'] is True
            assert all(1 <= flow['minRemainingTtlSeconds'] <= 30 for flow in projection['flows'])
            print('FINITE_LEASE_R10_READER_SECONDS=PASS BOTH_FAMILIES=true STRICT_CEILING=true',flush=True)
            assert counts['zeroTtl'] == 2 and counts['queries'] >= 10
            for family in ('inet', 'bridge'):
                data = json.loads(run([nft, '-j', 'list', 'table', family, owner['kernel']['tableName']]).stdout)
                sets = [v['set'] for v in data['nftables'] if 'set' in v]
                assert [s['elem'][0]['elem']['val'] for s in sets] == ['1.1.1.1', '8.8.8.8']
                assert all(0 < s['elem'][0]['elem']['expires'] <= 30 for s in sets)
            print('FINITE_LEASE_R10_NATIVE=TRANSIENT_ZERO_TTL_RESAMPLED TWO_CYCLES=true OLD_ADDRESSES_DISCARDED=true', flush=True)
            persistent.set()
            deadline = time.monotonic()+35
            while not (root/'worker-denial.json').exists():
                assert time.monotonic() < deadline, 'PERSISTENT_TTL_DENIAL_TIMEOUT'
                time.sleep(.2)
            failure = reader.parse(reader.private(root/'worker-denial.json'))
            window = next(v['dnsObservationWindow'] for v in failure['exceptionChain'] if 'dnsObservationWindow' in v)
            assert window['minimumObservedTtlSeconds'] == 0 and window['ttlNoncacheable'] is True
            assert window['freshObservationAttempts'] == 3 and failure['refreshCount'] == 2
            journal = reader.parse(reader.private(root/'journal.json'))
            assert journal['state'] == 'QUIESCED' and journal['leaseAuthorized'] is False
            for family in ('inet', 'bridge'):
                data = json.loads(run([nft, '-j', 'list', 'table', family, owner['kernel']['tableName']]).stdout)
                assert not any(v.get('set', {}).get('elem') for v in data['nftables'])
            before = (root/'journal.json').read_bytes()
            repeated = run([sys.executable, '-I', '-B', str(root/'activate.py'), '--supervise',
                            str(root/'authorization.json'), capsule_hash], check=False)
            assert repeated.returncode != 0 and (root/'journal.json').read_bytes() == before
            assert (root/'old-consumed-claim').read_bytes() == b'CI_CONSUMED_CLAIM_PRESERVED'
            assert all((root/'source'/name).read_bytes() == raw for name, raw in original.items())
            print('FINITE_LEASE_R10_NATIVE=PERSISTENT_ZERO_TTL_REVOKED THREE_ATTEMPTS=true REPLAY_DENIED=true ORIGINAL_SOURCES_PRESERVED=true REAL_SYSTEMD_DNS_NFT=true TARGET_ACTIONS=0', flush=True)
        finally:
            run(['/usr/bin/systemctl', 'stop', unit], check=False)
            run(['/usr/bin/systemctl', 'reset-failed', unit], check=False)
            for family in ('inet', 'bridge'):
                run([nft, 'delete', 'table', family, owner['kernel']['tableName']], check=False)
            server.close()


if __name__ == '__main__':
    main()

