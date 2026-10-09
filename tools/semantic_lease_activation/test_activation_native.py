"""Real installed algorithms, DNS UDP, nft and transient systemd in a CI netns.

No target constants, keys, endpoints or acceptance. The transient service joins
the test's explicit network namespace. All owned CI tables/files are temporary.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import activation_core as core
import activate_r8_lease as target
import worker_readback


def run(argv, raw=None, check=True):
    result = subprocess.run(argv, input=raw, capture_output=True, text=True, timeout=55)
    if check and result.returncode:
        raise RuntimeError(str(argv[:3]) + ': ' + result.stderr[:1000] + result.stdout[:1000])
    return result


def fixture(root, source, nft):
    order = ('scripts/run_semantic_coordinated_lease_owner.py',
             'tools/materialize_southbound_kernel.py', 'tools/materialize_southbound_lease_refresh.py',
             'tools/semantic_provider_coordinated_supervisor.py', 'tools/semantic_provider_dns.py',
             'tools/semantic_provider_lease_coordination.py', 'tools/semantic_provider_lease_nft.py',
             'tools/semantic_provider_lease_owner.py')
    hashes = {}
    for name in order:
        path = root/'source'/name
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        core.create(path, (source/name).read_bytes())
        hashes[name] = core.digest(path.read_bytes())
    module = load_compiler(root/'source/tools/materialize_southbound_kernel.py')
    cfg = {'tableName': 'r8_lease_test', 'guardedInterfaces': ['leasebr'], 'existingInterfaces': [], 'staticFlows': [],
           'providerFlows': [{'endpointRef': 'role' + str(i), 'endpoint': 'https://' + host + '/approved',
                             'source': '10.77.0.' + str(i + 2), 'addresses': [], 'leaseSeconds': 30,
                             'resolutionEvidenceRef': 'ci-only', 'allowedPrivateAddresses': []}
                            for i, host in enumerate(('provider.example', 'identity.example'))]}
    run([nft, '-f', '-'], module.materialize(cfg, empty_provider_sets=True)['nftRules'])
    tables = {family: json.loads(run([nft, '-j', 'list', 'table', family, cfg['tableName']]).stdout)
              for family in ('inet', 'bridge')}
    sys.path.insert(0, str(root/'source'))
    from tools.semantic_provider_lease_nft import structure_hash
    expected = structure_hash(tables)
    core.create(root/'common.lock', b'')
    binding = {'transactionId': 'a' * 64, 'configurationHash': 'b' * 64, 'leaseStructureHash': expected}
    journal = {'schema': 'ouf.semantic-lease-coordination.v1', **binding, 'state': 'QUIESCED',
               'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[], []]}
    core.create(root/'journal.json', journal)
    return {'kernel': cfg, 'dns': {'resolvers': ['127.0.0.1'], 'resolverPort': 15353, 'timeoutSeconds': 2,
            'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, 'sourceHashes': hashes,
            'expectedStructureHash': expected, 'nftPath': nft, 'readBudgetSeconds': 5,
            'journalFile': str(root/'journal.json'), 'commonLockFile': str(root/'common.lock'),
            'binding': binding, 'pollSeconds': 15}, core.digest(core.encoded(journal))


def load_compiler(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('ci_compiler', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHILD = r'''import hashlib,json,os,sys,threading,time
from pathlib import Path
root=Path(__file__).resolve().parent
sys.path.insert(0,str(root))
import activation_core as core
original_status=core.status
def delayed_status(root,value):
 if value.get('status')=='LEASE_ACTIVE' and value.get('refreshCount')==2:
  time.sleep(2) # Deterministic CI-only interleaving, never deployed to target.
 return original_status(root,value)
core.status=delayed_status
capsule=Path(sys.argv[2]).read_bytes()
assert hashlib.sha256(capsule).hexdigest()==sys.argv[3]
value=json.loads(capsule);owner=value['owner']
def read(path,expected):
 raw=Path(path).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected;return raw
modules,saved=core.load_installed(owner,root/'source',read,value['compilerOverride'])
c=modules['semantic_provider_lease_coordination']
backend=modules['semantic_provider_lease_nft'].NftBackend([owner['nftPath']],owner['kernel'],owner['expectedStructureHash'],5)
worker=modules['semantic_provider_lease_owner'].LeaseOwner(owner['kernel'],owner['dns'],backend)
journal=c.PrivateJournal(Path(owner['journalFile']))
coordinator=c.Coordinator(worker,owner['binding'],lambda:c.hold_common_lock(Path(owner['commonLockFile'])),journal.read,journal.write)
coordinator.configuration_poll_seconds=owner['pollSeconds']
stop=threading.Event();core.install_signal_handlers(stop)
sys.exit(core.supervise_claimed(root,coordinator,modules['semantic_provider_coordinated_supervisor'].supervise,
 value['approval'],value['journalHash'],lambda:None,stop))
'''


def main():
    assert os.geteuid() == 0 and Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    source = Path(sys.argv[1]).resolve()
    nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 15353))
    counts = {'queries': 0}
    deny = threading.Event()

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
                labels.append(query[end + 1:end + 1 + size])
                end += size + 1
            end += 1
            qtype = struct.unpack('!H', query[end:end + 2])[0]
            question = query[12:end + 4]
            if deny.is_set():
                answer = query[:2] + struct.pack('!HHHHH', 0x8182, 1, 0, 0, 0) + question
            else:
                ipv4 = '1.1.1.1' if labels[0] == b'provider' else '8.8.8.8'
                data = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                                        ipv4 if qtype == 1 else '2606:4700:4700::1111')
                answer = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question
                answer += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 30, len(data)) + data
            server.sendto(answer, peer)

    threading.Thread(target=serve, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ouf-r8-native-', dir='/etc') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        unit = 'ouf-ci-r8-lease-' + uuid.uuid4().hex[:8] + '.service'
        target.require_unit_absent(unit)
        owner, old_hash = fixture(root, source, nft)
        core.create(root/'activation_core.py', (HERE/'activation_core.py').read_bytes())
        core.create(root/'activate.py', CHILD.encode())
        compiler = root/'materialize_southbound_lease_refresh.py'
        core.create(compiler, (HERE/compiler.name).read_bytes())
        capsule = {'owner': owner, 'journalHash': old_hash, 'approval': {'scope': 'CI_NETNS_ONLY_NOT_TARGET_AUTHORITY'},
                   'compilerOverride': {'path': str(compiler), 'sha256': core.digest(compiler.read_bytes()),
                                        'originalSha256': owner['sourceHashes']['tools/' + compiler.name]}}
        core.create(root/'authorization.json', capsule)
        args = core.service_command(root, core.digest(core.encoded(capsule)), unit=unit,
                                     python=str(Path(sys.executable).resolve()))
        # CI-specific containment only. The production command does not join a test namespace.
        args.insert(1, '--property=NetworkNamespacePath=/proc/' + str(os.getpid()) + '/ns/net')
        try:
            run(args)
            try:
                target.require_unit_absent(unit)
            except ValueError as error:
                assert str(error) == 'LEASE_UNIT_NAME_ALREADY_OWNED'
            else:
                raise AssertionError('REAL_LOADED_SERVICE_NOT_DETECTED')
            print('R8_UNIT_INVENTORY=ABSENCE_AND_EXISTING_SERVICE_VERIFIED REAL_SYSTEMCTL=true', flush=True)
            deadline = time.monotonic() + 55
            while not (root/'cycle-2.json').exists():
                if (root/'worker-denial.json').exists():
                    raise RuntimeError((root/'worker-denial.json').read_text())
                assert time.monotonic() < deadline, 'CI_TWO_CYCLES_TIMEOUT'
                time.sleep(.2)
            cycle = json.loads((root/'cycle-2.json').read_bytes())
            lagging = json.loads((root/'worker-status.json').read_bytes())
            assert cycle['refreshCount'] == 2 and lagging['refreshCount'] == 1
            raw_properties = run(['/usr/bin/systemctl', 'show', unit,
                '--property=ActiveState,SubState,MainPID,Restart,ExecStart']).stdout
            unit_properties = dict(line.split('=',1) for line in raw_properties.splitlines() if '=' in line)
            assert all(worker_readback.compare(cycle, unit_properties, root).values())
            print('R8_WORKER_READBACK=OLD_FALSE_DENIAL_REPRODUCED IMMUTABLE_CYCLE_WITH_LIVE_SYSTEMD_PASS=true', flush=True)
            deadline = time.monotonic() + 5
            while json.loads((root/'worker-status.json').read_bytes())['refreshCount'] < 2:
                assert time.monotonic() < deadline
                time.sleep(.05)
            status = json.loads((root/'worker-status.json').read_bytes())
            assert status['refreshCount'] >= 2 and status['flowAddressCounts'] == [1, 1] and counts['queries'] >= 8
            for family in ('inet', 'bridge'):
                data = json.loads(run([nft, '-j', 'list', 'table', family, owner['kernel']['tableName']]).stdout)
                sets = [v['set'] for v in data['nftables'] if 'set' in v]
                assert [v['elem'][0]['elem']['val'] for v in sets] == ['1.1.1.1', '8.8.8.8']
                assert all(0 < v['elem'][0]['elem']['expires'] <= 30000 for v in sets)
            print('R8_LEASE_NATIVE=ACTIVE_AND_RENEWED REAL_SYSTEMD=true REAL_DNS=true REAL_NFT=true', flush=True)
            deny.set()
            deadline = time.monotonic() + 40
            while not (root/'worker-denial.json').exists():
                assert time.monotonic() < deadline, 'CI_DNS_DENIAL_NOT_OBSERVED'
                time.sleep(.2)
            failure = json.loads((root/'worker-denial.json').read_bytes())
            assert any(v['reason'].startswith('DNS_') for v in failure['exceptionChain']), failure
            journal = json.loads((root/'journal.json').read_bytes())
            assert journal['state'] == 'QUIESCED' and journal['leaseAuthorized'] is False
            for family in ('inet', 'bridge'):
                data = json.loads(run([nft, '-j', 'list', 'table', family, owner['kernel']['tableName']]).stdout)
                assert not any(v.get('set', {}).get('elem') for v in data['nftables'])
            before = (root/'journal.json').read_bytes()
            # Explicitly test a new invocation cannot replay this consumed claim.
            repeated = subprocess.run([sys.executable, '-I', '-B', str(root/'activate.py'), '--supervise',
                str(root/'authorization.json'), core.digest(core.encoded(capsule))], capture_output=True, timeout=10)
            assert repeated.returncode != 0 and (root/'journal.json').read_bytes() == before
            print('R8_LEASE_NATIVE=DNS_FAILURE_REVOKED ORIGINAL_CAUSE_RETAINED=true REPLAY_DENIED=true TARGET_ACTIONS=0', flush=True)
        finally:
            run(['/usr/bin/systemctl', 'stop', unit], check=False)
            run(['/usr/bin/systemctl', 'reset-failed', unit], check=False)
            for family in ('inet', 'bridge'):
                run([nft, 'delete', 'table', family, owner['kernel']['tableName']], check=False)
            server.close()


if __name__ == '__main__':
    main()
