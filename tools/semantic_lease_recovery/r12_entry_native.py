"""Real R12 apply/worker/service/DNS/nft; target metadata is an explicit CI fixture."""
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
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/'semantic_lease_activation'))
from test_activation_native import fixture, run
sys.path.insert(0, str(HERE))
import activate_resilient_r12 as target
import activation_core as core


CONFIGURE = r'''
def configure(m, meta, values):
    import hashlib,json,os,sys,time
    from pathlib import Path
    m.SNAPSHOT_BASE=meta/'snapshots'
    m.CLAIM=meta/'new-r12.claim'
    m.PRIOR_ROOT=meta/'old-r10'
    m.UNIT=values['unit']
    m.PYTHON=str(Path(sys.executable).resolve())
    m.APPROVAL_REF='CI_ONLY_R12_NOT_VPS_AUTHORITY'
    m.ISSUED_AT=values['issuedAt']
    m.EXECUTION_EXPIRES_AT=values['expiresAt']
    m.EXPECTED_PROCESSES={}
    m.MODULE_HASHES=values['hashes']
    original_readers=m.readers
    def readers(directory):
        reader,c=original_readers(directory)
        reader.GUARD=meta
        reader.CONTEXT=meta
        reader.OWNER_HASH=values['ownerHash']
        reader.TARGETS={}
        original_service=c.service_command
        def service(*args,**kw):
            argv=original_service(*args,**kw)
            argv.insert(1,'--property=NetworkNamespacePath=/proc/'+str(values['netnsPid'])+'/ns/net')
            return argv
        c.service_command=service
        return reader,c
    m.readers=readers
    def intake(reader,scope):
        cfg,owner=m.configuration(reader)
        return {'schema':'CI_ONLY_CURRENT_TARGET_METADATA','ownerConfigurationHash':values['ownerHash'],'workerNamespaceBindings':{}},cfg,owner,{}
    m.current_intake=intake
    original_runtime=m.runtime
    def runtime(reader,c,owner,cfg,scope,capsule,*,claimed=True):
        coordinator,loaded,recovery=original_runtime(reader,c,owner,cfg,scope,capsule,claimed=claimed)
        def fixture_guard():
            if (meta/'revoked').exists():
                raise loaded['bounded_recovery'].Permanent('AUTHORITY_REVOKED')
            if (meta/'generation-changed').exists():
                raise loaded['bounded_recovery'].Permanent('GENERATION_CHANGED')
            if m.boot_id()!=capsule['hostBootId']:
                raise loaded['bounded_recovery'].Permanent('GENERATION_CHANGED')
            if claimed:m.require(reader.parse(reader.private(m.CLAIM))==capsule['activationClaim'],'CI_CLAIM_DRIFT')
            else:m.require(not os.path.lexists(m.CLAIM),'CI_PRECLAIM_NOT_EMPTY')
        recovery.adapter.scope_guard=fixture_guard
        return coordinator,loaded,recovery
    m.runtime=runtime
    m.verify_r11=lambda reader,cfg,initial: {'startedWall':values['issuedAt']-17, 'startedMonotonic':values['startedMonotonic'], 'attempts':0, 'healthyWallSeconds':0, 'healthyMonotonicSeconds':0}
    m.stop_r11=lambda reader,cfg: None
'''


def main(source):
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    nft = str(Path(shutil.which('nft')).resolve())
    run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0)); port = server.getsockname()[1]
    control = {'ttl': 30, 'queries': 0}
    def dns():
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
    threading.Thread(target=dns, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ouf-r12-entry-ci-', dir='/etc') as tmp:
        meta = Path(tmp); meta.chmod(0o700)
        owner, quiescent_hash = fixture(meta, source, nft)
        owner['dns']['resolverPort'] = port
        owner['nftSha256'] = core.digest(Path(nft).read_bytes())
        core.create(meta/'coordinated-configuration.json', owner)
        cfg = {'commandBindings': {name: {'path': path, 'sha256': core.digest(Path(path).read_bytes())}
                for name, path in [('nft', nft), ('systemctl', '/usr/bin/systemctl')]}}
        core.create(meta/'execution-configuration.json', cfg)
        core.create(meta/'human-approval-binding.json', {'configurationHash': core.digest(core.encoded(cfg))})
        (meta/'snapshots').mkdir(mode=0o700); (meta/'old-r10').mkdir(mode=0o700)
        core.create(meta/'old-r10'/'claim', b'CI_ONLY_CONSUMED_R10_PRESERVED')
        retained = {name: (meta/'source'/name).read_bytes() for name in owner['sourceHashes']}
        delivery = meta/'delivery'; delivery.mkdir(mode=0o700)
        programs = {}
        for name in target.MODULE_HASHES:
            path = HERE/('r12_reader.py' if name == 'reader.py' else name)
            programs[name] = path.read_bytes()
        scope = {'schema': 'CI_ONLY_R12_METADATA',
                 'quiescentJournalHash': quiescent_hash,
                 'ownerConfigurationHash': core.digest(core.encoded(owner)),
                 'currentSemanticPeer': {'generation': {'pid': os.getpid(), 'startTicks': 1, 'namespaceInode': 1}}}
        programs['target_bindings_r11.json'] = core.encoded(scope)
        programs['entry.py'] = (HERE/'activate_resilient_r12.py').read_bytes()
        values = {'unit': 'ouf-ci-r12-' + uuid.uuid4().hex[:8] + '.service',
                  'startedMonotonic': time.monotonic()-18, 'issuedAt': int(time.time())-1, 'expiresAt': int(time.time())+180,
                  'hashes': {name: core.digest(raw) for name, raw in programs.items()},
                  'ownerHash': scope['ownerConfigurationHash'], 'netnsPid': os.getpid()}
        child = (
            'import importlib.util,json,sys\nfrom pathlib import Path\n'
            'root=Path(__file__).resolve().parent\n'
            'spec=importlib.util.spec_from_file_location("r12_ci_target",root/"entry.py")\n'
            'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n'
            + CONFIGURE + '\nvalues=' + repr(values) + '\n'
            + 'configure(m,root.parent.parent,values)\n'
            + 'sys.exit(m.main())\n').encode()
        programs['activate.py'] = child
        for name, raw in programs.items(): core.create(delivery/name, raw)
        exec(CONFIGURE, globals())
        configure(target, meta, values)
        target.__file__ = str(delivery/'activate.py')
        target.__verified_source_bytes__ = child
        unit = values['unit']
        root = None
        def wait_for(predicate, timeout=45):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data = json.loads((root/'worker-status.json').read_bytes())
                if predicate(data): return data
                if (root/'worker-denial.json').exists():
                    print((root/'worker-denial.json').read_text())
                    raise RuntimeError('CI_R12_WORKER_DENIED')
                time.sleep(.1)
            print(run(['/usr/bin/journalctl', '-u', unit, '--no-pager'], check=False).stdout)
            raise RuntimeError('CI_R12_STAGE_TIMEOUT_' + json.dumps(data))
        try:
            saved_preclaim=target.preclaim_guard
            def denied_preclaim(adapter): raise ValueError('CI_PRECLAIM_DENIED')
            target.preclaim_guard=denied_preclaim
            try: target.apply(target.APPROVAL_REF)
            except ValueError as error: assert str(error)=='CI_PRECLAIM_DENIED'
            else: raise AssertionError('CI_PRECLAIM_NOT_DENIED')
            assert not (meta/'new-r12.claim').exists()
            target.preclaim_guard=saved_preclaim
            result = target.apply(target.APPROVAL_REF)
            root = Path(result['evidenceDirectory'])
            assert result['status'] == 'TWO_FLOW_RESILIENT_LEASE_ACTIVE_AND_RENEWED'
            assert result['incidentRef']==target.R11_INCIDENT
            assert result['refreshCount'] >= 2 and result['flowAddressCounts'] == [1, 1]
            first = json.loads((root/'worker-status.json').read_bytes())
            claim_before = (meta/'new-r12.claim').read_bytes()
            journal_before = (meta/'journal.json').read_bytes()
            try: target.apply(target.APPROVAL_REF)
            except ValueError as error: assert str(error) == 'NEW_RECOVERY_ALREADY_CONSUMED_DO_NOT_REPLAY'
            else: raise AssertionError('CI_R12_APPLY_REPLAY_NOT_DENIED')
            assert (meta/'new-r12.claim').read_bytes() == claim_before
            assert (meta/'journal.json').read_bytes() == journal_before
            auth = (root/'authorization.json').read_bytes()
            repeated = run([sys.executable, '-I', '-B', str(root/'activate.py'), '--supervise',
                            str(root/'authorization.json'), core.digest(auth)], check=False)
            assert repeated.returncode != 0
            assert not (root/'worker-denial.json').exists()
            print('CI_R12_APPLY=ACTIVE_TWO_CYCLES_REPLAY_DENIED NEW_CLAIM_SEALED_CLOSURE=true REAL_SYSTEMD=true', flush=True)
            control['ttl'] = 4
            paused = wait_for(lambda v: v.get('state') == 'RETRY_WAIT')
            assert paused['setsRevoked'] is True and paused['ready'] is False
            assert json.loads((meta/'journal.json').read_bytes())['state'] == 'QUIESCED'
            control['ttl'] = 30
            recovered = wait_for(lambda v: v.get('ready') is True and v['refreshCount'] > first['refreshCount'])
            assert recovered['workerPid'] == first['workerPid']
            assert recovered['attempts'] > first['attempts']
            assert recovered['incidentRef'] == first['incidentRef']
            print('CI_R12_WORKER=PAUSED_FRESH_RECOVERY_SAME_PROCESS BUDGET_PRESERVED=true REAL_DNS_NFT=true', flush=True)
            (meta/'generation-changed').touch()
            blocked = wait_for(lambda v: v.get('state') == 'BLOCKED')
            assert blocked['setsRevoked'] is True
            before = control['queries']; time.sleep(.4)
            assert control['queries'] == before
            props = run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,Restart,NRestarts']).stdout
            assert 'ActiveState=active' in props and 'Restart=no' in props and 'NRestarts=0' in props
            run(['/usr/bin/systemctl', 'stop', unit])
            assert json.loads((meta/'journal.json').read_bytes())['state'] == 'QUIESCED'
            assert (meta/'old-r10'/'claim').read_bytes() == b'CI_ONLY_CONSUMED_R10_PRESERVED'
            assert all((meta/'source'/name).read_bytes() == raw for name, raw in retained.items())
            print('CI_R12_GENERATION=BLOCKED_ALIVE_NO_QUERY STOP_REVOKED=true OLD_R10_PRESERVED=true TARGET_ACTIONS=0', flush=True)
        finally:
            run(['/usr/bin/systemctl', 'stop', unit], check=False)
            run(['/usr/bin/systemctl', 'reset-failed', unit], check=False)
            for family in ('inet', 'bridge'):
                run([nft, 'delete', 'table', family, owner['kernel']['tableName']], check=False)
            server.close()


if __name__ == '__main__': main(Path(sys.argv[1]).resolve())
