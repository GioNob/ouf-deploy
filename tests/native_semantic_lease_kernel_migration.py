"""Linux root qualification inside a new netns. No host units or Docker writes."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
from test_semantic_lease_kernel_migration import Fixture, kernel, m, M, B


def run():
    B.need(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
           and sys.dont_write_bytecode and os.environ.get('OUF_LEASE_KERNEL_MIGRATION_NATIVE') == '1',
           'EXPLICIT_NATIVE_ROOT_REQUIRED')
    B.need(Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino, 'NETNS_REQUIRED')
    nft_path = shutil.which('nft')
    B.need(nft_path is not None, 'NFT_REQUIRED')
    nft = {'path': nft_path, 'sha256': B.sha(Path(nft_path).read_bytes())}
    B.need(not any('table' in r for r in B.document(B.command(nft, ['-j', 'list', 'tables']))['nftables']),
           'EMPTY_NAMESPACE_REQUIRED')

    class RealNft(Fixture):
        def __init__(self):
            super().__init__()
            cfg = self.owner['kernel']
            cfg['providerFlows'] += kernel(ipv6=True)['providerFlows']
            self.journal['leaseAddresses'] = [[], []]
            B.command(nft, ['-f', '-'], m.materialize(cfg, empty_provider_sets=True)['nftRules'].encode('ascii'))
            self.owner['expectedStructureHash'] = B.digest(B.structure(self.tables(cfg)))

        def tables(self, cfg):
            return B.tables(nft, cfg['tableName'])

        def template(self, cfg):
            # Independent compiler template in a nested disposable namespace.
            # Native custody uses a ROOT-owned delivery clone, not runner-owned files.
            with tempfile.TemporaryDirectory(prefix='lease-template-', dir='/root') as temp:
                root = Path(temp)
                root.chmod(0o700)
                sources = {}
                original = ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools'
                for name in ('materialize_southbound_kernel.py', 'materialize_southbound_kernel_v2.py'):
                    raw = (original / name).read_bytes()
                    B.write_once(root / name, raw)
                    sources[name] = {'path': str(root / name), 'sha256': B.sha(raw)}
                config = {'kernel': cfg, 'nft': nft, 'sources': sources,
                          'parentNamespace': Path('/proc/self/ns/net').stat().st_ino}
                unshare = shutil.which('unshare')
                process = subprocess.run([unshare, '--net', sys.executable, '-I', '-B',
                    str(ROOT / 'scripts/migrate-semantic-lease-kernel.py'), '--native-template'],
                    input=B.canonical(config), capture_output=True, timeout=45)
                B.need(process.returncode == 0, 'INDEPENDENT_TEMPLATE_FAILED')
                return B.document(process.stdout)

        def compile(self, cfg):
            return m.materialize(cfg, empty_provider_sets=True)['nftRules']

        def delete(self, cfg):
            return ''.join(f'delete table {f} {cfg["tableName"]}\n' for f in ('inet', 'bridge'))

        def batch(self, raw):
            B.need(self.locked, 'LOCK_REQUIRED')
            B.command(nft, ['-f', '-'], raw.encode('ascii'))

    io = RealNft()
    p = M.plan(io)
    source = copy.deepcopy(io.tables(io.owner['kernel']))
    # Semantic error after both valid creations must abort the whole batch.
    invalid = io.compile(p['destination']) + 'add rule inet missing_task65 missing_chain accept\n'
    try:
        B.command(nft, ['-f', '-'], invalid.encode('ascii'))
    except ValueError:
        pass
    else:
        raise AssertionError('invalid atomic batch succeeded')
    M.verify_tables(io.tables(io.owner['kernel']), p['before']['structure'])
    B.need(io.tables(p['destination']) is None, 'ATOMIC_BATCH_LEFT_TARGET')
    M.apply(io, p, p['planSha256'])
    M.verify_tables(io.tables(io.owner['kernel']), p['before']['structure'])
    M.restore(io, p, p['planSha256'])
    B.need(B.structure(io.tables(io.owner['kernel'])) == B.structure(source), 'RESTORE_EXACT_SEAL_FAILED')
    M.restore(io, p, p['planSha256'])
    # A fresh attempt/claim retains the same historical N; no replay of apply.
    again = RealNft.__new__(RealNft)
    Fixture.__init__(again)
    again.owner = copy.deepcopy(io.owner)
    again.journal = copy.deepcopy(io.journal)
    next_plan = M.plan(again)
    M.apply(again, next_plan, next_plan['planSha256'])
    again.upgrade()
    fp = M.finalize_plan(again, next_plan)
    M.finalize(again, next_plan, fp, fp['planSha256'])
    B.need(io.tables(io.owner['kernel']) is None, 'FINALIZE_LEFT_PREDECESSOR')
    M.verify_tables(io.tables(p['destination']), again.files['native-after.json']['seals']['structure'])

    # Boot exercises the REAL sealed runner through the REAL dispatcher, then
    # reconstructs the selected g2 after deleting it (simulated empty reboot).
    with tempfile.TemporaryDirectory(prefix='lease-boot-', dir='/root') as temp:
        root = Path(temp)
        root.chmod(0o700)
        (root / 'source').mkdir(mode=0o700)
        (root / 'source/tools').mkdir(mode=0o700)
        closure = {}
        for name in ('materialize_southbound_kernel.py', 'materialize_southbound_kernel_v2.py'):
            raw = (ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools' / name).read_bytes()
            relative = 'source/tools/' + name
            B.write_once(root / relative, raw)
            closure[relative] = B.sha(raw)
        runner = (ROOT / 'tools/semantic_lease_kernel_migration/boot_runner_v2.py').read_bytes()
        B.write_once(root / 'boot-runner-v2.py', runner)
        closure['boot-runner-v2.py'] = B.sha(runner)
        B.write_once(root / 'common.lock', b'')
        owner = {**again.new, 'nftPath': nft_path, 'nftSha256': nft['sha256'],
                 'commonLockFile': str(root / 'common.lock'), 'journalFile': str(root / 'journal.json')}
        journal = {**again.journal, **owner['binding'], 'leaseAddresses': [[], []]}
        boot = {'kernel': p['destination'], 'lockFile': owner['commonLockFile'], 'nftPath': nft_path,
                'expectedFootprint': p['expectedBootFootprint']}
        profile = {'coordinatedConfiguration': str(root / 'owner.json'), 'coordinatedConfigurationHash': B.digest(owner),
                   'bootConfiguration': str(root / 'boot.json'), 'bootConfigurationHash': B.digest(boot)}
        for name, value in {'owner.json': owner, 'boot.json': boot, 'profile.json': profile, 'journal.json': journal}.items():
            B.write_once(root / name, B.canonical(value))
            if name != 'journal.json':
                closure[name] = B.digest(value)
        receipt = {'schema': 'ouf.semantic-lease-kernel-generation.v1', 'directory': str(root), 'generation': 2,
                   'closure': closure, 'runner': 'boot-runner-v2.py',
                   'bootProfile': {'path': str(root / 'profile.json'), 'sha256': B.digest(profile)}}
        B.write_once(root / 'receipt.json', B.canonical(receipt))
        dispatcher = (ROOT / 'tools/semantic_lease_kernel_migration/boot_dispatcher.py').read_bytes()
        B.write_once(root / 'dispatcher.py', dispatcher)
        pointer = {'schema': 'ouf.semantic-coordinated-boot-pointer.v1', 'receiptFile': str(root / 'receipt.json'),
                   'receiptHash': B.digest(receipt), 'observerFile': str(root / 'dispatcher.py'), 'observerHash': B.sha(dispatcher)}
        B.write_once(root / 'pointer.json', B.canonical(pointer))
        argv = [sys.executable, '-I', '-B', str(root / 'dispatcher.py'), '--pointer', str(root / 'pointer.json'),
                '--self-sha256', B.sha(dispatcher)]
        first = subprocess.run(argv, capture_output=True, timeout=30)
        B.need(first.returncode == 0, 'BOOT_EXISTING_TABLES_FAILED')
        M.verify_tables(io.tables(p['destination']), owner['expectedStructureHash'])
        B.command(nft, ['-f', '-'], again.delete(p['destination']).encode('ascii'))
        rebuilt = subprocess.run(argv, capture_output=True, timeout=30)
        B.need(rebuilt.returncode == 0, 'BOOT_REBUILD_FAILED')
        new_journal = B.document(B.private(root / 'journal.json'))
        B.need(new_journal['state'] == 'BLOCKED' and new_journal['leaseAuthorized'] is False,
               'BOOT_RECONCILIATION_NOT_REQUIRED')
        B.need(B.digest(B.stable(io.tables(p['destination']))) == p['expectedBootFootprint'], 'BOOT_WRONG_GENERATION')
        # Real custody / CAS foreign-file preservation and exclusive creation.
        B.write_once(root / 'cas.json', b'old')
        with B.directory_lock(root):
            try:
                with B.directory_lock(root):
                    raise AssertionError('concurrent directory lock accepted')
            except BlockingIOError:
                pass
        B.cas(root / 'cas.json', b'old', b'new')
        try:
            B.cas(root / 'cas.json', b'old', b'foreign')
        except ValueError:
            pass
        else:
            raise AssertionError('foreign CAS accepted')
        B.need(B.private(root / 'cas.json') == b'new', 'CAS_FOREIGN_WRITE')
    return {'status': 'NATIVE_BLUE_GREEN_QUALIFIED', 'atomicFailurePreservedN': True,
            'restorePreservedExactN': True, 'finalizeRemovedN': True, 'dispatcherRebuiltG2': True,
            'bootRequiresReconciliation': True, 'hostServicesChanged': False}


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
