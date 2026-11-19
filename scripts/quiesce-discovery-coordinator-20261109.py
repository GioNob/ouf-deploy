#!/usr/bin/env python3
"""Invoke the existing Coordinator.quiesce contract for the observed empty guard.

Uses repository-pinned pure/core modules and an exact flush-only nft transport.
Does not authorize leases, reset admission journals or start a provider.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

HELPERS = {
    'reconcile-discovery-placeholder-20261109.py': '94649eefceddc348c92172872bf0cb180c21bd057ae84f7b371d9b2aa6c6259f',
    'read-discovery-lifecycle-20261109.py': '4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67',
}
CORE = {
    'materialize_southbound_kernel': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de',
    'semantic_provider_dns': 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930',
    'materialize_southbound_lease_refresh': '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084',
    'semantic_provider_lease_nft': '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93',
    'semantic_provider_lease_owner': '92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d',
    'semantic_provider_lease_coordination': 'e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587',
}
RECEIPT = Path('/var/lib/ouf-storage-migration/discovery-placeholder-cksr_p4w/result.json')
RECEIPT_SHA = 'd60aa0f491761c4882a6e8f41fdabbfe0dc493cfbeff957c7c6d0cab9a608afb'
CLAIM = Path('/var/lib/ouf-storage-migration/discovery-coordinator-quiesce-20261109')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def load_helper(name):
    path = Path(__file__).with_name(name); raw = path.read_bytes()
    need(sha(raw) == HELPERS[name], 'PINNED_HELPER_CHANGED')
    namespace = {'__name__': name, '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


def load_core():
    verified = {}
    for name, expected in CORE.items():
        path = Path(__file__).with_name('core') / (name + '.py')
        raw = path.read_bytes(); need(sha(raw) == expected, 'PINNED_COORDINATOR_SOURCE_CHANGED')
        verified[name] = (path, raw)
    package = types.ModuleType('tools'); package.__path__ = []; sys.modules['tools'] = package
    for name, (path, raw) in verified.items():
        module = types.ModuleType('tools.' + name); module.__file__ = str(path); module.__package__ = 'tools'
        sys.modules[module.__name__] = module; setattr(package, name, module)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    return package


class FlushOnlyNft:
    def __init__(self, binding, table, flow_count, binary, work):
        need(re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', table) and flow_count == 2, 'EXACT_TWO_FLOW_GUARD_REQUIRED')
        self.binding = dict(binding); self.table = table; self.binary = binary; self.work = work
        self.batch = ''.join('flush set ' + f + ' ' + table + ' provider_' + str(i) + '\n' for f in ('inet', 'bridge') for i in range(flow_count))
        self.armed = False; self.reads = 0; self.writes = 0

    def run(self, args, raw=None, timeout=None):
        write = args == ['-f', '-']
        if write:
            need(self.armed and self.writes == 0 and raw == self.batch, 'ONE_EXACT_FLUSH_BATCH_REQUIRED')
        else:
            need(raw is None and args in (['-j', 'list', 'table', 'inet', self.table], ['-j', 'list', 'table', 'bridge', self.table]), 'OWNED_TABLE_READ_ONLY_REQUIRED')
            need(self.reads < 32, 'NFT_READ_LIMIT')
        executable = self.binary(self.binding['path'], self.binding['sha256'])
        if write: self.writes += 1
        else: self.reads += 1
        with tempfile.TemporaryFile(dir=self.work) as output:
            result = subprocess.run([executable, *args], input=raw.encode() if raw is not None else None,
                stdout=output, stderr=subprocess.DEVNULL, timeout=min(timeout or 5, 5), env=ENV)
            output.seek(0); data = output.read(2097153)
        self.binary(self.binding['path'], self.binding['sha256'])
        need(result.returncode == 0 and len(data) <= 2097152, 'OWNED_NFT_OPERATION_UNPROVEN')
        return data.decode('utf-8')


def services(core, driver, transport):
    backend = core.semantic_provider_lease_nft.NftBackend(
        [transport.binding['path']], driver['kernel'], driver['coordinationBinding']['leaseStructureHash'], 5)
    backend.run = transport.run
    owner = core.semantic_provider_lease_owner.LeaseOwner(driver['kernel'], driver['dns'], backend)
    journal = core.semantic_provider_lease_coordination.PrivateJournal(Path(driver['coordinationJournal']))
    transitions = []
    def write(previous, current):
        need(transport.armed and current['leaseAuthorized'] is False and current['startAuthorized'] is False
             and (previous['state'], current['state']) in (('BLOCKED', 'QUIESCING'), ('QUIESCING', 'QUIESCED')),
             'QUIESCENCE_ONLY_JOURNAL_TRANSITION_REQUIRED')
        journal.write(previous, current)
        transitions.append(current['state'])
    # The caller holds the existing common lock around preflight, quiesce and
    # readback. Avoid reacquiring flock through a separate file description.
    coordinator = core.semantic_provider_lease_coordination.Coordinator(owner, driver['coordinationBinding'],
        contextlib.nullcontext, journal.read, write)
    return coordinator, journal, transitions


def check_empty_blocked(coordinator):
    value = coordinator.journal()
    need(value['state'] == 'BLOCKED' and value['leaseAuthorized'] is False and value['startAuthorized'] is False,
         'CURRENT_BLOCKED_COORDINATOR_REQUIRED')
    need(not any(coordinator.sets()), 'CURRENT_EMPTY_OWNED_SETS_REQUIRED')
    return value


def check_terminal(current):
    need(current.get('status') == 'DISCOVERY_LIFECYCLE_READ_COMPLETE', 'FRESH_LIFECYCLE_REQUIRED')
    expected = {'adapter': {'adapter': 'DELETED', 'admission': 'CLEANED', 'broker': 'CLEANED', 'preexec': 'ROLLED_BACK'},
                'southbound': {'adapter': 'DELETING', 'admission': 'PROTECTED', 'broker': 'PROTECTED', 'preexec': 'PROTECTED'}}
    for role in ('adapter', 'southbound'):
        row = current['components'][role]
        need(row['journalStates'] == expected[role] and row['classification'] == 'NO_NATIVE_RESIDUE_OBSERVED'
             and not row['namespaceHandle']['present'], 'OLD_PROVIDER_MUST_REMAIN_TERMINAL')
        need(set(row['generations']) == {'admission', 'preexec'} and all(v['recordedGenerationAlive'] is False
             and v['recordedPidPresent'] is False for v in row['generations'].values()), 'OLD_PROCESSES_MUST_BE_ABSENT')


def main():
    report = {'schema': 'ouf.discovery-coordinator-quiescence.v1', 'status': 'HELD',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'nftFlushBatchesAttempted': 0,
              'coordinatorJournalTransitions': [], 'runtimeAdmissionJournalWrites': 0, 'serviceStartDispatched': False,
              'serviceStops': 0, 'serviceConfigurationChanged': False, 'credentialFileContentsRead': 0,
              'credentialValuesEmitted': False, 'databaseRequests': 0, 'businessRequestsIssued': 0, 'providerRequests': 0,
              'tokenRequests': 0, 's3Requests': 0, 'dnsQueries': 0, 'historicalAuthorityReused': False,
              'automaticReplayAllowed': False, 'providerReady': False, 'newGenerationAdmitted': False,
              'leaseAuthorized': False, 'startAuthorized': False}
    work = None; transport = None; transitions = []; intended = False
    def deadline(*_): raise RuntimeError('QUIESCENCE_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(180)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_OPERATOR_REQUIRED')
        os.umask(0o077); p = load_helper('reconcile-discovery-placeholder-20261109.py'); l = load_helper('read-discovery-lifecycle-20261109.py')
        s = l.module(l.STARTUP, l.STARTUP_SHA); h = l.module(l.HELPER, l.HELPER_SHA)
        report['phase'] = 'VERIFY_COMPLETED_PLACEHOLDER_RECOVERY'
        receipt_raw = p.read_private(RECEIPT); need(sha(receipt_raw) == RECEIPT_SHA, 'RETAINED_COMPLETION_RECEIPT_CHANGED')
        need(not os.path.lexists(CLAIM), 'PRIOR_QUIESCENCE_PRESERVED_DO_NOT_REPLAY')
        bindings = l.parse(p.read_private(RECEIPT.parent / 'source-bindings.private.json'))
        matches = [path for path, v in bindings.items() if v['sha256'] == l.CONFIG_SHA]
        need(len(matches) == 1, 'ONE_RETAINED_RUNTIME_CONFIGURATION_REQUIRED')
        cfg_raw = p.read_private(matches[0]); need(sha(cfg_raw) == l.CONFIG_SHA, 'CURRENT_RUNTIME_CONFIGURATION_CHANGED')
        cfg = l.parse(cfg_raw); registry = s.exact_path(cfg['registryRoot']); cid = s.PINS['southbound'][0]; root = registry / cid
        need(registry.is_relative_to('/etc/ouf'), 'EXACT_RETAINED_REGISTRY_REQUIRED')
        record = l.parse(p.read_private(root / 'adapter.json')); driver_raw = p.read_private(root / 'driver.json')
        need(record['configurationHash'] == l.runtime_binding(cfg, cid) and sha(driver_raw) == record['driverHash'], 'SEALED_CURRENT_DRIVER_REQUIRED')
        driver = l.parse(driver_raw); core = load_core()
        work = Path(tempfile.mkdtemp(prefix='discovery-coordinator-quiesce-', dir=CLAIM.parent)); report['privateEvidenceDirectory'] = str(work)
        report['phase'] = 'LOCK_CURRENT_TERMINAL_COHORT'
        with contextlib.ExitStack() as locks:
            for role in ('southbound', 'adapter'): locks.enter_context(p.existing_lock(registry / s.PINS[role][0] / 'operation.lock'))
            locks.enter_context(p.existing_lock(registry, directory=True)); locks.enter_context(p.existing_lock(s.exact_path(driver['lockFile'])))
            report['phase'] = 'VERIFY_NATIVE_ABSENCE_AND_GUARD_OWNERSHIP'
            reader = s.Reader(); native = l.Native(work); current = {}
            l.collect(current, h, s, reader, native, work); check_terminal(current)
            need(sha(p.read_private(root / 'driver.json')) == sha(driver_raw), 'DRIVER_CHANGED_BEFORE_QUIESCENCE')
            broker_raw = p.read_private(root / 'broker.json')
            need(sha(broker_raw) == cfg['candidates'][cid]['admissionConfigurationHash'], 'CURRENT_BROKER_BINDING_REQUIRED')
            broker = l.parse(broker_raw); template_ref = broker['preparerTemplate']; template_raw = p.read_private(s.exact_path(template_ref['path']))
            need(sha(template_raw) == template_ref['sha256'], 'CURRENT_TEMPLATE_BINDING_REQUIRED')
            template = l.parse(template_raw); need(template['commands']['nft'] == driver['commands']['nft'], 'NFT_COMMAND_BINDING_MISMATCH')
            command = {'path': driver['commands']['nft'], 'sha256': template['commandHashes']['nft']}
            transport = FlushOnlyNft(command, driver['kernel']['tableName'], len(driver['kernel']['providerFlows']), native.binary, work)
            coordinator, journal, transitions = services(core, driver, transport)
            before = check_empty_blocked(coordinator)
            p.save(work / 'preflight.json', encoded(current)); p.save(work / 'coordinator.before.private.json', encoded(before))
            p.save(work / 'source-bindings.private.json', encoded(reader.seals))
            report['phase'] = 'RESERVE_QUIESCENCE_OPERATION'
            os.mkdir(CLAIM, 0o700); intended = True
            p.save(CLAIM / 'intent.json', encoded({'schema': 'ouf.discovery-coordinator-quiesce-intent.v1',
                'evidenceDirectory': str(work), 'prerequisiteReceiptSha256': RECEIPT_SHA,
                'coordinatorBeforeSha256': sha(encoded(before)), 'permittedEffect': 'ONE_EXACT_FOUR_SET_FLUSH_AND_QUIESCENCE_TRANSITIONS',
                'leaseGrantAllowed': False, 'startAllowed': False}))
            transport.armed = True; report['phase'] = 'QUIESCE_THROUGH_EXISTING_COORDINATOR'
            result = coordinator.quiesce()
            report['phase'] = 'VERIFY_QUIESCENCE_AND_PRESERVED_ADMISSION'
            after = coordinator.journal(); guard = coordinator.guard()
            need(result['state'] == after['state'] == guard['state'] == 'QUIESCED' and not after['leaseAuthorized']
                 and not after['startAuthorized'] and transitions == ['QUIESCING', 'QUIESCED'] and transport.writes == 1,
                 'QUIESCENCE_RESULT_UNPROVEN')
            verifier = s.Reader(); verifier.seals = {path: v for path, v in reader.seals.items() if path != driver['coordinationJournal']}
            for path in list(verifier.seals): verifier.read(path, 'postQuiesceRecheck')
            for role in ('adapter', 'southbound'):
                need(h.digest(h.frame(h.inspect(s.PINS[role][0]))) == s.PINS[role][1], 'PROVIDER_FRAME_CHANGED')
                need(not os.path.lexists(registry / s.PINS[role][0] / 'netns'), 'NAMESPACE_HANDLE_REAPPEARED')
            p.save(work / 'coordinator.after.private.json', encoded(after))
            report.update(status='DISCOVERY_COORDINATOR_QUIESCED', phase='COMPLETE', coordinationState='QUIESCED',
                existingTableStructureVerified=True, providerLeaseSetsEmpty=True, containerFramesUnchanged=True,
                admissionJournalsUnchanged=True, nftFlushBatchesAttempted=transport.writes, coordinatorJournalTransitions=list(transitions))
            p.save(CLAIM / 'complete.json', encoded(report))
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=reason, operationIntentPresent=intended,
            errorLocation=[{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        report['coordinatorJournalTransitions'] = list(transitions)
        if transport is not None: report.update(nftFlushBatchesAttempted=transport.writes, nftOwnedTableReads=transport.reads)
        if work is not None: p.save(work / 'result.json', encoded(report))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_COORDINATOR_QUIESCED' else 1


if __name__ == '__main__': sys.exit(main())
