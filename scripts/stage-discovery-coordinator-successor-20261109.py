#!/usr/bin/env python3
"""Stage a separate, unauthorized coordinator for the proven empty boot footprint.

Never rewrite the active owner, old driver/journals, boot pointer or nft tables.
The new context is not installed and does not admit a provider generation.
"""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

DRIFT = 'read-discovery-nft-drift-20261109.py'
DRIFT_SHA = '1c30699b12129fd2c322753167932871a171e744c8d780a31142789eb4326b06'
RECEIPT = Path('/var/lib/ouf-storage-migration/discovery-nft-drift-f02sxuus/result.json')
RECEIPT_SHA = 'ac43eb0ab617bb0039cfc431bf427ca88ec5e81f513a540da54ef21bc430fde2'
OLD_STRUCTURE = '0ae74914cbfcfaef1b2408e8d8de482772f3e524c08d5da231a032dd57863d09'
CURRENT_STRUCTURE = '1eddee4c1203c07a5643c97c7f8173cd1ea14e35fe7079ad4c73148bce647391'
BOOT_FOOTPRINT = '7e10bda7a1c83b9688f0f84a1be346061eba4f6e1db9ff3d80c3f59656a1fc7f'
CLAIM = Path('/var/lib/ouf-storage-migration/discovery-coordinator-successor-stage-20261109')
SNAPSHOTS = Path('/etc/ouf/deploy-snapshots')
EXTRA_SOURCE = {
    'scripts/run_semantic_coordinated_lease_owner.py': 'c2937a39578311018d47c0d414e6687278ce8b6b103de62c422cfe7b760b6889',
    'tools/semantic_provider_coordinated_supervisor.py': '25a952c9f6d1385ce7759ef61666d25c7ec24a5735d3d0d27c36ade8e1614dad',
    'scripts/run_semantic_coordinated_boot_guard.py': 'ff8d1e483496f9201f9663f58cc3f942c4b6c2ef9041743d52419050fe8134c6',
    'tools/semantic_provider_boot_coordination.py': '518ad91e209d379bc06ce7e209052230d327ce2fa86014d214f32a62b2985431',
}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(value): return sha(encoded(value))


def load_drift():
    path = Path(__file__).with_name(DRIFT); raw = path.read_bytes()
    need(sha(raw) == DRIFT_SHA, 'PINNED_DRIFT_HELPER_CHANGED')
    namespace = {'__name__': 'drift_stage_dependency', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


def qualify_tables(core, drift, owner, boot, tables, expected_current, expected_footprint):
    counts = drift.validate_tables(tables, owner['kernel']['tableName'])
    need(all(c['set'] == 2 and c['elements'] == 0 and c['other'] == 0 for c in counts.values()), 'EXACT_EMPTY_TWO_FLOW_GUARD_REQUIRED')
    need(owner['kernel'] == boot['kernel'] and owner['commonLockFile'] == boot['lockFile']
         and owner['nftPath'] == boot['nftPath'], 'BOOT_OWNER_SCOPE_CHANGED')
    need(len(owner['kernel']['providerFlows']) == 2 and all(f['addresses'] == [] for f in owner['kernel']['providerFlows']), 'EMPTY_CONFIGURED_PROVIDER_FLOWS_REQUIRED')
    need(boot['expectedFootprint'] == expected_footprint and digest(drift.boot_structure(tables)) == expected_footprint, 'REVIEWED_BOOT_FOOTPRINT_CHANGED')
    need(core.semantic_provider_lease_nft.structure_hash(tables) == expected_current, 'REVIEWED_NATIVE_GENERATION_CHANGED')
    return counts


def build_successor(root, owner, boot, profile, current_structure, transaction):
    need(root.is_absolute() and '..' not in root.parts and str(root) != str(Path(owner['journalFile']).parent), 'SEPARATE_SUCCESSOR_DIRECTORY_REQUIRED')
    owner_keys = {'schema','kernel','dns','expectedStructureHash','nftPath','nftSha256','readBudgetSeconds','pollSeconds','commonLockFile','journalFile','binding','sourceHashes'}
    boot_keys = {'schema','nftPath','kernel','compilerFile','compilerHash','expectedFootprint','journalFile','transactionId','lockFile'}
    profile_keys = {'schema','sourceHashes','coordinatedConfiguration','coordinatedConfigurationHash','bootConfiguration','bootConfigurationHash','bootGuardFile','bootGuardHash'}
    need(set(owner) == owner_keys and owner['schema'] == 'ouf.semantic-coordinated-owner-runtime.v1'
         and set(boot) == boot_keys and boot['schema'] == 'ouf.semantic-runtime-boot-guard.v1'
         and set(profile) == profile_keys and profile['schema'] == 'ouf.semantic-coordinated-boot-profile.v1', 'EXACT_SOURCE_PROFILE_SHAPES_REQUIRED')
    need(re.fullmatch('[0-9a-f]{64}', transaction) is not None and transaction != owner['binding']['transactionId']
         and re.fullmatch('[0-9a-f]{64}', current_structure) is not None, 'NEW_EXPLICIT_BINDING_REQUIRED')
    fresh_owner = copy.deepcopy(owner); fresh_owner.pop('binding')
    fresh_owner.update(expectedStructureHash=current_structure, journalFile=str(root / 'coordination-journal.json'))
    fresh_owner['binding'] = {'transactionId': transaction, 'configurationHash': digest(fresh_owner), 'leaseStructureHash': current_structure}
    fresh_boot = copy.deepcopy(boot)
    fresh_boot.update(journalFile=str(root / 'boot-journal.json'), transactionId=transaction)
    fresh_profile = copy.deepcopy(profile)
    fresh_profile.update(coordinatedConfiguration=str(root / 'coordinated-configuration.json'), coordinatedConfigurationHash=digest(fresh_owner),
                         bootConfiguration=str(root / 'boot-configuration.json'), bootConfigurationHash=digest(fresh_boot))
    journal = {'schema': 'ouf.semantic-lease-coordination.v1', **fresh_owner['binding'], 'state': 'QUIESCED',
               'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[], []]}
    boot_journal = {'schema': 'ouf.semantic-runtime-transition.v1', 'state': 'RUNTIME_EMPTY', 'transactionId': transaction,
                    'configurationHash': digest(fresh_boot), 'leaseStructureHash': current_structure, 'startAuthorized': False}
    return {'coordinated-configuration.json': fresh_owner, 'boot-configuration.json': fresh_boot,
            'boot-profile.json': fresh_profile, 'coordination-journal.json': journal, 'boot-journal.json': boot_journal}


def source_closure(q, owner, profile, read, oldroot):
    expected = {'tools/' + name + '.py': value for name, value in q.CORE.items()}
    expected.update(EXTRA_SOURCE)
    need(set(owner['sourceHashes']).isdisjoint(profile['sourceHashes'])
         and {**owner['sourceHashes'], **profile['sourceHashes']} == expected, 'EXACT_ORIGINAL_TEN_SOURCE_CLOSURE_REQUIRED')
    raw = {name: read(oldroot / 'source' / name) for name in expected}
    need(all(sha(raw[name]) == value for name, value in expected.items()), 'SOURCE_CLOSURE_BYTES_CHANGED')
    return raw


def write_successor(p, root, files, sources):
    for directory in ('source', 'source/scripts', 'source/tools'): (root / directory).mkdir(mode=0o700)
    for name, raw in sources.items(): p.save(root / 'source' / name, raw)
    for name, value in files.items(): p.save(root / name, encoded(value))


def verify_staged_owner(q, core, owner, native, work):
    transport = q.FlushOnlyNft({'path': owner['nftPath'], 'sha256': owner['nftSha256']},
                               owner['kernel']['tableName'], 2, native.binary, work)
    driver = {'kernel': owner['kernel'], 'dns': owner['dns'], 'coordinationBinding': owner['binding'], 'coordinationJournal': owner['journalFile']}
    coordinator, journal, transitions = q.services(core, driver, transport)
    result = coordinator.guard()  # outer caller holds existing common lock; writer remains unarmed
    need(result['state'] == 'QUIESCED' and result['dockerPrestartStructuralGate'] is True
         and result['startAuthorized'] is False and not journal.read()['leaseAuthorized']
         and transport.writes == 0 and transitions == [], 'STAGED_GUARD_NOT_PROVEN')
    return result, transport.reads


def main():
    report = {'schema': 'ouf.discovery-coordinator-successor-stage.v1', 'status': 'HELD',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'activeInstallationPointerChanged': False,
              'activeCoordinatorChanged': False, 'oldDriverChanged': False, 'oldRuntimeJournalWrites': 0,
              'nftWrites': 0, 'serviceConfigurationChanged': False, 'serviceStartDispatched': False, 'serviceStops': 0,
              'credentialFileContentsRead': 0, 'credentialValuesEmitted': False, 'databaseRequests': 0,
              'providerRequests': 0, 'businessRequestsIssued': 0, 's3Requests': 0, 'dnsQueries': 0, 'tokenRequests': 0,
              'newGenerationAdmitted': False, 'providerReady': False, 'activationPerformed': False,
              'automaticReplayAllowed': False, 'historicalAuthorityReused': False, 'stagedContextCreated': False}
    work = None; stage = None; saved = {}; intended = False
    def deadline(*_): raise RuntimeError('SUCCESSOR_STAGE_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(180)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_OPERATOR_REQUIRED')
        os.umask(0o077); d = load_drift(); q = d.load_quiesce(); p = q.load_helper('reconcile-discovery-placeholder-20261109.py')
        l = q.load_helper('read-discovery-lifecycle-20261109.py'); s = l.module(l.STARTUP, l.STARTUP_SHA); h = l.module(l.HELPER, l.HELPER_SHA)
        core = q.load_core()
        def read(path):
            path = str(path); need(len(saved) < 48 or path in saved, 'STAGE_METADATA_READ_LIMIT')
            raw = p.read_private(path)
            need(path not in saved or saved[path] == raw, 'SOURCE_CHANGED_DURING_STAGE')
            saved[path] = raw; return raw
        report['phase'] = 'VERIFY_REVIEWED_DRIFT_RECEIPT'
        need(sha(read(RECEIPT)) == RECEIPT_SHA, 'EXACT_DRIFT_RECEIPT_REQUIRED')
        need(not os.path.lexists(CLAIM) and not os.path.lexists(q.CLAIM), 'PREVIOUS_INTENT_PRESERVED_DO_NOT_REPLAY')
        retained = l.parse(read(RECEIPT.parent / 'selected.private.json'))
        bindings = l.parse(read(q.RECEIPT.parent / 'source-bindings.private.json'))
        matches = [path for path, value in bindings.items() if value['sha256'] == l.CONFIG_SHA]
        need(len(matches) == 1, 'ONE_RETAINED_RUNTIME_CONFIGURATION_REQUIRED')
        raw = read(matches[0]); need(sha(raw) == l.CONFIG_SHA, 'RUNTIME_CONFIGURATION_CHANGED'); cfg = l.parse(raw)
        registry = s.exact_path(cfg['registryRoot']); cid = s.PINS['southbound'][0]; root = registry / cid
        need(registry.is_relative_to('/etc/ouf'), 'BOUND_REGISTRY_REQUIRED')
        record = l.parse(read(root / 'adapter.json')); driver_raw = read(root / 'driver.json'); driver = l.parse(driver_raw)
        need(record['configurationHash'] == l.runtime_binding(cfg, cid) and sha(driver_raw) == record['driverHash']
             and driver == retained['driver'] and driver['coordinationBinding']['leaseStructureHash'] == OLD_STRUCTURE, 'RETAINED_DRIVER_CHANGED')
        work = Path(tempfile.mkdtemp(prefix='discovery-coordination-stage-', dir=CLAIM.parent)); report['privateEvidenceDirectory'] = str(work)
        native = l.Native(work)
        report['phase'] = 'VERIFY_CURRENT_EMPTY_COHORT_UNDER_LOCKS'
        with contextlib.ExitStack() as locks:
            for role in ('southbound', 'adapter'): locks.enter_context(p.existing_lock(registry / s.PINS[role][0] / 'operation.lock'))
            locks.enter_context(p.existing_lock(registry, directory=True)); locks.enter_context(p.existing_lock(s.exact_path(driver['lockFile'])))
            for path in list(saved): read(path)
            reader = s.Reader(); current = {}; l.collect(current, h, s, reader, native, work); q.check_terminal(current)
            baseline = d.boot_baseline(read, l.parse, s.exact_path, driver)
            need(baseline['allOwnerBindingsMatchDriver'] and baseline['expectedFootprintSha256'] == BOOT_FOOTPRINT, 'REVIEWED_ACTIVE_BOOT_BINDING_CHANGED')
            pointer = l.parse(saved[str(d.POINTER)]); oldroot = s.exact_path(pointer['receiptFile']).parent
            owner = l.parse(saved[str(oldroot / 'coordinated-configuration.json')]); profile = l.parse(saved[str(oldroot / 'boot-profile.json')])
            boot = l.parse(saved[profile['bootConfiguration']])
            old_journal = l.parse(read(s.exact_path(owner['journalFile'])))
            journal_transport = q.FlushOnlyNft({'path': owner['nftPath'], 'sha256': owner['nftSha256']},
                                               owner['kernel']['tableName'], 2, native.binary, work)
            previous_coordinator, _, _ = q.services(core, driver, journal_transport)
            need(previous_coordinator.journal() == old_journal and old_journal['state'] == 'BLOCKED'
                 and old_journal['leaseAuthorized'] is False and old_journal['startAuthorized'] is False,
                 'VALID_BLOCKED_UNAUTHORIZED_JOURNAL_REQUIRED')
            need(owner['expectedStructureHash'] == OLD_STRUCTURE and owner['binding'] == driver['coordinationBinding'], 'OLD_OWNER_BINDING_CHANGED')
            for field, expected in ((boot['compilerFile'], boot['compilerHash']), (profile['bootGuardFile'], profile['bootGuardHash'])):
                need(sha(read(s.exact_path(field))) == expected, 'RETAINED_BOOT_SOURCE_CHANGED')
            sources = source_closure(q, owner, profile, read, oldroot)
            nft = d.ReadOnlyNft({'path': owner['nftPath'], 'sha256': owner['nftSha256']}, owner['kernel']['tableName'], native.binary, work, l.parse)
            tables = nft.tables('default'); qualify_tables(core, d, owner, boot, tables, CURRENT_STRUCTURE, BOOT_FOOTPRINT)
            qualify_tables(core, d, owner, boot, nft.tables('default'), CURRENT_STRUCTURE, BOOT_FOOTPRINT)
            p.save(work / 'preflight.json', q.encoded(current)); p.save(work / 'active-owner.before.private.json', encoded(owner))
            p.save(work / 'active-coordination.before.private.json', encoded(old_journal)); p.save(work / 'native.before.private.json', encoded(tables))
            report['phase'] = 'RESERVE_SEPARATE_SUCCESSOR_CONTEXT'
            os.mkdir(CLAIM, 0o700); intended = True
            p.save(CLAIM / 'intent.json', q.encoded({'schema': 'ouf.discovery-coordinator-successor-stage-intent.v1',
                   'evidenceDirectory': str(work), 'prerequisiteReceiptSha256': RECEIPT_SHA, 'activePublicationAllowed': False,
                   'leaseGrantAllowed': False, 'startAllowed': False}))
            # Verify parent custody without accepting a supplied destination or symlink.
            parent = p.open_parent(SNAPSHOTS / 'unused'); os.close(parent)
            stage = Path(tempfile.mkdtemp(prefix='discovery-coordinator-successor-20261109-', dir=SNAPSHOTS))
            report.update(stagedContextCreated=True, stagedContextDirectory=str(stage))
            p.save(CLAIM / 'created.json', q.encoded({'contextDirectory': str(stage)}))
            files = build_successor(stage, owner, boot, profile, CURRENT_STRUCTURE, sha(os.urandom(32)))
            write_successor(p, stage, files, sources)
            report['phase'] = 'VERIFY_SUCCESSOR_GUARD_AND_PRESERVED_ACTIVE_CONTEXT'
            fresh_owner = files['coordinated-configuration.json']
            result, guard_reads = verify_staged_owner(q, core, fresh_owner, native, work)
            for name, value in files.items(): need(p.read_private(stage / name) == encoded(value), 'STAGED_PROFILE_READBACK_CHANGED')
            for name, raw in sources.items(): need(p.read_private(stage / 'source' / name) == raw, 'STAGED_SOURCE_READBACK_CHANGED')
            qualify_tables(core, d, owner, boot, nft.tables('default'), CURRENT_STRUCTURE, BOOT_FOOTPRINT)
            for path in list(saved): read(path)
            verifier = s.Reader(); verifier.seals = dict(reader.seals)
            for path in list(verifier.seals): verifier.read(path, 'postStageRecheck')
            for role in ('adapter', 'southbound'):
                need(h.digest(h.frame(h.inspect(s.PINS[role][0]))) == s.PINS[role][1], 'PROVIDER_FRAME_CHANGED')
                need(not os.path.lexists(registry / s.PINS[role][0] / 'netns'), 'OLD_NAMESPACE_REAPPEARED')
            receipt = {'schema': 'ouf.discovery-coordinator-successor-preparation.v1', 'status': 'STAGED_NOT_ACTIVE',
                       'directory': str(stage), 'previousActivePointerSha256': sha(saved[str(d.POINTER)]),
                       'previousOwnerSha256': sha(saved[str(oldroot / 'coordinated-configuration.json')]),
                       'previousDriverSha256': sha(driver_raw), 'reviewedDriftReceiptSha256': RECEIPT_SHA,
                       'previousExactStructureSha256': OLD_STRUCTURE, 'currentExactStructureSha256': CURRENT_STRUCTURE,
                       'bootFootprintSha256': BOOT_FOOTPRINT, 'configurationHash': digest(fresh_owner),
                       'bootProfileHash': digest(files['boot-profile.json']), 'fileHashes': {name: digest(value) for name, value in files.items()},
                       'sourceHashes': {name: sha(raw) for name, raw in sources.items()}, 'leaseAuthorized': False,
                       'startAuthorized': False, 'activePointerChanged': False, 'historicalJournalsPreserved': True}
            p.save(stage / 'preparation-receipt.json', encoded(receipt))
            p.save(work / 'source-hashes.private.json', encoded({path: sha(raw) for path, raw in saved.items()}))
            report.update(status='DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED', phase='COMPLETE',
                          stagedOwnerGuardPassed=True, stagedCoordinationState='QUIESCED', activeCoordinationState='BLOCKED',
                          stagedLeaseAuthorized=False, stagedStartAuthorized=False, originalContextsPreserved=True,
                          containerFramesUnchanged=True, nativeStructureUnchanged=True, sourceFilesCopied=len(sources),
                          newConfigurationSha256=digest(fresh_owner), newBootProfileSha256=digest(files['boot-profile.json']),
                          successorPreparationReceiptSha256=digest(receipt), nftAdditionalReads=nft.calls + guard_reads)
            p.save(CLAIM / 'complete.json', q.encoded(report))
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(reason=reason, operationIntentPresent=intended,
                      errorLocation=[{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        if work is not None: p.save(work / 'result.json', encoded(report) + b'\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED' else 1


if __name__ == '__main__': sys.exit(main())
