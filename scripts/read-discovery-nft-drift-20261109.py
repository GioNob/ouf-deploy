#!/usr/bin/env python3
"""Compare retained driver seal, current nft renderings and installed boot footprint.

Read-only: no ownership adoption, coordinator call, journal or nft write.
The boot comparison is diagnostic and never replaces the exact owner seal.
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

PRIOR = Path('/var/lib/ouf-storage-migration/discovery-coordinator-quiesce-j3rrvd1i')
PRIOR_SHA = '87b112700f76483227c5db8e0fa08b047f3fdd27886d1495e862263c03b0743a'
QUIESCE = 'quiesce-discovery-coordinator-20261109.py'
QUIESCE_SHA = '23028447dbc9980f1e04a3c2f4583d9d9ec16624c9200854955b1ba72e69baa8'
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value): return sha(encoded(value).removesuffix(b'\n'))


def load_quiesce():
    path = Path(__file__).with_name(QUIESCE); raw = path.read_bytes()
    need(sha(raw) == QUIESCE_SHA, 'PINNED_HELPER_CHANGED')
    namespace = {'__name__': 'quiesce_read_only_dependency', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


def boot_structure(value):
    # Exact diagnostic profile used by extend_empty_lease_guard.stable.
    # Keep rule order, expressions, chain hooks/priorities/policies and set data.
    if isinstance(value, list):
        return [boot_structure(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    if isinstance(value, dict):
        return {k: boot_structure(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes', 'expires')}
    return value


def validate_tables(tables, table):
    need(set(tables) == {'inet', 'bridge'}, 'BOTH_GUARD_FAMILIES_REQUIRED')
    counts = {}
    for family, document in tables.items():
        rows = document.get('nftables')
        need(isinstance(rows, list) and len(rows) <= 4096, 'BOUNDED_NFT_TABLE_REQUIRED')
        counts[family] = {'table': 0, 'chain': 0, 'rule': 0, 'set': 0, 'metainfo': 0, 'other': 0, 'elements': 0}
        for row in rows:
            need(isinstance(row, dict) and len(row) == 1, 'NFT_OBJECT_SHAPE_UNPROVEN')
            kind, value = next(iter(row.items()))
            counts[family][kind if kind in counts[family] and kind != 'elements' else 'other'] += 1
            if kind in ('table', 'chain', 'rule', 'set'):
                need(isinstance(value, dict) and value.get('family') == family and
                     value.get('name' if kind == 'table' else 'table') == table, 'NFT_OBJECT_SCOPE_UNPROVEN')
            if kind == 'set':
                need(isinstance(value.get('elem', []), list), 'NFT_ELEMENTS_FORMAT_UNPROVEN')
                counts[family]['elements'] += len(value.get('elem', []))
        need(counts[family]['table'] == 1, 'ONE_BOUND_TABLE_REQUIRED')
    return counts


def differences(left, right):
    """Counts only: never print arbitrary nft expressions, addresses or names."""
    result = {}
    def walk(a, b, kind='other'):
        if a == b: return
        if type(a) is not type(b): result[kind] = result.get(kind, 0) + 1; return
        if isinstance(a, dict):
            for key in sorted(set(a) | set(b)):
                category = key if key in ('metainfo', 'handle', 'rule', 'chain', 'set', 'table') else kind
                if key not in a or key not in b: result[category] = result.get(category, 0) + 1
                else: walk(a[key], b[key], category)
        elif isinstance(a, list):
            if len(a) != len(b): result[kind + 'Length'] = result.get(kind + 'Length', 0) + 1
            for x, y in zip(a, b): walk(x, y, kind)
        else: result[kind] = result.get(kind, 0) + 1
    walk(left, right)
    return result


class ReadOnlyNft:
    def __init__(self, binding, table, binary, work, parse):
        need(re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', table), 'BOUND_TABLE_NAME_REQUIRED')
        self.binding, self.table, self.binary, self.work, self.parse = binding, table, binary, work, parse
        self.calls = 0

    def tables(self, mode):
        need(mode in ('default', 'numeric') and self.calls <= 6, 'BOUNDED_NFT_READ_MODE_REQUIRED')
        result = {}
        for family in ('inet', 'bridge'):
            executable = self.binary(self.binding['path'], self.binding['sha256'])
            args = ['-j'] + (['-n'] if mode == 'numeric' else []) + ['list', 'table', family, self.table]
            self.calls += 1
            with tempfile.TemporaryFile(dir=self.work) as output:
                process = subprocess.run([executable, *args], stdin=subprocess.DEVNULL, stdout=output,
                                         stderr=subprocess.DEVNULL, timeout=5, env=ENV)
                output.seek(0); raw = output.read(2097153)
            self.binary(self.binding['path'], self.binding['sha256'])
            need(process.returncode == 0 and len(raw) <= 2097152, 'NFT_TABLE_READ_FAILED')
            result[family] = self.parse(raw)
        validate_tables(result, self.table)
        return result


def compare(structure_hash, structure, expected, retained, samples):
    hashes = {name: structure_hash(value) for name, value in samples.items()}
    stable = hashes['default'] == hashes['defaultAgain'] and hashes['numeric'] == hashes['numericAgain']
    return {'expectedDriverStructureSha256': expected, 'observedStructureSha256': hashes,
            'retainedPreflightStructureSha256': structure_hash(retained), 'stableAcrossReads': stable,
            'defaultMatchesExpected': hashes['default'] == expected,
            'numericMatchesExpected': hashes['numeric'] == expected,
            'numericMatchesHeldPreflight': hashes['numeric'] == structure_hash(retained),
            'renderingDifferences': differences(structure(samples['default']), structure(samples['numeric'])),
            'heldToCurrentNumericDifferences': differences(structure(retained), structure(samples['numeric'])),
            'bootComparisonProfile': 'EXCLUDES_METAINFO_HANDLES_AND_COUNTER_EXPIRY_FIELDS_ONLY_NOT_AUTHORITY'}


def boot_baseline(read, parse, exact_path, driver):
    pointer = parse(read(POINTER))
    need(pointer.get('schema') == 'ouf.semantic-coordinated-boot-pointer.v1', 'KNOWN_BOOT_POINTER_REQUIRED')
    receipt_path = exact_path(pointer['receiptFile']); root = receipt_path.parent
    need(root.is_relative_to('/etc/ouf/deploy-snapshots') and receipt_path.name == 'installation-receipt.json', 'BOUND_BOOT_RECEIPT_PATH_REQUIRED')
    raw = read(receipt_path); need(sha(raw) == pointer['receiptHash'], 'BOOT_RECEIPT_HASH_CHANGED')
    receipt = parse(raw)
    need(receipt.get('schema') in ('ouf.semantic-coordinated-boot-installation.v1', 'ouf.semantic-provider-network-guard-installation.v1')
         and receipt.get('state') == 'INSTALLED' and receipt.get('directory') == str(root), 'KNOWN_INSTALLED_BOOT_RECEIPT_REQUIRED')
    owner_raw = read(root / 'coordinated-configuration.json'); profile_raw = read(root / 'boot-profile.json')
    need(sha(owner_raw) == receipt['configurationHash'] and sha(profile_raw) == receipt['bootProfileHash'], 'BOOT_INPUT_HASH_CHANGED')
    owner, profile = parse(owner_raw), parse(profile_raw)
    need(owner.get('schema') == 'ouf.semantic-coordinated-owner-runtime.v1' and profile.get('schema') == 'ouf.semantic-coordinated-boot-profile.v1'
         and profile['coordinatedConfiguration'] == str(root / 'coordinated-configuration.json')
         and profile['coordinatedConfigurationHash'] == sha(owner_raw), 'BOOT_OWNER_PROFILE_BINDING_CHANGED')
    boot_path = exact_path(profile['bootConfiguration'])
    need(boot_path.is_relative_to('/etc/ouf/deploy-snapshots'), 'BOUND_BOOT_CONFIGURATION_PATH_REQUIRED')
    boot_raw = read(boot_path); need(sha(boot_raw) == profile['bootConfigurationHash'], 'BOOT_CONFIGURATION_HASH_CHANGED')
    boot = parse(boot_raw)
    need(boot.get('schema') == 'ouf.semantic-runtime-boot-guard.v1' and boot['kernel'] == owner['kernel']
         and boot['lockFile'] == owner['commonLockFile'] and boot['nftPath'] == owner['nftPath'], 'BOOT_INTERNAL_BINDING_CHANGED')
    need(re.fullmatch('[0-9a-f]{64}', boot['expectedFootprint']) is not None, 'BOOT_FOOTPRINT_HASH_REQUIRED')
    matches = {'kernel': owner['kernel'] == driver['kernel'], 'lockFile': owner['commonLockFile'] == driver['lockFile'],
               'journalFile': owner['journalFile'] == driver['coordinationJournal'], 'nftPath': owner['nftPath'] == driver['commands']['nft'],
               'coordinationBinding': owner['binding'] == driver['coordinationBinding'],
               'expectedStructureHash': owner['expectedStructureHash'] == driver['coordinationBinding']['leaseStructureHash']}
    return {'status': 'BOUND_BOOT_BASELINE_READ', 'installedOwnerMatchesDriver': matches,
            'allOwnerBindingsMatchDriver': all(matches.values()), 'expectedFootprintSha256': boot['expectedFootprint'],
            'installedOwnerExpectedStructureSha256': owner['expectedStructureHash'], 'systemdLoadedConfigurationRead': False,
            'scope': 'HASH_BOUND_ACTIVE_POINTER_FILES_NOT_EFFECTIVE_SYSTEMD_OR_NEW_AUTHORITY'}


def classification(comparison, boot):
    if not comparison['stableAcrossReads']: return 'NFT_STRUCTURE_CHANGED_DURING_READ'
    if comparison['defaultMatchesExpected']: return 'CURRENT_DEFAULT_MATCHES_EXPECTED_PRIOR_FAILURE_NOT_REPRODUCED'
    if comparison['numericMatchesExpected']: return 'EXPECTED_HASH_MATCHES_NUMERIC_RENDERING_ONLY'
    if boot.get('status') != 'BOUND_BOOT_BASELINE_READ': return 'DRIVER_HASH_DIFFERS_BOOT_COMPARISON_UNAVAILABLE'
    if not boot['allOwnerBindingsMatchDriver']: return 'INSTALLED_BOOT_OWNER_AND_RETAINED_DRIVER_DIFFER'
    if boot.get('anyCurrentFootprintMatches'): return 'BOOT_FOOTPRINT_MATCHES_EXACT_DRIVER_HASH_DIFFERS'
    return 'DRIVER_HASH_AND_BOOT_FOOTPRINT_DIFFER'


def main():
    report = {'schema': 'ouf.discovery-nft-drift-read.v1', 'status': 'READ_INCOMPLETE',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'nftWrites': 0, 'runtimeJournalWrites': 0,
              'serviceConfigurationChanged': False, 'serviceStartDispatched': False, 'serviceStops': 0,
              'credentialFileContentsRead': 0, 'credentialValuesEmitted': False, 'databaseRequests': 0,
              'businessRequestsIssued': 0, 'providerRequests': 0, 'dnsQueries': 0, 'tokenRequests': 0, 's3Requests': 0,
              'quiescenceAttempted': False, 'expectedHashesChanged': False, 'historicalAuthorityReused': False,
              'automaticReplayAllowed': False, 'causeOfHistoricalDriftProven': False, 'rawRulesEmitted': False}
    work = None; nft = None; saved = {}
    def deadline(*_): raise RuntimeError('NFT_DIAGNOSIS_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(120)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED')
        os.umask(0o077); q = load_quiesce(); p = q.load_helper('reconcile-discovery-placeholder-20261109.py')
        l = q.load_helper('read-discovery-lifecycle-20261109.py'); s = l.module(l.STARTUP, l.STARTUP_SHA)
        core = q.load_core(); nft_core = core.semantic_provider_lease_nft
        def read(path):
            path = str(path); need(len(saved) < 32 or path in saved, 'METADATA_FILE_READ_LIMIT')
            raw = p.read_private(path)
            need(path not in saved or saved[path] == raw, 'SOURCE_CHANGED_DURING_READ')
            saved[path] = raw; return raw
        report['phase'] = 'READ_HELD_RECEIPT_AND_BOUND_DRIVER'
        need(sha(read(PRIOR / 'result.json')) == PRIOR_SHA, 'EXACT_HELD_RECEIPT_REQUIRED')
        need(not os.path.lexists(q.CLAIM), 'QUIESCENCE_INTENT_NOW_PRESENT')
        retained = l.parse(read(PRIOR / 'native-selected.private.json'))['leaseTables']
        bindings = l.parse(read(q.RECEIPT.parent / 'source-bindings.private.json'))
        matches = [path for path, value in bindings.items() if value['sha256'] == l.CONFIG_SHA]
        need(len(matches) == 1, 'ONE_RETAINED_RUNTIME_CONFIGURATION_REQUIRED')
        raw = read(matches[0]); need(sha(raw) == l.CONFIG_SHA, 'RETAINED_RUNTIME_CONFIGURATION_CHANGED')
        cfg = l.parse(raw); registry = s.exact_path(cfg['registryRoot']); cid = s.PINS['southbound'][0]; root = registry / cid
        need(registry.is_relative_to('/etc/ouf'), 'BOUND_RUNTIME_REGISTRY_REQUIRED')
        record = l.parse(read(root / 'adapter.json')); driver_raw = read(root / 'driver.json'); driver = l.parse(driver_raw)
        need(record['configurationHash'] == l.runtime_binding(cfg, cid) and sha(driver_raw) == record['driverHash'], 'BOUND_DRIVER_REQUIRED')
        broker_raw = read(root / 'broker.json'); need(sha(broker_raw) == cfg['candidates'][cid]['admissionConfigurationHash'], 'BOUND_BROKER_REQUIRED')
        ref = l.parse(broker_raw)['preparerTemplate']; template_raw = read(s.exact_path(ref['path']))
        need(sha(template_raw) == ref['sha256'], 'BOUND_TEMPLATE_REQUIRED'); template = l.parse(template_raw)
        need(template['commands']['nft'] == driver['commands']['nft'], 'NFT_COMMAND_BINDING_CHANGED')
        command = {'path': driver['commands']['nft'], 'sha256': template['commandHashes']['nft']}
        work = Path(tempfile.mkdtemp(prefix='discovery-nft-drift-', dir=PRIOR.parent)); report['privateEvidenceDirectory'] = str(work)
        native = l.Native(work); nft = ReadOnlyNft(command, driver['kernel']['tableName'], native.binary, work, l.parse)
        report['phase'] = 'COMPARE_NFT_UNDER_EXISTING_LOCKS'
        with contextlib.ExitStack() as locks:
            for role in ('southbound', 'adapter'): locks.enter_context(p.existing_lock(registry / s.PINS[role][0] / 'operation.lock'))
            locks.enter_context(p.existing_lock(registry, directory=True)); locks.enter_context(p.existing_lock(s.exact_path(driver['lockFile'])))
            for path in list(saved): read(path)
            journal = l.parse(read(s.exact_path(driver['coordinationJournal'])))
            need(all(journal.get(k) == v for k, v in driver['coordinationBinding'].items()), 'COORDINATOR_BINDING_CHANGED')
            report['coordination'] = {k: journal[k] for k in ('state', 'leaseAuthorized', 'startAuthorized')}
            samples = {name: nft.tables(mode) for name, mode in (('default', 'default'), ('numeric', 'numeric'), ('defaultAgain', 'default'), ('numericAgain', 'numeric'))}
            report['currentObjectCounts'] = validate_tables(samples['numeric'], driver['kernel']['tableName'])
            validate_tables(retained, driver['kernel']['tableName'])
            report['comparison'] = compare(nft_core.structure_hash, nft_core.structure, driver['coordinationBinding']['leaseStructureHash'], retained, samples)
            try:
                boot = boot_baseline(read, l.parse, s.exact_path, driver)
                boot['currentFootprintMatches'] = {name: digest(boot_structure(value)) == boot['expectedFootprintSha256'] for name, value in samples.items()}
                boot['retainedPreflightFootprintMatches'] = digest(boot_structure(retained)) == boot['expectedFootprintSha256']
                boot['anyCurrentFootprintMatches'] = any(boot['currentFootprintMatches'].values())
                boot['currentFootprintSha256'] = {name: digest(boot_structure(value)) for name, value in samples.items()}
            except Exception as exc:
                boot = {'status': 'BOOT_BASELINE_READ_INCOMPLETE', 'reason': l.code(exc)}
            report['installedBoot'] = boot
            report['classification'] = classification(report['comparison'], boot)
            for path in list(saved): read(path)
            need(not os.path.lexists(q.CLAIM), 'QUIESCENCE_INTENT_APPEARED_DURING_READ')
            p.save(work / 'selected.private.json', encoded({'driver': driver, 'heldPreflight': retained, 'samples': samples}))
            p.save(work / 'source-hashes.private.json', encoded({path: sha(raw) for path, raw in saved.items()}))
            report.update(status='DISCOVERY_NFT_DRIFT_READ_COMPLETE', phase='COMPLETE', sourceFilesUnchanged=True,
                          metadataFilesRead=len(saved), quiescenceIntentPresent=False)
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(reason=reason, errorLocation=[{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        if nft is not None: report['nftTableReadAttempts'] = nft.calls
        if work is not None: p.save(work / 'result.json', encoded(report))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_NFT_DRIFT_READ_COMPLETE' else 1


if __name__ == '__main__': sys.exit(main())
