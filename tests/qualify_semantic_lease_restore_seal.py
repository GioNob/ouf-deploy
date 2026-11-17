"""D-050 feasibility witness, NOT a migration implementation.

Only fixture tables in an explicitly opted-in disposable network namespace.
Exit zero means the witness completed, not that the restore seal was proved.
The JSON status states whether the exact historical seal survived recreation.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_lease_kernel_v2 import kernel, old, m
from tools.semantic_guard_extension.extend_empty_lease_guard import stable, digest


def historical_backend():
    path = ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py'
    spec = importlib.util.spec_from_file_location('task65_historical_nft', path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': old}):
        spec.loader.exec_module(module)
    return module


H = historical_backend()


class SealUnproven(RuntimeError):
    pass


def require_seal(expected, tables):
    """Use the unchanged historical hash, including EVERY object's handle."""
    if H.structure_hash(tables) != expected:
        raise SealUnproven('LEASE_KERNEL_RESTORE_SEAL_UNPROVEN')


def replacement(config):
    """Both deletes and both creations belong to ONE nft invocation."""
    table = config['tableName']
    # Validate names and all syntax through the versioned compiler first.
    compiled = m.materialize(config, empty_provider_sets=True)['nftRules']
    return ''.join(f'delete table {family} {table}\n' for family in ('inet', 'bridge')) + compiled


def prove():
    if (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0
            or os.environ.get('OUF_LEASE_RESTORE_SEAL_NATIVE') != '1'
            or not sys.flags.isolated or not sys.dont_write_bytecode):
        raise RuntimeError('explicit Linux root isolated native opt-in required')
    if os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
        raise RuntimeError('disposable network namespace required')
    nft = shutil.which('nft')
    if nft is None:
        raise RuntimeError('nft executable required')

    def run(argv, raw=None, *, fails=False):
        result = subprocess.run([nft, *argv], input=raw, capture_output=True,
                                text=True, timeout=15)
        if (result.returncode != 0) != fails:
            raise AssertionError('unexpected fixture nft result: ' + result.stderr)
        return result.stdout

    # Do not run in a reused namespace containing any tables.
    inventory = json.loads(run(['-j', 'list', 'tables']))['nftables']
    if any('table' in item for item in inventory):
        raise RuntimeError('empty disposable namespace required')
    source = kernel()
    source['tableName'] = 'ouf_task65_seal'
    source['providerFlows'] += kernel(ipv6=True)['providerFlows']
    target = copy.deepcopy(source)
    target.update(generation=2, providerFlowMatch='ORIGINAL_TUPLE')

    def read():
        tables = {family: json.loads(run(['-j', 'list', 'table', family, source['tableName']]))
                  for family in ('inet', 'bridge')}
        if any(item['set'].get('elem') for value in tables.values()
               for item in value['nftables'] if 'set' in item):
            raise AssertionError('fixture provider sets must stay empty')
        return tables

    run(['-f', '-'], old.materialize(source, empty_provider_sets=True)['nftRules'])
    before = read()
    expected = H.structure_hash(before)

    # A semantic error AFTER both recreations must roll back the entire batch.
    invalid = replacement(target) + 'add rule inet ouf_task65_seal absent_chain counter drop\n'
    run(['-f', '-'], invalid, fails=True)
    require_seal(expected, read())

    # This is the actual requested delete/recreate mechanism in the SAME netns.
    run(['-f', '-'], replacement(target))
    migrated = read()
    run(['-f', '-'], replacement(source))
    restored = read()
    # Prove reproducibility again, without a generation change as confounder.
    run(['-f', '-'], replacement(source))
    repeated = read()

    def handles(tables):
        return {family: [item['table']['handle'] for item in tables[family]['nftables']
                         if 'table' in item] for family in ('inet', 'bridge')}

    actual = H.structure_hash(restored)
    # Equal boot footprints do not authorize adoption of a different lease seal.
    if digest(stable(before)) != digest(stable(restored)):
        raise AssertionError('fixture recreation changed the boot footprint')
    reason = None
    try:
        require_seal(expected, restored)
        require_seal(expected, repeated)
    except SealUnproven as error:
        reason = str(error)
    return {'schema': 'ouf.lease-kernel-restore-seal-feasibility.v1',
            'status': 'HELD' if reason else 'RESTORE_SEAL_PROVEN_IN_FIXTURE',
            'reason': reason, 'nativeFixtureOnly': True,
            'atomicFailurePreservedGenerationN': True,
            'expectedStructureHash': expected, 'migratedStructureHash': H.structure_hash(migrated),
            'restoredStructureHash': actual, 'repeatedStructureHash': H.structure_hash(repeated),
            'tableHandles': {'before': handles(before), 'migrated': handles(migrated),
                             'restored': handles(restored), 'repeated': handles(repeated)},
            'bootFootprintPreserved': True, 'migrationImplemented': False,
            'startAuthorized': False, 'leaseAuthorized': False}


if __name__ == '__main__':
    print(json.dumps(prove(), sort_keys=True), flush=True)
