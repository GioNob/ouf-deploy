"""Read existing R12/input custody without repeating preparation or creating an intent."""
import hashlib
import json
import os
import re
import sys
import types

SOURCE_HASHES = {
    'planner': '38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28',
    'prepare': '693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b',
    'custody': 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf',
    'creation': 'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665',
}

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def modules(sources):
    require(type(sources) is dict and set(sources) == set(SOURCE_HASHES),
            'EXACT_READ_ONLY_SOURCE_CLOSURE_REQUIRED')
    for name, expected in SOURCE_HASHES.items():
        raw = sources[name]
        require(type(raw) is bytes and len(raw) <= 131072 and hashlib.sha256(raw).hexdigest() == expected,
                'READ_ONLY_SOURCE_HASH_MISMATCH')
    planner = types.ModuleType('sealed_current_planner')
    exec(compile(sources['planner'], 'sealed-current-planner', 'exec'), planner.__dict__)
    loaded = planner.load_sources({k: sources[k] for k in ('prepare', 'custody', 'creation')})
    return planner, loaded['prepare'], loaded['custody'], loaded['creation']

def observe(planner, prepare, custody, creation):
    raw = custody.file_bytes(planner.DECLARATION, 0, {0o600}, expected=planner.DECLARATION_HASH)
    declaration = json.loads(raw)
    reader_raw = custody.file_bytes(prepare.R10/'reader.py', 0, {0o600}, expected=prepare.PROGRAMS['reader.py'])
    reader = types.ModuleType('sealed_retained_read_only_reader')
    reader.__file__ = str(prepare.R10/'reader.py')
    exec(compile(reader_raw, 'sealed-retained-read-only-reader', 'exec'), reader.__dict__)
    human = reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'))
    cfg = reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json', human['configurationHash']))
    before = prepare.r12_state(reader, cfg['commandBindings'])
    args = ['inspect', '--type', 'container', reader.SEMANTIC_ID]
    current = reader.parse(prepare.native(reader, cfg['commandBindings']['docker'], args, True))[0]
    scope = reader.collect_cutover()
    planner.native_lease_ready(scope['lease'])
    require(scope['currentSemanticPeer']['generation']['pid'] == current['State']['Pid'],
            'CURRENT_RECIPROCAL_PEER_GENERATION_DRIFT')
    planner.verify_secret_custody(custody, declaration, current)
    after = reader.parse(prepare.native(reader, cfg['commandBindings']['docker'], args, True))[0]
    last = prepare.r12_state(reader, cfg['commandBindings'])
    final_scope = reader.collect_cutover()
    planner.native_lease_ready(final_scope['lease'])
    require(prepare.frame(after) == prepare.frame(current)
            and last['workerGeneration'] == before['workerGeneration']
            and last['authorizationHash'] == before['authorizationHash']
            and last['refreshCount'] >= before['refreshCount']
            and final_scope['currentSemanticPeer']['generation']['pid'] == after['State']['Pid'],
            'CURRENT_GENERATION_CHANGED_DURING_READ')
    require(custody.file_bytes(planner.DECLARATION, 0, {0o600}, expected=planner.DECLARATION_HASH) == raw,
            'CURRENT_INPUT_DECLARATION_CHANGED')
    planner.verify_secret_custody(custody, declaration, after)
    flows = final_scope['lease']['flows']
    return {
        'status': 'CURRENT_R12_CUSTODY_REVERIFIED_READ_ONLY',
        'existingInputFilesReverified': 4,
        'declarationHash': planner.DECLARATION_HASH,
        'workerPid': last['workerPid'],
        'refreshCount': last['refreshCount'],
        'workerGenerationHash': creation.digest(last['workerGeneration']),
        'authorizationHash': last['authorizationHash'],
        'currentSemanticFrameHash': creation.digest(prepare.frame(after)),
        'flowCount': 2,
        'flows': [{'approvedAddressCount': f['approvedAddressCount'],
                   'minRemainingTtlSeconds': f['minRemainingTtlSeconds']} for f in flows],
        'continuousLivenessProven': False,
        'readConsistencyMode': 'STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY',
        'newCandidateImageCustodyProven': False,
        'newTransportClosureProven': False,
    }

def main():
    report = {
        'schema': 'ouf.discovery.current-r12-custody-read.v1',
        'containerLifecycleOperations': 0, 'imageImports': 0, 'databaseQueries': 0,
        'databaseWrites': 0, 'firewallWrites': 0, 'protectedFileWrites': 0,
        'commonLockAcquired': False, 'providerCalls': 0, 'dnsQueries': 0,
        'signaturesIssued': 0, 'newClaimCreated': False, 'budgetReset': False,
        'r12Touched': False, 'privateValuesPrinted': False, 'productionApplyReady': False,
        'notReleaseAcceptance': True,
    }
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_READ_ONLY_ENTRY_REQUIRED')
        report.update(observe(*modules(globals().get('__read_only_sources__'))))
        result = 0
    except Exception as error:
        reason = str(error)
        report.update(status='CURRENT_R12_CUSTODY_READ_BLOCKED',
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'CURRENT_R12_CUSTODY_UNPROVEN')
        result = 1
    print('OUF_CURRENT_R12_CUSTODY=' + json.dumps(report, sort_keys=True))
    return result

if __name__ == '__main__':
    raise SystemExit(main())
