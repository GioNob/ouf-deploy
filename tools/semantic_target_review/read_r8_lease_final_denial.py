"""One consolidated root read of the consumed lease attempt; no recovery."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-r8-lease-ao5xt5og')
READER = Path('/home/oufadmin/ouf-r8-post-read.Tl08rnjI/read.py')
READER_HASH = 'ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8'
UNIT = 'ouf-semantic-provider-lease-r8.service'
PHASE = 'READ_ONLY_LOAD_EXISTING_VERIFIED_READER'


def main():
    global PHASE
    facts = {'schema': 'ouf.provider-r8-lease-final-denial-read-only.v1',
             'containerLifecycleOperations': 0, 'existingConfigurationWrites': 0,
             'privateKeysRead': 0, 'signaturesIssued': 0, 'dnsQueries': 0, 'providerCalls': 0,
             'claimReset': False, 'leaseGrantedHere': False, 'startAuthorized': False,
             'doNotRerunApply': True, 'notReleaseAcceptance': True}
    try:
        assert os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
        with READER.open('rb') as stream:
            raw = stream.read(131073)
        assert len(raw) <= 131072 and hashlib.sha256(raw).hexdigest() == READER_HASH
        reader = {'__name__': 'retained_r8_reader', '__file__': str(READER)}
        exec(compile(raw, str(READER), 'exec'), reader)
        private, parse = reader['private'], reader['parse']
        PHASE = 'READ_ALL_RETAINED_LEASE_RECEIPTS_AND_PROGRAM_BINDINGS'
        records = {}
        allowed = ('schema', 'status', 'refreshCount', 'workerPid', 'flowAddressCounts',
                   'journalHash', 'freshDnsObserved', 'leaseAuthorized', 'setsRevoked',
                   'reason', 'phase', 'cleanup', 'errorType', 'exceptionChain', 'retainedWorkerDenial')
        for name in ('cycle-1.json', 'cycle-2.json', 'worker-status.json', 'worker-denial.json',
                     'operator-denial.json', 'cleanup-denial.json', 'worker-activation-claim.json'):
            path = ROOT/name
            if not os.path.lexists(path):
                records[name] = {'present': False}
                continue
            raw = private(path)
            value = parse(raw)
            records[name] = {'present': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                             **{k: value[k] for k in allowed if k in value}}
        raw = private(ROOT/'authorization.json')
        auth = parse(raw)
        assert set(auth['programHashes']) == {'activate.py', 'activation_core.py', 'reader.py', 'materialize_southbound_lease_refresh.py'}
        records['authorization.json'] = {'present': True, 'sha256': hashlib.sha256(raw).hexdigest(),
            'approvalRef': auth['approvalRef'], 'expectedProcessGenerations': auth['expectedProcessGenerations'],
            'expectedJournalHash': auth['expectedJournalHash'], 'programHashes': auth['programHashes'],
            'leaseCompilerBinding': auth['leaseCompilerBinding'],
            'allProgramHashesMatched': all(hashlib.sha256(private(ROOT/name)).hexdigest() == digest
                                          for name, digest in auth['programHashes'].items())}
        claim = parse(private('/etc/ouf/provider-r8-network-lease.claim'))
        records['rootActivationClaim'] = {'present': True, 'matchesThisSnapshot': claim['directory'] == str(ROOT),
                                         'approvalRef': claim['approvalRef']}
        facts['retainedRecords'] = records
        PHASE = 'READ_CURRENT_SERVICE_PROPERTIES_WITHOUT_START_STOP_OR_RESET'
        human = parse(private(reader['CONTEXT']/'human-approval-binding.json'))
        cfg = parse(private(reader['CONTEXT']/'execution-configuration.json', human['configurationHash']))
        binding = cfg['commandBindings']['systemctl']
        private(binding['path'], binding['sha256'], executable=True)
        result = subprocess.run([binding['path'], 'show', UNIT,
            '--property=LoadState,ActiveState,SubState,MainPID,Restart,ExecStart'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        assert len(result.stdout) <= 131072 and len(result.stderr) <= 131072
        values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        facts['currentService'] = {'exitCode': result.returncode,
            **{k: values.get(k) for k in ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart')},
            'execStartMatchesSnapshot': str(ROOT/'activate.py') in values.get('ExecStart', '')}
        PHASE = 'READ_CURRENT_R8_PROCESSES_AND_NATIVE_LEASE_STATE'
        current = reader['collect']()
        facts['currentRoles'] = current['roles']
        facts['currentNetworkLease'] = current['networkLease']
        facts['currentLeaseUnitNames'] = current['leaseServiceUnitNames']
        facts['historicalFinalComparisonValuesRetained'] = False
        facts['status'] = 'CONSUMED_LEASE_ATTEMPT_EVIDENCE_CAPTURED'
        facts['privateValuesPrinted'] = False
        print('OUF_R8_LEASE_FINAL_READ_ONLY=' + json.dumps(facts, sort_keys=True))
        return 0
    except Exception as error:
        facts.update(status='READ_ONLY_DENIED', phase=PHASE, errorType=type(error).__name__,
                     exceptionPoints=[{'file': Path(t.filename).name, 'function': t.name, 'line': t.lineno}
                                      for t in traceback.extract_tb(error.__traceback__)[-6:]],
                     privateValuesPrinted=False)
        print('OUF_R8_LEASE_FINAL_READ_ONLY=' + json.dumps(facts, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
