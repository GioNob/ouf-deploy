"""Disposable CI: real Engine,13-container cohort and protected metadata."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import hashlib
import urllib.request


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


assert os.geteuid() == os.getegid() == 0
base = Path(__file__).resolve().parents[1]
root = Path('/usr/local/lib/ouf-managed-csv-native-ci'); root.mkdir(mode=0o700)
sealed = root/'retained_inputs.py'; sealed.write_bytes((base/'tools/managed_csv_recovery/retained_inputs.py').read_bytes()); sealed.chmod(0o400)
m = load('sealed_capture', sealed)
fixtures = load('capture_fixtures', base/'tests/test_managed_csv_recovery_inputs.py')
roles = ['onboarding', 'mcp'] + ['peer'+str(i) for i in range(11)]
observations = {role: json.loads(subprocess.check_output(['docker', 'inspect', 'ouf-csv-capture-'+role]))[0] for role in roles}
history = root/'history'; history.mkdir(mode=0o700)
review, result, journal, case, _, _ = fixtures.fixture(observations, m.process_pin, str(history))
selected = Path('/var/run/docker.sock').resolve(); info = selected.lstat()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect(str(selected))
peer = list(struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))); sock.close()
binding = {'socketPath': str(selected), 'socketBinding': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)], 'peerCredentials': peer}
review['bootId'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
review['nativePlan']['proposal']['engineBinding'] = binding
case['reviewHash'] = result['reviewHash'] = journal['reviewHash'] = m.digest(review)
for effect in journal['effects']:
    effect['intentHash'] = m.digest({'reviewHash': case['reviewHash'], 'stage': effect['stage']})
documents = {'review.json': review, 'result.json': result, 'recovery.json': journal}
for name, value in documents.items():
    target = history/name; target.write_bytes(m.encoded(value)); target.chmod(0o400)
before = {name: (history/name).read_bytes() for name in documents}
# Reproduce the reported failure with the exact old consumer and the actual
# installed producer's peer-* map. This must stop before even creating Engine.
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/4dcffc7e299cda79d70b0a973e6e270ce4f36718/tools/managed_csv_recovery/retained_inputs.py'
with urllib.request.urlopen(url, timeout=30) as response:
    old_raw = response.read(65537)
assert len(old_raw) <= 65536 and hashlib.sha256(old_raw).hexdigest() == '5c390ebcb75857ef244b06d104bfbe988af899fc2f7a1e18288320a2c39780ed'
old_source = root/'old-consumer.py'; old_source.write_bytes(old_raw); old_source.chmod(0o400)
old = load('exact_consumed_capture', old_source)
stopped = old.Capture(root/'consumed-capture', 13)
def no_engine(*_):
    raise AssertionError('Engine reached before cohort reconciliation')
try:
    old.prepare(stopped, case, engine_factory=no_engine)
    raise AssertionError('old defect did not reproduce')
except old.Stop as error:
    assert str(error) == 'EXACT_RETAINED_COHORT_REQUIRED'
assert stopped.counts['privateMetadataReads'] == 3 and stopped.counts['engineGets'] == 0
stop_result = {'schema': 'ouf.managed-csv-recovery-input-capture-result.v1', 'status': 'STOP_RECONCILE',
               'reasonCode': 'EXACT_RETAINED_COHORT_REQUIRED', 'complete': False, 'counts': dict(stopped.counts),
               'containerWrites': 0, 'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False,
               'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
stopped.put('result.json', stop_result)
stop_claim = m.decode((stopped.root/'claim.json').read_bytes())
case['reconcilePriorStop'] = {'root': str(stopped.root), 'continuationName': 'reconcile-retained-peer-binding-v1',
                              'claim': stop_claim, 'result': stop_result, 'claimSha256': m.digest(stop_claim),
                              'resultSha256': m.digest(stop_result), 'counts': dict(stopped.counts)}
retained_before = {path: path.read_bytes() for path in stopped.root.iterdir() if path.is_file()}
capture = m.Capture(stopped.root/'reconcile-retained-peer-binding-v1', 13, reconcile=True)
output = m.prepare(capture, case)
assert output['complete'] is True and output['cohortSize'] == 13
assert output['counts']['engineGets'] == 27 and output['counts']['privateMetadataReads'] == 5
assert output['captureAccounting']['cumulativeCounts']['privateMetadataReads'] == 8
assert output['captureAccounting']['retainedConsumedScopeCounts'] == stopped.counts
assert output['containerWrites'] == output['sqlSessions'] == output['humanBudgetsGranted'] == output['resumes'] == 0
assert output['runtimeAuthorityIssued'] is False and output['currentJobOrBudgetStateObserved'] is False
assert all((history/name).read_bytes() == value for name, value in before.items())
assert all(path.read_bytes() == value for path, value in retained_before.items())
assert not (stopped.root/'inputs.json').exists()
assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in capture.root.iterdir())
for action in [lambda: m.Capture(capture.root, 13),
               lambda: m.Engine(capture, binding, [value['Id'] for value in observations.values()]).get('/v1.44/info')]:
    try:
        action(); raise AssertionError('replay or28th GET accepted')
    except m.Stop:
        pass
wrong = {**binding, 'peerCredentials': [peer[0]+1, *peer[1:]]}
other = m.Capture(root/'wrong-peer', 13)
try:
    m.Engine(other, wrong, [value['Id'] for value in observations.values()]).get('/v1.44/info')
    raise AssertionError('foreign Engine accepted')
except m.Stop as error:
    assert str(error) == 'EXACT_CAPTURE_ROOT_ENGINE_PEER_REQUIRED'
print(json.dumps({'status': 'MANAGED_CSV_NATIVE_CAPTURE_PASS', 'cohortSize': 13, 'engineGets': 27,
                  'metadataReads': 5, 'retainedMetadataReads': 3, 'cumulativeMetadataReads': 8,
                  'actualInstalledProducerUsed': True, 'exactOldDefectReproducedBeforeEngine': True,
                  'sourceRoot0400': True, 'oldFilesWritten': 0, 'runtimeEffects': 0,
                  'fixtureHistoryNotTargetProof': True, 'applicationE2EProven': False}, sort_keys=True))
