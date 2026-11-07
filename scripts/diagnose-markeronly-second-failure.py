
import hashlib,json,pathlib,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
archive=root/'evidence/markeronly-second-native-41882562646.zip'
raw=archive.read_bytes();assert hashlib.sha256(raw).hexdigest()=='eef93e9e5d413759c871d8ceac21b901fe29c0e8b712c1028d38d6b4f2172e3d'
with zipfile.ZipFile(archive) as z:payload={n:z.read(n) for n in z.namelist()}
checks=dict((name,digest) for digest,name in (line.split('  ',1) for line in payload['SHA256SUMS'].decode().splitlines()))
assert set(checks)==set(payload)-{'SHA256SUMS'}
assert all(hashlib.sha256(payload[n]).hexdigest()==d for n,d in checks.items())
failure=json.loads(payload['markeronly-crash-lab/markeronly-failure.json'])
receipt={'status':'FAILED_NATIVE_ARCHIVE_DIAGNOSED_NOT_QUALIFIED','nativeQualification':False,
'originalZipSha256':hashlib.sha256(raw).hexdigest(),'originalZipBytes':len(raw),'members':len(payload),'checksumsVerified':len(checks),
'nativeRun':41882562646,'nativeJob':126758546819,'producerCommit':'84706b4fa014df74fdbd3685a56d2aba16934c84',
'readbackRun':41883215358,'readbackJob':126760754240,'verifierCommit':'e5e59d027826d9727fdab51557215fee81986e12',
'underlyingFailure':failure['failure'],'readbackFailure':'NATIVE_SCENARIO_PASS: markeronly-crash-lab',
'diagnosis':'Observer incorrectly requires marker unlink on the same OS thread as IDX rename. This is not a protocol invariant: the committing Go goroutine may migrate. Old compound assertion did not retain its operands, so this archive alone cannot distinguish thread mismatch from a missing sync. Preserve failure; require fresh native success with explicit ordered trace and exact fsync/path/process checks.',
'completeFailure':failure,'scenarioReceipt':json.loads(payload['markeronly-crash-lab/receipt.json']),
'interrenameReceipt':json.loads(payload['interrename-crash-lab/receipt.json']),
'nativeRegressionTestsPassed':186,'priorScenariosPassed':13,'targetOperations':0}
(root/'evidence/storage-markeronly33-second-failure-diagnosis-20261104.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['members','checksumsVerified','underlyingFailure','priorScenariosPassed']}))
