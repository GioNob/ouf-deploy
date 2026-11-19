import hashlib,importlib.util,json,pathlib,struct,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
archive=root/'evidence/markeronly-failed-native-41878669053.zip'
raw=archive.read_bytes();assert hashlib.sha256(raw).hexdigest()=='ee6220bfc751860ce366b859838b5cd6f5154853e22574b93a7849890b8a0a03'
with zipfile.ZipFile(archive) as z:
    payload={n:z.read(n) for n in z.namelist()}
checks=dict((name,digest) for digest,name in (line.split('  ',1) for line in payload['SHA256SUMS'].decode().splitlines()))
assert set(checks)==set(payload)-{'SHA256SUMS'}
assert all(hashlib.sha256(payload[n]).hexdigest()==d for n,d in checks.items())
failure=json.loads(payload['interrename-crash-lab/interrename-failure.json'])
spec=importlib.util.spec_from_file_location('inter',root/'scripts/storage-generation33-interrename-crash.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
prefix='interrename-crash-lab/interrename-before-dat-retained'
witness=m.relocation.identity(failure['witnessBeforeDatRename'])
proof=m.mixed_witness(payload[prefix+'.idx'],payload[prefix+'.cpx'],payload[prefix+'.cpd'],witness,failure['filesBefore']['.dat']['bytes'])
receipt={'status':'FAILED_NATIVE_ARCHIVE_DIAGNOSED_NOT_QUALIFIED','originalZipSha256':hashlib.sha256(raw).hexdigest(),
'originalZipBytes':len(raw),'members':len(payload),'checksumsVerified':len(checks),
'nativeRun':41878669053,'nativeJob':126745091191,'producerCommit':'87fc66ca9a2b24fb55e983392f573c0c1f54d96c',
'readbackRun':41878956434,'verifierCommit':'3767de36cb23876739bbb255e088e74dd2ca92fb',
'underlyingFailure':failure['failure'],'harnessFailure':'POSTMARKER_OBSERVATION_BUDGET',
'diagnosis':'Hardcoded pending witness offset 8 rejects valid live prefix in selected volume.',
'retainedPreRenameCopiesDecoded':proof,'beforeDatBytes':failure['filesBefore']['.dat']['bytes'],
'compactedCopyBytes':failure['filesBeforeDatRename']['.cpd']['bytes'],
'localArchiveReadback':True,'nativeMarkerOnlyExecuted':False,'nativeQualification':False,
'cleanupFailure':json.loads(payload['interrename-crash-lab/receipt.json'])['cleanupFailure'],
'completeFailure':failure,'targetOperations':0}
out=root/'evidence/storage-markeronly33-first-failure-diagnosis-20261104.json'
out.write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ['members','checksumsVerified','underlyingFailure','beforeDatBytes','compactedCopyBytes','retainedPreRenameCopiesDecoded']}))
