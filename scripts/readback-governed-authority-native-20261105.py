import hashlib,io,json,pathlib,subprocess,sys,zipfile
from xml.etree import ElementTree as E
archive=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'target/governed-authority-native.zip')
expected='6eb268070ca9c96743cb399b51558016fdc96aa5'
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
assert archive.stat().st_size==166945 and digest=='b920b07197c99748e2432214e2123812e765b2c06b7191e0ec1ee465bd433abe'
with zipfile.ZipFile(archive) as z:
    infos=z.infolist()
    assert len(infos)==len({i.filename for i in infos}) and sum(i.file_size for i in infos)<32*1024*1024
    assert all(not i.is_dir() and not pathlib.PurePosixPath(i.filename).is_absolute() and '..' not in pathlib.PurePosixPath(i.filename).parts for i in infos)
    data={i.filename:z.read(i) for i in infos}
manifest={}
for line in data['upload-native/SHA256SUMS'].decode().splitlines():
    h,name=line.split('  ',1)
    assert name not in manifest
    manifest[name]=h
assert set(manifest)==set(data)-{'upload-native/SHA256SUMS'}
for name,h in manifest.items():assert hashlib.sha256(data[name]).hexdigest()==h,name
assert data['upload-native/source-commit.txt'].decode().strip()==expected
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==expected
bindings=json.loads(data['upload-native/source-bindings.json'])
queries=''.join(expected+':'+p+'\n' for p in bindings).encode()
batch=io.BytesIO(subprocess.run(['git','cat-file','--batch'],input=queries,stdout=subprocess.PIPE,check=True).stdout)
for path,h in bindings.items():
    header=batch.readline().decode().strip().split()
    assert len(header)==3 and header[1]=='blob',path
    content=batch.read(int(header[2]));assert batch.read(1)==b'\n'
    assert hashlib.sha256(content).hexdigest()==h,path
assert batch.read()==b''
suites=[E.fromstring(v) for k,v in data.items() if k.startswith('surefire-reports/TEST-') and k.endswith('.xml')]
assert len(suites)==4 and sum(int(s.attrib['tests']) for s in suites)==97
assert all(all(int(s.attrib[k])==0 for k in ('failures','errors','skipped')) for s in suites)
native=next(s for s in suites if s.attrib['name'].endswith('ManagedFileUploadNativeTest'))
assert int(native.attrib['tests'])==89
required={
 'restart-idempotency':dict(generation=2,revoked=True,sameProofAfterRestart=True,deadlineUnchanged=True,stalePublicationRejected=True,filesystem='ext4'),
 'cross-process-commit':dict(blockedDuringOwnerCommit=True,publishedAfterCommit=True,generation=2,revoked=True),
 'killed-holder':dict(ownerDeniedWhileHeld=True,holderKilled=True,durableLatchPresent=True,ownerDeniedAfterDeath=True,publisherDeniedAfterRestart=True,noAutomaticRegrant=True),
 'crash-and-logical-replay':dict(publisherExit=86,generation=2,revoked=True,exactPublicationReconciled=True,samePostmaster=True,restoredSnapshotUnchanged=True,prepareDeliveryOwnerRejected=True),
 'concurrent-publication':dict(successes=1,denials=1,generation=2),
 'invalid-state':dict(corruptionRejected=True,oversizeRejected=True,missingStateRejected=True,automaticReprovisionRejected=True,symlinkRejected=True),
 'pending-and-guard':dict(pendingNeverUsedAsAuthority=True,replacementPublished=True,staleGuardRejected=True),
 'invalid-publication':dict(expiredRejected=True,ambientTransactionRejected=True,insecurePermissionsRejected=True,generationUnchanged=True),
 'unknown-completion':dict(unknownCompletionInjected=True,durableLatchPresent=True,restartStillDenied=True,automaticClearAbsent=True)
}
required.update({
 'observation':dict(readOnly=True,contendedNotReady=True,stableIncidentAcrossRestart=True,wrongBindingRedacted=True,malformedUnavailable=True),
 'resolution-denials':dict(missingGateDenied=True,staleOrBorrowedEvidenceDenied=True,activeGenerationDenied=True,wrongLeaseDenied=True,ambientTransactionDenied=True,stateUnchanged=True),
 'resolution-late-commit':dict(unknownInjected=True,actualPostgresLockDeniedEarlyResolution=True,committedOutcomePreserved=True,revokedAfterResolution=True,oldWorkerDenied=True),
 'resolution-governed-resume':dict(actualRollbackVerified=True,separateGeneration3AdmissionRequired=True,oldWorkerAndDecisionDenied=True,freshDrainSucceeded=True,budgetStill128=True,getCalls=0),
 'resolution-crash':dict(haltBeforeLatchClear87=True,lostReplyAfterCompletion86=True,exactReplayAcrossJvm=True,receiptUnchanged=True,deadlineUnchanged=True,noAutomaticAdmission=True),
 'resolution-concurrent':dict(successes=1,denials=1,receipts=1,generation=2),
 'resolution-stale-command':dict(exactReplay=True,changedIntentDenied=True,newLeaseNotCleared=True),
 'resolution-evidence-retention':dict(capacity128Blocks=True,noReceiptDeletion=True,corruptReceiptBlocks=True,latchRetained=True),
 'resolution-final-check':dict(expiredFinalEvidenceDenied=True,revokedStatePersisted=True,latchRetained=True,freshReconciliationCompleted=True)
})
names=[n for n in data if n.startswith('upload-native/file-authority-') and n.endswith('.json')]
assert len(names)==18
for scenario,fields in required.items():
    p=json.loads(data['upload-native/file-authority-'+scenario+'.json'])
    assert p['status']=='PASS' and p['scenario']==scenario
    assert all(p[k]==v for k,v in fields.items()),scenario
child_logs=[v.decode() for k,v in data.items() if k.startswith('upload-native/file-platform-') and k.endswith('.log')]
assert len(child_logs)==16
assert sum('FILE_AUTHORITY_PUBLISHED 2' in x for x in child_logs)==3
assert sum('FILE_AUTHORITY_DENIED' in x for x in child_logs)==3
assert sum('FILE_AUTHORITY_READ' in x for x in child_logs)==1
assert sum('FILE_AUTHORITY_OBSERVED' in x for x in child_logs)==1
assert sum('FILE_AUTHORITY_RECONCILED' in x for x in child_logs)==3
result=dict(status='PASS',artifactId=13418679034,commit=expected,archiveSha256=digest,archiveBytes=archive.stat().st_size,members=len(data),checksums=len(manifest),sourceGitBlobsVerified=len(bindings),nativeTests=89,apiStorageTests=8,providerReceipts=18,childJvmLogs=16,filesystem='ext4',nativeExecutionRepeated=False,targetOperations=0)
print(json.dumps(result))

