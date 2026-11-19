import hashlib,io,json,pathlib,subprocess,sys,zipfile
from xml.etree import ElementTree as E
archive=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'target/human-approval-native.zip')
expected='d5155899b09dda298494b68cefa7e1f281167652'
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
assert archive.stat().st_size==202548 and digest=='28b1ff512a3be82b8be3fbb6f27b6a7b05802857e4c2acbffdbbd52190e25c1e'
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
assert len(suites)==5 and sum(int(s.attrib['tests']) for s in suites)==116
assert all(all(int(s.attrib[k])==0 for k in ('failures','errors','skipped')) for s in suites)
native=next(s for s in suites if s.attrib['name'].endswith('ManagedFileUploadNativeTest'))
assert int(native.attrib['tests'])==103
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
required.update({
 'pg-transaction-binding':dict(exactOwnerXid=True,reopenedBindingEqual=True,missingOrOtherDatasourceDenied=True,legacyGateDenied=True,missingAdmissionCannotDowngrade=True),
 'pg-commit-reply-loss':dict(realSocketFailure=True,serverCommitObserved=True,springCommitFailed=True,freshJvmResolver=True,xidOutcome='COMMITTED',oldWorkerDenied=True,unknownNotificationInjected=False),
 'pg-unsent-commit':dict(realSocketFailure=True,commitNotForwarded=True,xidOutcome='ROLLED_BACK',noOwnerEffectBeforeResume=True,separateFreshAdmissionResumed=True,unknownNotificationInjected=False),
 'pg-delayed-commit':dict(clientLostBeforeServerFinished=True,inProgressDenied=True,generationUnchangedUntilTerminal=True,lateCommitObserved=True,xidOutcome='COMMITTED'),
 'pg-prepared':dict(preparedInProgressDenied=True,commitPreparedResolved=True,rollbackPreparedResolved=True,noHeuristicOutcome=True),
 'pg-admission-denials':dict(otherDatabaseDenied=True,invalidApprovalDenied=True,failedPreflightClosesApproval=True,latchRetained=True),
 'pg-restart-fence':dict(actualPostgresRestart=True,sameSystemIdentifier=True,changedPostmaster=True,oldTransactionResolutionDenied=True,oldAdmissionDenied=True,noAutomaticRebind=True),
 'pg-preflight-recheck':dict(revokedApprovalDenied=True,noGenerationChangeOnDenial=True,stalePreparedProofCannotClearNewLease=True)
})
required.update({
 'human-authenticated':dict(realRsaSignature=True,iamConverterAndBridge=True,serverActorAndDecision=True,changedCommandDenied=True,postgresRollbackResolved=True,receiptReplay=True,httpEndpointInstalled=False),
 'human-policy-revoked':dict(revokedAfterPreflightDenied=True,latchRetained=True,generationUnchangedOnDenial=True,freshAuthenticatedRequestRequired=True),
 'pg-least-privilege':dict(withoutIdentityGrantDenied=True,publicExecuteRemovedInFixture=True,singleControlFunctionGrant=True,noSuperuserOrAdminRoles=True,ownerReadWriteDenied=True,authorizationReadDenied=True,ddlDenied=True,authenticatedResolutionSucceeded=True),
 'pg-privilege-revoked':dict(livePermissionRevocationDenied=True,latchRetained=True,restrictedCommitResolved=True,productionGrantIssued=False),
 'pg-pool-deadline':dict(maximumMillis=4000,configuredAcquireMillis=1000,poolSize=1,latchRetainedOnTimeout=True,explicitRetrySucceeded=True,noActiveConnectionLeak=True),
 'pg-silent-peer':dict(actualTcpAcceptedWithoutReply=True,maximumMillis=4000,configuredLoginSeconds=3,configuredSocketSeconds=2,noActiveConnectionLeak=True)
})
names=[n for n in data if n.startswith('upload-native/file-authority-') and n.endswith('.json')]
assert len(names)==32
for scenario,fields in required.items():
    p=json.loads(data['upload-native/file-authority-'+scenario+'.json'])
    assert p['status']=='PASS' and p['scenario']==scenario
    assert all(p[k]==v for k,v in fields.items()),scenario
for scenario in ('pg-pool-deadline','pg-silent-peer'):
    p=json.loads(data['upload-native/file-authority-'+scenario+'.json'])
    assert 800<=p['elapsedMillis']<=4000
auth=next(s for s in suites if s.attrib['name'].endswith('StorageRecoveryHumanApprovalTest'))
assert int(auth.attrib['tests'])==5
assert 'authorization-sdk/SOURCE_SHA256SUMS' in bindings
sdk_manifest=subprocess.check_output(['git','show',expected+':authorization-sdk/SOURCE_SHA256SUMS'],text=True)
for line in sdk_manifest.splitlines():
    h,name=line.split('  ',1)
    assert bindings['authorization-sdk/'+name]==h
child_logs=[v.decode() for k,v in data.items() if k.startswith('upload-native/file-platform-') and k.endswith('.log')]
assert len(child_logs)==17
assert sum('FILE_AUTHORITY_PUBLISHED 2' in x for x in child_logs)==3
assert sum('FILE_AUTHORITY_DENIED' in x for x in child_logs)==3
assert sum('FILE_AUTHORITY_READ' in x for x in child_logs)==1
assert sum('FILE_AUTHORITY_OBSERVED' in x for x in child_logs)==1
assert sum('FILE_AUTHORITY_RECONCILED' in x for x in child_logs)==3
assert sum('POSTGRES_AUTHORITY_RECONCILED' in x for x in child_logs)==1
outcomes={'lost-commit-reply':'COMMITTED','unsent-commit':'ROLLED_BACK','delayed-commit':'COMMITTED','prepared-true':'COMMITTED','prepared-false':'ROLLED_BACK'}
outcomes.update({'human-authenticated':'ROLLED_BACK','least-privilege-human':'ROLLED_BACK','least-privilege-commit':'COMMITTED'})
receipts={}
import re
for name,outcome in outcomes.items():
    r=json.loads(data['upload-native/postgres-resolution-'+name+'.json'])
    assert r['schema']=='ouf.platform-storage-resolution.v1'
    assert r['evidence']['outcome']==outcome
    assert r['request']['expectedGeneration']==1 and r['request']['revokedNext']['generation']==2 and r['request']['revokedNext']['revoked'] is True
    assert re.fullmatch('postgres/[a-f0-9]{64}',r['evidence']['databaseIdentity'])
    assert re.fullmatch('postgres/xid8/[1-9][0-9]*',r['evidence']['ownerEvidenceRef'])
    receipts[name]=r
assert len({r['request']['leaseId'] for r in receipts.values()})==8
pgline=next(line for log in child_logs for line in log.splitlines() if line.startswith('POSTGRES_AUTHORITY_RECONCILED '))
assert json.loads(pgline.split(' ',1)[1])==receipts['lost-commit-reply']
for name in ('human-authenticated','least-privilege-human'):
    r=receipts[name]['request']
    assert r['actorRef']=='operator'
    assert r['decisionRef']=='human-recovery:1:installation.storage.authority.reconcile'
result=dict(status='PASS',artifactId=13426581283,commit=expected,archiveSha256=digest,archiveBytes=archive.stat().st_size,members=len(data),checksums=len(manifest),sourceGitBlobsVerified=len(bindings),nativeTests=103,apiStorageTests=8,humanApprovalTests=5,providerReceipts=32,childJvmLogs=17,postgresOutcomeReceipts=8,filesystem='ext4',nativeExecutionRepeated=False,targetOperations=0)
print(json.dumps(result))

