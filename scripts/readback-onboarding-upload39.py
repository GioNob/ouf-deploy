#!/usr/bin/env python3
"""Read original native evidence; bind every checksum and source before reporting PASS."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile
from xml.etree import ElementTree as ET

SOURCE='9d8a1ecea00ac5f614c8e3d6fed61d3d1df85e5f'
TREE='b6734fba1befe90033fd49585ca4b034569ec226'
ARCHIVE_SHA='91b7f31c4e73510a0d58aefd7408ec6a91c988db404db2baa9aac753cacca37a'
IMAGE='sha256:5bfda2ef577b3c33216b82fb3eb1bed3ad76842ed13fc0a114ef94084b20da4d'
BINARY='c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc'

def require(value,code):
    if not value:raise ValueError(code)

def check(archive,source,git_tree):
    raw=archive.read_bytes()
    require(len(raw)==61920 and hashlib.sha256(raw).hexdigest()==ARCHIVE_SHA,'ORIGINAL_ARCHIVE_IDENTITY')
    with zipfile.ZipFile(archive) as z:
        names=z.namelist();require(len(names)==len(set(names)),'DUPLICATE_MEMBER')
        require(all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names),'UNSAFE_MEMBER')
        require(sum(i.file_size for i in z.infolist())<10_000_000,'EXPANSION_LIMIT')
        payload={n:z.read(n) for n in names}
    checks={}
    for line in payload['upload-native/SHA256SUMS'].decode().splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line);require(match is not None,'CHECKSUM_FORMAT')
        digest,name=match.groups();require(name not in checks,'DUPLICATE_CHECKSUM');checks[name]=digest
        require(name in payload and hashlib.sha256(payload[name]).hexdigest()==digest,'MEMBER_HASH:'+name)
    require(set(checks)==set(payload)-{'upload-native/SHA256SUMS'},'EXHAUSTIVE_CHECKSUM_COVERAGE')
    require(payload['upload-native/source-commit.txt'].decode().strip()==SOURCE,'SOURCE_COMMIT')
    require(payload['upload-native/source-tree.txt'].decode().strip()==TREE,'SOURCE_TREE')
    tree=json.loads(git_tree.read_bytes());require(not tree['truncated'],'FULL_SOURCE_TREE')
    blob_count=0
    for entry in tree['tree']:
        if entry['type']!='blob':continue
        content=(source/entry['path']).read_bytes();blob_count+=1
        digest=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        require(digest==entry['sha'],'SOURCE_GIT_BLOB:'+entry['path'])
    bindings=json.loads(payload['upload-native/source-bindings.json'])
    for name,digest in bindings.items():
        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,'SOURCE_PATH')
        require(hashlib.sha256((source/name).read_bytes()).hexdigest()==digest,'SOURCE_SHA256:'+name)
    suites={};total=0
    for name,data in payload.items():
        if name.startswith('surefire-reports/TEST-') and name.endswith('.xml'):
            suite=ET.fromstring(data);count=int(suite.attrib['tests'])
            require(all(int(suite.attrib[k])==0 for k in ('failures','errors','skipped')),'NATIVE_TEST_NOT_PASS')
            suites[suite.attrib['name']]=count;total+=count
    require(suites.get('it.comune.trieste.ouf.onboarding.application.ManagedFileUploadNativeTest')==15,'FIFTEEN_NATIVE_CASES')
    require(total==23 and len(suites)==4,'EXACT_TEST_COHORT')
    def case(name):
        value=json.loads(payload['upload-native/'+name+'.json']);require(value['scenario']==name,'CASE_IDENTITY');return value
    expected={
      'processCrashAfterPutReconcilesWithoutReupload':('ACKED',0,1),
      'processCrashBeforePutRemainsPendingWithoutBlindReplay':('DISPATCHED',0,1),
      'lostReplyReconcilesExactBytesWithFreshOwnerAndNoSecondPut':('ACKED',1,1),
      'changedGenerationRejectsLateAckAndFurtherStorageAccess':('DISPATCHED',1,0),
      'alteredObjectCannotBeAcknowledgedByReconciliation':('DISPATCHED',0,1),
      'reconciliationBudgetSurvivesFreshOwnerAndNeverResends':('DISPATCHED',0,1),
      'expiredReconciliationWindowCannotBeRenewedByNewCall':('DISPATCHED',0,0)}
    for name,(state,puts,gets) in expected.items():
        c=case(name);require(len(c['intents'])==1,'ONE_INTENT:'+name);intent=c['intents'][0]
        require(intent['state']==state and (intent['asset_id'] is not None)==(state=='ACKED'),'ACK_STATE:'+name)
        require(c['parentPutCalls']==puts and c['parentGetCalls']==gets,'IO_COUNTS:'+name)
        require(intent['staging_ref']=='object://managed-files/'+intent['intent_id'],'STABLE_REFERENCE:'+name)
    require(case('reconciliationBudgetSurvivesFreshOwnerAndNeverResends')['intents'][0]['reconciliation_reads']==128,'PERSISTENT_READ_BUDGET')
    for name in ('drainingAndFrozenRejectNewIntentsBeforeS3','ambientTransactionCannotReachIntentOrS3','storageFenceCannotRegressOrBeDeleted'):
        c=case(name);require(c['intents']==[] and c['parentPutCalls']==0,'DENY_WITHOUT_EFFECT:'+name)
    require(len(case('tenantSubjectAndRouteNamespacesDoNotShareAnIntent')['intents'])==4,'OWNER_NAMESPACES')
    require(len(case('directUploadDeduplicatesOnlyAnExplicitRequestKey')['intents'])==3,'UNKEYED_REQUESTS_DISTINCT')
    upgrade=json.loads(payload['upload-native/v38-upgrade.json'])
    require(upgrade['before']==upgrade['after'] and upgrade['replayedAsset']==upgrade['before']['asset_id'],'LEGACY_RECEIPT_UNCHANGED')
    child_logs=[data for name,data in payload.items() if name.endswith('-child.log')]
    require(len(child_logs)==4 and all(b'DURABLE_INTENT object://managed-files/' in data for data in child_logs),'FOUR_PROCESS_CRASHES')
    require(sum(b'PUT_RETURNED_BEFORE_ACK' in data for data in child_logs)==1,'ONE_POST_PUT_PROCESS_CRASH')
    image=json.loads(payload['upload-native/exact-image.json'])
    require(image['manifestDigest']==IMAGE and image['binarySha256']==BINARY,'EXACT_OCI33')
    containers=json.loads(payload['upload-native/containers.json'])
    require(len(containers)==4 and all(c['Image']==image['configDigest'] and c['Config']['User']=='65532:65532' and c['HostConfig']['ReadonlyRootfs'] for c in containers),'EXACT_CONTAINER_BINDINGS')
    run=json.loads(payload['upload-native/run.json'])
    require(run['runId']=='41989631975' and run['runAttempt']=='1' and run['targetOperations']==0 and run['releaseAdmitted'] is False,'RUN_SCOPE')
    return {'schema':'ouf.onboarding-upload39-readback.v1','status':'NATIVE_OWNER_QUALIFIED_NOT_DEPLOYED',
      'sourceCommit':SOURCE,'sourceTree':TREE,'runId':41989631975,'jobId':127118496112,'artifactId':13397423414,
      'archiveBytes':len(raw),'archiveSha256':ARCHIVE_SHA,'members':len(payload),'checksums':len(checks),
      'sourceGitBlobs':blob_count,'sourceSha256Bindings':len(bindings),'nativeScenarios':15,'tests':total,'suites':suites,
      'processCrashReceipts':len(child_logs),'legacyV38ReceiptUnchanged':True,'ociManifestDigest':IMAGE,
      'targetOperations':0,'sourceLockPromoted':False,'releaseAdmitted':False,
      'limits':['application lost-response injection, not wire-level proxy fault','owner ACK fence is not physical credential revocation',
                'other deployed writers and common-cut integration remain open','unkeyed HTTP requests are distinct operations']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--git-tree',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=check(a.archive,a.source,a.git_tree);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
