#!/usr/bin/env python3
"""Read five sealed local receipts; emit only allowlisted diagnostic counts.
No provider calls, credentials, object bodies, DB rows, writes or replay.
Local hashes bind this readback; they are not a prior independent trusted seal.
"""
import collections, hashlib, json, os, stat, sys
from pathlib import Path
SCOPE = Path('/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v2')
MANIFEST = '1496517d24b65aaa20dce7cdb3bb4440ffbf2bc620c3dfd0ffffc17ea22b0f69'
EXPECTED = json.loads("{\"acceptanceCreditAdded\":0,\"automaticReplayAllowed\":false,\"childScopes\":{\"ingestion\":{\"claimed\":true,\"summaryPresent\":true},\"onboarding\":{\"claimed\":true,\"summaryPresent\":true},\"s3\":{\"claimed\":true,\"summaryPresent\":true},\"udp\":{\"claimed\":true,\"summaryPresent\":true}},\"cumulativeEngineGets\":345,\"databaseExportsAttempted\":3,\"engineBytes\":2334536,\"engineGets\":292,\"g0Complete\":false,\"hostListObservation\":{\"containerCount\":145,\"maximumContainers\":192,\"responseIsList\":true},\"operatorEvidenceAuthenticated\":false,\"phase\":\"SEALED\",\"pointInTimeCommonCutProven\":false,\"priorControls\":17,\"priorEngineGets\":53,\"runtimeAuthorityIssued\":false,\"s3Requests\":1370,\"schema\":\"ouf.storage-g0-package-result.v1\",\"scopeConsumed\":true,\"sections\":{\"ACCESS\":{\"classifications\":2,\"status\":\"MISSING_OPERATOR_EVIDENCE\"},\"CAPACITY\":{\"status\":\"OBSERVED_REVIEW_REQUIRED\"},\"CUSTODY\":{\"status\":\"MISSING_OPERATOR_EVIDENCE\"},\"DB\":{\"findings\":18,\"status\":\"OBSERVED_REVIEW_REQUIRED\"},\"OBJECTS\":{\"status\":\"OBSERVED_REVIEW_REQUIRED\",\"verifiedBodies\":120},\"RUNTIME\":{\"status\":\"OBSERVED_REVIEW_REQUIRED\"},\"WINDOW\":{\"status\":\"MISSING_OPERATOR_EVIDENCE\"},\"WRITERS\":{\"intake\":{\"evidenceAuthenticityVerified\":false,\"intakeComplete\":false,\"missingOrUnknownPaths\":[\"onboarding-human-upload\",\"onboarding-delegated-upload\",\"onboarding-profile-worker\",\"ingestion-execution-replay\",\"ingestion-outbox-ack-watermark\",\"udp-store\",\"udp-shadow\",\"udp-purge-compaction\",\"udp-maintenance\",\"administrative-tools\",\"external-consumers\"],\"operatorDeclaredPaths\":0,\"reportedPaths\":0,\"runtimeAuthorityIssued\":false,\"technicalPaths\":0,\"writersQuiescentProven\":false},\"status\":\"MISSING_OPERATOR_EVIDENCE\"}},\"status\":\"HELD_RECONCILIATION_FINDINGS\",\"targetWrites\":0,\"technicalCaptureComplete\":true,\"writerQuiescenceProven\":false}")
DB_CODES = frozenset(["ACK_RECEIPT_BINDING_MISMATCH","ACK_SOURCE_RAW_BINDING_MISMATCH","ADDITIONAL_REFERENCE_REQUIRES_CLASSIFICATION","ASSET_OWNER_UNRESOLVED","ASSET_REFERENCE_BINDING_MISMATCH","BINDING_REFERENCE_REQUIRES_CLASSIFICATION","COMPACTED_SLICE_VERIFICATION_REQUIRED","CONFIGURATION_BUNDLE_MISMATCH","CONTENT_HASH_MISMATCH","CONTENT_SIZE_MISMATCH","DANGLING_ACK_RECEIPT","DANGLING_ASSET","DANGLING_ATTEMPT","DANGLING_CONFIGURATION_ASSET","DANGLING_HANDOFF","DANGLING_LINEAGE","DANGLING_MANIFEST","DANGLING_MANIFEST_INPUT","DANGLING_MANIFEST_OUTPUT","DANGLING_OUTBOX_RAW","DANGLING_PROFILE","DANGLING_PROFILE_JOB","DANGLING_RAW_ENVELOPE","DANGLING_REPLAY_QUARANTINE","DANGLING_REPLAY_RAW","DANGLING_REPLAY_RESULT","DANGLING_REPLAY_SOURCE","DANGLING_RUN","DANGLING_SHADOW_OBJECT","DANGLING_SHADOW_PLAN","DANGLING_SOURCE_RAW","DANGLING_UPLOAD_ASSET","DANGLING_WATERMARK_HANDOFF","DELETED_CATALOG_BODY_PRESENT","LINEAGE_OUTPUT_HASH_MISMATCH","LINEAGE_RUN_MISMATCH","MANIFEST_OUTPUT_HASH_MISMATCH","MANIFEST_RANGE_VALIDATION_REQUIRED","MISSING_BODY","OUTBOX_RAW_HASH_MISMATCH","PREVIOUS_LOCATOR_REQUIRES_LIFECYCLE_CLASSIFICATION","QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION","RAW_LINEAGE_BINDING_UNPROVEN","SHADOW_LIFECYCLE_RECONCILIATION_REQUIRED","UNCLASSIFIED_BODY","UNRESOLVED_LAKE_LOCATOR","UNRESOLVED_MANAGED_REFERENCE","UNSUPPORTED_PHYSICAL_LOCATOR","UPLOAD_ASSET_BINDING_MISMATCH","UPLOAD_INTENT_UNRESOLVED","WATERMARK_ACK_BINDING_MISMATCH","WATERMARK_OVERTAKES_UNACKED"])
ACCESS_CODES = frozenset(['ACL_OWNER_OR_GRANTS_UNPROVEN','ACL_OWNER_GRANT','ACL_NONOWNER_GRANT_REVIEW','ACL_BROAD_GROUP_REVIEW'] + [f'{k}_{s}_REVIEW' for k in ('POLICY','PUBLICACCESSBLOCK') for s in ('PRESENT','ABSENT','UNSUPPORTED','UNKNOWN')])
def require(ok):
    if not ok: raise ValueError('LOCAL_RECEIPT_MISMATCH')
def identity(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read_at(parent,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=32*1024*1024)
        chunks=[];remaining=before.st_size
        while remaining:
            chunk=os.read(fd,min(remaining,65536));require(bool(chunk));chunks.append(chunk);remaining-=len(chunk)
        raw=b''.join(chunks)
        require(identity(before)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        return json.loads(raw),hashlib.sha256(raw).hexdigest()
    finally: os.close(fd)
def summarize(docs,hashes):
    result,joined,access,capacity,claim=(docs[n] for n in ('result.json','reconciliation.json','access-review.json','capacity.private.json','claim.private.json'))
    require(result==EXPECTED)
    require(claim['operationId']==SCOPE.name and claim['collectionDecisionRef']=='OUF-G0-COLLECT-20261106-02' and claim['packageManifestSha256']==MANIFEST)
    require(claim['limits']['engineGets']==386 and claim['limits']['priorEngineGets']==53 and claim['limits']['hostContainers']==192)
    require(joined['schema']=='ouf.storage-g0-reconciliation.v1' and joined['findingsCount']==18 and len(joined['observationFindings'])==18 and joined['bodyObjects']==120)
    require(access['schema']=='ouf.storage-g0-access-classification.v1' and len(access['findings'])==2)
    require(capacity['schema']=='ouf.storage-g0-capacity-observation.v1')
    def counts(items,allowed):
        return dict(sorted(collections.Counter(x['code'] if x.get('code') in allowed else 'UNKNOWN_CODE_REQUIRES_LOCAL_REVIEW' for x in items).items()))
    stats={k:joined[k] for k in ('bodyObjects','bodyReferencesChecked','classifiedBodies','exportRows')}
    require(all(type(n) is int and n>=0 for n in stats.values()) and stats['classifiedBodies']<=120)
    fs=capacity['filesystems'];require(set(fs)=={'source','destination','backup'})
    sizes={}
    for role,v in fs.items():
        require(all(type(v[k]) is int and v[k]>=0 for k in ('totalBytes','availableBytes','device')))
        require(v['availableBytes']<=v['totalBytes'])
        sizes[role]={k:v[k] for k in ('totalBytes','availableBytes')}
    return {'schema':'ouf.storage-g0-sealed-findings-readback.v1','status':'LOCAL_SEALED_FINDINGS_READ',
        'resultMatchesReported':True,'localReceiptSha256':hashes,
        'dbFindingCounts':counts(joined['observationFindings'],DB_CODES),'dbStatistics':stats,
        'accessClassificationCounts':counts(access['findings'],ACCESS_CODES),
        'capacityBytes':sizes,'capacityPathsShareDevice':len({v['device'] for v in fs.values()})==1,
        'effectiveAuthorizationProven':False,'independentBackupVerified':False,
        'pointInTimeCommonCutProven':False,'writerQuiescenceProven':False,
        'historicalIntegrityAgainstPriorTrustedDigestProven':False,
        'filesRead':5,'filesModified':0,'credentialsRead':0,'providerRequests':0,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'g0Complete':False,'acceptanceCreditAdded':0}
def main():
    parent=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        for part in SCOPE.parts[1:]:
            info=os.fstat(parent);require(info.st_uid==0 and not info.st_mode&0o022)
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        info=os.fstat(parent);require(info.st_uid==0 and not info.st_mode&0o022)
        docs={};hashes={}
        for name in ('result.json','reconciliation.json','access-review.json','capacity.private.json','claim.private.json'):
            docs[name],hashes[name]=read_at(parent,name)
        print(json.dumps(summarize(docs,hashes),sort_keys=True));return 0
    except Exception:
        print(json.dumps({'status':'HELD','reason':'LOCAL_SEALED_READBACK_UNPROVEN','filesModified':0,'providerRequests':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False}));return 1
    finally:
        if parent is not None: os.close(parent)
if __name__=='__main__':raise SystemExit(main())
