"""New host-file hash input, excluding renewable tokens and the live SQLite DB.

Zero Engine calls. Same boot/root/ten process pins; current container config is
not freshly observed. This does not rearm the failed readonly hash attempt or
admit live mount members. All four consumed predecessor scopes stay untouched.
"""
import copy, json, os, re
from pathlib import Path
from .custody_capture import attrs, decode, digest, encoded, process_pin, require, Stop
from .retained_mount_capture import RetainedCapture
from .retained_mount_intake import validate_capture
from . import retained_readonly_hashes as previous
from . import retained_hash_reconciliation as reconciliation
from . import retained_mount_lifecycle as lifecycle

OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-retained-static-custody-050ba14d-20261101-v1')
CASE={**copy.deepcopy(previous.CASE),'reconciliationScope':str(reconciliation.OUTPUT),
    'reconciliationCandidateHash':'050ba14dd8f407749ed5cad912a4d700ede6a69dbae4037be60ccaa7a0a1f1d2',
    'reconciliationResultHash':'621124d289f36598cd7ae3675d3853303f5498d1600183a404486ecc633a6143',
    'failedHashScope':str(reconciliation.FAILED_SCOPE),'failedHashResultHash':reconciliation.FAILED_HASH}
ROSTER=copy.deepcopy(previous.ROSTER)
BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')
PROFILE={'schema':'ouf.retained-static-host-file-custody-profile.v1','maximumAttempts':1,'maximumSeconds':90,
    'maximumEngineGets':0,'maximumFileBytes':8388608,'maximumTotalHashedBytes':67108864,'maximumUniqueFiles':2048,
    'priorControlAttempts':4,'cumulativeControlAttempts':5,'maximumCumulativeDirectEngineGets':22,
    'liveTokenAndOperationalStoreContentsExcluded':True,'currentContainerConfigurationFreshlyObserved':False,
    'oldHashAttemptRearmed':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False}
PUBLIC_COUNTS=previous.PUBLIC_COUNTS


class StaticCustody(RetainedCapture):
    hash_file=previous.ReadonlyHashPreparation.hash_file
    reject_mutable_overlap=previous.ReadonlyHashPreparation.reject_mutable_overlap
    def __init__(self,scope):
        super().__init__(scope);self.hashes={};self.mutable_sources=[]
        self.counts.update(readonlyRegularFilesHashed=0,readonlyFileBytesHashed=0)
        self.put('static-custody.claim.json',{'schema':'ouf.retained-static-custody-claim.v1',
            'caseHash':digest(CASE),'lifecycleContractHash':lifecycle.CONTRACT_HASH,'profile':PROFILE,
            'automaticReplayAllowed':False})


def collect(c):
    case_hash=digest(CASE)
    scopes={CASE['failedScope']:('capture.claim.json','result.json'),
        str(Path(CASE['candidatePath']).parent):('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json'),
        CASE['failedHashScope']:('capture.claim.json','readonly-hash-preparation.claim.json','result.json'),
        CASE['reconciliationScope']:('capture.claim.json','reconciliation.claim.json','reconciliation.private.json','result.json')}
    frames={}
    for root,names in scopes.items():frames.update(previous.history_frames(root,names))
    def read(path,maximum):return decode(c.read(Path(path),0,0,0o600,maximum,'metadataReads'))
    prior_failure=read(Path(CASE['failedScope'])/'result.json',4096)
    require(digest(prior_failure)==previous.PREDECESSOR_HASH,'EXACT_FIRST_CONSUMED_CAPTURE_RESULT_REQUIRED')
    failed=read(Path(CASE['failedHashScope'])/'result.json',16384)
    require(digest(failed)==CASE['failedHashResultHash'],'EXACT_FAILED_HASH_RESULT_REQUIRED')
    failed_claim=read(Path(CASE['failedHashScope'])/'readonly-hash-preparation.claim.json',16384)
    require(failed_claim=={'schema':'ouf.retained-readonly-hash-claim.v1','caseHash':digest(previous.CASE),
        'profile':previous.PROFILE,'automaticReplayAllowed':False},'EXACT_FAILED_HASH_CLAIM_REQUIRED')
    receipt=read(Path(CASE['reconciliationScope'])/'result.json',131072)
    record=read(Path(CASE['reconciliationScope'])/'reconciliation.private.json',8388608)
    require(digest(receipt)==CASE['reconciliationResultHash'] and digest(record)==CASE['reconciliationCandidateHash']
        and receipt['candidateHash']==digest(record) and record['schema']=='ouf.retained-hash-metadata-reconciliation-private.v1'
        and record['failedResultHash']==CASE['failedHashResultHash'] and record['metadataCandidateHash']==CASE['candidateHash']
        and record['profile']==reconciliation.PROFILE and record['role']=='gateway-owner'
        and record['hashPreparationRearmed'] is False and record['permissionOrContentPolicyEstablished'] is False,
        'EXACT_SUCCESSFUL_METADATA_RECONCILIATION_REQUIRED')
    candidate=read(CASE['candidatePath'],8388608);result=read(CASE['resultPath'],16384);seed=read(CASE['seedPath'],2097152)
    validate_capture(candidate,result,seed,candidate_hash=CASE['candidateHash'],result_hash=CASE['resultHash'],
        seed_hash=CASE['seedHash'],roster=ROSTER)
    peers=candidate['peers'];classes,totals=lifecycle.plan(peers,exact_static_input=True)
    def roots():
        c.guarded();require(digest(CASE)==case_hash and digest(lifecycle.CONTRACT)==lifecycle.CONTRACT_HASH
            and BOOT_PATH.read_text().strip()==seed['bootId']
            and all(process_pin(v['pid'])==v for v in seed['rootProcessPins'].values())
            and all(process_pin(v['processPin']['pid'])==v['processPin'] for v in peers.values()),
            'STATIC_CUSTODY_BOOT_PROCESS_CASE_OR_LIFECYCLE_CONTRACT_CHANGED')
    roots();proofs={};files={};c.mutable_sources=lifecycle.excluded_sources(peers,classes)
    for role,peer in sorted(peers.items()):
        for mount,kind in zip(peer['mounts'],classes[role]):
            if kind=='STATIC_CAPTURE_CANDIDATE':
                path=mount['source'];metadata=mount['metadataTree']['metadata']
                require(path not in files or files[path]==metadata,'SHARED_STATIC_FILE_METADATA_DISAGREES')
                files[path]=metadata
    # Whole allowlist and overlap preflight BEFORE any static file content.
    for path,metadata in sorted(files.items()):c.reject_mutable_overlap(Path(path),metadata)
    for role,peer in sorted(peers.items()):proofs[role]=lifecycle.observe_mounts(c,role,peer['mounts'])
    roots()
    for path,metadata in sorted(files.items()):c.hash_file(Path(path),metadata)
    for path,(before,static) in c.observed.items():
        fd=c.node(path)
        try:require((attrs(os.fstat(fd))==before if static else attrs(os.fstat(fd))[:5]==before[:5]),
            'STATIC_CUSTODY_SOURCE_CHANGED_DURING_READ')
        finally:os.close(fd)
    roots();require(all(attrs(Path(p).lstat())==v for p,v in {**frames,**c.seals}.items())
        and c.counts['engineGets']==0 and 0<len(c.hashes)<=PROFILE['maximumUniqueFiles'],
        'STATIC_CUSTODY_HISTORY_INPUT_OR_ZERO_ENGINE_EFFECT_CHANGED')
    private={'schema':'ouf.retained-static-host-file-candidates.v1','caseHash':case_hash,
        'metadataCandidateHash':CASE['candidateHash'],'reconciliationCandidateHash':CASE['reconciliationCandidateHash'],
        'lifecycleContractHash':lifecycle.CONTRACT_HASH,'lifecyclePlanHash':digest(classes),
        'rootAndStaticMetadataHash':digest(proofs),'files':c.hashes,'profile':PROFILE,'bootId':seed['bootId'],
        'currentContainerConfigurationFreshlyObserved':False,'liveMembersObservedOrAdmitted':False,
        'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(private))<=8388608,'BOUNDED_PRIVATE_STATIC_CUSTODY_OUTPUT_REQUIRED')
    c.put('static-custody.private.json',private)
    return {'schema':'ouf.retained-static-host-file-custody-result.v1',
        'status':'STATIC_HOST_FILE_CANDIDATES_PREPARED_LIVE_INPUTS_NOT_ADMITTED','scope':str(c.scope),
        'candidateHash':digest(private),'lifecycleContractHash':lifecycle.CONTRACT_HASH,'classifiedMounts':totals,
        'counts':{k:c.counts[k] for k in PUBLIC_COUNTS},'allFourPriorScopesPreserved':True,
        'cumulativeDirectEngineGets':22,'cumulativeControlAttempts':5,'currentContainerConfigurationFreshlyObserved':False,
        'liveTokenAndOperationalStoreContentBytesRead':0,'liveMembersObservedOrAdmitted':False,
        'staticCredentialOrKeyFilesMayHaveBeenHashed':True,'rawValuesOrIndividualFileHashesPrinted':False,
        'oldHashAttemptRearmed':False,'expectedPermissionOrContentPolicyEstablished':False,
        'completePrivateCustodyProven':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=StaticCustody(OUTPUT);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'STATIC_HOST_FILE_CUSTODY_UNPROVEN'
        result={'schema':'ouf.retained-static-host-file-custody-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),
            'counts':{k:c.counts[k] for k in PUBLIC_COUNTS} if c is not None else {},
            'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
