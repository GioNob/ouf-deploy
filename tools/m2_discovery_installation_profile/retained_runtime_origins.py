"""Join the exact consumed selected-runtime proof to thirteen public origin refs.

Read only three already verified image configurations for unresolved source
claims. No new capture/export/byte verification, layer read, registry fetch,
Engine call, mounted host file, credential, import or runtime authority.
"""
import hashlib,json,os,re,sys,tarfile,time
from pathlib import Path,PurePosixPath
from .custody_capture import Capture,Stop,attrs,decode,digest,encoded,require
from .retained_readonly_hashes import history_frames
from .retained_image_reader import RetainedArchiveReader
from . import retained_selected_image_verification as previous
from .retained_runtime_origin_profile import PUBLIC_PROFILE,PROFILE_HASH

OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-runtime-origins-c52a0e2a-20261101-v1')
SELECTED_SCOPE=previous.OUTPUT
RESULT_HASH='039f03a7593c0b826e6597f755c838f85efa197d17d7df3339512f5ee7c52bcc'
PRIVATE_HASH='c52a0e2a0ebcdb9c8a826426386a9172c0507231199815c09ab32eb144fd713e'
PROFILE={'schema':'ouf.retained-runtime-origin-control.v1','maximumAttempts':1,'maximumSeconds':180,
    'maximumEngineGets':0,'priorControlAttempts':11,'maximumCumulativeControlAttempts':12,
    'cumulativeDirectEngineGets':35,'selectedRuntimeResultHash':RESULT_HASH,'selectedRuntimePrivateHash':PRIVATE_HASH,
    'publicOriginProfileHash':PROFILE_HASH,'maximumPrivateEvidenceBytes':2097152,
    'maximumConfigurationBytes':2097152,'maximumClassicManifestBytes':131072,'maximumArchiveMembers':512,
    'purpose':'JOIN_ALREADY_VERIFIED_THIRTEEN_RUNTIME_ROLES_AND_READ_THREE_SOURCE_IDENTITY_CONFIGURATIONS',
    'verificationReplayed':False,'captureReplayed':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False}


def history(control):
    frames,_,_=previous.graph_history(control)
    frames.update(history_frames(SELECTED_SCOPE,('capture.claim.json','selected-runtime-verification.claim.json',
        'selected-runtime-byte-evidence.private.json','result.json')))
    def read(name,maximum):return decode(control.read(SELECTED_SCOPE/name,0,0,0o600,maximum,'metadataReads'))
    require(read('capture.claim.json',4096)==
        {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},'EXACT_SELECTED_RUNTIME_CAPTURE_CLAIM_REQUIRED')
    require(read('selected-runtime-verification.claim.json',16384)==
        {'schema':'ouf.selected-runtime-verification-claim.v1','profile':previous.PROFILE,'automaticReplayAllowed':False},
        'EXACT_CONSUMED_SELECTED_RUNTIME_PROFILE_REQUIRED')
    result=read('result.json',65536);proof=read('selected-runtime-byte-evidence.private.json',PROFILE['maximumPrivateEvidenceBytes'])
    require(digest(result)==RESULT_HASH and result.get('privateEvidenceHash')==PRIVATE_HASH and digest(proof)==PRIVATE_HASH
        and proof.get('schema')=='ouf.retained-selected-runtime-byte-set.v1' and proof.get('profile')==previous.PROFILE,
        'EXACT_SUCCESSFUL_SELECTED_RUNTIME_RESULT_AND_PRIVATE_PROOF_REQUIRED')
    return frames,result,proof


def config_identity(stream,proof,budget):
    """Seek over layer bodies. Config digest and execution hash bind this read."""
    with tarfile.open(fileobj=stream,mode='r:') as tar:
        members={}
        for member in tar:
            budget.check();name=member.name.rstrip('/') if member.isdir() else member.name;path=PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and str(path)==name and name not in members
                and len(members)<PROFILE['maximumArchiveMembers'] and (member.isfile() or member.isdir())
                and 0<=member.size<=2147483648,'EXACT_BOUNDED_SAFE_ORIGINAL_ARCHIVE_MEMBERS_REQUIRED')
            members[name]=member
        def small(name,maximum):
            require(name in members and members[name].isfile() and 0<members[name].size<=maximum,
                'EXACT_ALREADY_VERIFIED_CONFIGURATION_MEMBER_REQUIRED')
            with tar.extractfile(members[name]) as source:raw=source.read(maximum+1)
            budget.check();require(len(raw)==members[name].size,'COMPLETE_CONFIGURATION_METADATA_REQUIRED');return raw
        classic=small('manifest.json',PROFILE['maximumClassicManifestBytes'])
        require(hashlib.sha256(classic).hexdigest()==proof['classicManifestHash'],'ALREADY_VERIFIED_CLASSIC_MANIFEST_CHANGED')
        rows=decode(classic);require(type(rows) is list and len(rows)==1 and type(rows[0]) is dict
            and len(rows[0].get('Layers',[]))==proof['layerCount'],'SAME_SINGLE_VERIFIED_CLASSIC_RUNTIME_REQUIRED')
        raw=small(rows[0]['Config'],PROFILE['maximumConfigurationBytes'])
        require('sha256:'+hashlib.sha256(raw).hexdigest()==proof['configurationDigest'],'ALREADY_VERIFIED_IMAGE_CONFIGURATION_CHANGED')
        config=decode(raw)
        require(type(config) is dict and config.get('os')==proof['selectedPlatform']['os']
            and config.get('architecture')==proof['selectedPlatform']['architecture']
            and type(config.get('config')) is dict and digest(config['config'])==proof['executionConfigurationHash'],
            'SAME_VERIFIED_EXECUTION_CONFIGURATION_AND_PLATFORM_REQUIRED')
        labels=config['config'].get('Labels') or {}
        require(type(labels) is dict,'TYPED_IMAGE_CONFIGURATION_LABELS_REQUIRED')
        return labels,len(raw)+len(classic)


def source_claim(role,labels):
    # Untrusted labels can claim provenance, never authenticate a publisher.
    source=labels.get('org.opencontainers.image.source');revision=labels.get('org.opencontainers.image.revision')
    allowed=PUBLIC_PROFILE['sourceLabelAllowlist'][role]
    result={'sourceLabelStatus':'ABSENT' if source is None else 'UNRECOGNIZED_NOT_PRINTED',
        'revisionLabelStatus':'ABSENT' if revision is None else 'NONCANONICAL_NOT_PRINTED',
        'declaredSourceAuthenticated':False}
    if source==allowed:result.update(sourceLabelStatus='ALLOWLISTED_DECLARED_REPOSITORY',declaredSourceRepository=allowed)
    if source==allowed and type(revision) is str and re.fullmatch('[a-f0-9]{40}',revision):
        result.update(revisionLabelStatus='DECLARED_GIT_SHA_NOT_AUTHENTICATED',declaredRevision=revision)
    return result


def reconcile(control):
    require(digest(PUBLIC_PROFILE)==PROFILE_HASH==PROFILE['publicOriginProfileHash']
        and PUBLIC_PROFILE['selectedRuntimeResultHash']==RESULT_HASH
        and PUBLIC_PROFILE['selectedRuntimePrivateHash']==PRIVATE_HASH,'EXACT_SEALED_PUBLIC_ORIGIN_PROFILE_REQUIRED')
    frames,result,private=history(control);reader=RetainedArchiveReader()
    reader.budget.until=min(reader.budget.until,control.until);seed,rows=reader.material();reader.roots(seed)
    roles=PUBLIC_PROFILE['roles'];proofs=private['images'];unknown=PUBLIC_PROFILE['unknownConfigurationRoles']
    require(set(roles)==set(rows)==set(proofs) and len(roles)==result['imageCount']==13
        and unknown==['gateway-owner','minio','semantic']
        and {r for r,v in roles.items() if v['configurationDigest'] is None}==set(unknown),
        'EXACT_THIRTEEN_ROLES_TEN_PUBLIC_CONFIG_BINDINGS_AND_THREE_UNKNOWN_ORIGINS_REQUIRED')
    def stable():
        control.check();reader.roots(seed)
        require(all(attrs(Path(path).lstat())==frame for path,frame in frames.items()),
            'CONSUMED_SELECTED_RUNTIME_OR_PRIOR_SCOPE_CHANGED_DURING_ORIGIN_JOIN')
    joined={};unresolved=[];metadata_bytes=0
    for role,row in sorted(rows.items()):
        stable();proof=proofs[role];public=roles[role]
        require(proof['schema']=='ouf.retained-selected-runtime-byte-identity.v1'
            and proof['requestedNativeDigest']==row['imageIdRequested']==public['nativeImageId']
            and proof['archiveSha256']==row['sha256'] and proof['archiveBytes']==row['bytes']
            and proof['selectedRuntimeBytesProven'] is True and proof['selectedRuntimeContentComplete'] is True,
            'SAME_ALREADY_VERIFIED_PRIVATE_RUNTIME_AND_PUBLIC_ROLE_NATIVE_ID_REQUIRED')
        require(all(proof[k] is False for k in ('completeIndexAccepted','nonselectedBranchesAdmitted',
            'sourcePublisherAuthenticated','scanAdmissionProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance')),
            'PRIVATE_BYTE_PROOF_CANNOT_BECOME_PUBLISHER_SCAN_OR_RUNTIME_AUTHORITY')
        for key in ('configurationDigest','selectedRuntimeManifestDigest'):
            require(type(proof[key]) is str and re.fullmatch('sha256:[a-f0-9]{64}',proof[key]),'CANONICAL_VERIFIED_RUNTIME_DIGEST_REQUIRED')
        if public['configurationDigest'] is not None:
            require(proof['configurationDigest']==public['configurationDigest']
                and ('selectedRuntimeManifestDigest' not in public or proof['selectedRuntimeManifestDigest']==public['selectedRuntimeManifestDigest']),
                'VERIFIED_RUNTIME_CONFIG_OR_MANIFEST_DIFFERS_FROM_EXACT_PUBLIC_ORIGIN')
        else:
            path=reader.path.parent/row['filename'];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                require(attrs(os.fstat(stream.fileno()))==row['metadata'],'SAME_ORIGINAL_ARCHIVE_FD_REQUIRED_FOR_SOURCE_CONFIG')
                labels,size=config_identity(stream,proof,reader.budget);metadata_bytes+=size
                require(attrs(os.fstat(stream.fileno()))==attrs(path.lstat())==row['metadata'],
                    'ORIGINAL_ARCHIVE_CHANGED_DURING_SOURCE_CONFIGURATION_READ')
            unresolved.append({'role':role,'configurationDigest':proof['configurationDigest'],
                'selectedRuntimeManifestDigest':proof['selectedRuntimeManifestDigest'],**source_claim(role,labels)})
        joined[role]={'nativeImageId':proof['requestedNativeDigest'],'configurationDigest':proof['configurationDigest'],
            'selectedRuntimeManifestDigest':proof['selectedRuntimeManifestDigest'],'selectedByteProofHash':digest(proof),
            'publicOriginReferenceHash':digest(public),'knownPublicConfigurationBindingMatched':public['configurationDigest'] is not None}
    stable();evidence={'schema':'ouf.retained-runtime-origin-join-private.v1','profile':PROFILE,
        'selectedRuntimeResultHash':RESULT_HASH,'selectedRuntimePrivateHash':PRIVATE_HASH,'publicOriginProfileHash':PROFILE_HASH,
        'roles':joined,'unresolvedOriginBindings':unresolved,'sourcePublisherAuthenticated':False,
        'allRuntimeArtifactMembershipProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(evidence))<=PROFILE['maximumPrivateEvidenceBytes'],'BOUNDED_PRIVATE_ORIGIN_JOIN_EVIDENCE_REQUIRED')
    report={'schema':'ouf.retained-runtime-origin-join-result.v1','status':'VERIFIED_RUNTIME_ROLES_JOINED_ORIGIN_CLAIMS_NOT_ADMITTED',
        'imageCount':13,'knownPublicConfigurationBindingsMatched':10,'sourceConfigurationMembersOpened':3,
        'sourceConfigurationMetadataBytesRead':metadata_bytes,'unresolvedOriginBindings':unresolved,
        'publicOriginProfileHash':PROFILE_HASH,'selectedRuntimeResultHash':RESULT_HASH,'selectedRuntimePrivateHash':PRIVATE_HASH,
        'privateEvidenceHash':digest(evidence),'allElevenPriorScopesPreserved':True,'newOriginControlScopeCreated':True,
        'cumulativeControlAttempts':12,'cumulativeDirectEngineGets':35,'directEngineGets':0,'layerMembersOpened':0,
        'archiveBytesRehashed':0,'expandedLayerBytesRead':0,'externalBlobFetches':0,'credentialFileReads':0,
        'mountedHostFileContentBytesRead':0,'captureReplayed':False,'verificationReplayed':False,'automaticReplayAllowed':False,
        'sourcePublisherAuthenticated':False,'allRuntimeArtifactMembershipProven':False,'completePrivateCustodyProven':False,
        'currentApplicationConfigurationOrLivenessProven':False,'runtimeBudgetResetOrGrant':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    stable();return evidence,report


def main():
    control=None
    try:
        require(sys.argv[1:]==[],'RUNTIME_ORIGIN_JOIN_ACCEPTS_NO_ARGUMENTS')
        require(os.geteuid()==os.getegid()==0,'ROOT_RUNTIME_ORIGIN_JOIN_REQUIRED')
        os.umask(0o077);started=time.monotonic();control=Capture(OUTPUT);control.until=started+PROFILE['maximumSeconds']
        control.put('runtime-origin.claim.json',{'schema':'ouf.retained-runtime-origin-claim.v1','profile':PROFILE,'automaticReplayAllowed':False})
        evidence,report=reconcile(control);control.put('runtime-origin.private.json',evidence);control.put('result.json',report);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'RUNTIME_ORIGIN_JOIN_UNPROVEN'
        report={'schema':'ouf.retained-runtime-origin-join-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'scopeConsumed':os.path.lexists(OUTPUT),'newOriginControlScopeCreated':control is not None,
            'cumulativeControlAttempts':12 if control is not None else None,'cumulativeDirectEngineGets':35,
            'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
        if control is not None:
            try:control.put('result.json',report)
            except Exception:pass
        code=1
    print(json.dumps(report,sort_keys=True));return code


if __name__=='__main__':raise SystemExit(main())
