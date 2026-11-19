"""Read the exact retained installation selections; no target service calls.

This root-custody adapter reads four reviewed noncredential JSON artifacts and
the one session journal selected by the completed owner plan. It never scans
directories, opens a bearer file, starts authentication or writes a journal.
File seals stay private, including the credential journal's byte digest.
"""
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat
import time
from tools.ingestion_rollout_execution.contract import require,digest,path,hashed
from tools.ingestion_rollout_execution import private_file
from tools.governed_human_successor import contract,window
CHECKPOINT={'phase':'NOT_STARTED'}
FILE_METADATA={}

def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'DUPLICATE_RETAINED_JSON_FIELD');value[key]=item
        return value
    def nonfinite(value):raise ValueError('NONFINITE_RETAINED_JSON')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)

def read_selected(selected,*,maximum=1048576):
    """FD-relative no-follow root custody; return a private full file seal."""
    require(type(maximum)is int and 1<=maximum<=8388608,'FINITE_SELECTED_DOCUMENT_READ_BOUND_REQUIRED')
    FILE_METADATA.clear()
    path(selected);p=PurePosixPath(selected);fds=[];ancestors=[]
    identity=lambda s:[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        current='/'
        for name in p.parts[1:-1]:
            s=os.fstat(parent)
            require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,
                    'ROOT_CUSTODIED_RETAINED_ANCESTRY_REQUIRED')
            ancestors.append({'path':current,'identity':identity(s)})
            parent=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(parent)
            current=current.rstrip('/')+'/'+name
        s=os.fstat(parent)
        require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,
                'ROOT_CUSTODIED_RETAINED_PARENT_REQUIRED')
        ancestors.append({'path':current,'identity':identity(s)})
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
        before=os.fstat(fd)
        FILE_METADATA.update(regularFile=stat.S_ISREG(before.st_mode),uid=before.st_uid,gid=before.st_gid,
            mode=stat.S_IMODE(before.st_mode),linkCount=before.st_nlink,sizeBytes=before.st_size,maximumBytes=maximum)
        require(stat.S_ISREG(before.st_mode),'RETAINED_DOCUMENT_MUST_BE_REGULAR_FILE')
        require(before.st_uid==before.st_gid==0,'RETAINED_DOCUMENT_ROOT_UID_GID_REQUIRED')
        require(stat.S_IMODE(before.st_mode)==0o600,'RETAINED_DOCUMENT_EXACT_MODE0600_REQUIRED')
        require(before.st_nlink==1,'RETAINED_DOCUMENT_SINGLE_LINK_REQUIRED')
        require(0<before.st_size<=maximum,'RETAINED_DOCUMENT_SIZE_OUTSIDE_SELECTED_BOUND')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
        require(len(raw)==before.st_size and private_file.metadata(before)==private_file.metadata(os.fstat(fd))
            ==private_file.metadata(os.stat(p.name,dir_fd=parent,follow_symlinks=False)),
            'RETAINED_FILE_CHANGED_DURING_READ')
        seal={'path':selected,'sha256':hashlib.sha256(raw).hexdigest(),
            'metadata':private_file.metadata(before),'ancestors':ancestors}
        # Recheck every held ancestor and the path binding, without a second
        # credential-content read or permission changes.
        private_file.check_metadata(seal,maximum=maximum)
        return decode(raw),seal
    finally:
        for fd in reversed(fds):os.close(fd)

def inspect_retained(case,source_closure_hash):
    CHECKPOINT['phase']='EXACT_RETAINED_CASE_SELECTION'
    require(type(case)is dict and case.get('schema')=='ouf.ingestion-rollout-retained-case.v1'
        and case.get('purpose')=='EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT'
        and case.get('runtimeAuthorityIssued')is False and case.get('budgetReset')is False,
        'EXACT_RETAINED_INSTALLATION_SELECTION_REQUIRED')
    artifacts={};seals={}
    for key in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'):
        CHECKPOINT['phase']='RETAINED_'+key.upper()
        binding=case.get(key)
        require(type(binding)is dict and set(binding)=={'path','sha256'}and hashed(binding['sha256']),
                'EXACT_RETAINED_NONCREDENTIAL_ARTIFACT_BINDING_REQUIRED')
        value,seal=read_selected(binding['path'])
        require(digest(value)==binding['sha256'],'RETAINED_CANONICAL_ARTIFACT_CHANGED')
        artifacts[key]=value;seals[key]=seal
    packet,inputs,plan,result=(artifacts[k]for k in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'))
    require(type(packet)is dict and packet.get('schema')=='ouf.ingestion-rollout-private-packet.v3'
        and packet.get('kind')=='PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY'
        and all(packet.get(k)is False for k in('runtimeAuthorityIssued','targetApplyAuthorized',
            'automaticReplayAllowed','budgetReset','newLoginAllowed'))
        and packet.get('verifiedInputsHash')==digest(inputs)
        and packet.get('ownerPlanSha256')==digest(plan),
        'SAME_UNAUTHORIZED_RETAINED_PACKET_INPUTS_AND_COMPLETED_PLAN_REQUIRED')
    require(type(result)is dict and result.get('complete')is True
        and result.get('planHash')==digest(plan),'EXACT_COMPLETED_OWNER_RESULT_REQUIRED')
    history={'minimumRetainedOAuthAttempts':result.get('oauthAttemptsAfter'),
        'maximumCumulativeOAuthAttempts':result.get('maximumCumulativeOAuthAttempts'),
        'ownerPlanHash':digest(plan),'completedResultHash':digest(result)}
    binding=plan.get('humanBinding')
    require(type(binding)is dict,'EXACT_COMPLETED_OWNER_HUMAN_BINDING_REQUIRED')
    recorded=case.get('lastReportedHuman')
    require(type(recorded)is dict and type(recorded.get('attempts'))is int
        and type(history['minimumRetainedOAuthAttempts'])is int
        and type(history['maximumCumulativeOAuthAttempts'])is int
        and history['minimumRetainedOAuthAttempts']<=recorded['attempts']<=history['maximumCumulativeOAuthAttempts']
        and recorded.get('maximumCumulativeOAuthAttempts')==history['maximumCumulativeOAuthAttempts']
        and recorded.get('windowExpiresAt')==binding.get('expiresAt')
        and recorded.get('snapshotIsRuntimeAuthority')is False,
        'RETAINED_POST_PUBLICATION_CUMULATIVE_HUMAN_FLOOR_REQUIRED')
    # Publication can consume attempts after Owner7 completes. Its retained
    # public floor must survive even though the owner result has an older count.
    history['minimumRetainedOAuthAttempts']=recorded['attempts']
    # The completed plan pins the hash of the FULL original selection. The
    # issuer/tenant/subject projection is not its preimage. Recover the exact
    # original document through the retained capsule, never invent a reduced
    # selection or relax that hash check.
    CHECKPOINT['phase']='RETAINED_OWNER_CAPSULE_SELECTION_REFERENCE'
    context=path(plan.get('authorityDirectory'))
    require(context==str(PurePosixPath(case['ownerPlanBinding']['path']).parent),
            'OWNER_CAPSULE_MUST_MATCH_COMPLETED_PLAN_DIRECTORY')
    capsule,capsule_seal=read_selected(context+'/case.json')
    original_binding=capsule.get('originalBinding')if type(capsule)is dict else None
    require(type(original_binding)is dict and set(original_binding)=={'path','sha256'}
        and hashed(original_binding['sha256']),'EXACT_RETAINED_ORIGINAL_SELECTION_DOCUMENT_REQUIRED')
    CHECKPOINT['phase']='RETAINED_ORIGINAL_FULL_SELECTION'
    FILE_METADATA.clear()
    profile=case.get('originalDocumentReadProfile')
    require(type(profile)is dict and set(profile)=={'schema','maximumBytes'}
        and profile['schema']=='ouf.retained-prepared-inputs-read-profile.v1'
        and type(profile['maximumBytes'])is int and 1048576<=profile['maximumBytes']<=8388608,
        'EXPLICIT_QUALIFIED_ORIGINAL_DOCUMENT_READ_PROFILE_REQUIRED')
    original_maximum=profile['maximumBytes']
    original,original_seal=read_selected(original_binding['path'],maximum=original_maximum)
    require(original_seal['sha256']==original_binding['sha256'],
            'RETAINED_ORIGINAL_DOCUMENT_BYTES_CHANGED')
    require(type(original)is dict and original.get('schema')=='ouf.chatbot-file-cohort-prepared-inputs.v1'
        and original.get('engine')==plan.get('engine')and type(original.get('engine'))is dict
        and type(original.get('authorization'))is dict
        and type(original['authorization'].get('plan'))is dict
        and type(original['authorization']['plan'].get('selection'))is dict,
        'ORIGINAL_AUTHORIZATION_PLAN_FULL_SELECTION_REQUIRED')
    selection=original['authorization']['plan']['selection']
    require(digest(selection)==binding.get('selectionHash')
        and all(selection.get(k)==binding.get(k)for k in('issuer','tenant','subject')),
        'FULL_ORIGINAL_SELECTION_MUST_MATCH_PINNED_OWNER_BINDING')
    directory=path(binding.get('sessionDirectory'))
    CHECKPOINT['phase']='RETAINED_SUCCESSFUL_HUMAN_JOURNAL'
    row,journal=read_selected(directory+'/recovery.json')
    require(row.get('binding')==binding,'SAME_SUCCESSFUL_OWNER_SESSION_JOURNAL_REQUIRED')
    operations={k:digest(v)for k,v in artifacts.items()}
    operations['retainedFullSelectionHash']=digest(selection)
    CHECKPOINT['phase']='EXPIRED_READY_PUBLIC_HISTORY'
    review=contract.compile_review(selection,row,history,operations,source_closure_hash,
        now=time.time(),monotonic=time.monotonic(),boot_id=window.boot_id())
    CHECKPOINT['phase']='FINAL_FILE_CUSTODY'
    for seal in [*seals.values(),capsule_seal,journal]:private_file.check_metadata(seal)
    private_file.check_metadata(original_seal,maximum=original_maximum)
    CHECKPOINT['phase']='COMPLETE'
    # This bundle contains private seals. Only review/public_status may be
    # printed; do not serialize the bundle as an operator diagnostic.
    m=original_seal['metadata']
    original_metadata={'regularFile':True,'uid':m[2],'gid':m[3],'mode':stat.S_IMODE(m[4]),
        'linkCount':m[5],'sizeBytes':m[6],'maximumBytes':original_maximum,
        'exceedsPredecessor1MiBBound':m[6]>1048576}
    return review,{'selection':selection,'history':history,'predecessorJournal':journal,
        'originalDocumentMetadata':original_metadata}
