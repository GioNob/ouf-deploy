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

def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'DUPLICATE_RETAINED_JSON_FIELD');value[key]=item
        return value
    def nonfinite(value):raise ValueError('NONFINITE_RETAINED_JSON')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)

def read_selected(selected):
    """FD-relative no-follow root custody; return a private full file seal."""
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
        require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0
            and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=1048576,
            'EXACT_PRIVATE_RETAINED_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(1048577)
        require(len(raw)==before.st_size and private_file.metadata(before)==private_file.metadata(os.fstat(fd))
            ==private_file.metadata(os.stat(p.name,dir_fd=parent,follow_symlinks=False)),
            'RETAINED_FILE_CHANGED_DURING_READ')
        seal={'path':selected,'sha256':hashlib.sha256(raw).hexdigest(),
            'metadata':private_file.metadata(before),'ancestors':ancestors}
        # Recheck every held ancestor and the path binding, without a second
        # credential-content read or permission changes.
        private_file.check_metadata(seal)
        return decode(raw),seal
    finally:
        for fd in reversed(fds):os.close(fd)

def inspect_retained(case,source_closure_hash):
    require(type(case)is dict and case.get('schema')=='ouf.ingestion-rollout-retained-case.v1'
        and case.get('purpose')=='EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT'
        and case.get('runtimeAuthorityIssued')is False and case.get('budgetReset')is False,
        'EXACT_RETAINED_INSTALLATION_SELECTION_REQUIRED')
    artifacts={};seals={}
    for key in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'):
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
    directory=path(binding.get('sessionDirectory'))
    row,journal=read_selected(directory+'/recovery.json')
    require(row.get('binding')==binding,'SAME_SUCCESSFUL_OWNER_SESSION_JOURNAL_REQUIRED')
    selection={k:binding[k]for k in('issuer','tenant','subject')}
    operations={k:digest(v)for k,v in artifacts.items()}
    review=contract.compile_review(selection,row,history,operations,source_closure_hash,
        now=time.time(),monotonic=time.monotonic(),boot_id=window.boot_id())
    for seal in [*seals.values(),journal]:private_file.check_metadata(seal)
    # This bundle contains private seals. Only review/public_status may be
    # printed; do not serialize the bundle as an operator diagnostic.
    return review,{'selection':selection,'history':history,'predecessorJournal':journal}
