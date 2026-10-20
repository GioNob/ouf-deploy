"""Foreground bridge to the frozen114-module native executor.

Loaded as separately pinned control source by a stdlib-only bootstrap. No tools
imports are added to the frozen native module graph. Each call is one explicit
mode. Preparation never opens HUMAN credentials or issues runtime authority.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

PROFILE='ouf.ingestion-rollout-explicit-production-control.v1'
CHECKPOINT={'phase':'NOT_STARTED','contextPath':None}

def read_json(entry,selected,expected=None,*,canonical=False):
    c=entry.c;c.path(selected);p=Path(selected);fds=[];ancestors=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd);current='/'
        for part in[*p.parts[1:-1],None]:
            row=os.fstat(fd);c.require(stat.S_ISDIR(row.st_mode)and row.st_uid==row.st_gid==0 and not row.st_mode&0o022,
                'ROOT_PRIVATE_PRODUCTION_CONTROL_ANCESTRY_REQUIRED')
            ancestors.append({'path':current,'identity':[row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode]})
            if part is None:break
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd);current=current.rstrip('/')+'/'+part
        file=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(file);row=os.fstat(file)
        c.require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==0o600
            and row.st_nlink==1 and 0<row.st_size<=1048576,'EXACT_PRIVATE_PRODUCTION_DOCUMENT_REQUIRED')
        with os.fdopen(os.dup(file),'rb')as stream:raw=stream.read(1048577)
        metadata=entry.authority.private_file.metadata
        c.require(len(raw)==row.st_size and metadata(row)==metadata(os.fstat(file))
            ==metadata(os.stat(p.name,dir_fd=fd,follow_symlinks=False)),'PRODUCTION_DOCUMENT_CHANGED_DURING_READ')
        def unique(pairs):
            result={}
            for k,v in pairs:c.require(k not in result,'DUPLICATE_PRODUCTION_DOCUMENT_FIELD');result[k]=v
            return result
        value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:c.require(False,'FINITE_PRODUCTION_JSON_REQUIRED'))
        digest=c.digest(value)if canonical else hashlib.sha256(raw).hexdigest()
        c.require(expected is None or digest==expected,'EXACT_RETAINED_PRODUCTION_DOCUMENT_HASH_REQUIRED')
        seal={'path':selected,'sha256':hashlib.sha256(raw).hexdigest(),'metadata':metadata(row),'ancestors':ancestors}
        entry.authority.private_file.check_metadata(seal)
        return value,seal
    finally:
        for fd in reversed(fds):os.close(fd)

def write(entry,context,name,value):
    entry.c.require(name in('preparation.json','review.json'),'EXACT_PRODUCTION_CONTROL_MEMBER_REQUIRED')
    journal=entry.Journal(context);journal.create(Path(context)/name,entry.c.encoded(value));journal.sync()

def update(journal,**changes):
    row=journal.read();journal.compare_and_save(row,{**row,**changes});return journal.read()

def retained(entry,case):
    c=entry.c;selected={};seals={}
    for name in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'):
        binding=case[name];selected[name],seals[name]=read_json(entry,binding['path'],binding['sha256'],canonical=True)
    packet=selected['packetBinding'];plan=selected['ownerPlanBinding'];result=selected['ownerResultBinding']
    c.require(packet['verifiedInputsHash']==c.digest(selected['verifiedInputsBinding'])
        and packet['ownerPlanSha256']==c.digest(plan)==result['planHash']and result['complete']is True,
        'EXACT_COMPLETED_OWNER_AND_RETAINED_PACKET_REQUIRED')
    profiles_case=case['nativeProfiles'];root=Path(profiles_case['contextPath'])
    c.require(root.parent==Path(plan['authorityDirectory']).parent
        and re.fullmatch('ingestion-native-profiles-[A-Za-z0-9_-]{8,64}',root.name),'EXACT_COMPLETED_NATIVE_PROFILE_CONTEXT_REQUIRED')
    record,_=read_json(entry,str(root/'recovery.json'))
    c.require(record['schema']=='ouf.ingestion-native-profile-preparation.v1'and record['complete']is True
        and record['phase']=='COMPLETE'and record['sourceClosureHash']==profiles_case['sourceClosureHash']
        and record['budgetReset']is False and record['runtimeAuthorityIssued']is False,
        'COMPLETED_NATIVE_PROFILE_PREPARATION_REQUIRED')
    logical=c.digest({'profile':record['schema'],'captureContext':profiles_case['captureContext'],'packetBinding':case['packetBinding']})
    claim,_=read_json(entry,str(root.parent/('ingestion-native-profiles-'+logical+'.claim.json')))
    c.require(record['logicalRef']==logical and claim['logicalRef']==logical and claim['contextPath']==str(root)
        and claim['sourceClosureHash']==record['sourceClosureHash'],'EXACT_RETAINED_NATIVE_PROFILE_CLAIM_REQUIRED')
    profiles,seal=read_json(entry,str(root/'profiles.json'));seals['profiles']=seal
    entry.authority.native_review.validate_profiles(profiles,packet)
    entry.authority.native_review.reconcile_owner(packet,profiles,plan,result)
    for name,key in(('owner','ownerControlProfile'),('ingestion','ingestionReadinessProfile'),('gateway','gatewayTransportProfile')):
        c.require(profiles[key]['endpoint']==profiles_case['selectedEndpoints'][name],'TARGET_PROFILE_ENDPOINT_RECEIPT_CHANGED')
    return selected,profiles,seals,str(root.parent)

def qualification(entry,manifest,case,packet):
    q=case['qualification'];entry.authority.qualification_valid(q,{'declaration':manifest},packet['candidate'])
    entry.c.require(all(v['repository']=='GioNob/ouf-deploy'and v['sourceCommit']==manifest['sourceCommit']for v in q['evidenceRefs'].values()),
        'EXACT_PINNED_NATIVE_QUALIFICATION_REFERENCES_REQUIRED')

def ipv6_loopback_metadata(entry,pid,namespace,endpoint):
    c=entry.c;address=ipaddress.ip_address(endpoint['host'])
    if address.version!=6:return {'required':False}
    c.require(address.is_loopback and type(pid)is int and pid>0,'EXACT_SELECTED_IPV6_LOOPBACK_REQUIRED')
    selected=Path('/proc')/str(pid)/'ns/net';before=os.stat(selected)
    c.require({'device':before.st_dev,'inode':before.st_ino}==namespace,'SELECTED_IPV6_PROCESS_NAMESPACE_CHANGED')
    with(Path('/proc')/str(pid)/'net/if_inet6').open('rb')as stream:raw=stream.read(16385)
    c.require(len(raw)<=16384,'BOUNDED_IPV6_INTERFACE_METADATA_REQUIRED')
    rows=raw.decode('ascii').splitlines();c.require(len(rows)<=128,'BOUNDED_IPV6_INTERFACE_ROWS_REQUIRED')
    assigned=False
    for row in rows:
        fields=row.split();c.require(len(fields)==6 and re.fullmatch('[0-9a-fA-F]{32}',fields[0]),
            'TYPED_IPV6_INTERFACE_METADATA_REQUIRED')
        if ipaddress.IPv6Address(bytes.fromhex(fields[0]))==address:
            c.require(all(re.fullmatch('[0-9a-fA-F]{1,8}',v)for v in fields[1:5]),'EXACT_IPV6_INTERFACE_FLAGS_REQUIRED')
            assigned|=int(fields[1],16)>0 and int(fields[2],16)==128 and int(fields[3],16)==0x10 and not int(fields[4],16)&0x48
    c.require(assigned,'SELECTED_IPV6_LOOPBACK_NOT_ASSIGNED_IN_PINNED_NAMESPACE')
    after=os.stat(selected);c.require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'SELECTED_IPV6_PROCESS_NAMESPACE_CHANGED')
    return {'required':True,'assignedInPinnedNamespace':True,'tcpReachabilityProven':False}

def prepare(entry,manifest,case,control_hash):
    c=entry.c;a=entry.authority;started=time.time();clock=time.monotonic();CHECKPOINT['phase']='RETAINED_PRIVATE_PROFILES'
    selected,profiles,seals,parent=retained(entry,case);packet=selected['packetBinding'];qualification(entry,manifest,case,packet)
    logical=c.digest({'profile':PROFILE,'packetBinding':case['packetBinding'],'nativeProfileContext':case['nativeProfiles']['contextPath']})
    claim=Path(parent)/('ingestion-rollout-control-'+logical+'.claim.json')
    c.require(not os.path.lexists(claim),'PRODUCTION_CONTROL_ALREADY_CLAIMED_RECONCILE_ONLY')
    with a.protected_directory(Path(parent)):context=Path(tempfile.mkdtemp(prefix='ingestion-rollout-native-',dir=parent));context.chmod(0o700)
    CHECKPOINT.update(phase='RESERVE_PRIVATE_PRODUCTION_CONTROL',contextPath=str(context))
    with a.protected_directory(Path(parent))as directory:
        c.require(a.publish(directory,claim.name,c.encoded({'schema':PROFILE,'contextPath':str(context),'logicalRef':logical,
            'caseHash':c.digest(case),'controlSourceHash':control_hash,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})),
            'PRODUCTION_CONTROL_ALREADY_CLAIMED_RECONCILE_ONLY')
    control=context/'operator-control';control.mkdir(mode=0o700);journal=entry.Journal(control)
    journal.initialize({'schema':PROFILE,'logicalRef':logical,'caseHash':c.digest(case),'controlSourceHash':control_hash,
        'sourceDeclarationHash':c.digest(manifest),'state':'PREPARING','complete':False,'budgetReset':False,'runtimeAuthorityIssued':False})
    CHECKPOINT['phase']='PUBLIC_EXISTING_ISSUER_AND_EXECUTABLES'
    issuer_case=case['existingIssuer'];installed,installed_seal=read_json(entry,issuer_case['installationAuthority']['path'],issuer_case['installationAuthority']['sha256'])
    unused,policy_seal=read_json(entry,issuer_case['policy']['path'],issuer_case['policy']['sha256'])
    issuer={'schema':'ouf.ingestion-rollout-existing-issuer-profile.v1','installationAuthority':installed_seal,
        'policy':policy_seal,'authorityContext':issuer_case['authorityContext']}
    a.current_issuer(issuer,int(time.time())+900)
    programs={'python':profiles['ownerControlProfile']['pythonExecutable'],'docker':profiles['databaseControlProfile']['dockerExecutable']}
    for program in programs.values():c.require(a.governance.executable(program['path'])==program,'RETAINED_NATIVE_PROGRAM_CHANGED')
    c.require(a.governance.executable(sys.executable)==programs['python'],'PRODUCTION_CONTROL_MUST_USE_RETAINED_PYTHON')
    program=a.governance.executable(issuer_case['opensslExecutablePath'])
    observed=subprocess.run([program['path'],'version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=5,env={'LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
    match=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',observed.stdout)
    c.require(observed.returncode==0 and len(observed.stdout)<=256 and match is not None,'EXACT_NATIVE_OPENSSL_VERSION_REQUIRED')
    programs['openssl']={**program,'version':match[1].decode('ascii')}
    CHECKPOINT['phase']='SELECTED_IPV6_LOOPBACK_METADATA'
    ipv6={}
    for name in('owner','ingestion'):
        key='ownerControlProfile'if name=='owner'else'ingestionReadinessProfile';endpoint=profiles[key]['endpoint']
        if ipaddress.ip_address(endpoint['host']).version==6:
            binding=profiles['ownerControlProfile']['runtimeBinding']if name=='owner'else packet['expectedRuntimeBindings']['ingestion']
            namespace=profiles['ownerControlProfile']['networkNamespace']if name=='owner'else case['nativeProfiles']['observedNamespaces']['ingestion']
            ipv6[name]=ipv6_loopback_metadata(entry,binding['pid'],namespace,endpoint)
        else:ipv6[name]={'required':False}
    CHECKPOINT['phase']='EXACT_NATIVE_STDLIB_CLOSURE';library=a.stdlib_binding()
    closure={'declaration':manifest,'executables':programs,'stdlibHash':c.digest(library),'stdlibFileCount':len(library['fileHashes'])}
    a.closure_shape(closure)
    for seal in seals.values():a.private_file.check_metadata(seal)
    a.current_issuer(issuer,int(time.time())+900)
    prepared={'schema':'ouf.ingestion-rollout-production-preparation.v1','caseHash':c.digest(case),'controlSourceHash':control_hash,
        'sourceClosure':closure,'issuerProfile':issuer,'retainedDocuments':seals,'qualification':case['qualification'],'ipv6EndpointMetadata':ipv6,
        'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False}
    write(entry,context,'preparation.json',prepared)
    update(journal,state='PRIVATE_READY',preparationHash=c.digest(prepared))
    CHECKPOINT['phase']='PRIVATE_READY'
    return {'status':'PRODUCTION_BOOTSTRAP_PREPARED_NO_AUTHORITY','complete':True,'contextPath':str(context),
        'startedAtUnix':started,'finishedAtUnix':time.time(),'elapsedSeconds':time.monotonic()-clock,
        'sourceModuleCount':manifest['moduleCount'],'currentExistingIssuerPolicyProvenForSeconds':900,
        'nativeControlProfilesReused':True,'selectedIpv6LoopbacksChecked':sum(v['required']for v in ipv6.values()),
        'serviceReachabilityProven':False,'humanWindowOpeningAuthorized':False,'freshHumanStillRequired':True,
        'signaturesIssued':0,'privateKeysRead':0,'humanCredentialJournalsRead':0,'bearerFilesOpened':0,
        'oauthRequests':0,'engineRequests':0,'databaseCalls':0,'gatewayRequests':0,'ownerRequests':0,'containerLifecycleOperations':0,
        'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False,'newLoginPerformed':False,
        'windowExtended':False,'databaseAdmissionProven':False,'nativeClientProfilePublished':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}

def opened(entry,manifest,case,control_hash,context):
    c=entry.c;c.path(context);target=Path(context);CHECKPOINT.update(phase='RETAINED_PRODUCTION_CONTROL',contextPath=context)
    parent=Path(case['ownerPlanBinding']['path']).parent.parent
    c.require(target.parent==parent and re.fullmatch('ingestion-rollout-native-[A-Za-z0-9_-]{8,64}',target.name),
        'EXACT_PRIVATE_PRODUCTION_CONTEXT_REQUIRED')
    journal=entry.Journal(target/'operator-control');row=journal.read()
    c.require(row['schema']==PROFILE and row['caseHash']==c.digest(case)and row['controlSourceHash']==control_hash
        and row['sourceDeclarationHash']==c.digest(manifest)and row['budgetReset']is False,'SAME_RETAINED_PRODUCTION_CONTROL_REQUIRED')
    claim,_=read_json(entry,str(parent/('ingestion-rollout-control-'+row['logicalRef']+'.claim.json')))
    c.require(claim['contextPath']==context and claim['logicalRef']==row['logicalRef']and claim['caseHash']==c.digest(case)
        and claim['controlSourceHash']==control_hash,'EXACT_PRODUCTION_CONTROL_CLAIM_REQUIRED')
    return target,journal,row

def preparation(entry,manifest,case,control_hash,target,row):
    c=entry.c;prepared,_=read_json(entry,str(target/'preparation.json'))
    c.require(c.digest(prepared)==row['preparationHash']and prepared['caseHash']==c.digest(case)
        and prepared['controlSourceHash']==control_hash and prepared['sourceClosure']['declaration']==manifest,
        'EXACT_RETAINED_PRODUCTION_PREPARATION_REQUIRED')
    for seal in prepared['retainedDocuments'].values():entry.authority.private_file.check_metadata(seal)
    return prepared

def human(entry,case,profile):
    c=entry.c;p=entry.authority.human_reader.validate(profile)
    plan,_=read_json(entry,case['ownerPlanBinding']['path'],case['ownerPlanBinding']['sha256'],canonical=True)
    c.require(c.digest(p['selection'])==plan['humanBinding']['selectionHash']
        and p['minimumCumulativeAttempts']>=case['retainedHumanAttempts']
        and p['maximumCumulativeAttempts']==case['maximumCumulativeOAuthAttempts']
        and p['expectedBinding']['createdAt']>case['expiredHumanWindowExpiresAt'],
        'SAME_ORIGINAL_SELECTION_FRESH_HUMAN_AND_CUMULATIVE_HISTORY_REQUIRED')
    return entry.authority.human_reader.open_existing(p)

def review(entry,manifest,case,control_hash,target,journal,row,profile_path):
    c=entry.c;a=entry.authority;c.require(row['state']=='PRIVATE_READY','EXPLICIT_REVIEW_NOT_REPLAYABLE_RECONCILE_REQUIRED')
    prepared=preparation(entry,manifest,case,control_hash,target,row);a.verify_closure(prepared['sourceClosure'])
    profile,profile_seal=read_json(entry,profile_path);h=human(entry,case,profile)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    selected,profiles,seals,parent=retained(entry,case);qualification(entry,manifest,case,selected['packetBinding'])
    update(journal,state='REVIEW_COMPILING',humanProfile=profile_seal)
    native=a.native_review.compile_native_review(selected['packetBinding'],case['packetBinding'],selected['verifiedInputsBinding'],
        h.current(),str(target),profiles,selected['ownerPlanBinding'],selected['ownerResultBinding'],human_read_profile=profile)
    result=a.compile_action_review(native,selected['packetBinding'],prepared['sourceClosure'],prepared['issuerProfile'],prepared['qualification'],900)
    result['absoluteExpiresAt']=min(h.expires_at-5,int(h._read()['accessExpiresAt'])-30)
    result['operatorBinding']={'controlSourceHash':control_hash,'caseHash':c.digest(case),'preparationHash':row['preparationHash'],
        'modeContract':'EXPLICIT_ONE_STAGE_NO_AUTOMATIC_REPLAY_V1'}
    a.validate_action_review(result);a.current_issuer(prepared['issuerProfile'],int(time.time())+900)
    write(entry,target,'review.json',result);update(journal,state='REVIEW_READY',reviewHash=c.digest(result))
    return {'status':'EXACT_RUNTIME_REVIEW_PREPARED_APPROVAL_REQUIRED','complete':False,'contextPath':str(target),
        'maximumRuntimeSeconds':900,'plannedStages':len(native['stages']),'runtimeAuthorityIssued':False,'oauthRequests':0,
        'databaseAdmissionProven':False,'freshTerminalInfrastructureConsentRequired':True,'semanticOrSourceApprovalGranted':False}

def load_review(entry,manifest,case,control_hash,target,row):
    c=entry.c;prepared=preparation(entry,manifest,case,control_hash,target,row)
    review,_=read_json(entry,str(target/'review.json'),row['reviewHash'],canonical=True)
    c.require(review['operatorBinding']=={'controlSourceHash':control_hash,'caseHash':c.digest(case),
        'preparationHash':row['preparationHash'],'modeContract':'EXPLICIT_ONE_STAGE_NO_AUTOMATIC_REPLAY_V1'},
        'SAME_REVIEWED_PRODUCTION_OPERATOR_REQUIRED')
    profile=read_json(entry,row['humanProfile']['path'],row['humanProfile']['sha256'])[0]
    h=human(entry,case,profile);entry.authority.validate_action_review(review)
    return prepared,review,h

def approve(entry,manifest,case,control_hash,target,journal,row):
    c=entry.c;a=entry.authority;c.require(row['state']=='REVIEW_READY','EXPLICIT_ISSUANCE_NOT_REPLAYABLE_RECONCILE_REQUIRED')
    prepared,review,h=load_review(entry,manifest,case,control_hash,target,row)
    c.require(h._read()['accessExpiresAt']>time.time()+930,'CURRENT_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    a.verify_closure(review['sourceClosure']);a.current_issuer(review['issuerProfile'],int(time.time())+900)
    decision=a.terminal_consent(review,
        'Rollout infrastrutturale distinto, massimo900secondi. Due sostituzioni: Ingestion e Gateway.\n'
        'Una chiave dedicata nuova; import della sola immagine gia qualificata; massimo2PUT Gateway e80altre route conservate.\n'
        'Schema applicativo VALIDATE_ONLY, zero migrazioni SQL. Owner7 e proiezione7 restano conclusi.\n'
        'Ogni passo e un comando manuale; dopo STOP contesti e claim restano, senza replay o rinnovi.\n'
        'I gate correnti HUMAN/Owner/DB/Gateway e i due ruoli firmati restano obbligatori prima degli effetti.\n'
        'Nessuna approvazione semantica o attivazione fonte/job e nessuna pubblicazione del profilo client.\n'
        'Revisione privata: '+str(target/'review.json'))
    update(journal,state='ISSUING',decisionHash=c.digest(decision))
    a.issue_action(review,decision,h,c.digest(decision))
    mandate=read_json(entry,str(target/'human.json'))[1]['sha256']
    update(journal,state='ISSUED',mandateHash=mandate,runtimeAuthorityIssued=True)
    return {'status':'AUTHORITY_ISSUED_EXPLICIT_INITIALIZE_REQUIRED','complete':False,'contextPath':str(target),
        'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'newLoginPerformed':False,'oauthRequests':0,
        'automaticReplayAllowed':False,'budgetReset':False,'sourceOrSemanticApprovalGranted':False}

def runtime(entry,manifest,case,control_hash,target,journal,row,mode):
    c=entry.c
    allowed={'initialize':{'ISSUED'},'step':{'INITIALIZED','RUNNING'},
        'reconcile':{'INITIALIZED','RUNNING','DISPATCHING','RECONCILE_REQUIRED'}}
    c.require(row['state']in allowed[mode],'EXPLICIT_RUNTIME_STATE_REQUIRES_RECONCILIATION_NO_REPLAY')
    prepared,review,h=load_review(entry,manifest,case,control_hash,target,row)
    decision=read_json(entry,str(target/'decision.json'),row['decisionHash'],canonical=True)[0]
    action=entry.load_action(review,decision,h,row['decisionHash'],row['mandateHash'])
    packet=read_json(entry,case['packetBinding']['path'],case['packetBinding']['sha256'],canonical=True)[0]
    update(journal,state='DISPATCHING',lastExplicitMode=mode)
    try:result=entry.execute(mode,review,packet,h,action,manifest)
    except BaseException:
        update(journal,state='RECONCILE_REQUIRED');raise
    state='COMPLETE'if result.get('complete')is True else'INITIALIZED'if mode=='initialize'else'RUNNING'
    update(journal,state=state,complete=state=='COMPLETE')
    return {'status':'EXPLICIT_NATIVE_INVOCATION_COMPLETED','contextPath':str(target),'controlState':state,**result}

def status(entry,target,row):
    result={'status':'RETAINED_PRODUCTION_CONTROL_METADATA_ONLY','contextPath':str(target),'state':row['state'],
        'complete':row['complete'],'readOnly':True,'humanCredentialJournalsRead':0,'engineRequests':0,'oauthRequests':0,
        'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
    if os.path.lexists(target/'recovery.json'):
        native=entry.Journal(target).read();result.update(nextStage=native['nextStage'],readAttempts=native['readAttempts'],
            readState=native['readState'],runtimeEffectsRecorded=len(native['effects']))
    return result

def execute(entry,manifest,case,control_hash,args):
    c=entry.c;c.require(type(args)is list and args,'ONE_EXPLICIT_PRODUCTION_MODE_REQUIRED')
    mode=args[0];shapes={'prepare':1,'status':2,'review':3,'approve':2,'initialize':2,'step':2,'reconcile':2}
    c.require(mode in shapes and len(args)==shapes[mode],'EXACT_PRODUCTION_MODE_ARGUMENTS_REQUIRED')
    if mode=='prepare':result=prepare(entry,manifest,case,control_hash)
    else:
        target,journal,row=opened(entry,manifest,case,control_hash,args[1])
        if mode=='status':result=status(entry,target,row)
        else:
            with journal.invocation():
                row=journal.read()
                if mode=='review':result=review(entry,manifest,case,control_hash,target,journal,row,args[2])
                elif mode=='approve':result=approve(entry,manifest,case,control_hash,target,journal,row)
                else:result=runtime(entry,manifest,case,control_hash,target,journal,row,mode)
    return {'schema':'ouf.ingestion-rollout-production-control-result.v1','completedTechnicalPhases':8,
        'functionalMilestonesProven':4,'notReleaseAcceptance':True,**result}
