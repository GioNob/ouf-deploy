#!/usr/bin/env python3
"""Prepare ONE fresh role-review draft; preserve the live finite action and deadline."""
import base64,hashlib,json,os,re,stat,subprocess,sys,time,types
from datetime import datetime,timezone
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-b96d2afabbd3275beadb0bbb525608278d5f098af1e14de1f5e4333bff9b488d')
EXPIRED_ID='adf95413-92b0-460b-a112-2fd80bd208ac'
SOURCE='6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a'
KEY='cohort-role-recovery:'+EXPIRED_ID

def require(ok,reason):
    if not ok:raise RuntimeError(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def unique(rows):
    value={}
    for key,item in rows:
        require(key not in value,'RECOVERY_DUPLICATE_JSON_KEY');value[key]=item
    return value
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
def emit(phase,**safe):
    print(json.dumps({'schema':'ouf.chatbot-role-review-recovery.v1','phase':phase,
        'budgetReset':False,'authorityRenewed':False,'processRestarted':False,
        'rolePublicationPerformedByScript':False,**safe},sort_keys=True),flush=True)

def private_read(path, limit):
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts and str(target) == str(path),
            'CHILD_EXACT_PRIVATE_ARTIFACT_PATH_REQUIRED')
    held = []
    flags = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
    parent = os.open('/',flags)
    held.append(parent)
    ancestry = []
    try:
        for name in target.parts[1:-1]:
            fd = os.open(name,flags,dir_fd=parent)
            held.append(fd)
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode&0o022,
                    'CHILD_ROOT_CONTROLLED_ANCESTRY_REQUIRED')
            ancestry.append((parent,name,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = fd
        info = os.fstat(parent)
        require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'CHILD_PRIVATE_ARTIFACT_PARENT_REQUIRED')
        fd = os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        held.append(fd)
        before = os.fstat(fd)
        pin = lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
                          row.st_size,row.st_mtime_ns,row.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= limit, 'CHILD_PRIVATE_ARTIFACT_CUSTODY_REQUIRED')
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd,min(65536,limit+1-len(raw)))
            if not part:
                break
            raw.extend(part)
        require(len(raw) == before.st_size and pin(before) == pin(os.fstat(fd))
                == pin(os.stat(target.name,dir_fd=parent,follow_symlinks=False)), 'CHILD_ARTIFACT_READ_DRIFT')
        for directory,name,fd,expected in ancestry:
            current = os.stat(name,dir_fd=directory,follow_symlinks=False)
            require(expected == (current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode),
                    'CHILD_ARTIFACT_ANCESTRY_CHANGED')
        return bytes(raw)
    finally:
        for fd in reversed(held):
            os.close(fd)


def propose_once(transport,plan,guard):
    guard()
    current_roles=transport.roles()
    if current_roles==plan['targetRoles']:
        return {'state':'TARGET_ALREADY_PUBLISHED_NO_PROPOSAL_CREATED'}
    require(current_roles==plan['baseline']['roles'],'ROLE_RECOVERY_BASELINE_DRIFT')
    previous=transport.tool('authorization.proposal.read',{'proposalId':EXPIRED_ID},'cohort:expired-role:read')
    require(previous.get('proposalId')==EXPIRED_ID and previous.get('state')=='EXPIRED'
        and previous.get('finalPolicyRef') is None,'EXACT_UNPUBLISHED_EXPIRED_ROLE_PROPOSAL_REQUIRED')
    current=transport.active()
    expected=plan['candidatePolicy'] if plan['addedDescriptors'] else plan['baseline']['active']['policy']
    require(all(current['policy'].get(k)==expected.get(k) for k in ('bundleId','version','capabilities','grants')),
        'ROLE_RECOVERY_ACTIVE_POLICY_DRIFT')
    require(plan['roleProposal']['operation']=='REPLACE_ROLES'
        and plan['roleProposal']['roleCatalogue']==plan['targetRoles'],'EXACT_REVIEWED_ROLE_PAYLOAD_REQUIRED')
    guard()
    # Stable NEW draft key: retries return the same draft, never renew its TTL.
    receipt=transport.tool('authorization.permissions.propose',plan['roleProposal'],KEY)
    require(receipt.get('proposalId')!=EXPIRED_ID and receipt.get('state') in ('PENDING','PUBLISHED','EXPIRED','REJECTED'),
        'BOUNDED_NEW_ROLE_PROPOSAL_RECEIPT_REQUIRED')
    return receipt

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ISOLATED_ROOT_RECOVERY_REQUIRED')
    review=decode(private_read(CONTEXT/'review.json',262144))
    process=review['scopes']['finiteActionProcess']
    require(process['authorityDirectory']==str(CONTEXT),'EXACT_ROLE_RECOVERY_CONTEXT_REQUIRED')
    bundle_raw=private_read(process['bundle']['path'],8388608)
    require(hashlib.sha256(bundle_raw).hexdigest()==process['bundle']['sha256'],'ROLE_RECOVERY_BUNDLE_DRIFT')
    bundle=decode(bundle_raw);decl=review['sourceClosure']['declaration']
    require(decl['sourceCommit']==SOURCE and bundle['declaration']==decl,'EXACT_RUNNING_SOURCE_REQUIRED')
    loader=base64.b64decode(bundle['loader'],validate=True)
    require(hashlib.sha256(loader).hexdigest()==decl['loaderHash'],'ROLE_RECOVERY_LOADER_DRIFT')
    require(set(bundle['sources'])==set(decl['sourceHashes']),'EXACT_RECOVERY_SOURCE_SET_REQUIRED')
    sources={name:base64.b64decode(raw,validate=True) for name,raw in bundle['sources'].items()}
    require(all(hashlib.sha256(raw).hexdigest()==decl['sourceHashes'][name] for name,raw in sources.items()),
        'ROLE_RECOVERY_SOURCE_HASH_DRIFT')
    prepared=bundle['prepared']
    require(digest(prepared)==review['privateInputHashes']['preparedInputs'],'ROLE_RECOVERY_PREPARED_INPUT_DRIFT')
    runtime=types.ModuleType('verified_role_recovery_loader')
    exec(compile(loader,'<verified-existing-cohort-loader>','exec'),runtime.__dict__)
    entry,manifest=runtime.load_entry(SOURCE,sources,loader,digest(decl),decl['sourcePins'])
    require(manifest==decl and digest(review['sourceClosure'])==review['sourceClosureHash'],'ROLE_RECOVERY_CLOSURE_DRIFT')
    decision=decode(private_read(CONTEXT/'decision.json',8192))
    entry.validate_decision(review,decision,int(time.time()))
    require(time.time()+300<decision['expiresAt'],'LESS_THAN_FIVE_MINUTES_REMAIN_NO_NEW_PROPOSAL')
    for value in review['sourceClosure']['executables'].values():entry.command_matches(value)
    require(digest(entry.stdlib_binding())==review['sourceClosure']['stdlibHash'],'ROLE_RECOVERY_STDLIB_DRIFT')
    authority_raw=private_read(CONTEXT/'authority.json',131072)
    mandate_raw=private_read(CONTEXT/'human.json',131072)
    expected={k:review[k] for k in ('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
    expected['intakeHash']=digest(review)
    verifier=entry.DetachedAuthenticator(entry.governance.POLICY,str(CONTEXT),review['sourceClosure']['executables']['openssl'])
    mandate_hash=hashlib.sha256(mandate_raw).hexdigest()
    profile=entry.FileOnlyProfile(prepared['registry']['creationRequest'],prepared['registry']['configtree'])
    gate=entry.CutoverAuthority(verifier,{'path':str(CONTEXT/'human.json'),'sha256':mandate_hash},mandate_hash,
        entry.governance.CONTEXT,expected,execution_profile=profile)
    action=entry.AggregateAction(gate,authority_raw,review['sourceClosureHash'])
    auth=prepared['authorization'];plan=auth['plan']
    module=sys.modules['tools.chatbot_file_cohort.authorization']
    scope=module.authorization_scope(plan)
    require(scope==review['scopes']['chatbotFileAuthorization'],'ROLE_RECOVERY_SIGNED_SCOPE_DRIFT')
    def guard():
        entry.validate_decision(review,decision,int(time.time()))
        action.guard('chatbotFileAuthorization',scope)
        require(time.time()+120<decision['expiresAt'],'LESS_THAN_TWO_MINUTES_REMAIN_NO_NEW_PROPOSAL')
        status=decode(private_read(CONTEXT/'delivery-status.json',8192))
        require(status.get('phase')=='HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED'
            and status.get('proposalId')==EXPIRED_ID and status.get('state')=='EXPIRED'
            and status.get('authorityHash')==hashlib.sha256(authority_raw).hexdigest(),
            'LIVE_ACTION_NO_LONGER_WAITS_FOR_THIS_EXPIRED_PROPOSAL')
        result=subprocess.run(['/usr/bin/systemctl','show',process['unit'],'--property=ActiveState','--value'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
        require(result.returncode==0 and result.stdout.strip()==b'active','LIVE_FINITE_ACTION_REQUIRED')
    guard()
    def wait(seconds):
        until=time.monotonic()+max(0,seconds)
        while time.monotonic()<until:
            guard();time.sleep(min(5,until-time.monotonic()))
    binding=plan['sessionBinding']
    session=entry.HumanSession(plan['selection'],binding['sessionDirectory'],binding['tokenPath'],binding['expiresAt'],action=action)
    transport=entry.OwnerTransport(plan['selection'],auth['adminTokenFile'],auth['mcpTokenFile'],wait=wait,human_session=session)
    emit('PREPARING_ONE_EXACT_ROLE_REVIEW_DRAFT',originalProposalId=EXPIRED_ID,
        originalAuthorityExpiresAt=decision['expiresAt'],rolePayloadHash=digest(plan['roleProposal']))
    receipt=propose_once(transport,plan,guard)
    safe={k:receipt[k] for k in ('proposalId','revision','state','expiresAt','approvalPath','finalPolicyRef') if k in receipt}
    emit('ROLE_REVIEW_RECEIPT',**safe,originalAuthorityExpiresAt=decision['expiresAt'])
    if receipt['state']=='PENDING':
        expected_path=plan['selection']['origin'].rstrip('/')+'/trusted-human/authorization/?proposal='+str(receipt['proposalId'])
        require(receipt['approvalPath']==expected_path,'EXACT_OWNER_BROWSER_REVIEW_PATH_REQUIRED')
        print('\nAPRI ORA QUESTO LINK NEL BROWSER E REVISIONA I RUOLI:\n'+expected_path,flush=True)
        print('Scadenza proposta: '+str(receipt['expiresAt'])+'; il mandato esistente termina comunque alle '+
            datetime.fromtimestamp(decision['expiresAt'],timezone.utc).isoformat()+' (UTC).',flush=True)
        print('La conferma avviene solo nel browser. Questo script NON pubblica i ruoli e NON riavvia il processo.',flush=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)
        emit('STOPPED_RECONCILE_WITHOUT_RESTART',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,159}',reason) else type(error).__name__)
        raise SystemExit(1)
