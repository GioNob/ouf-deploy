"""One bounded, read-only review of the four known token-writer layouts.

Source is parsed, never imported/executed. Static observations do not certify
credential exclusivity, runtime source custody or effective data flow.
"""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

SOURCE_COMMIT='a0f50691a530ae28148264f3607056f3774b0f5c'
GUARD_SHA='a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'
ROOT_BODY=r'''
import ast,json,os,re,resource,shlex,signal,stat,subprocess,tempfile,time
HOST_HASH='93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4'
POLICY_HASH='3aef37971d405e0a84c60e0e110f7ababdba8e5c62cbda815e44e9ea5077d060'
WRITERS={
 'ouf-policy-token@semantic.service':'/opt/ouf/ops/refresh-policy-token.py',
 'ouf-gateway-policy-token.service':'/opt/ouf/ops/refresh-gateway-policy-token.py',
 'ouf-ingestion-policy-token.service':'/opt/ouf/ops/refresh-ingestion-policy-token.py',
 'ouf-onboarding-identity-token.service':'/var/lib/ouf-r4a-identity/r4a_onboarding_token_runtime.py'}
SAFE_ENV={'OUF_POLICY_TOKEN_'+key for key in ('CLIENT_ID','ENDPOINT','REQUIRED_SCOPE','RUNTIME_DIR','RUNTIME_GID','SECRET_FILE')}
SERVICE_PROPS=('Id','LoadState','ActiveState','SubState','UnitFileState','TriggeredBy','ExecStart','EnvironmentFiles',
 'Environment','UnsetEnvironment','RootDirectory','RootImage','BindPaths','BindReadOnlyPaths','TemporaryFileSystem')
TIMER_PROPS=('Id','LoadState','ActiveState','SubState','UnitFileState')

def reason(error):
    value=str(error)
    return value if type(error)is guard.CandidateDenied and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',value)else type(error).__name__

def file_read(path,limit):
    """No symlinks, bounded regular files, stable identities; weak ancestry is reported.

    Weak source ancestry is observable but is never accepted as execution custody.
    Callers limit paths to known code, selected .conf files or the bound executable.
    """
    path=guard.Path(path)
    guard.require(path.is_absolute() and '..'not in path.parts and len(path.parts)<=32,'READ_PATH_INVALID')
    fds=[];seals=[];controlled=True
    def seal(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        for part in path.parts[1:-1]:
            before=os.stat(part,dir_fd=parent,follow_symlinks=False)
            guard.require(stat.S_ISDIR(before.st_mode),'READ_ANCESTOR_NOT_DIRECTORY')
            controlled=controlled and before.st_uid==before.st_gid==0 and not bool(before.st_mode&0o022)
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(child)
            guard.require(seal(before)==seal(os.fstat(child)),'READ_ANCESTOR_CHANGED')
            seals.append((parent,part,child,seal(before)));parent=child
        before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        guard.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=limit,'READ_FILE_METADATA_UNSUPPORTED')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
        guard.require(guard.identity(before)==guard.identity(os.fstat(fd)),'READ_FILE_CHANGED')
        pieces=[];total=0
        while total<=limit:
            chunk=os.read(fd,min(65536,limit+1-total))
            if not chunk:break
            pieces.append(chunk);total+=len(chunk)
        guard.require(total==before.st_size and guard.identity(before)==guard.identity(os.fstat(fd))
            ==guard.identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'READ_FILE_CHANGED')
        for ancestor,part,child,expected in seals:
            guard.require(expected==seal(os.fstat(child))==seal(os.stat(part,dir_fd=ancestor,follow_symlinks=False)),
                'READ_ANCESTOR_CHANGED')
        controlled=controlled and before.st_uid==before.st_gid==0 and not bool(before.st_mode&0o022)
        return b''.join(pieces),{'rootControlledAncestryAndFile':controlled,'uid':before.st_uid,'gid':before.st_gid,
            'modeOctal':format(stat.S_IMODE(before.st_mode),'04o'),'executionCustodyAccepted':False}
    finally:
        for fd in reversed(fds):os.close(fd)

def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(131073,131073))

def command(args,report,deadline,runner=subprocess.run):
    guard.require(report['systemctlReadAttempts']<9 and time.monotonic()<deadline,'FINITE_SYSTEMCTL_BUDGET_EXHAUSTED')
    report['systemctlReadAttempts']+=1
    with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as err:
        try:result=runner(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
            timeout=min(5,max(0.001,deadline-time.monotonic())),preexec_fn=output_limit,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','SYSTEMD_COLORS':'0'})
        except subprocess.TimeoutExpired:raise guard.CandidateDenied('SYSTEMCTL_READ_TIMEOUT')from None
        out.seek(0);raw=out.read(131073)
    guard.require(result.returncode==0,'SYSTEMCTL_READ_FAILED_EXIT_'+str(result.returncode).replace('-','SIGNAL_'))
    guard.require(len(raw)<=131072,'SYSTEMCTL_OUTPUT_UNBOUNDED')
    return raw.decode('utf-8')

def properties(raw,unit,allowed):
    fields={}
    for line in raw.splitlines():
        if not line:continue
        key,sep,value=line.partition('=')
        guard.require(sep and key in allowed and (key not in fields or key=='EnvironmentFiles'),'SYSTEMCTL_PROPERTY_SCHEMA_UNPROVEN')
        fields[key]=((fields[key]+' ')if key=='EnvironmentFiles'and key in fields else '')+value
    guard.require(fields.get('Id')==unit,'SYSTEMCTL_UNIT_IDENTITY_MISMATCH')
    return fields

def public_states(fields):
    # Unknown values are not copied to public output.
    values={}
    for key in TIMER_PROPS[1:]:
        value=fields.get(key)
        values[key]=value if value in {'loaded','not-found','masked','error','bad-setting','active','inactive','failed',
            'activating','deactivating','reloading','maintenance','dead','running','exited','waiting','elapsed',
            'enabled','enabled-runtime','disabled','static','indirect','generated','transient','linked','linked-runtime',
            'alias','masked-runtime'}else 'UNRECOGNIZED_OR_ABSENT'
    return values

def config_path(value):
    return bool(re.fullmatch(r'/etc/ouf/policy-token/[A-Za-z0-9_.@-]+\.conf',value)) and '..'not in guard.Path(value).parts

def environment(fields):
    selected={};findings=[]
    for word in shlex.split(fields.get('Environment','')):
        key,sep,value=word.partition('=')
        if sep and key in SAFE_ENV:
            if key in selected:findings.append('DUPLICATE_INLINE_CONFIGURATION_KEY')
            else:selected[key]=value
    if fields.get('UnsetEnvironment'):findings.append('UNSET_ENVIRONMENT_REQUIRES_REVIEW')
    return selected,findings

def configuration(raw):
    selected={};findings=[]
    for line in raw.decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        key,sep,value=line.partition('=')
        if not sep or key not in SAFE_ENV:
            findings.append('CONFIGURATION_CONTAINS_UNREVIEWED_KEYS_OR_SYNTAX');continue
        words=shlex.split(value)
        if len(words)!=1 or key in selected:
            findings.append('CONFIGURATION_VALUE_OR_DUPLICATE_UNSUPPORTED');continue
        selected[key]=words[0]
    return selected,sorted(set(findings))

def source_facts(raw,env,client,issuer):
    tree=ast.parse(raw);nodes=list(ast.walk(tree))
    guard.require(len(nodes)<=20000,'SOURCE_AST_UNBOUNDED')
    assignments={};ambiguous=set()
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in assignments:ambiguous.add(name)
            assignments[name]=node.value
    def value(node,seen=()):
        if len(seen)>12:return None
        if isinstance(node,ast.Constant) and type(node.value)is str:return node.value if len(node.value)<=4096 else None
        if isinstance(node,ast.Name) and node.id in assignments and node.id not in seen and node.id not in ambiguous:
            return value(assignments[node.id],(*seen,node.id))
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            left,right=value(node.left,seen),value(node.right,seen)
            return left+right if left is not None and right is not None and len(left+right)<=4096 else None
        # This is a static lookup observation, not an assertion about helper semantics.
        if isinstance(node,ast.Call) and node.args:
            key=value(node.args[0],seen)
            if key in SAFE_ENV and ((isinstance(node.func,ast.Name) and node.func.id=='required')
                or (isinstance(node.func,ast.Attribute) and node.func.attr in {'get','getenv'})):
                return env.get(key)
        if isinstance(node,ast.Subscript) and isinstance(node.value,ast.Attribute) and node.value.attr=='environ':
            return env.get(value(node.slice,seen))
        return None
    expressions=[];config_refs=set();keys=[];issuer_values=[]
    for name,node in assignments.items():
        if name in {'CLIENT','CLIENT_ID','client_id'}:expressions.append(node)
        if name in {'ISSUER','ENDPOINT','TOKEN_ENDPOINT'}:issuer_values.append(value(node))
    for node in nodes:
        if isinstance(node,ast.Dict):
            for key,item in zip(node.keys,node.values):
                if isinstance(key,ast.Constant) and key.value=='client_id':expressions.append(item)
        if isinstance(node,ast.Constant) and type(node.value)is str:
            if config_path(node.value):config_refs.add(node.value)
            if node.value in SAFE_ENV:keys.append(node.value)
    found=[value(node)for node in expressions]
    resolved=[item for item in found if item is not None]
    bindings=sorted(set(resolved))
    return {'sourceSha256':guard.sha(raw),'astNodeCount':len(nodes),'clientIdExpressionCount':len(expressions),
        'resolvedClientIdExpressionCount':len(resolved),'unresolvedClientIdExpressionCount':sum(v is None for v in found),
        'distinctStaticClientIdentifierCount':len(bindings),'selectedClientIdentifierObserved':client in bindings,
        'otherStaticClientIdentifierCount':sum(v!=client for v in bindings),
        'staticIssuerMatchesRetained':any(v in {issuer,issuer+'/protocol/openid-connect/token'}for v in issuer_values),
        'selectedClientInSupportedConfiguration':env.get('OUF_POLICY_TOKEN_CLIENT_ID')==client,
        'supportedConfigurationKeysReferenced':sorted(set(keys)),
        'unresolvedClientExpressionKinds':sorted({type(node).__name__ for node in expressions if value(node)is None}),
        'effectiveDataFlowProven':False},sorted(config_refs)

def observe_unit(unit,path,client,issuer,report,deadline,read=file_read,run=command):
    row={'unit':unit,'knownSourcePath':path,'findings':[],'credentialConsumerScopeProven':False}
    fields={};raw=None;env={};refs=set();timer=unit[:-8]+'.timer'
    try:
        fields=properties(run(['show',unit,'--no-pager','--property='+','.join(SERVICE_PROPS)],report,deadline),unit,SERVICE_PROPS)
        row['service']=public_states(fields)
        start=fields.get('ExecStart','')
        row['knownSourcePathMentionedInExecStart']=bool(re.search(r'(?<![A-Za-z0-9_/.-])'+re.escape(path)+r'(?=[\s;]|$)',start))
        row['expectedTimerAssociationObserved']=timer in fields.get('TriggeredBy','').split()
        row['environmentFilesPropertyReturned']='EnvironmentFiles'in fields
        row['namespaceOverridesObserved']=any(fields.get(k)for k in ('RootDirectory','RootImage','BindPaths','BindReadOnlyPaths','TemporaryFileSystem'))
        env,findings=environment(fields);row['findings']+=findings
        env_paths=re.findall(r'(/[^\s]+) \(ignore_errors=(?:yes|no)\)',fields.get('EnvironmentFiles',''))
        for selected in env_paths:
            if config_path(selected):refs.add(selected)
            else:row['findings'].append('ENVIRONMENT_FILE_OUTSIDE_REVIEWED_LAYOUT')
        if fields.get('EnvironmentFiles') and not env_paths:row['findings'].append('ENVIRONMENT_FILES_LAYOUT_UNRECOGNIZED')
        if not row['knownSourcePathMentionedInExecStart']:row['findings'].append('COMMAND_ROUTE_REQUIRES_REVIEW')
    except Exception as error:row['findings'].append('SERVICE_'+reason(error))
    # The exact four known source paths are inspected even if their current command mapping is unresolved.
    try:
        raw,metadata=read(path,524288);report['sourceFilesRead']+=1;row['sourceMetadata']=metadata
        initial,source_refs=source_facts(raw,env,client,issuer);refs.update(source_refs)
    except Exception as error:row['findings'].append('SOURCE_'+reason(error))
    row['configurations']=[]
    if len(refs)>4:row['findings'].append('CONFIGURATION_REFERENCE_LIMIT');refs=set()
    config_values={};conflicting=set()
    for selected in sorted(refs):
        entry={'referenceSha256':guard.sha(selected.encode())}
        try:
            data,metadata=read(selected,65536);report['configurationFilesRead']+=1
            values,findings=configuration(data);entry.update(metadata=metadata,findings=findings)
            for key,val in values.items():
                if key in config_values and config_values[key]!=val:conflicting.add(key)
                config_values[key]=val
        except Exception as error:entry['reason']=reason(error)
        row['configurations'].append(entry)
    for key,val in config_values.items():
        if key in env and env[key]!=val:conflicting.add(key)
        else:env[key]=val
    for key in conflicting:env.pop(key,None)
    if conflicting:row['findings'].append('CONFIGURATION_VALUE_CONFLICT_REQUIRES_REVIEW')
    if raw is not None:
        try:row['staticSource'],_=source_facts(raw,env,client,issuer)
        except Exception as error:row['findings'].append('ANALYSIS_'+reason(error))
    try:
        row['timer']=public_states(properties(run(['show',timer,'--no-pager','--property='+','.join(TIMER_PROPS)],report,deadline),timer,TIMER_PROPS))
    except Exception as error:row['findings'].append('TIMER_'+reason(error))
    row['findings']=sorted(set(row['findings']))
    return row

def collect(client,issuer,report,read=file_read,run=command):
    deadline=time.monotonic()+60
    report['writers']=[observe_unit(unit,path,client,issuer,report,deadline,read,run)for unit,path in WRITERS.items()]
    try:
        raw=run(['list-unit-files','--type=service','--no-legend','--no-pager','ouf-*token*.service'],report,deadline)
        names=[line.split()[0]for line in raw.splitlines()if line.strip()]
        guard.require(len(names)<=64 and all(re.fullmatch(r'ouf-[A-Za-z0-9_.@-]+\.service',name)for name in names),
            'ADDITIONAL_UNIT_INVENTORY_UNBOUNDED_OR_UNRECOGNIZED')
        report['additionalTokenNamedUnits']=sorted(set(names)-set(WRITERS)-{'ouf-policy-token@.service'})
        report['tokenNamedUnitInventoryObserved']=True
    except Exception as error:report['inventoryReason']=reason(error)
    report['staticSelectedClientWriterCount']=sum(row.get('staticSource',{}).get('selectedClientIdentifierObserved',False)
        or row.get('staticSource',{}).get('selectedClientInSupportedConfiguration',False)for row in report['writers'])
    report['allConsumerDiscoveryProven']=False
    report['credentialConsumerScopeProven']=False
    report['observationHasFindings']=bool(report.get('inventoryReason') or report.get('additionalTokenNamedUnits')
        or any(row['findings'] or any(c.get('reason')or c.get('findings')for c in row['configurations'])for row in report['writers']))
    return report

report={'schema':'ouf.policy-token-consumer-review-receipt.v1','phase':'RETAINED_INPUTS','status':'BLOCKED',
 'observationProfile':'ouf.policy-token-known-consumer-review.single-attempt.v1','systemctlReadAttempts':0,
 'sourceFilesRead':0,'configurationFilesRead':0,'credentialFilesRead':0,'mountedTokenFilesRead':0,'privateKeysRead':0,
 'privateEvidenceWrites':0,'iamMutations':0,'serviceMutations':0,'providerCalls':0,'tokenGrantRequests':0,
 'sourceCodeExecuted':False,'rawSourceOrEnvironmentPrinted':False,'embeddedCredentialAbsenceProven':False,
 'credentialConsumerScopeProven':False,'runtimeAuthorityIssued':False,'productionApplyReady':False,
 'baselineRefreshed':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
try:
    guard.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ROOT_ISOLATED_CONSUMER_REVIEW_REQUIRED')
    def timeout(*_):raise guard.CandidateDenied('FINITE_CONSUMER_REVIEW_DEADLINE')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(90)
    with guard.protected_parent()as directory:
        host_raw=guard.read_member(directory,'policy-token-migration-host-inputs-'+HOST_HASH+'.private.json')
        policy_raw=guard.read_member(directory,'policy-token-client-policies-'+POLICY_HASH+'.private.json')
        guard.require(guard.sha(host_raw)==HOST_HASH and guard.sha(policy_raw)==POLICY_HASH,'RETAINED_CONSUMER_INPUT_HASH_DRIFT')
        host=guard.decode(host_raw);policy=guard.decode(policy_raw)
        guard.require(policy.get('schema')=='ouf.policy-token-client-policy-observation.v1','RETAINED_POLICY_SCHEMA_MISMATCH')
        client=policy['clientCore']['clientId'];guard.require(type(client)is str and 0<len(client)<=128,'RETAINED_CLIENT_ID_INVALID')
        report['phase']='BOUND_SYSTEMCTL_EXECUTABLE'
        executable=host['executables']['systemctl'];resolved=guard.Path('/usr/bin/systemctl').resolve(strict=True)
        executable_raw,metadata=file_read(resolved,64000000)
        guard.require(str(resolved)==executable['path'] and guard.sha(executable_raw)==executable['sha256']
            and metadata['rootControlledAncestryAndFile'],'SYSTEMCTL_EXECUTABLE_DRIFT')
        report['phase']='KNOWN_CONSUMER_METADATA_AND_STATIC_REVIEW'
        collect(client,'https://auth.ouf-lab.it/realms/ouf',report)
        report.update(status='KNOWN_CONSUMER_REVIEW_OBSERVED_NOT_ACCEPTED',phase='PRIVATE_REDACTED_REVIEW_PUBLICATION',
            hostInputsHash=HOST_HASH,clientPolicyObservationHash=POLICY_HASH)
        body=guard.encoded(report);digest=guard.sha(body);name='policy-token-consumer-review-'+digest+'.private.json'
        guard.require(len(body)<=262144,'CONSUMER_REVIEW_OUTPUT_UNBOUNDED')
        try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        except FileExistsError:guard.require(guard.read_member(directory,name)==body,'CONSUMER_REVIEW_EVIDENCE_CONFLICT')
        else:
            report['privateEvidenceWrites']=1
            with os.fdopen(fd,'wb')as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
        guard.require(guard.read_member(directory,name)==body,'CONSUMER_REVIEW_PUBLICATION_UNPROVEN')
        report.update(phase='OBSERVED_NOT_ACCEPTED',privateEvidenceHash=digest,privateEvidencePath=str(guard.PARENT/name))
    code=0
except Exception as error:
    report.update(status='BLOCKED',reason=reason(error),evidencePublicationMayBePartial=report['phase']=='PRIVATE_REDACTED_REVIEW_PUBLICATION')
    code=1
finally:signal.alarm(0)
print(guard.encoded(report).decode());raise SystemExit(code)
'''

def main():
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred)if preferred.is_file()and os.access(preferred,os.X_OK)else shutil.which('gh')
    if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref='+SOURCE_COMMIT
    try:
        response=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if len(response.stdout)>65536:raise ValueError()
        raw=base64.b64decode(b''.join(response.stdout.split()),validate=True)
        if hashlib.sha256(raw).hexdigest()!=GUARD_SHA:raise ValueError()
    except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_GUARD_UNAVAILABLE; no sudo executed')from None
    bootstrap='import sys,hashlib,types\nraw=sys.stdin.buffer.read(65537)\nif hashlib.sha256(raw).hexdigest()!='+repr(GUARD_SHA)+':raise SystemExit("phase=ROOT_DELIVERY reason=GUARD_HASH_MISMATCH")\nguard=types.ModuleType("qualified_metadata_guard")\nexec(compile(raw,"qualified-metadata-guard","exec"),guard.__dict__)\n'+ROOT_BODY
    try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',bootstrap],input=raw,timeout=110).returncode
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=CONSUMER_REVIEW_RESULT_UNAVAILABLE; preserve output, no automatic retry')from None

if __name__=='__main__':raise SystemExit(main())
