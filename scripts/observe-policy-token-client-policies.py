"""One read-only observation of previously unobserved client/global policy metadata."""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

SOURCE_COMMIT='a0f50691a530ae28148264f3607056f3774b0f5c'
GUARD_SHA='a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'
ROOT_BODY=r'''
import json,os,re,resource,signal,stat,subprocess,tempfile,time
HOST_HASH='93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4'
SNAPSHOT_HASH='7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927'
CORE='id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol'

def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(262145,262145))

def observe(snapshot,report,runner=subprocess.run):
    client=snapshot['client'];identifier=client['id']
    guard.require(type(identifier)is str and re.fullmatch('[0-9a-fA-F-]{36}',identifier),'EXACT_RETAINED_CLIENT_REQUIRED')
    deadline=time.monotonic()+60;values=[]
    requests=[('CURRENT_CLIENT_CORE','clients/'+identifier,['--fields',CORE]),
        ('CLIENT_AND_GLOBAL_POLICIES','client-policies/policies',['-q','include-global-policies=true']),
        ('CLIENT_AND_GLOBAL_PROFILES','client-policies/profiles',['-q','include-global-profiles=true'])]
    for phase,path,args in requests:
        report['phase']=phase;remaining=deadline-time.monotonic()
        guard.require(remaining>0,'CLIENT_POLICY_OBSERVATION_DEADLINE')
        argv=['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh','get',path,
            '--server','http://localhost:8080','-r','ouf',*args]
        report['iamMetadataGetAttempts']+=1
        with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as err:
            try:result=runner(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=min(15,remaining),
                preexec_fn=output_limit,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            except subprocess.TimeoutExpired:
                report['diagnosticCategories']=['COMMAND_TIMEOUT'];raise guard.CandidateDenied('CLIENT_POLICY_GET_TIMEOUT')from None
            out.seek(0);raw=out.read(262145);err.seek(0);diagnostic=err.read(16385)
        report['lastIamGetExitCode']=result.returncode
        if result.returncode!=0:
            text=diagnostic[:16384].decode('utf-8','replace').lower()
            report['diagnosticCategories']=[label for pattern,label in (
                ('not logged in|session.*expired|failed to refresh|invalid_grant|unauthorized','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
                ('forbidden|not authorized|permission denied','PERMISSION_FAILURE_TEXT_OBSERVED'),
                ('connection refused|connectexception','CONNECTION_FAILURE_TEXT_OBSERVED'))if re.search(pattern,text)]or ['UNCLASSIFIED_COMMAND_FAILURE']
            report['diagnosticTextTruncated']=len(diagnostic)>16384
            raise guard.CandidateDenied('CLIENT_POLICY_GET_UNAVAILABLE')
        guard.require(0<len(raw)<=262144,'CLIENT_POLICY_METADATA_RESPONSE_UNBOUNDED')
        value=guard.decode(raw);values.append(value)
        if phase=='CURRENT_CLIENT_CORE':
            guard.require(type(value)is dict and value=={k:client[k]for k in CORE.split(',')},'CURRENT_CLIENT_CORE_DRIFT')
    core,policies,profiles=values
    guard.require(type(policies)is dict and set(policies)=={'policies','globalPolicies'}
        and type(profiles)is dict and set(profiles)=={'profiles','globalProfiles'},'COMPLETE_GLOBAL_POLICY_METADATA_REQUIRED')
    for value in (*policies.values(),*profiles.values()):
        guard.require(type(value)is list and len(value)<=128 and all(type(row)is dict for row in value),'BOUNDED_POLICY_METADATA_REQUIRED')
    for rows in policies.values():
        guard.require(all(type(row.get('name'))is str and type(row.get('enabled'))is bool for row in rows),'POLICY_ENABLEMENT_SCHEMA_UNPROVEN')
    executors=[]
    for rows in profiles.values():
        for row in rows:
            entries=row.get('executors',[])
            guard.require(type(entries)is list and len(entries)<=128 and all(type(e)is dict and type(e.get('executor'))is str for e in entries),
                'PROFILE_EXECUTOR_SCHEMA_UNPROVEN')
            executors.extend(e['executor']for e in entries)
    report.update(clientCoreStillMatchesRetained=True,globalPolicyMetadataIncluded=True,
        realmPolicyCount=len(policies['policies']),globalPolicyCount=len(policies['globalPolicies']),
        enabledRealmPolicyCount=sum(p['enabled']for p in policies['policies']),
        enabledGlobalPolicyCount=sum(p['enabled']for p in policies['globalPolicies']),
        secretRotationExecutorPresentInProfileMetadata='secret-rotation'in executors,
        effectivePolicyApplicabilityProven=False,credentialConsumerScopeProven=False)
    return {'schema':'ouf.policy-token-client-policy-observation.v1','hostInputsHash':HOST_HASH,
        'retainedSnapshotHash':SNAPSHOT_HASH,'clientCore':core,'policies':policies,'profiles':profiles,
        'globalMetadataIncluded':True,'effectivePolicyApplicabilityProven':False,'credentialConsumerScopeProven':False,
        'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}

report={'schema':'ouf.policy-token-client-policy-observation-receipt.v1','phase':'RETAINED_INPUT_READ','status':'BLOCKED',
    'iamMetadataGetAttempts':0,'privateEvidenceWrites':0,'iamMutations':0,'serviceMutations':0,'tokenGrantRequests':0,
    'credentialFilesRead':0,'mountedTokenFilesRead':0,'privateKeysRead':0,'runtimeAuthorityIssued':False,
    'productionApplyReady':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True,
    'rawDiagnosticTextPrinted':False,'diagnosticCategoriesAreNotRootCauseProof':True,'baselineRefreshed':False}
try:
    guard.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ROOT_ISOLATED_POLICY_OBSERVATION_REQUIRED')
    def timeout(*_):raise guard.CandidateDenied('FINITE_POLICY_OBSERVATION_DEADLINE')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(90)
    with guard.protected_parent()as directory:
        host_raw=guard.read_member(directory,'policy-token-migration-host-inputs-'+HOST_HASH+'.private.json')
        snapshot_raw=guard.read_member(directory,'policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json')
        guard.require(guard.sha(host_raw)==HOST_HASH and guard.sha(snapshot_raw)==SNAPSHOT_HASH,'RETAINED_POLICY_INPUT_HASH_DRIFT')
        host=guard.decode(host_raw);snapshot=guard.decode(snapshot_raw)
        program=host['executables']['docker'];path=guard.Path('/usr/bin/docker').resolve(strict=True)
        guard.require(str(path)==program['path'],'DOCKER_EXECUTABLE_ROUTE_DRIFT')
        previous=guard.PARENT
        try:
            guard.PARENT=path.parent
            with guard.protected_parent()as executable_parent:
                fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=executable_parent)
                try:
                    info=os.fstat(fd)
                    guard.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022
                        and 0<info.st_size<=64000000,'DOCKER_EXECUTABLE_CUSTODY_UNPROVEN')
                    digest=hashlib.sha256()
                    while chunk:=os.read(fd,65536):digest.update(chunk)
                    guard.require(digest.hexdigest()==program['sha256'] and guard.identity(info)==guard.identity(os.fstat(fd))
                        ==guard.identity(os.stat(path.name,dir_fd=executable_parent,follow_symlinks=False)),'DOCKER_EXECUTABLE_CHANGED')
                finally:os.close(fd)
        finally:guard.PARENT=previous
        value=observe(snapshot,report)
        raw=guard.encoded(value);digest=guard.sha(raw);name='policy-token-client-policies-'+digest+'.private.json'
        report['phase']='PRIVATE_POLICY_METADATA_PUBLICATION'
        try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        except FileExistsError:guard.require(guard.read_member(directory,name)==raw,'POLICY_EVIDENCE_CONFLICT')
        else:
            report['privateEvidenceWrites']=1
            with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
        guard.require(guard.read_member(directory,name)==raw,'POLICY_EVIDENCE_PUBLICATION_UNPROVEN')
        report.update(status='CLIENT_POLICY_METADATA_OBSERVED_NOT_ACCEPTED',phase='OBSERVED_NOT_ACCEPTED',
            privateEvidencePath=str(guard.PARENT/name),privateEvidenceHash=digest)
    code=0
except Exception as error:
    reason=str(error)
    report.update(reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else type(error).__name__,
        evidencePublicationMayBePartial=report['phase']=='PRIVATE_POLICY_METADATA_PUBLICATION')
    if isinstance(error,OSError):report['errno']=error.errno
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
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=POLICY_OBSERVATION_RESULT_UNAVAILABLE; preserve output, no automatic retry')from None

if __name__=='__main__':raise SystemExit(main())
