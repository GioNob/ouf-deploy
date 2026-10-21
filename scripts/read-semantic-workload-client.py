#!/usr/bin/env python3
"""Read existing workload registration; optional memory-only local admin login.
No client secret retrieval, saved login file, registration or grant mutation.
"""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
IAM_IMAGE='sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c'
CLIENT='ouf-semantic'
FIELDS='id,clientId,enabled,publicClient,serviceAccountsEnabled,clientAuthenticatorType,directAccessGrantsEnabled,standardFlowEnabled,fullScopeAllowed,protocol,defaultClientScopes,optionalClientScopes'
def require(ok,reason):
    if not ok:raise ValueError(reason)
def project(rows):
    require(type(rows) is list and len(rows)<=1,'EXACT_WORKLOAD_CLIENT_SELECTION_REQUIRED')
    if not rows:return {'status':'SELECTED_WORKLOAD_CLIENT_ABSENT','clientId':CLIENT,'registrationChanged':False}
    row=rows[0];require(row.get('clientId')==CLIENT and re.fullmatch('[A-Za-z0-9-]{1,128}',row.get('id','')),'EXACT_WORKLOAD_CLIENT_REQUIRED')
    result={k:row.get(k) for k in ('clientId','enabled','publicClient','serviceAccountsEnabled','clientAuthenticatorType','directAccessGrantsEnabled','standardFlowEnabled','fullScopeAllowed','protocol','defaultClientScopes','optionalClientScopes')}
    result.update(status='EXISTING_WORKLOAD_CLIENT_METADATA_CAPTURED',profileSupportsConfidentialServiceAccount=(row.get('enabled') is True and row.get('publicClient') is False and row.get('serviceAccountsEnabled') is True and row.get('clientAuthenticatorType')=='client-secret'),credentialCustodyProven=False,actualTokenAdmissionProven=False,registrationChanged=False)
    return result
def memory_only_query(cid,env):
    values={}
    for row in env:
        key,value=row.split('=',1);require(key not in values,'UNIQUE_IAM_ENVIRONMENT_REQUIRED');values[key]=value
    selected=[(values.get(u),values.get(p)) for u,p in (('KC_BOOTSTRAP_ADMIN_USERNAME','KC_BOOTSTRAP_ADMIN_PASSWORD'),('KEYCLOAK_ADMIN','KEYCLOAK_ADMIN_PASSWORD')) if values.get(u) and values.get(p)]
    require(len(selected)==1,'EXACT_EXISTING_LOCAL_ADMIN_CREDENTIAL_REQUIRED')
    user,password=selected[0]
    require(re.fullmatch('[A-Za-z0-9_.@-]{1,128}',user) and len(password)<=4096 and '\n' not in password and '\r' not in password,'BOUNDED_LOCAL_ADMIN_CREDENTIAL_REQUIRED')
    wrapper='IFS= read -r KC_CLI_PASSWORD || exit 2; export KC_CLI_PASSWORD; exec /opt/keycloak/bin/kcadm.sh "$@"'
    args=['exec','-i',cid,'/bin/bash','-c',wrapper,'ouf-read-only-client','get','clients','--no-config','--server','http://127.0.0.1:8080','--realm','master','--user',user,'-r','ouf','-q','clientId='+CLIENT,'--fields',FIELDS]
    return args,(password+'\n').encode()
def main():
    report={'schema':'ouf.discovery.semantic-workload-client-read.v1','workloadClientSecretRetrieved':False,'secretRotated':False,'workloadTokenGrantRequests':0,'iamConfigurationWrites':0,'containerLifecycleOperations':0,'existingConfigurationWrites':0,'externalProviderCalls':0,'privateKeysRead':0,'privateValuesPrinted':False,'savedAuthenticationFiles':0,'administrativeLoginAttemptsIssued':0,'notReleaseAcceptance':True}
    with tempfile.TemporaryDirectory(prefix='ouf-workload-read-cli-') as cli:
        def run(args,input_bytes=None):
            p=subprocess.run(['/usr/bin/docker','--config',cli,*args],input=input_bytes,capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            require(len(p.stdout)<=131072 and len(p.stderr)<=131072,'IAM_RESPONSE_UNBOUNDED')
            if p.returncode:
                report['nativeFailure']={'exitCode':p.returncode,'stdoutBytes':len(p.stdout),'stderrBytes':len(p.stderr),'stderrSha256':hashlib.sha256(p.stderr).hexdigest()}
                raise ValueError('EXISTING_IAM_READ_SESSION_UNAVAILABLE_OR_COMMAND_DENIED')
            return json.loads(p.stdout)
        try:
            before=run(['inspect','--type','container','ouf-keycloak'])[0]
            require(before['Name']=='/ouf-keycloak' and before['Image']==IAM_IMAGE and before['State']['Running'] is True,'EXACT_EXISTING_IAM_GENERATION_REQUIRED')
            cid=before['Id'];require(re.fullmatch('[0-9a-f]{64}',cid),'FULL_IAM_CONTAINER_ID_REQUIRED')
            argv=['exec',cid,'/opt/keycloak/bin/kcadm.sh','get','clients','-r','ouf','-q','clientId='+CLIENT,'--fields',FIELDS]
            memory_auth=None
            try:rows=run(argv)
            except ValueError as error:
                if str(error)!='EXISTING_IAM_READ_SESSION_UNAVAILABLE_OR_COMMAND_DENIED':raise
                argv,memory_auth=memory_only_query(cid,before['Config'].get('Env',[]))
                report.update(administrativeCredentialReadFromExistingEnvironment=True,authenticationMode='LOCAL_LOOPBACK_MEMORY_ONLY_NO_CONFIG')
                report['administrativeLoginAttemptsIssued']+=1;rows=run(argv,memory_auth)
            result=project(rows)
            if memory_auth is not None:report['administrativeLoginAttemptsIssued']+=1
            require(run(argv,memory_auth)==rows,'WORKLOAD_PROFILE_CHANGED_DURING_READ')
            after=run(['inspect','--type','container',cid])[0]
            require(all(before[k]==after[k] for k in ('Id','Image','Config','HostConfig')) and all(before['State'][k]==after['State'][k] for k in ('Pid','StartedAt','Running')),'IAM_GENERATION_CHANGED_DURING_READ')
            report.update(**result,iamReadRequests=2,iamContainerId=cid,iamImageId=IAM_IMAGE,profileHash=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        except Exception as error:
            reason=str(error);report.update(status='WORKLOAD_METADATA_READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'WORKLOAD_METADATA_UNPROVEN',errorType=type(error).__name__)
    print('OUF_SEMANTIC_WORKLOAD_CLIENT_READ='+json.dumps(report,sort_keys=True))
    return 0
if __name__=='__main__':raise SystemExit(main())
