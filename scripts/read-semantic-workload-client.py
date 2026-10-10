#!/usr/bin/env python3
"""Read the exact existing Semantic workload registration; no login/secret/grant."""
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
def main():
    report={'schema':'ouf.discovery.semantic-workload-client-read.v1','secretRetrieved':False,'secretRotated':False,'tokenGrantRequests':0,'iamWrites':0,'containerLifecycleOperations':0,'existingConfigurationWrites':0,'externalProviderCalls':0,'privateKeysRead':0,'privateValuesPrinted':False,'notReleaseAcceptance':True}
    with tempfile.TemporaryDirectory(prefix='ouf-workload-read-cli-') as cli:
        def run(args):
            p=subprocess.run(['/usr/bin/docker','--config',cli,*args],capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            require(p.returncode==0 and len(p.stdout)<=131072,'EXISTING_IAM_READ_SESSION_UNAVAILABLE_OR_RESPONSE_UNBOUNDED')
            return json.loads(p.stdout)
        try:
            before=run(['inspect','--type','container','ouf-keycloak'])[0]
            require(before['Name']=='/ouf-keycloak' and before['Image']==IAM_IMAGE and before['State']['Running'] is True,'EXACT_EXISTING_IAM_GENERATION_REQUIRED')
            cid=before['Id'];require(re.fullmatch('[0-9a-f]{64}',cid),'FULL_IAM_CONTAINER_ID_REQUIRED')
            argv=['exec',cid,'/opt/keycloak/bin/kcadm.sh','get','clients','-r','ouf','-q','clientId='+CLIENT,'--fields',FIELDS]
            rows=run(argv);result=project(rows)
            require(run(argv)==rows,'WORKLOAD_PROFILE_CHANGED_DURING_READ')
            after=run(['inspect','--type','container',cid])[0]
            require(all(before[k]==after[k] for k in ('Id','Image','Config','HostConfig')) and all(before['State'][k]==after['State'][k] for k in ('Pid','StartedAt','Running')),'IAM_GENERATION_CHANGED_DURING_READ')
            report.update(**result,iamReadRequests=2,iamContainerId=cid,iamImageId=IAM_IMAGE,profileHash=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        except Exception as error:
            reason=str(error);report.update(status='WORKLOAD_METADATA_READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'WORKLOAD_METADATA_UNPROVEN',errorType=type(error).__name__)
    print('OUF_SEMANTIC_WORKLOAD_CLIENT_READ='+json.dumps(report,sort_keys=True))
    return 0
if __name__=='__main__':raise SystemExit(main())
