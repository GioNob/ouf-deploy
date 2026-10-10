#!/usr/bin/env python3
"""Privately copy the selected existing workload credential; no rotation/grants.
Capture main Gateway process identities for later role-owned receipt-key copies.
"""
import hashlib,hmac,importlib.util,json,os,re,subprocess,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read-semantic-workload-client.py'))
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
PROFILE_HASH='05ac25e1dba32460d934865a0e2555ae22890eca7ce56392dfaa98aea7ed8a0b'
IAM_ID='5c3967a7a0cf1a054ba1fec702ddc0b97cf96d1e45bd45d45d27b393f6a1f273'
GATEWAY_IMAGE='sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(v):return hashlib.sha256(encoded(v)).hexdigest()
def require(ok,reason):reader.require(ok,reason)
def stable(v):return {k:v[k] for k in ('Id','Image','Config','HostConfig','Mounts')}|{'networks':v['NetworkSettings']['Networks'],'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')}}
def identity(v):return {'containerId':v['Id'],'imageId':v['Image'],'configurationHash':sha({k:v[k] for k in ('Config','HostConfig','Mounts')}|{'networks':v['NetworkSettings']['Networks']}),'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')}}
def create(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
def worker_identity(raw):
    lines=raw.decode().splitlines();uids=set();gids=set()
    require(len(lines)<=256,'BOUNDED_GATEWAY_PROCESS_LIST_REQUIRED')
    for line in lines[1:]:
        parts=line.split()
        require(len(parts)==4,'EXACT_GATEWAY_PROCESS_METADATA_REQUIRED')
        if parts[3] in ('nginx','openresty'):
            require(all(x.isdecimal() for x in parts[:3]),'NUMERIC_GATEWAY_PROCESS_IDENTITY_REQUIRED')
            uid,gid=map(int,parts[1:3]);uids.add(uid);gids.add(gid)
    candidates=uids-{0};groups=gids-{0}
    require(uids and gids and len(candidates)<=1 and len(groups)<=1,'UNIQUE_GATEWAY_NGINX_IDENTITY_REQUIRED')
    return {'uid':next(iter(candidates)) if candidates else 0,'gid':next(iter(groups)) if groups else 0,'observedNginxUids':sorted(uids),'observedNginxGids':sorted(gids),'hostUserNamespaceTranslationRequired':False}
def main():
    os.umask(0o077)
    report={'schema':'ouf.discovery.semantic-workload-credential-stage.v1','secretRotated':False,'iamConfigurationWrites':0,'workloadTokenGrantRequests':0,'externalProviderCalls':0,'existingConfigurationWrites':0,'containerLifecycleOperations':0,'privateKeyFilesOpened':0,'privateValuesPrinted':False,'roleOwnedRuntimeCredentialInstalled':False,'administrativeLoginAttemptsIssued':0,'iamReadRequests':0,'workloadClientSecretRetrieved':False,'notReleaseAcceptance':True}
    try:
        root=Path(tempfile.mkdtemp(prefix='ouf-semantic-workload-custody-',dir=Path.home()));root.chmod(0o700)
        report['evidenceDirectory']=str(root)
        cli=root/'empty-docker-cli';cli.mkdir(mode=0o700)
        def native(args,stdin=None,parsed=True):
            if '--no-config' in args:
                report['administrativeLoginAttemptsIssued']+=1;report['iamReadRequests']+=1
            p=subprocess.run(['/usr/bin/docker','--config',str(cli),*args],input=stdin,capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            require(p.returncode==0 and len(p.stdout)<=2000000 and len(p.stderr)<=131072,'EXACT_EXISTING_CUSTODY_READ_DENIED')
            if any(type(v) is str and v.endswith('/client-secret') for v in args):report['workloadClientSecretRetrieved']=True
            return json.loads(p.stdout) if parsed else p.stdout
        iam=native(['inspect','--type','container',IAM_ID])[0]
        require(iam['Name']=='/ouf-keycloak' and iam['Image']==reader.IAM_IMAGE and iam['State']['Running'] is True,'EXACT_IAM_GENERATION_REQUIRED')
        argv,password=reader.memory_only_query(IAM_ID,iam['Config']['Env'])
        profile=native(argv,password)
        require(sha(profile)==PROFILE_HASH and reader.project(profile)['profileSupportsConfidentialServiceAccount'] is True,'EXACT_EXISTING_WORKLOAD_PROFILE_REQUIRED')
        resource='clients/'+profile[0]['id']+'/client-secret'
        args=argv.copy();args[args.index('clients')]=resource
        q=args.index('-q');del args[q:q+2];args[args.index('--fields')+1]='value'
        first=native(args,password);second=native(args,password)
        require(set(first)=={'value'} and set(second)=={'value'} and type(first['value']) is str and re.fullmatch('[!-~]{16,1024}',first['value']) and hmac.compare_digest(first['value'],second['value']),'STABLE_BOUNDED_EXISTING_WORKLOAD_CREDENTIAL_REQUIRED')
        require(native(argv,password)==profile,'WORKLOAD_PROFILE_CHANGED_DURING_CREDENTIAL_READ')
        gateway=native(['inspect','--type','container','ouf-apisix'])[0]
        require(gateway['Name']=='/ouf-apisix' and gateway['Image']==GATEWAY_IMAGE and gateway['State']['Running'] is True and gateway['HostConfig'].get('UsernsMode','') in ('','host'),'EXACT_MAIN_GATEWAY_GENERATION_REQUIRED')
        raw=native(['top',gateway['Id'],'-eo','pid,uid,gid,comm'],parsed=False)
        report['observedGatewayProcessNames']=sorted({line.split()[-1] for line in raw.decode().splitlines()[1:] if re.fullmatch('[A-Za-z0-9_.+-]{1,32}',line.split()[-1])})
        worker=worker_identity(raw)
        require(stable(iam)==stable(native(['inspect','--type','container',IAM_ID])[0]) and stable(gateway)==stable(native(['inspect','--type','container',gateway['Id']])[0]),'CUSTODY_GENERATIONS_CHANGED_DURING_READ')
        envelope={'schema':'ouf.discovery.private-semantic-workload-custody.v1','clientId':'ouf-semantic','credential':first['value'],'profileHash':PROFILE_HASH,'profile':profile,'iam':identity(iam),'gateway':identity(gateway),'gatewayWorkerIdentity':worker}
        data=encoded(envelope);create(root/'private-workload-custody.json',data)
        report.update(status='EXISTING_WORKLOAD_CREDENTIAL_STAGED_PRIVATELY_NOT_INSTALLED',evidenceDirectory=str(root),privateEnvelopeSha256=hashlib.sha256(data).hexdigest(),clientId='ouf-semantic',profileHash=PROFILE_HASH,gatewayContainerId=gateway['Id'],gatewayImageId=GATEWAY_IMAGE,gatewayWorkerIdentity=worker,sourceGenerationsUnchanged=True)
        create(root/'receipt.json',encoded(report))
    except Exception as error:
        reason=str(error);report.update(status='WORKLOAD_CUSTODY_STAGE_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'WORKLOAD_CUSTODY_UNPROVEN',errorType=type(error).__name__)
    print('OUF_SEMANTIC_WORKLOAD_CUSTODY_STAGE='+json.dumps(report,sort_keys=True));return 0 if report['status']=='EXISTING_WORKLOAD_CREDENTIAL_STAGED_PRIVATELY_NOT_INSTALLED' else 1
if __name__=='__main__':raise SystemExit(main())
