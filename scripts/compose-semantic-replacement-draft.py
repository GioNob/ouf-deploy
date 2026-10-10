"""Compose a private replacement recipe; no imports, lifecycle, mounts or apply."""
import copy,hashlib,json,os,re,stat,subprocess,tempfile
from pathlib import Path
SEM='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
SOUTH='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
DELTA=Path('/home/oufadmin/ouf-semantic-replacement-config-mkwqooe5/private-configuration-delta.json')
CONFIG_HASH='847b113194ff45eaf96b498cf27224b85ed4d0f8ab6d17413aa7b49909313c65'
INPUTS='/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky'
TRUST='/etc/ouf/deploy-snapshots/semantic-discovery-java-trust-4pgerb71'
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(encoded(v)).hexdigest()
def require(v,reason):
    if not v:raise ValueError(reason)
def env(v):
    rows=v['Config'].get('Env',[]);result={}
    for item in rows:
        k,value=item.split('=',1);require(k not in result,'DUPLICATE_RUNTIME_ENVIRONMENT');result[k]=value
    return result
def stable(v):return {k:v[k] for k in ('Id','Image','Config','HostConfig','Mounts')}|{'networks':v['NetworkSettings']['Networks'],'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')}}
def compose(delta,semantic,mcp,southbound):
    require(sha(delta['candidateConfig'])==CONFIG_HASH and delta['public']['unreviewedEnvironmentOverrideNames']==[] and delta['public']['explicitCommandOrUserOverrideNames']==[],'EXACT_REVIEWED_CONFIGURATION_DELTA_REQUIRED')
    require(stable(delta['retainedContainer'])==stable(semantic) and semantic['Id']==SEM and semantic['State']['Running'] is True and semantic['State']['Pid']==3789123,'CURRENT_PRIMARY_CONFIGURATION_DRIFT')
    incoming=env(semantic);caller=env(mcp);issuer=incoming.get('OUF_IAM_ISSUER','');audience=incoming.get('OUF_IAM_AUDIENCE','');workload=incoming.get('OUF_SEMANTIC_DELEGATION_WORKLOAD','')
    require(re.fullmatch('https://[A-Za-z0-9.-]+(?::[0-9]+)?/realms/[A-Za-z0-9_-]+',issuer) and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',audience) and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',workload),'EXACT_EXISTING_PUBLIC_IAM_BINDINGS_REQUIRED')
    require(mcp['State']['Running'] is True and mcp['Name'] in ('/ouf-mcp','/ouf-mcp-server'),'EXACT_ACTIVE_MCP_SERVICE_REQUIRED')
    require(southbound['Id']==SOUTH and southbound['State']['Running'] is True,'EXACT_ACTIVE_SOUTHBOUND_REQUIRED')
    common=set(semantic['NetworkSettings']['Networks'])&set(southbound['NetworkSettings']['Networks'])
    alias='ouf-semantic-southbound-v2';resolved=[n for n in common if alias in (southbound['NetworkSettings']['Networks'][n].get('Aliases') or [])]
    require(len(resolved)==1,'EXACT_CURRENT_SHARED_PROVIDER_DNS_ALIAS_REQUIRED')
    cfg=copy.deepcopy(delta['candidateConfig']);settings=env({'Config':cfg})
    require(not settings.get('JAVA_TOOL_OPTIONS') and not settings.get('JDK_JAVA_OPTIONS'),'JVM_OPTIONS_REQUIRE_SEPARATE_REVIEW')
    additions={'OUF_SCHEMA_GOV_ENABLED':'true','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED':'true','OUF_SCHEMA_GOV_GATEWAY_BASE_URL':'https://'+alias+':10443','OUF_SCHEMA_GOV_SEARCH_PATH':'/internal/providers/schema-gov/search','OUF_SCHEMA_GOV_FETCH_PATH':'/internal/providers/schema-gov/fetch','OUF_SCHEMA_GOV_TOKEN_ENDPOINT':issuer+'/protocol/openid-connect/token','OUF_SCHEMA_GOV_CLIENT_ID':'ouf-semantic','OUF_SCHEMA_GOV_CLIENT_SECRET_FILE':'/run/secrets/schema-gov-client-secret','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'gateway.southbound.invoke','OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE':'/run/secrets/semantic-discovery-owner.key','OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD':workload,'JAVA_TOOL_OPTIONS':'-Djavax.net.ssl.trustStore=/run/ouf-discovery-trust/java-truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'}
    settings.update(additions);cfg['Env']=[k+'='+settings[k] for k in sorted(settings)]
    retained=delta['public']['retainedAuthMounts'];require(len(retained)==2 and all(v['readOnly'] is True for v in retained),'RETAINED_CONSULTATION_MOUNTS_REQUIRED')
    plan={'schema':'ouf.discovery.private-replacement-configuration-draft.v1','candidateConfig':cfg,'retainedContainer':delta['retainedContainer'],'mcpObservation':stable(mcp),'southboundObservation':stable(southbound),'newReadOnlyMounts':[{'source':INPUTS+'/schema-gov-client-secret','target':additions['OUF_SCHEMA_GOV_CLIENT_SECRET_FILE'],'uid':10001,'gid':10001,'mode':256,'readOnly':True},{'source':INPUTS+'/semantic-discovery-owner.key','target':additions['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE'],'uid':10001,'gid':10001,'mode':256,'readOnly':True},{'source':TRUST+'/java-truststore.p12','target':'/run/ouf-discovery-trust/java-truststore.p12','uid':10001,'gid':10001,'mode':256,'readOnly':True,'sha256':'dcfb221cf3382ab02b752bce3274f64a63c0d822227a5359d1329dee38008079'}],'retainedAuthMounts':retained,'runtimeInputManifestHash':'732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70','privateKeyAndCredentialHashesRequireProtectedManifestRead':True,'providerPathsRequireFrozenBindingRead':True,'completeReplacementOciProven':False,'applyAuthorized':False}
    public={'candidateConfigHash':sha(cfg),'privateDraftHash':sha(plan),'addedEnvironmentNames':sorted(additions),'existingDelegationWorkload':workload,'observedMcpOidcClientId':caller.get('MCP_OIDC_CLIENT_ID','') if re.fullmatch('[A-Za-z0-9_.:-]{1,128}',caller.get('MCP_OIDC_CLIENT_ID','')) else None,'mcpClientIdEqualsExistingDelegationWorkload':caller.get('MCP_OIDC_CLIENT_ID')==workload,'mcpRenewableIdentityBindingsPresent':all(caller.get(k) for k in ('MCP_OIDC_TOKEN_ENDPOINT','MCP_OIDC_CLIENT_ID','MCP_OIDC_CLIENT_SECRET_FILE')),'publicIssuer':issuer,'publicAudience':audience,'providerSharedNetwork':resolved[0],'mcpContainerId':mcp['Id'],'mcpImageId':mcp['Image'],'retainedReadOnlyConsultationMountCount':2,'proposedReadOnlyDiscoveryMountCount':3,'routePathsRequireFrozenBindingRead':True,'completeReplacementOciProven':False,'productionApplyReady':False}
    return plan,public

def read_private(path):
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'PRIVATE_DELTA_ANCESTOR_REQUIRED')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        s=os.fstat(f.fileno());require(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=2097152,'PRIVATE_DELTA_CUSTODY_REQUIRED');raw=f.read(2097153)
        require(len(raw)==s.st_size and os.fstat(f.fileno()).st_mtime_ns==s.st_mtime_ns,'PRIVATE_DELTA_CHANGED');return raw

def main():
    os.umask(0o077);report={'schema':'ouf.discovery.replacement-configuration-composition.v1','containerLifecycleOperations':0,'imageImports':0,'existingConfigurationWrites':0,'privateKeyFilesOpened':0,'privateValuesPrinted':False,'databaseWrites':0,'firewallWrites':0,'providerCalls':0,'iamGrantRequests':0,'commonLockAcquired':False,'r9Touched':False,'mountsInstalled':False,'notReleaseAcceptance':True}
    try:
        root=Path(tempfile.mkdtemp(prefix='ouf-replacement-configuration-draft-',dir=Path.home()));root.chmod(0o700);cli=root/'empty-docker-cli';cli.mkdir(mode=0o700)
        def native(args,parsed=True):
            p=subprocess.run(['/usr/bin/docker','--config',str(cli),*args],capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            require(p.returncode==0 and len(p.stdout)<=2097152 and len(p.stderr)<=131072,'EXACT_RUNTIME_BINDING_METADATA_UNPROVEN');return json.loads(p.stdout) if parsed else p.stdout
        names=native(['container','ls','--format','{{.Names}}'],parsed=False).decode().splitlines()
        selected=[n for n in names if n in ('ouf-mcp','ouf-mcp-server')];require(len(selected)==1,'EXACT_ONE_CURRENT_MAIN_MCP_REQUIRED')
        records=[native(['inspect','--type','container',cid])[0] for cid in (SEM,selected[0],SOUTH)]
        raw=read_private(DELTA);delta=json.loads(raw);plan,public=compose(delta,*records)
        for before in records:require(stable(before)==stable(native(['inspect','--type','container',before['Id']])[0]),'RUNTIME_BINDING_CHANGED_DURING_COMPOSITION')
        require(read_private(DELTA)==raw,'PRIVATE_DELTA_CHANGED_DURING_COMPOSITION')
        file=root/'private-replacement-configuration.json'
        fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(encoded(plan));f.flush();os.fsync(f.fileno())
        report.update(status='PRIVATE_REPLACEMENT_CONFIGURATION_COMPOSED_NOT_APPLY_READY',evidenceDirectory=str(root),privateConfigurationFilesCreated=1,**public)
        (root/'receipt.json').write_bytes(encoded(report))
    except Exception as error:
        reason=str(error);report.update(status='COMPOSITION_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'REPLACEMENT_CONFIGURATION_UNPROVEN',errorType=type(error).__name__)
    print('OUF_REPLACEMENT_CONFIGURATION_DRAFT='+json.dumps(report,sort_keys=True));return 0 if report.get('status')=='PRIVATE_REPLACEMENT_CONFIGURATION_COMPOSED_NOT_APPLY_READY' else 1
if __name__=='__main__':raise SystemExit(main())
