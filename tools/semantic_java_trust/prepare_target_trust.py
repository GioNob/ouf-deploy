"""One-use Java public trust preparation only; no application/lease cutover.
Uses an isolated existing Java21 image for keytool, never imports an image.
"""
import hashlib,json,os,pwd,re,subprocess,sys,tempfile,types
from pathlib import Path
INPUTS=Path('/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky')
MANIFEST_HASH='732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70'
BASELINE=Path('/home/oufadmin/ouf-candidate-public-roots-c4wog2c0/candidate-cacerts')
BASELINE_HASH='98d34a90fca2688ef5674862d2a484e09e5ca25d2f07c5d654aa28f1581f3419'
CLAIM=Path('/etc/ouf/semantic-discovery-java-trust-20261010.claim')
HASHES={'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf','reader':'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf','merge':'e65e009b3c5daac722248d7793fea73cbfef50d2cd3f6da5f1a6e2c82f91a78b'}
def load(name):
    raw=globals().get('__sources__',{}).get(name)
    if type(raw) is not bytes or len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=HASHES[name]:raise ValueError('SEALED_JAVA_TRUST_SOURCE_REQUIRED')
    m=types.ModuleType('sealed_'+name);m.__file__='sealed-'+name;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def isolated_merge(native,merge,root,image,report):
    """Only the new uniquely named offline tool container may be removed."""
    tool=None
    try:
        name='ouf-java-public-trust-'+root.name.rsplit('-',1)[1]
        report['toolContainerLifecycleOperations']+=1
        raw=native(['run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','512m','--user','0:0','--mount','type=bind,source='+str(root)+',target='+str(root),'--tmpfs','/tmp:rw,noexec,nosuid,size=67108864','--entrypoint','/bin/sh',image,'-c','exec sleep 300'])
        candidate=raw.decode().strip()
        if not re.fullmatch('[a-f0-9]{64}',candidate):raise ValueError('EXACT_NEW_JAVA_TOOL_CONTAINER_REQUIRED')
        tool=candidate
        facts=json.loads(native(['inspect','--type','container',tool]))[0];host=facts['HostConfig']
        if not (facts['Image']==image and facts['Name']=='/'+name and host['NetworkMode']=='none' and host['ReadonlyRootfs'] is True and host['Privileged'] is False and host['CapDrop']==['ALL'] and 'no-new-privileges:true' in host['SecurityOpt'] and facts['Config']['User']=='0:0'):raise ValueError('JAVA_TOOL_ISOLATION_UNPROVEN')
        original=merge.run
        try:
            merge.run=lambda keytool,args:native(['exec',tool,str(keytool),'-J-Duser.language=en','-J-Duser.country=US',*args],include_stderr=True)
            return merge.merge('/opt/java/openjdk/bin/keytool',root/'candidate-cacerts',root/'provider-public-ca.crt',root/'java-truststore.p12')
        finally:merge.run=original
    finally:
        if tool:
            report['toolContainerLifecycleOperations']+=1;native(['rm','-f',tool])
            if native(['ps','-a','--filter','id='+tool,'--format','{{.ID}}']).strip():raise ValueError('JAVA_TOOL_CLEANUP_UNPROVEN')
            report['toolContainerCleanupProven']=True

def main():
    report={'schema':'ouf.discovery.java-trust-preparation.v1','existingConfigurationWrites':0,'applicationContainerLifecycleOperations':0,'toolContainerLifecycleOperations':0,'toolContainerCleanupProven':False,'imageImports':0,'databaseWrites':0,'firewallWrites':0,'iamConfigurationWrites':0,'workloadTokenGrantRequests':0,'privateKeyFilesOpened':0,'installationAuthorityKeysRead':0,'deploymentSignaturesIssued':0,'commonLockAcquired':False,'r9Touched':False,'mountsInstalled':False,'applicationCutoverAuthorized':False,'applicationHealthProven':False,'notReleaseAcceptance':True,'privateValuesPrinted':False}
    root=None;tool=None;native=None;custody=None
    try:
        if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode or len(sys.argv)!=1:raise ValueError('EXACT_ISOLATED_ROOT_JAVA_TRUST_REQUIRED')
        custody,reader,merge=load('custody'),load('reader'),load('merge')
        custody.require(not os.path.lexists(CLAIM),'JAVA_TRUST_ALREADY_CLAIMED_DO_NOT_REPLAY')
        manifest_raw=custody.file_bytes(INPUTS/'private-input-manifest.json',0,{0o600},expected=MANIFEST_HASH);manifest=reader.parse(manifest_raw)
        receipt=reader.parse(custody.file_bytes(INPUTS/'receipt.json',0,{0o600}))
        old_claim=reader.parse(custody.file_bytes(custody.CLAIM,0,{0o600}))
        custody.require(receipt['status']=='ROOT_RUNTIME_INPUTS_PREPARED_NOT_MOUNTED' and receipt['privateManifestHash']==MANIFEST_HASH and old_claim['directory']==str(INPUTS) and manifest['mountsInstalled'] is False,'CONSUMED_INPUT_CUSTODY_REQUIRED')
        ca=custody.file_bytes(INPUTS/'provider-public-ca.crt',0,{0o600},65536,manifest['publicCaHash']);merge.certificates(ca)
        user=pwd.getpwnam('oufadmin').pw_uid;baseline=custody.file_bytes(BASELINE,user,{0o600},expected=BASELINE_HASH)
        approval=reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'));cfg=reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json',approval['configurationHash']))
        custody.require(approval['approvalRef']==reader.APPROVAL and cfg['outputRoot']==str(reader.OUTPUT),'EXACT_ROOT_COMMAND_CUSTODY_REQUIRED')
        binding=cfg['commandBindings']['docker'];reader.private(binding['path'],binding['sha256'],executable=True)
        cli=reader.OUTPUT/'activation-docker-cli';st=cli.lstat();custody.require(st.st_uid==0 and (st.st_mode&0o777)==0o700 and not os.path.lexists(cli/'config.json'),'EXISTING_EMPTY_ROOT_DOCKER_CLI_REQUIRED')
        def native(args,timeout=30,include_stderr=False):
            reader.private(binding['path'],binding['sha256'],executable=True)
            p=subprocess.run([binding['path'],'--config',str(cli),*args],capture_output=True,timeout=timeout,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            custody.require(p.returncode==0 and len(p.stdout)<=2097152 and len(p.stderr)<=131072,'ISOLATED_JAVA_TOOL_OPERATION_UNPROVEN')
            reader.private(binding['path'],binding['sha256'],executable=True);return p.stdout+(p.stderr if include_stderr else b'')
        primary=reader.parse(native(['inspect','--type','container',custody.SEMANTIC]))[0]
        custody.require(primary['Image']==custody.SEMANTIC_IMAGE and primary['State']['Running'] is True and primary['State']['Pid']==3789123,'UNCHANGED_PRIMARY_REQUIRED')
        root=Path(tempfile.mkdtemp(prefix='semantic-discovery-java-trust-',dir=custody.BASE));root.chmod(0o700)
        custody.create(CLAIM,custody.encoded({'schema':'ouf.discovery.java-trust-claim.v1','directory':str(root),'runtimeInputManifestHash':MANIFEST_HASH,'baselineHash':BASELINE_HASH,'applicationCutoverAuthorized':False}))
        custody.create(root/'candidate-cacerts',baseline);custody.create(root/'provider-public-ca.crt',ca)
        result=isolated_merge(native,merge,root,custody.SEMANTIC_IMAGE,report)
        custody.require(custody.identity(reader.parse(native(['inspect','--type','container',custody.SEMANTIC]))[0])==custody.identity(primary),'PRIMARY_CHANGED_DURING_TRUST_PREPARATION')
        custody.require(custody.file_bytes(INPUTS/'private-input-manifest.json',0,{0o600},expected=MANIFEST_HASH)==manifest_raw and custody.file_bytes(BASELINE,user,{0o600},expected=BASELINE_HASH)==baseline and custody.file_bytes(INPUTS/'provider-public-ca.crt',0,{0o600},65536,manifest['publicCaHash'])==ca,'JAVA_TRUST_INPUT_CHANGED')
        os.chown(root/'java-truststore.p12',10001,10001);(root/'java-truststore.p12').chmod(0o400)
        custody.file_bytes(root/'java-truststore.p12',10001,{0o400},expected=result['truststoreHash'])
        report.update(status='CANDIDATE_PUBLIC_JAVA_TRUST_PREPARED_NOT_MOUNTED',evidenceDirectory=str(root),runtimeInputManifestHash=MANIFEST_HASH,candidateImageId='sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b',keytoolImageId=custody.SEMANTIC_IMAGE,semanticUid=10001,doNotRerunApply=True,**result)
        custody.create(root/'receipt.json',custody.encoded(report));code=0
    except Exception as error:
        if tool and native:
            try:report['toolContainerLifecycleOperations']+=1;native(['rm','-f',tool]);report['toolContainerCleanupProven']=True
            except Exception:pass
        reason=str(error);report.update(status='JAVA_TRUST_PREPARATION_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'JAVA_TRUST_PREPARATION_UNPROVEN',errorType=type(error).__name__,evidenceDirectory=str(root) if root else None,doNotRerunApply=os.path.lexists(CLAIM));code=1
    print('OUF_APPLICATION_JAVA_TRUST='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
