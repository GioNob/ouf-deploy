"""Actual compiled systemd sandbox, sealed runtime, signatures, Docker/DNS/nft.

Disposable CI only. Application admission profiles and installation authority
are synthetic. This is not a target deployment, boot controller or E2E proof.
"""
import dataclasses,errno,hashlib,json,os,re,shutil,socket,stat,struct,subprocess,sys,threading,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import lease_capsule,lease_unit
from tools.m2_discovery_installation_profile import native_generation_probe as native
from tools.m2_discovery_installation_profile.lease_worker import DiscoveryRecovery
from tools.semantic_provider_deployment_authentication import signing_bytes
from tools.materialize_southbound_kernel import materialize
from bounded_recovery import Policy,fingerprint
from recovery_journal import Journal
from nft_seconds_backend import structure_hash


def command(*args,raw=None,check=True):
    p=subprocess.run(list(args),input=raw,capture_output=True,timeout=40)
    if check and p.returncode:raise RuntimeError('CI_COMMAND_FAILED '+str(args[:3])+' '+p.stderr.decode(errors='replace')[-1500:])
    return p.stdout


def create(path,value,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    raw=value if isinstance(value,bytes) else encoded(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    path.chmod(mode)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
    s=Path(path).stat();return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink]


def main():
    assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert command('docker','version','--format','{{.Server.Version}}').strip()==b'29.8.1'
    tag=uuid.uuid4().hex[:8];install=Path('/etc/ouf-lease-ci')/tag;ledger=Path('/var/lib/ouf-lease-ci')/tag
    sandbox=Path(str(install)+'-sandbox');private=Path('/etc/ouf-lease-private-ci')/tag
    fences=Path(str(ledger)+'-fences');kernel=Path(str(ledger)+'-kernel');unit='ouf-lease-sandbox-'+tag+'.service'
    link=Path('/etc/systemd/system')/unit;diagnostic_unit='ouf-lease-diagnostic-'+tag+'.service'
    diagnostic_link=Path('/etc/systemd/system')/diagnostic_unit;ids=[];interface='olci'+tag;table='ouf_ci_'+tag
    nft=str(Path(shutil.which('nft')).resolve());openssl=str(Path(shutil.which('openssl')).resolve())
    python=str(Path(sys.executable).resolve());server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    server.bind(('127.0.0.1',0));port=server.getsockname()[1];control={'queries':0,'ttl':30}
    def dns_server():
        while True:
            try:query,peer=server.recvfrom(4096)
            except OSError:return
            control['queries']+=1;end=12
            while query[end]:end+=query[end]+1
            end+=1;qtype=struct.unpack('!H',query[end:end+2])[0]
            address=socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,
                '1.1.1.1' if qtype==1 else '2606:4700:4700::1111')
            reply=query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:end+4]
            reply+=b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,control['ttl'],len(address))+address
            server.sendto(reply,peer)
    threading.Thread(target=dns_server,daemon=True).start()
    def cli(*args):
        return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=30,
            env={**os.environ,'DOCKER_API_VERSION':'1.44'}).strip()
    def row():return json.loads((ledger/'recovery.json').read_bytes())
    def pid():return int(command('systemctl','show',unit,'--property=MainPID','--value').strip() or b'0')
    def wait_for(predicate,seconds=70):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                value=row()
                if predicate(value):return value
            except FileNotFoundError:pass
            time.sleep(.1)
        print(command('journalctl','-u',unit,'--no-pager','-n','50',check=False).decode(errors='replace'),flush=True)
        raise RuntimeError('CI_COMPILED_LEASE_SANDBOX_TIMEOUT')
    def tables():return {f:json.loads(command(nft,'-j','list','table',f,table)) for f in ('inet','bridge')}
    def sets_empty():
        return not any(item.get('set',{}).get('elem') for family in tables().values() for item in family['nftables'])
    try:
        for directory in (install,ledger,sandbox,private,fences,kernel):directory.mkdir(parents=True,mode=0o700);directory.chmod(0o700)
        (install/'receipt-signatures').mkdir(mode=0o700);(install/'observations').mkdir(mode=0o700)
        create(install/'host-boot-id',b'BIND_TARGET_ONLY')
        cli('pull','alpine:3.22');peers={}
        for role in ('registry','provider'):
            cid=cli('run','-d','--network','bridge','--user','10001:10001','--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','alpine:3.22','sleep','600');ids.append(cid)
            value=json.loads(cli('inspect',cid))[0];ns=Path(value['NetworkSettings']['SandboxKey']).resolve();info=ns.stat()
            peers[role]={'containerId':cid,'imageId':value['Image'],
                'dockerBindingHash':native.digest({k:value[k] for k in native.DOCKER_FIELDS}),
                'pid':value['State']['Pid'],'startedAt':value['State']['StartedAt'],'startTicks':native.ticks(value['State']['Pid']),
                'namespace':{'path':str(ns),'identity':[info.st_dev,info.st_ino]},
                'allowedPausedStates':[False,True] if role=='registry' else [False]}
        sockpath=Path('/var/run/docker.sock').resolve();info=sockpath.stat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.connect(str(sockpath));credentials=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        assert int(command('systemctl','show','ouf-docker-contract-daemon.service','--property=MainPID','--value'))==credentials[0]
        profiles={role:{k:('1' if role=='registry' else '2')*64 for k in
            ('nodeRecipeHash','applicationHash','imageConfigurationHash','rootfsSealHash')} for role in peers}
        snapshot={'schema':'ouf.discovery-lease-generation-observation.v1','desiredProfileHash':'3'*64,
            'nativeProfileHash':native.digest(profiles),'profiles':profiles,
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'engineBinding':{'socketPath':str(sockpath),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],
                'peerCredentials':credentials,'startTicks':native.ticks(credentials[0])},'peers':peers}
        snapshot['generationRef']=native.generation_reference(snapshot);snapshot_sha=native.digest(snapshot)
        create(install/'observations'/(snapshot_sha+'.json'),snapshot)
        cli('pause',peers['registry']['containerId'])
        command('ip','link','add',interface,'type','bridge');command('ip','link','set',interface,'up')
        cfg={'tableName':table,'guardedInterfaces':[interface],'existingInterfaces':[],'staticFlows':[],
            'providerFlows':[{'endpointRef':'ci-'+str(i),'endpoint':'https://'+host+'/approved','source':'10.77.0.'+str(i+2),
                'addresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'synthetic-ci','allowedPrivateAddresses':[]}
                for i,host in enumerate(('provider.example','identity.example'))]}
        command(nft,'-f','-',raw=materialize(cfg,empty_provider_sets=True)['nftRules'].encode())
        expected=structure_hash(tables());binding={'transactionId':sha(tag.encode()),'configurationHash':fingerprint(cfg),
            'leaseStructureHash':expected}
        dns={'resolvers':['127.0.0.1'],'resolverPort':port,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1}
        raw,manifest=lease_capsule.build(ROOT);create(install/'capsule.py',raw,0o400)
        policy=Policy(delays=(1,2),max_attempts=8,max_elapsed=600,attempt_timeout=30,jitter=0)
        scope={'sourceClosureHash':manifest['dependencyClosureHash'],'installationInputsHash':'4'*64,'contextRef':'5'*64,
            'generationRef':snapshot['generationRef'],'policyHash':fingerprint(dataclasses.asdict(policy)),
            'coordinatorBindingHash':fingerprint(binding),'configurationHash':fingerprint(cfg),'dnsProfileHash':fingerprint(dns),
            'leaseStructureHash':expected,'pollSeconds':1,'heartbeatSeconds':1}
        logical=fences/'owner.lock';shared=kernel/'kernel.lock';create(logical,b'');create(shared,b'')
        def program(path):return {'path':path,'sha256':sha(Path(path).read_bytes()),'maximumBytes':67108864}
        py=program(python);nft_ref=program(nft);openssl_ref=program(openssl)
        recipe={'schema':'ouf.discovery-operational-lease-recipe.v1','kernel':cfg,'dns':dns,'binding':binding,
            'policy':json.loads(encoded(dataclasses.asdict(policy))),'scope':scope,'nft':nft_ref,
            'coordinationJournal':str(ledger/'coordination.json'),'leaseCommonLock':str(shared),
            'leaseCommonLockIdentity':identity(shared)}
        create(install/'worker-recipe.json',recipe)
        create(ledger/'coordination.json',{'schema':'ouf.semantic-lease-coordination.v1',**binding,
            'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[],[]]})
        journal=Journal(ledger);recovery=DiscoveryRecovery(journal,None,policy,scope['contextRef'],scope['generationRef'],
            lambda:(time.time(),time.monotonic()),lambda:.5)
        journal.initialize({**recovery.initial(),'discoveryLeaseScopeHash':fingerprint(scope)})
        key=private/'native.pem';command(openssl,'genpkey','-algorithm','ED25519','-out',str(key));key.chmod(0o600)
        create(private/'unrelated-credential',b'SYNTHETIC_CI_PRIVATE_VALUE_NOT_FOR_WORKER')
        public=command(openssl,'pkey','-in',str(key),'-pubout','-outform','DER')[12:].hex();now=int(time.time())
        context={'installationRef':'synthetic-ci-installation','entityRef':'synthetic-ci-entity','attestorRef':'synthetic-ci-attestor'}
        trust={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':context['installationRef'],
            'entityRef':context['entityRef'],'keys':[{'keyRef':'synthetic-ci-key','issuerRef':context['attestorRef'],
                'roles':['CREATION_ATTESTATION'],'publicKey':public,'notBefore':now-30,'expiresAt':now+900,'state':'ACTIVE'}]}
        trust_path=install/'public-trust/policy.json';create(trust_path,trust)
        readonly_probe=install/'readonly-probe';create(readonly_probe,b'SYNTHETIC_CI_READ_ONLY')
        refs=[py,nft_ref,openssl_ref,{'path':str(install/'capsule.py'),'sha256':sha(raw),'maximumBytes':2097152},
            {'path':str(install/'worker-recipe.json'),'sha256':sha(encoded(recipe)),'maximumBytes':1048576},
            {'path':str(readonly_probe),'sha256':sha(readonly_probe.read_bytes()),'maximumBytes':4096}]
        c={'schema':'ouf.discovery-operational-lease-configuration.v1','installationInputsHash':scope['installationInputsHash'],
            'desiredProfileHash':snapshot['desiredProfileHash'],'sourceManifest':manifest,'sources':refs,
            'verification':{'trustPolicy':{'path':str(trust_path),'sha256':sha(encoded(trust))},
                'openssl':{'path':openssl,'sha256':openssl_ref['sha256'],'version':command(openssl,'version').decode().split()[1]},
                'context':context},'serviceUnitPath':str(install/'owner.service'),'serviceUnitHash':'0'*64,
            'commonInvocationLock':str(logical),'commonLockIdentity':identity(logical),
            'generationReceiptPath':str(install/'current-generation.json'),'hostBootIdPath':str(install/'host-boot-id'),
            'ledgerRoot':str(ledger),'scopePolicyHash':scope['policyHash']}
        compiled=lease_unit.compile_unit(c,recipe,snapshot,py,installation_root=str(install),
            signing_key_paths=[str(key),str(private/'unrelated-credential')],engine_unit='ouf-docker-contract-daemon.service')
        c['serviceUnitHash']=compiled['unitSha256']
        assert lease_unit.compile_unit(c,recipe,snapshot,py,installation_root=str(install),
            signing_key_paths=[str(key)],engine_unit='ouf-docker-contract-daemon.service')['unitBody']==compiled['unitBody']
        create(install/'owner.service',compiled['unitBody'].encode(),0o644);create(install/'configuration.json',c)
        def sign(value):
            raw=encoded(value);header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
                'keyRef':'synthetic-ci-key','role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],
                'installationRef':context['installationRef'],'entityRef':context['entityRef'],'payloadHash':sha(raw)}
            frame=private/(sha(raw)+'.frame');create(frame,signing_bytes(raw,header))
            signature=command(openssl,'pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(frame))
            create(install/'receipt-signatures'/(sha(raw)+'.CREATION_ATTESTATION.json'),{**header,'signature':signature.hex()})
            return value
        create(install/'installed.json',sign({'schema':'ouf.discovery-operational-lease-installation-receipt.v1','complete':True,
            'configurationHash':native.digest(c),'installationInputsHash':c['installationInputsHash'],
            'desiredProfileHash':c['desiredProfileHash'],'sourceManifestHash':native.digest(manifest),
            'serviceUnitHash':c['serviceUnitHash'],'scopePolicyHash':c['scopePolicyHash'],
            'finiteApprovalAuthorizesInstallationOnly':True,
            'operationalLifetime':'UNTIL_DISABLE_CUSTODY_OR_INSTALLATION_TRUST_REVOCATION',
            'runtimeSigningKeyAccessAllowed':False,'containerLifecycleOperationsAllowed':False}))
        generation={'schema':'ouf.discovery-operational-lease-generation-receipt.v1','configurationHash':native.digest(c),
            'desiredProfileHash':c['desiredProfileHash'],'scopePolicyHash':c['scopePolicyHash'],'scopeHash':fingerprint(scope),
            'generationRef':scope['generationRef'],'bootId':snapshot['bootId'],'nativeObservationHash':snapshot_sha,
            'nativeProfileHash':snapshot['nativeProfileHash'],'ledgerRoot':str(ledger),
            'state':'NATIVE_GENERATION_ADMITTED','containerStartAuthorized':False}
        create(install/'current-generation.json',sign(generation));link.symlink_to(install/'owner.service')
        # CI-only diagnosis uses the identical namespace/capability settings.
        # Neither this helper nor its manager entry is exported for deployment.
        batch='\n'.join('flush set '+f+' '+table+' provider_'+str(i) for f in ('inet','bridge') for i in range(2))+'\n'
        diagnostic='''import json,os,subprocess,tempfile
nft=__NFT__
batch=__BATCH__
def run(args,raw=None):
 p=subprocess.run([nft]+args,input=raw,capture_output=True,text=True,timeout=5)
 return {'returncode':p.returncode,'stderr':p.stderr[:1500]}
stdin=run(['-f','-'],batch)
with tempfile.TemporaryDirectory(prefix='ouf-ci-nft-input-') as d:
 p=d+'/transaction.nft'
 with open(p,'w') as f:f.write(batch)
 os.chmod(p,0o600)
 file=run(['-f',p])
print('CI_SANDBOX_NFT_DIAGNOSTIC='+json.dumps({'stdin':stdin,'privateFile':file,'devStdinExists':os.path.exists('/dev/stdin')},sort_keys=True),flush=True)
'''.replace('__NFT__',repr(nft)).replace('__BATCH__',repr(batch))
        create(install/'diagnostic.py',diagnostic.encode(),0o400)
        diagnostic_body='\n'.join(('Type=oneshot' if line=='Type=simple' else 'Restart=no' if line.startswith('Restart=')
            else 'ExecStart=:'+python+' -I -B -S '+str(install/'diagnostic.py') if line.startswith('ExecStart=') else line)
            for line in compiled['unitBody'].split('\n'))
        create(install/'diagnostic.service',diagnostic_body.encode(),0o644)
        diagnostic_link.symlink_to(install/'diagnostic.service');command('systemctl','daemon-reload')
        command('systemctl','start',diagnostic_unit)
        print(command('journalctl','-u',diagnostic_unit,'--no-pager','-n','8').decode(),flush=True)
        command('systemctl','daemon-reload');command('systemctl','start',unit)
        first=wait_for(lambda v:v['state']=='ACTIVE' and v['publicationCount']>=2);first_pid=pid();assert first_pid>1
        view=Path('/proc')/str(first_pid)/'root'
        process={k:v.strip() for k,v in (line.split(':',1) for line in (Path('/proc')/str(first_pid)/'status').read_text().splitlines() if ':' in line)}
        assert all(int(process[k],16)==1<<12 for k in ('CapEff','CapPrm','CapBnd','CapAmb')) and process['NoNewPrivs']=='1'
        assert sorted(v.name for v in (view/'proc').iterdir())==sorted(str(p) for p in
            [credentials[0],peers['registry']['pid'],peers['provider']['pid']])
        for p in (view/'proc').iterdir():assert [v.name for v in p.iterdir()]==['stat']
        assert not (view/str(key).lstrip('/')).exists() and not (view/str(private/'unrelated-credential').lstrip('/')).exists()
        assert not (view/'bin/sh').exists() and not (view/'usr/bin/docker').exists()
        try:
            with (view/str(readonly_probe).lstrip('/')).open('ab') as stream:stream.write(b'FORBIDDEN')
            raise AssertionError('READ_ONLY_CONTROL_BIND_WRITABLE')
        except OSError as error:assert error.errno==errno.EROFS
        cli('unpause',peers['registry']['containerId']);wait_for(lambda v:v['publicationCount']>first['publicationCount'])
        before=row();command('systemctl','kill','--signal=KILL','--kill-who=main',unit)
        recovered=wait_for(lambda v:pid() not in (0,first_pid) and v['state']=='ACTIVE'
            and v['attempts']>before['attempts'] and v['reentryCount']>before['reentryCount'])
        assert recovered['publicationCount']>=before['publicationCount'] and recovered['startedWall']==first['startedWall']
        second_pid=pid();command('systemctl','stop',unit);stopped=row()
        assert stopped['state']=='NEW' and stopped['reason']=='DISCOVERY_MANAGER_STOP_QUIESCENT' and sets_empty()
        assert stopped['attempts']==recovered['attempts'] and stopped['publicationCount']>=recovered['publicationCount']
        command('systemctl','start',unit)
        restarted=wait_for(lambda v:pid() not in (0,second_pid) and v['state']=='ACTIVE' and v['attempts']>stopped['attempts'])
        assert restarted['startedWall']==first['startedWall'] and restarted['publicationCount']>=stopped['publicationCount']
        replacement=trust_path.with_suffix('.replacement');create(replacement,b'SYNTHETIC_REVOKED_PUBLIC_POLICY');os.replace(replacement,trust_path)
        blocked=wait_for(lambda v:v['state']=='BLOCKED');assert sets_empty();queries=control['queries'];time.sleep(1.5)
        assert control['queries']==queries and pid()>1
        create(replacement,trust);os.replace(replacement,trust_path);time.sleep(1.5)
        assert row()['state']=='BLOCKED' and control['queries']==queries
        current_pid=pid();logical.rename(logical.with_suffix('.preserved'));create(logical,b'')
        visible=Path('/proc')/str(current_pid)/'root'/str(logical).lstrip('/')
        assert visible.stat().st_ino==logical.stat().st_ino and identity(visible)!=c['commonLockIdentity']
        cli('stop','--time','1',peers['provider']['containerId'])
        try:native.NativeLeaseGenerationProbe(install/'observations')(generation);raise AssertionError('STOPPED_PROVIDER_ACCEPTED')
        except (ValueError,OSError):pass
        command('systemctl','stop',unit);assert row()['state']=='BLOCKED' and row()['attempts']==blocked['attempts']
        print(json.dumps({'schema':'ouf.m2-discovery-lease-sandbox-native-ci.v1','dockerVersion':'29.8.1',
            'actualCompiledUnitAndClosedCapsule':True,'actualInstalledAndGenerationEd25519Signatures':True,
            'actualDockerPeers':2,'onlyCapNetAdminAndNoNewPrivileges':True,'onlyThreePidStatFilesVisible':True,
            'signingKeyUnrelatedCredentialShellAndDockerCliHidden':True,'readOnlyControlBindingsEnforced':True,
            'atomicTrustRevocationObserved':True,'atomicLogicalFenceReplacementVisible':True,
            'sameGenerationPausedToRunningAccepted':True,'sigkillReentryAndOrderlyManagerRestartQualified':True,
            'attemptsPublicationsStartedTimeAndHistoryPreserved':True,'blockedRemainsAliveNoQueriesAndNoAutomaticRearm':True,
            'actualDnsAndNft':True,'sourceModuleCount':len(manifest['sourceHashes']),
            'applicationAdmissionAndAuthorityFixturesSynthetic':True,'bootOrRotationQualified':False,
            'targetActions':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False,
            'releaseAcceptance':False},sort_keys=True),flush=True)
    finally:
        command('systemctl','stop',unit,check=False);command('systemctl','stop',diagnostic_unit,check=False)
        link.unlink(missing_ok=True);diagnostic_link.unlink(missing_ok=True)
        command('systemctl','daemon-reload',check=False);command('systemctl','reset-failed',unit,check=False)
        for family in ('inet','bridge'):command(nft,'delete','table',family,table,check=False)
        command('ip','link','delete',interface,check=False)
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
        server.close()
        for directory in (install,ledger,sandbox,private,fences,kernel):shutil.rmtree(directory,ignore_errors=True)

if __name__=='__main__':main()
