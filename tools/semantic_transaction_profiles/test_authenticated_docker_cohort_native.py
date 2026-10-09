"""Disposable CI only: full-frame/node-v4 peer-bound real Docker cohort.

Independent frozen Engine baseline and offline filesystem; no target authority.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import io
import tarfile

sys.path.insert(0,str(Path.cwd()))
from scripts import semantic_provider_docker_runtime as adapter
from tests.fixtures.semantic_operational_broker_setup import configure
from tests.test_semantic_shared_coordination_native import NativeTest
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_deployment_admission import transport_hash
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_frame_profile_setup import assemble
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "semantic_frame_compiler"))
from compile_creation_frame_policy import compile_policy
from build_role_frame_template import build_role_template
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(ok,reason):
    if not ok:raise RuntimeError(reason)
def private(path,value):
    path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')));path.chmod(0o600)
def main():
    require(os.geteuid()==0,'CI_ROOT_REQUIRED')
    repository=Path.cwd();suffix=uuid.uuid4().hex[:7];bridge='ccb'+suffix
    python=str(Path('/usr/bin/python3').resolve())
    commands={k:str(Path(shutil.which(k)).resolve()) for k in ('ip','nft','nsenter','mount','umount','unshare','runc','openssl','sysctl')}
    def run(*argv,payload=None,check=True,cwd=None):
        with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
            process=subprocess.run(argv,input=payload,stdout=out,stderr=err,timeout=45,cwd=cwd)
            out.seek(0);err.seek(0);result=subprocess.CompletedProcess(argv,process.returncode,out.read(1048577),err.read(1048577))
        require(len(result.stdout)<=1048576 and len(result.stderr)<=1048576,'CI_OUTPUT_UNBOUNDED')
        if check:require(result.returncode==0,'CI_COMMAND_FAILED:'+Path(argv[0]).name+':'+result.stderr.decode()[:1200])
        return result
    engine=Path(os.environ['OUF_DOCKER_WINDOW_ENGINE_DIRECTORY'])
    require(engine.is_absolute(),'EXPLICIT_CI_ENGINE_REQUIRED')
    commands['runc']=str(engine/'runc')
    cids=[];tables=[];processes=[]
    runtime=Path('/run/ouf-docker-cohort-'+suffix);runtime.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='ouf-controlled-cohort-',dir='/root') as temporary:
        root=Path(temporary)
        downloaded_engine=engine;engine=root/'engine';engine.mkdir(mode=0o700)
        for binary in downloaded_engine.iterdir():
            if binary.is_file():
                target=engine/binary.name;shutil.copyfile(binary,target);target.chmod(0o755)
                require(sha(target)==sha(binary),'CI_PINNED_ENGINE_COPY_DRIFT')
        commands['runc']=str(engine/'runc')
        source=root/'source';source.mkdir(mode=0o700)
        registry=root/'registry';registry.mkdir(mode=0o700)
        for name in ('scripts','tools'):
            destination=source/name;destination.mkdir(mode=0o700)
            for path in (repository/name).glob('*.py'):
                shutil.copyfile(path,destination/path.name);(destination/path.name).chmod(0o600)
        # Temporary source-bound CI diagnosis; never target source/authority.
        node_cli=source/'scripts/semantic_provider_node_attestor.py'
        node_raw=node_cli.read_text()
        node_raw=node_raw.replace("    except Exception:\n        print('SEMANTIC_NODE_ATTESTOR",
            "    except Exception as error:\n        import re\n        reason=str(error)\n        if not re.fullmatch('[A-Z0-9_]{1,96}',reason):reason='CI_NODE_OPERATION_UNPROVEN'\n        diagnosis=Path(args.configuration).parent/'ci-node-denial.json'\n        diagnosis.write_text(json.dumps({'reason':reason,'errorClass':type(error).__name__,'secretValuesPrinted':False}));diagnosis.chmod(0o600)\n        print('SEMANTIC_NODE_ATTESTOR")
        node_cli.write_text(node_raw);node_cli.chmod(0o600)
        observation=source/'tools/semantic_provider_node_observation.py'
        observation_raw=observation.read_text().replace('    def add(item):\n        raw=encoded(item)', '    trace=[]\n    def add(item):\n        trace.append(item)\n        raw=encoded(item)')
        observation_raw=observation_raw.replace("    budget.check();return {'schema':'ouf.semantic-rootfs-seal.v1'", "    trace_path=Path(__file__).parent/('ci-rootfs-trace-'+str(os.getpid())+'.json')\n    trace_path.write_bytes(encoded(trace));trace_path.chmod(0o600)\n    budget.check();return {'schema':'ouf.semantic-rootfs-seal.v1'")
        observation.write_text(observation_raw);observation.chmod(0o600)
        wrapper=root/'admission.py';shutil.copyfile(Path(__file__).with_name('ci_frame_profile_broker.py'),wrapper);wrapper.chmod(0o600)
        lock=root/'guard.lock';lock.touch(mode=0o600)
        config_path=root/'adapter.json';cfg={'schema':'ouf.semantic-docker-runtime-adapter.v4',
            'sourceHash':sha(source/'scripts/semantic_provider_docker_runtime.py'),
            'runtimePath':commands['runc'],'runtimeSha256':sha(commands['runc']),
            'pythonPath':python,'pythonSha256':sha(python),
            'driverPath':str(source/'scripts/semantic_provider_preexec_hook.py'),'driverSha256':sha(source/'scripts/semantic_provider_preexec_hook.py'),
            'admissionPath':str(wrapper),'admissionSha256':sha(wrapper),'registryRoot':str(registry),'runtimeStateRoot':'/run','candidates':{}}
        specs=[];policies=[];networks=[];processes=[]
        socket='unix://'+str(root/'docker.sock');daemon=None;containerd=None;network=None;image=None
        bundle_parent=runtime/'containerd-state/io.containerd.runtime.v2.task/moby'
        expected_mount=root/'expected-overlay';expected_mount.mkdir(mode=0o700);mounted=False
        def dock(*args,check=True):return run(str(engine/'docker'),'-H',socket,*args,check=check)
        log=(root/'daemon.log').open('wb')
        try:
            containerd_config=root/'containerd.toml';containerd_config.write_text('version = 2\n')
            containerd=subprocess.Popen([str(engine/'containerd'),'--config',str(containerd_config),
                '--address',str(root/'containerd.sock'),'--root',str(root/'containerd-root'),'--state',str(runtime/'containerd-state')],
                stdout=log,stderr=log,env={**os.environ,'PATH':str(engine)+':/usr/sbin:/usr/bin:/sbin:/bin'})
            deadline=time.monotonic()+15
            while not (root/'containerd.sock').exists():
                require(containerd.poll() is None and time.monotonic()<deadline,'CI_OWNED_CONTAINERD_READINESS_UNPROVEN');time.sleep(.1)
            daemon_path=root/'daemon.json'
            private(daemon_path,{'features':{'containerd-snapshotter':True},'runtimes':{
                'ouf-ci-cohort':{'path':python,'runtimeArgs':['-I','-B',str(source/'scripts/semantic_provider_docker_runtime.py'),'--configuration',str(config_path)]}}})
            private(config_path,cfg)
            daemon=subprocess.Popen([str(engine/'dockerd'),'--config-file',str(daemon_path),
                '--data-root',str(root/'data'),'--exec-root',str(runtime),'--pidfile',str(root/'daemon.pid'),
                '-H',socket,'--containerd',str(root/'containerd.sock'),'--bridge','none','--iptables=false','--ip6tables=false','--storage-driver','overlayfs'],
                stdout=log,stderr=log,env={**os.environ,'PATH':str(engine)+':/usr/sbin:/usr/bin:/sbin:/bin'})
            deadline=time.monotonic()+50
            while dock('info',check=False).returncode:
                require(daemon.poll() is None and time.monotonic()<deadline,'CI_ENGINE_READINESS_UNPROVEN');time.sleep(.1)
            info=json.loads(dock('info','--format','{{json .}}').stdout)
            require(info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs' and info['CgroupDriver']=='systemd','CI_ENGINE_PROFILE_DRIFT')
            # Independently authored archive and expected Docker initlayer tree.
            # No candidate rootfs or observed OCI contributes to this acceptance.
            offline=root/'offline';offline.mkdir(mode=0o755);offline.chmod(0o755)
            for name in ('bin','dev','dev/pts','dev/shm','dev/mqueue','proc','sys','sys/fs','sys/fs/cgroup','etc'):
                (offline/name).mkdir(parents=True,exist_ok=True);(offline/name).chmod(0o755)
            shutil.copyfile(shutil.which('busybox'),offline/'bin/busybox');(offline/'bin/busybox').chmod(0o755)
            (offline/'approved-source').touch(mode=0o644)
            archive=io.BytesIO()
            with tarfile.open(fileobj=archive,mode='w') as tar:
                for path in sorted(offline.rglob('*')):tar.add(path,arcname=str(path.relative_to(offline)),recursive=False)
            image=run(str(engine/'docker'),'-H',socket,'image','import','-',payload=archive.getvalue()).stdout.decode().strip()
            # Exact pinned Moby initlayer semantics: files are unlinked/recreated 0755.
            for name in ('.dockerenv','etc/resolv.conf','etc/hosts','etc/hostname','dev/console'):
                (offline/name).touch(mode=0o755);(offline/name).chmod(0o755)
            (offline/'etc/mtab').symlink_to('/proc/mounts')
            upper=root/'expected-upper';work=root/'expected-work';upper.mkdir();work.mkdir()
            run(commands['mount'],'-t','overlay','overlay','-o','lowerdir='+str(offline)+',upperdir='+str(upper)+',workdir='+str(work),str(expected_mount));mounted=True
            def expected_trace():
                import stat
                def entry(path):
                    st=path.lstat();item={'path':str(path.relative_to(expected_mount)) if path!=expected_mount else '',
                        'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'links':st.st_nlink}
                    if path.is_symlink():item.update(kind='symlink',target=os.readlink(path))
                    else:
                        item['xattrs']={name:os.getxattr(path,name).hex() for name in os.listxattr(path)}
                        if path.is_dir():item['kind']='directory'
                        else:item.update(kind='file',size=st.st_size,sha256=sha(path))
                    return item
                return {value['path']:value for value in [entry(expected_mount),*(entry(path) for path in expected_mount.rglob('*'))]}
            approved_trace=expected_trace()
            seal=rootfs_seal(expected_mount,{'maxEntries':10000,'maxBytes':268435456,'maxDepth':32},VerificationBudget(12))
            network=dock('network','create','--internal','--subnet','198.19.123.0/24','--opt','com.docker.network.bridge.name='+bridge,'ouf-ci-'+suffix).stdout.decode().strip()
            baseline=json.loads(Path(__file__).with_name('containerd-overlayfs-adapter.json').read_bytes())
            for i in range(2):
                approved_source=root/('approved-source-'+str(i));approved_source.write_bytes(b'CI_APPROVED_READ_ONLY_SOURCE');approved_source.chmod(0o600);os.chown(approved_source,10006,10006)
                mac='02:42:c6:1b:00:'+format(i+2,'02x');address='198.19.123.'+str(i+2)
                argv=['/bin/busybox','sh','-c','echo APP > /dev/shm/started; /bin/busybox sleep 60']
                cid=dock('create','--runtime','ouf-ci-cohort','--network',network,'--ip',address,'--mac-address',mac,
                    '--user','10006:10006','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                    '--memory','256m','--memory-swap','256m','--pids-limit','128','--no-healthcheck','--env','PATH=/bin',
                    '--mount','type=bind,source='+str(approved_source)+',target=/approved-source,readonly',image,*argv).stdout.decode().strip();cids.append(cid)
                mount={'source':str(approved_source),'target':'/approved-source','readOnly':True}
                launch={'schema':'ouf.semantic-creation-frame-launch.v1',
                    'manifest':{'user':'10006:10006','readOnlyRoot':True,'memoryBytes':268435456,'pidsLimit':128,'mounts':[mount]},
                    'startup':{'uid':10006,'gid':10006,'umask':None,'cwd':'/','args':argv,'env':['PATH=/bin','HOSTNAME=$OUF_HOSTNAME']},
                    'sources':[{**mount,'uid':10006,'gid':10006,'mode':0o600,'maxBytes':131072,'sha256':sha(approved_source)}]}
                template=build_role_template(baseline['template'],baseline['launch'],launch,baseline['approvedUser'],mount_ordering=baseline['mountOrdering'])
                context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':cid,
                    'bundleParent':str(bundle_parent),
                    'metadataParent':str(root/'data/containers'),'networkNamespaceParent':str(runtime/'netns'),
                    'networkNamespaceName':None,'cgroupDriver':'systemd','rootfsPath':str(root/'data/rootfs/overlayfs'/cid),'storageParent':str(root/'data')}
                policy=compile_policy(template,launch,context);policies.append(policy);specs.append(policy['expectedOci'])
                networks.append([{'interface':'eth0','bridge':bridge,'mac':mac,'ipv4':address,'workloadRef':'ci-role-'+str(i),'bindingRef':'ci-binding-'+str(i)}])
            kernels=[]
            for i in range(2):
                kernel=NativeTest.kernel(None);kernel['tableName']='ccl_'+suffix+str(i)
                kernel['guardedInterfaces']=[bridge];kernel['providerFlows'][0]['source']=networks[i][0]['ipv4']
                kernels.append(kernel)
                networks[i][0]['leaseGuard']={'configurationHash':digest(kernel),'tableName':kernel['tableName']}
            # Both OCI documents, guard scopes and sibling identities predate create.
            declarations=[{'containerId':cids[i],'applicationHash':digest(specs[i]),'networkBindings':networks[i]} for i in range(2)]
            now=int(time.time())
            for i,cid in enumerate(cids):
                directory=registry/cid;directory.mkdir(mode=0o700);(directory/'operation.lock').touch(mode=0o600)
                shared='ccs_'+suffix+str(i);lease='ccl_'+suffix+str(i);tables.extend([shared,lease])
                peer=1-i;flow={'purpose':'GATEWAY_ADAPTER','authorityRef':'ci-infrastructure',
                    'source':networks[0][0]['ipv4'],'destination':networks[1][0]['ipv4'],'protocol':'tcp','port':9443,
                    'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':declarations[peer],'bindingRef':networks[peer][0]['bindingRef']}}
                datum={'authority':True,'startAuthorized':True,'leaseDrift':False,'signatureDrift':False,'rootfsDrift':False,
                    'command':specs[i]['process']['args'],'proof':str(root/'unused-proof'),'ipv4':networks[i][0]['ipv4'],'bridge':bridge,'sharedTable':shared,'leaseTable':lease}
                intent={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':'ci-installer','installationRef':'ci-installation','entityRef':'ci-entity',
                    'containerId':cid,'transactionId':hashlib.sha256(cid.encode()).hexdigest(),'artifactHash':digest(policies[i]),
                    'deploymentConstraintsHash':digest(datum),'transportHash':transport_hash({'networkBindings':networks[i],'transport':[flow],'tableName':shared}),
                    'runtimeExecutableHash':sha(commands['runc']),'issuedAt':now,'expiresAt':now+240,
                    'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
                signatures=directory/'signatures';signatures.mkdir(mode=0o700);keys={};grants=[]
                for ref,issuer,roles in [('installer-key','ci-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('verifier-key','ci-node-verifier',['CREATION_ATTESTATION'])]:
                    key=directory/(ref+'.pem');run(commands['openssl'],'genpkey','-algorithm','ED25519','-out',str(key));key.chmod(0o600)
                    public=run(commands['openssl'],'pkey','-in',str(key),'-pubout','-outform','DER').stdout
                    require(public[:12]==bytes.fromhex('302a300506032b6570032100'),'CI_PUBLIC_KEY_FORMAT')
                    keys[ref]=str(key);grants.append({'keyRef':ref,'issuerRef':issuer,'roles':roles,'publicKey':public[12:].hex(),'notBefore':now-30,'expiresAt':now+300,'state':'ACTIVE'})
                policy=directory/'trust.json';private(policy,{'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':'ci-installation','entityRef':'ci-entity','keys':grants})
                crypto={'policyBinding':{'path':str(policy),'sha256':sha(policy)},'signatureDirectory':str(signatures),
                    'opensslBinding':{'path':commands['openssl'],'sha256':sha(commands['openssl']),'version':run(commands['openssl'],'version').stdout.decode().split()[1]},'privateKeys':keys}
                kernel=kernels[i]
                datum_cfg={'approved':{cid:datum},'intent':intent,'crypto':crypto,'kernel':kernel,'commands':{k:commands[k] for k in ('nft','ip','nsenter','unshare')},
                    'mountCommands':{k:commands[k] for k in ('mount','umount')},'runc':commands['runc'],'runcHash':sha(commands['runc']),
                    'lock':str(lock),'networkBindings':networks[i],'transport':[flow],'busyboxHash':sha(shutil.which('busybox'))}
                broker=configure(directory,datum_cfg,repository,source,python,run,live_authority=True)
                original_node=json.loads((directory/'attestation-producer.json').read_bytes())
                broker,unused=assemble(directory,source,python,crypto,intent,broker,policies[i],original_node,registry,independently_expected_rootfs=seal)
                entry_config=directory/'broker.json'
                cfg['candidates'][cid]={'intentRef':digest(intent),'bundleParents':[str(bundle_parent)],'admissionConfiguration':str(entry_config),'admissionConfigurationHash':sha(entry_config)}
            private(config_path,cfg)
            for cid in cids:private(registry/cid/'adapter.json',{'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':cid,
                'configurationHash':adapter.binding(cfg,cid),'state':'STAGED','runtimeRoot':None,'bundleHash':None,'driverHash':None})
            def start(cid):
                out=tempfile.TemporaryFile();err=tempfile.TemporaryFile()
                process=subprocess.Popen([str(engine/'docker'),'-H',socket,'start',cid],stdin=subprocess.DEVNULL,stdout=out,stderr=err)
                processes.append((process,out,err));return process
            def application_proof(cid):
                journal=json.loads((registry/cid/'adapter.json').read_bytes())
                if not journal.get('runtimeRoot'):return None
                state=run(commands['runc'],'--root',journal['runtimeRoot'],'state',cid,check=False)
                if state.returncode:return None
                pid=json.loads(state.stdout).get('pid',0)
                if pid<=0:return None
                path=Path('/proc')/str(pid)/'root/dev/shm/started'
                return path.read_text().strip() if path.exists() else None
            first=start(cids[0])
            time.sleep(.3)
            if first.poll() is not None:
                processes[0][2].seek(0)
                print('CI_FIRST_REQUEST_FAILED='+json.dumps({'exitCode':first.returncode,'stderr':processes[0][2].read(1600).decode()}))
                require(False,'CI_START_REQUEST_TERMINATED_BEFORE_PEER')
            require(application_proof(cids[0]) is None,'CI_PREMATURE_COHORT_RELEASE')
            second=start(cids[1])
            outcomes=[]
            for process,out,err in processes:
                status=process.wait(timeout=30);err.seek(0)
                outcomes.append((status,err.read(1200).decode()))
            for trace_file in (source/'tools').glob('ci-rootfs-trace-*.json'):
                actual_trace={item['path']:item for item in json.loads(trace_file.read_bytes())}
                diffs=[{'path':path,'expected':approved_trace.get(path),'actual':actual_trace.get(path)} for path in sorted(set(approved_trace)|set(actual_trace)) if approved_trace.get(path)!=actual_trace.get(path)]
                print('CI_OFFLINE_ROOTFS_DIFFERENCES='+json.dumps(diffs[:30]))
            for status,message in outcomes:
                if status:
                    for index,cid in enumerate(cids):
                        for filename in ('ci-broker-denial.json','ci-node-denial.json'):
                            path=registry/cid/filename
                            if path.exists():print('CONTROLLED_COHORT_DIAG='+json.dumps({'candidateIndex':index,**json.loads(path.read_bytes())}))
                        phases={}
                        for filename in ('adapter.json','broker-state.json','deployment.json','admission.json','preexec.json'):
                            path=registry/cid/filename
                            if path.exists():phases[filename]=json.loads(path.read_bytes()).get('state')
                        print('CONTROLLED_COHORT_PHASES='+json.dumps({'candidateIndex':index,'states':phases}))
                        state_result=dock('inspect','--format','{{json .State}}',cid,check=False)
                        if state_result.returncode==0:
                            state=json.loads(state_result.stdout)
                            print('FRAME_PROFILE_RUNTIME_STATE='+json.dumps({'candidateIndex':index,
                                'status':state.get('status'),'pid':state.get('pid')}))
                    print('FRAME_PROFILE_PROCESS_RESULTS='+json.dumps(outcomes))
                require(status==0,'CI_COHORT_ADMISSION_FAILED:'+message)
            require(all(application_proof(cid)=='APP' for cid in cids),'CI_COHORT_APP_PROOF_MISSING')
            for i,cid in enumerate(cids):
                grant=json.loads((registry/cid/'driver.json').read_bytes())
                require(grant['schema']=='ouf.semantic-preexec-driver.v6' and set(grant['peerBinding']['observations'])=={cids[1-i]},'CI_V6_PEER_GRANT_MISSING')
                require(grant['profile']['bundleHash']==digest(specs[i]),'CI_SIGNED_FULL_OCI_DRIFT')
            print('AUTHENTICATED_DOCKER_COHORT=PASS ENGINE_29_8_1=true FULL_OCI_FIXED_BEFORE_CREATE=true INDEPENDENT_OFFLINE_ROOTFS=true NODE_V4=true PEER_BOUND_V6=true TWO_APPLICATION_MARKERS=true CI_KEYS_ONLY=true TARGET_AUTHORITY=false')
        finally:
            for process,out,err in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                out.close();err.close()
            for cid in cids:dock('rm','--force',cid,check=False)
            for table in tables:
                for family in ('inet','bridge'):run(commands['nft'],'delete','table',family,table,check=False)
            if network:dock('network','rm',network,check=False)
            if image:dock('image','rm',image,check=False)
            if daemon is not None and daemon.poll() is None:
                daemon.terminate()
                try:daemon.wait(timeout=20)
                except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=5)
            if containerd is not None and containerd.poll() is None:
                containerd.terminate()
                try:containerd.wait(timeout=15)
                except subprocess.TimeoutExpired:containerd.kill();containerd.wait(timeout=5)
            log.close()
            if mounted:run(commands['umount'],str(expected_mount),check=False)
            shutil.rmtree(runtime,ignore_errors=True)

if __name__=='__main__':main()
