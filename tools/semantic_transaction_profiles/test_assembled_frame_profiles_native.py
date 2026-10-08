"""CI-only two-peer node-v4 admission using the new profile assembler.

Both complete synthetic OCI documents are fixed before create. Ephemeral CI
keys/Busybox acceptance are not target authority or target image acceptance.
No Docker daemon configuration is changed by this fixture.
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

sys.path.insert(0,str(Path.cwd()))
from scripts import semantic_provider_docker_runtime as adapter
from tests.fixtures.semantic_operational_broker_setup import configure
from tests.test_semantic_shared_coordination_native import NativeTest
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_deployment_admission import transport_hash
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_frame_profile_setup import frame, assemble

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
    cids=[hashlib.sha256((suffix+str(i)).encode()).hexdigest() for i in range(2)]
    namespaces=['ccn'+str(i)+suffix for i in range(2)];hosts=[];tables=[];children=[];created=[]
    runtime=Path('/run/ouf-cohort-'+suffix);runtime.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='ouf-controlled-cohort-',dir='/root') as temporary:
        root=Path(temporary);source=root/'source';source.mkdir(mode=0o700)
        registry=root/'registry';registry.mkdir(mode=0o700);inputs=root/'inputs';inputs.mkdir(mode=0o700)
        for name in ('scripts','tools'):
            destination=source/name;destination.mkdir(mode=0o700)
            for path in (repository/name).glob('*.py'):
                shutil.copyfile(path,destination/path.name);(destination/path.name).chmod(0o600)
        wrapper=root/'admission.py';shutil.copyfile(Path(__file__).with_name('ci_frame_profile_broker.py'),wrapper);wrapper.chmod(0o600)
        lock=root/'guard.lock';lock.touch(mode=0o600)
        config_path=root/'adapter.json';cfg={'schema':'ouf.semantic-docker-runtime-adapter.v4',
            'sourceHash':sha(source/'scripts/semantic_provider_docker_runtime.py'),
            'runtimePath':commands['runc'],'runtimeSha256':sha(commands['runc']),
            'pythonPath':python,'pythonSha256':sha(python),
            'driverPath':str(source/'scripts/semantic_provider_preexec_hook.py'),'driverSha256':sha(source/'scripts/semantic_provider_preexec_hook.py'),
            'admissionPath':str(wrapper),'admissionSha256':sha(wrapper),'registryRoot':str(registry),'runtimeStateRoot':'/run','candidates':{}}
        specs=[];policies=[];networks=[];proofs=[];processes=[]
        try:
            run(commands['ip'],'link','add',bridge,'type','bridge');run(commands['ip'],'link','set',bridge,'up')
            for i,cid in enumerate(cids):
                namespace=namespaces[i];run(commands['ip'],'netns','add',namespace)
                for option in ('net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'):
                    run(commands['ip'],'netns','exec',namespace,commands['sysctl'],'-q','-w',option)
                host='cch'+str(i)+suffix;child='ccc'+str(i)+suffix;hosts.append(host)
                run(commands['ip'],'link','add',host,'type','veth','peer','name',child)
                run(commands['ip'],'link','set',host,'master',bridge);run(commands['ip'],'link','set',host,'up')
                run(commands['ip'],'link','set',child,'netns',namespace)
                run(commands['ip'],'-n',namespace,'link','set',child,'name','eth0')
                mac='02:42:c6:1b:00:'+format(i+2,'02x');address='198.19.123.'+str(i+2)
                run(commands['ip'],'-n',namespace,'link','set','eth0','address',mac)
                run(commands['ip'],'-n',namespace,'addr','add',address+'/24','dev','eth0')
                run(commands['ip'],'-n',namespace,'link','set','eth0','up');run(commands['ip'],'-n',namespace,'link','set','lo','up')
                networks.append([{'interface':'eth0','bridge':bridge,'mac':mac,'ipv4':address,'workloadRef':'ci-role-'+str(i),'bindingRef':'ci-binding-'+str(i)}])
                input_bundle=inputs/cid;input_bundle.mkdir(mode=0o700)
                rootfs=root/('rootfs'+str(i));(rootfs/'bin').mkdir(parents=True);(rootfs/'proof').mkdir()
                shutil.copyfile(shutil.which('busybox'),rootfs/'bin/busybox');(rootfs/'bin/busybox').chmod(0o755)
                proof=root/('proof'+str(i));proof.mkdir(mode=0o777);proof.chmod(0o777);proofs.append(proof)
                spec,frame_policy=frame(root,rootfs,cid,i,namespace)
                policies.append(frame_policy)
                private(input_bundle/'config.json',spec);specs.append(spec)
            # Both OCI documents and complete sibling identities predate create.
            declarations=[{'containerId':cids[i],'applicationHash':digest(specs[i]),'networkBindings':networks[i]} for i in range(2)]
            now=int(time.time())
            for i,cid in enumerate(cids):
                directory=registry/cid;directory.mkdir(mode=0o700);(directory/'operation.lock').touch(mode=0o600)
                shared='ccs_'+suffix+str(i);lease='ccl_'+suffix+str(i);tables.extend([shared,lease])
                peer=1-i;flow={'purpose':'GATEWAY_ADAPTER','authorityRef':'ci-infrastructure',
                    'source':networks[0][0]['ipv4'],'destination':networks[1][0]['ipv4'],'protocol':'tcp','port':9443,
                    'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':declarations[peer],'bindingRef':networks[peer][0]['bindingRef']}}
                datum={'authority':True,'startAuthorized':True,'leaseDrift':False,'signatureDrift':False,'rootfsDrift':False,
                    'command':specs[i]['process']['args'],'proof':str(proofs[i]),'ipv4':networks[i][0]['ipv4'],'bridge':bridge,'sharedTable':shared,'leaseTable':lease}
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
                kernel=NativeTest.kernel(None);kernel['tableName']=lease;kernel['guardedInterfaces']=[bridge];kernel['providerFlows'][0]['source']=datum['ipv4']
                datum_cfg={'approved':{cid:datum},'intent':intent,'crypto':crypto,'kernel':kernel,'commands':{k:commands[k] for k in ('nft','ip','nsenter','unshare')},
                    'mountCommands':{k:commands[k] for k in ('mount','umount')},'runc':commands['runc'],'runcHash':sha(commands['runc']),
                    'lock':str(lock),'networkBindings':networks[i],'transport':[flow],'busyboxHash':sha(shutil.which('busybox'))}
                broker=configure(directory,datum_cfg,repository,source,python,run,live_authority=True)
                original_node=json.loads((directory/'attestation-producer.json').read_bytes())
                broker,unused=assemble(directory,source,python,crypto,intent,broker,policies[i],original_node,registry)
                entry_config=directory/'broker.json'
                cfg['candidates'][cid]={'intentRef':digest(intent),'bundleParents':[str(inputs)],'admissionConfiguration':str(entry_config),'admissionConfigurationHash':sha(entry_config)}
            private(config_path,cfg)
            for cid in cids:private(registry/cid/'adapter.json',{'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':cid,
                'configurationHash':adapter.binding(cfg,cid),'state':'STAGED','runtimeRoot':None,'bundleHash':None,'driverHash':None})
            def invoke(operation,cid,*extra):
                return [python,'-I','-B',str(source/'scripts/semantic_provider_docker_runtime.py'),'--configuration',str(config_path),'--root',str(runtime),operation,*extra,cid]
            created.append(cids[0]);run(*invoke('create',cids[0],'--bundle',str(inputs/cids[0])))
            require(digest(json.loads((registry/cids[0]/'bundle/config.json').read_bytes()))==digest(specs[0]),'CI_FULL_OCI_CHANGED')
            def start(cid):
                out=tempfile.TemporaryFile();err=tempfile.TemporaryFile()
                process=subprocess.Popen(invoke('start',cid),stdin=subprocess.DEVNULL,stdout=out,stderr=err)
                processes.append((process,out,err));return process
            def application_proof(cid):
                state=json.loads(run(commands['runc'],'--root',str(runtime),'state',cid).stdout)
                path=Path('/proc')/str(state['pid'])/'root/dev/shm/started'
                return path.read_text().strip() if path.exists() else None
            first=start(cids[0])
            # The first waits for an actually absent sibling; no application may run.
            time.sleep(0.3)
            require(first.poll() is None and application_proof(cids[0]) is None,'CI_PREMATURE_COHORT_RELEASE')
            created.append(cids[1]);run(*invoke('create',cids[1],'--bundle',str(inputs/cids[1])))
            require(digest(json.loads((registry/cids[1]/'bundle/config.json').read_bytes()))==digest(specs[1]),'CI_FULL_OCI_CHANGED')
            second=start(cids[1])
            for process,out,err in processes:
                status=process.wait(timeout=60);err.seek(0)
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
                require(status==0,'CI_COHORT_ADMISSION_FAILED:'+err.read(1200).decode())
            require(all(application_proof(cid)=='APP' for cid in cids),'CI_COHORT_APP_PROOF_MISSING')
            for i,cid in enumerate(cids):
                grant=json.loads((registry/cid/'driver.json').read_bytes())
                require(grant['schema']=='ouf.semantic-preexec-driver.v6' and set(grant['peerBinding']['observations'])=={cids[1-i]},'CI_V6_PEER_GRANT_MISSING')
                require(grant['profile']['bundleHash']==digest(specs[i]),'CI_SIGNED_FULL_OCI_DRIFT')
            print('ASSEMBLED_FRAME_PROFILES_NATIVE=PASS NODE_V4=true EFFECTIVE_READONLY_SOURCE_OBSERVED=true PROFILES_GENERATED_BY_ASSEMBLER=true TWO_REAL_CREATED_CANDIDATES=true EXPECTED_COMPLETE_OCI_BEFORE_CREATE=true ABSENT_PEER_PREVENTED_EARLY_RELEASE=true TWO_AUTHENTICATED_V6_STARTS=true REAL_ED25519_NODE_INSTALLER=true CI_ACCEPTANCE_AUTHORITY_ONLY=true TARGET_START_AUTHORIZED=false')
        finally:
            for process,out,err in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                out.close();err.close()
            for cid in created:run(commands['runc'],'--root',str(runtime),'delete','--force',cid,check=False)
            for table in tables:
                for family in ('inet','bridge'):run(commands['nft'],'delete','table',family,table,check=False)
            for host in hosts:run(commands['ip'],'link','delete',host,check=False)
            run(commands['ip'],'link','delete',bridge,check=False)
            for namespace in namespaces:run(commands['ip'],'netns','delete',namespace,check=False)
            shutil.rmtree(runtime,ignore_errors=True)

if __name__=='__main__':main()
