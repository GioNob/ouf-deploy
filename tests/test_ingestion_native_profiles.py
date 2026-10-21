"""Native validator composition, metadata-only seals and confined proc tools."""
import ast
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_native_review as fixture
from tools.ingestion_rollout_preparation import native_profiles as p,profile_delivery
from tools.ingestion_rollout_preparation import native_inputs
from tools.ingestion_rollout_execution import contract as c,runtime_bindings as rb
from tools.chatbot_file_cohort.gateway import apisix_runtime_binding
from tools.semantic_lease_recovery.recovery_journal import Journal
import iam_governance_intake as governance

class Profiles(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.NativeReview();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;profiles=f.profiles;db=profiles['databaseControlProfile'];owner=profiles['ownerControlProfile']
        self.root=Path(owner['projection']['path']).parent
        self.selected={'packet':copy.deepcopy(f.packet),'inputs':copy.deepcopy(f.inputs),'ownerPlan':copy.deepcopy(f.owner_plan),
            'ownerResult':copy.deepcopy(f.completed),'parent':str(self.root),'expected':copy.deepcopy(f.owner_plan['currentApplications']),
            'databaseIdentity':{**{k:v for k,v in db['identity'].items()if k!='postgresPort'},'schema':'ouf_ingestion'}}
        self.selected['expected']['postgres']=copy.deepcopy(db['postgresRuntimeBinding'])
        self.snapshots={n:{'container':copy.deepcopy(v),'bindingProfile':rb.SORTED,
            'processMetadata':{'networkNamespace':{'device':1,'inode':2}}}for n,v in profiles['runtimeGuardProfile']['beforeContainers'].items()}
        for n in('onboarding','mcp','udp','postgres'):
            restart=db['postgresRestartCount']if n=='postgres'else profiles['runtimeGuardProfile']['unchangedApplications'][n]['restartCount']
            self.snapshots[n]={'container':{'RestartCount':restart,'State':{'Pid':os.getpid()}},
                'bindingProfile':db['runtimeBindingProfile']if n=='postgres'else profiles['runtimeGuardProfile']['unchangedApplications'][n]['bindingProfile'],
                'processMetadata':{'networkNamespace':copy.deepcopy(owner['networkNamespace'])}}
        self.environment={k:copy.deepcopy(db[k])for k in('dockerExecutable','dockerConfigDirectory','dockerConfigIdentity','containerPrograms','unixSocketDirectory')}
        self.environment.update(pythonExecutable=copy.deepcopy(owner['pythonExecutable']),ownerEndpoint=copy.deepcopy(owner['endpoint']),
            ingestionEndpoint=copy.deepcopy(profiles['ingestionReadinessProfile']['endpoint']),
            gatewayEndpoint=copy.deepcopy(profiles['gatewayTransportProfile']['endpoint']),
            oldGatewayConfig=copy.deepcopy(profiles['retainedGatewayTransportProfile']['config']),
            stagedGatewayConfig=copy.deepcopy(profiles['gatewayTransportProfile']['config']),
            adminKey=None,archive=copy.deepcopy(profiles['imageImportProfile']['archive']),projection=copy.deepcopy(owner['projection']),
            postgresPort=db['identity']['postgresPort'])
    def test_private_composition_matches_all_qualified_native_profiles(self):
        actual=p.compile_profiles(self.selected,self.snapshots,self.environment)
        self.assertEqual(actual,self.fixture.profiles)
        self.assertNotIn('humanReadProfile',actual)
    def test_second_ente_endpoints_and_namespace_are_explicit_inputs(self):
        environment=copy.deepcopy(self.environment);environment['ownerEndpoint']={'host':'::1','port':18181}
        environment['ingestionEndpoint']={'host':'127.0.0.3','port':28282};environment['gatewayEndpoint']={'host':'127.0.0.4','port':39393}
        snapshots=copy.deepcopy(self.snapshots);snapshots['onboarding']['processMetadata']['networkNamespace']={'device':23,'inode':456}
        result=p.compile_profiles(self.selected,snapshots,environment)
        self.assertEqual(result['ownerControlProfile']['endpoint'],environment['ownerEndpoint'])
        self.assertEqual(result['ownerControlProfile']['networkNamespace'],{'device':23,'inode':456})
        self.assertEqual(result['gatewayTransportProfile']['endpoint'],environment['gatewayEndpoint'])
        self.assertEqual(result['ingestionReadinessProfile']['endpoint'],environment['ingestionEndpoint'])
    def test_foreign_projection_owner_or_gateway_config_never_compile(self):
        for part in('projection','stagedGatewayConfig','archive'):
            changed=copy.deepcopy(self.environment);changed[part]['sha256']='0'*64
            with self.subTest(part=part),self.assertRaises(c.Denied):p.compile_profiles(self.selected,self.snapshots,changed)
        changed=copy.deepcopy(self.selected);changed['ownerResult']['active']['generation']+=1
        with self.assertRaises(c.Denied):p.compile_profiles(changed,self.snapshots,self.environment)
    def test_v6_wildcard_is_v6_loopback_not_assumed_v4_dual_stack(self):
        metadata={'tcpProcessOwnershipProven':True,'tcpListeners':[{'family':6,'addressHex':'0'*32,'port':18888}]}
        self.assertEqual(p.listener_endpoint(metadata),{'host':'::1','port':18888})
        metadata['tcpListeners'].append({'family':4,'addressHex':'0100007F','port':19999})
        with self.assertRaisesRegex(c.Denied,'UNAMBIGUOUS'):p.listener_endpoint(metadata)
        self.assertEqual(p.listener_endpoint(metadata,19999),{'host':'127.0.0.1','port':19999})
        metadata['tcpProcessOwnershipProven']=False
        with self.assertRaises(c.Denied):p.listener_endpoint(metadata,19999)
    def test_duplicate_workers_keep_one_selected_retained_gateway_endpoint(self):
        rows=[{'family':4,'addressHex':'0100007F','port':29180}for _ in range(8)]
        rows.append({'family':4,'addressHex':'00000000','port':29080})
        self.assertEqual(p.listener_endpoint({'tcpProcessOwnershipProven':True,'tcpListeners':rows},29180),{'host':'127.0.0.1','port':29180})
        with self.assertRaises(c.Denied):p.listener_endpoint({'tcpProcessOwnershipProven':True,'tcpListeners':rows},9180)
    def test_metadata_seal_does_not_open_or_hash_already_audited_bytes(self):
        binding=self.environment['archive'];selected={k:binding[k]for k in('path','sha256','metadata')}
        with patch.object(os,'read',side_effect=AssertionError('No audited file byte reads')):
            self.assertEqual(p.metadata_seal(selected,{}),binding)
        file=Path(selected['path']);file.write_bytes(b'changed')
        with self.assertRaisesRegex(c.Denied,'METADATA_CHANGED'):p.metadata_seal(selected,{})
    def test_container_absolute_symlink_stays_in_container_root_and_argv0_preserved(self):
        root=self.root/'container-root';(root/'bin').mkdir(parents=True);program=root/'bin/toolbox';program.write_bytes(b'fixture');program.chmod(0o755)
        (root/'bin/env').symlink_to('/bin/toolbox');fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            self.assertEqual(p.process_root_program(fd,'/bin/env'),'/bin/env')
            (root/'bin/escape').symlink_to('/../../etc/passwd')
            with self.assertRaises(FileNotFoundError):p.process_root_program(fd,'/bin/escape')
            (root/'bin/loop').symlink_to('/bin/loop')
            with self.assertRaisesRegex(c.Denied,'BOUNDED_CONTAINER_PROGRAM_LINKS'):p.process_root_program(fd,'/bin/loop')
        finally:os.close(fd)
    def test_live_unix_socket_path_and_port_belong_to_selected_process(self):
        if not Path('/proc/self/net/unix').exists():self.skipTest('Proc Unix ownership mandatory in root Linux CI')
        selected=self.root/'.s.PGSQL.45454'
        try:listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        except PermissionError:
            if os.environ.get('GITHUB_ACTIONS')=='true':raise
            self.skipTest('Sandbox denies sockets; mandatory root Linux CI')
        with listener:
            listener.bind(str(selected));listener.listen(1)
            self.assertEqual(p.postgres_socket({'State':{'Pid':os.getpid()}}),{'directory':str(self.root),'port':45454})
    def preparation_fixture(self):
        plan=self.selected['ownerPlan'];gateway=self.snapshots['gateway'];transport={
            'runtimeBinding':apisix_runtime_binding(gateway['container']),
            'networkNamespace':gateway['processMetadata']['networkNamespace'],
            'configBinding':self.selected['packet']['gatewayConfigBefore'],
            'adminKeyBinding':None,'pythonExecutable':self.environment['pythonExecutable'],'port':self.environment['gatewayEndpoint']['port']}
        plan['gateway']={'transport':transport}
        # Fixture-only plan change is re-bound to the synthetic packet/result.
        self.selected['packet']['ownerPlanSha256']=c.digest(plan);self.selected['ownerResult']['planHash']=c.digest(plan)
        self.selected['original']={'authorization':{'plan':{'selection':{'docker':self.environment['dockerExecutable']}}}}
        self.case={'packetBinding':{'path':str(self.root/'packet.json'),'sha256':c.digest(self.selected['packet'])},
            'nativeProfilePreparation':{'captureContext':str(self.root/'captured'),
                'allowedAncestorOwners':{},'publishedProjection':{k:self.environment['projection'][k]for k in('path','sha256')}}}
        for name,key in(('onboarding','ownerEndpoint'),('ingestion','ingestionEndpoint'),('gateway','gatewayEndpoint')):
            endpoint=self.environment[key]
            self.snapshots[name]['processMetadata'].update(tcpProcessOwnershipProven=True,tcpListeners=[{'family':4,'addressHex':'0200007F','port':endpoint['port']}])
        patches=[patch.object(p,'load_capture',return_value=(self.selected,self.snapshots,[])),
            patch.object(p,'exact_executable',side_effect=lambda v:copy.deepcopy(v)),patch.object(p,'check_process_namespaces'),
            patch.object(p,'container_programs',return_value=self.environment['containerPrograms']),
            patch.object(p,'postgres_socket',return_value={'directory':self.environment['unixSocketDirectory'],'port':self.environment['postgresPort']})]
        for patched in patches:patched.start();self.addCleanup(patched.stop)
    def test_private_preparation_claim_complete_no_runtime_or_auth_effects(self):
        self.preparation_fixture();result=p.execute('prepare',None,self.case,None,'a'*64)
        self.assertTrue(result['complete']);self.assertTrue(result['privateNativeControlProfilesCompiled'])
        self.assertFalse(result['runtimeAuthorityIssued']);self.assertEqual(result['engineRequests'],0);self.assertEqual(result['oauthRequests'],0)
        context=Path(result['contextPath']);self.assertTrue((context/'profiles.json').is_file());self.assertFalse(list((context/'empty-docker-config').iterdir()))
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):p.execute('prepare',None,self.case,None,'a'*64)
        status=p.execute('inspect',str(context),self.case,None,'a'*64);self.assertTrue(status['complete']);self.assertEqual(status['engineRequests'],0)
    def test_failed_preparation_keeps_claim_and_partial_context(self):
        self.preparation_fixture()
        with patch.object(p,'exact_executable',side_effect=c.Denied('SYNTHETIC_EXECUTABLE_DRIFT')):
            with self.assertRaisesRegex(c.Denied,'SYNTHETIC_EXECUTABLE_DRIFT'):p.execute('prepare',None,self.case,None,'a'*64)
        context=p.CHECKPOINT['contextPath'];self.assertFalse(Journal(context).read()['complete'])
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):p.execute('prepare',None,self.case,None,'a'*64)
        self.assertFalse(p.execute('inspect',context,self.case,None,'a'*64)['complete'])
    def test_delivery_reproducible_and_actual_isolated_mode_rejection(self):
        artifact=ROOT/'scripts/prepare-ingestion-native-profiles-20261020.py'
        case=next(ast.literal_eval(n.value)for n in ast.parse(artifact.read_bytes()).body
            if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='CASE')
        raw,declaration=profile_delivery.generate(ROOT,case);self.assertEqual(raw,artifact.read_bytes())
        selected=self.root/'sealed.py';selected.write_bytes(raw)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(selected),'open-window'],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,2);self.assertEqual(json.loads(run.stdout)['status'],'STOP_RECONCILE')
        self.assertFalse(declaration['runtimeAuthorityIssued'])
    def test_complete_sealed_preparation_actual_proc_root_and_unix_socket(self):
        if not Path('/proc/self/ns/net').exists():self.skipTest('Actual proc root and Unix metadata mandatory root Linux CI')
        root=self.root/'pg-root';(root/'bin').mkdir(parents=True);(root/'s').mkdir()
        for name in('env','timeout','psql'):
            file=root/'bin'/name;file.write_bytes(b'fixture-only-never-executed');file.chmod(0o755)
        # A minimal child changes root and owns a real Unix listening socket;
        # no PostgreSQL server or SQL process is launched by this preparation.
        ready_read,ready_write=os.pipe();stop_read,stop_write=os.pipe();pid=os.fork()
        if pid==0:
            try:
                os.close(ready_read);os.close(stop_write);os.chroot(root);os.chdir('/')
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as sock:
                    sock.bind('/s/.s.PGSQL.45454');sock.listen(1);os.write(ready_write,b'1');os.read(stop_read,1)
                os._exit(0)
            except BaseException:os._exit(2)
        os.close(ready_write);os.close(stop_read)
        def stop_child():
            os.close(stop_write);os.close(ready_read);os.waitpid(pid,0)
        self.addCleanup(stop_child);self.assertEqual(os.read(ready_read,1),b'1')
        packet=copy.deepcopy(self.selected['packet']);plan=copy.deepcopy(self.selected['ownerPlan']);completed=copy.deepcopy(self.selected['ownerResult'])
        actual={n:copy.deepcopy(self.snapshots[n]['container'])for n in('ingestion','gateway')}
        for n in('onboarding','mcp','udp','postgres'):
            actual[n]=copy.deepcopy(actual['ingestion']);actual[n]['Id']=self.selected['expected'][n]['containerId']
        for n,v in actual.items():
            v['State']['Pid']=pid if n=='postgres'else os.getpid()
            if n=='postgres':v['Config']['Env']=['PATH=/bin']
        pins={n:rb.observed(v,rb.SORTED)for n,v in actual.items()}
        namespaces={}
        for n,v in actual.items():
            s=os.stat('/proc/'+str(v['State']['Pid'])+'/ns/net');namespaces[n]={'device':s.st_dev,'inode':s.st_ino}
        plan['currentApplications']={n:v for n,v in pins.items()if n!='postgres'}
        # Root-custodied distro program is a fixture metadata reference. The
        # matrix interpreter lives in a runner-writable toolcache and must not
        # be mislabeled as a qualified runtime transport executable.
        executable=governance.executable('/usr/bin/python3')
        plan['gateway']={'transport':{'runtimeBinding':apisix_runtime_binding(actual['gateway']),
            'networkNamespace':namespaces['gateway'],'configBinding':packet['gatewayConfigBefore'],
            'adminKeyBinding':None,'pythonExecutable':executable,'port':29180}}
        owner=self.root/'retained-owner';owner.mkdir(mode=0o700);plan['authorityDirectory']=str(owner)
        selection={'issuer':'https://fixture.invalid','tenant':'fixture','subject':'fixture','docker':executable}
        plan['humanBinding']={'selectionHash':c.digest(selection)}
        packet['expectedRuntimeBindings']={n:pins[n]for n in('ingestion','gateway')}
        packet['ownerPlanSha256']=c.digest(plan);completed['planHash']=c.digest(plan)
        original={'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1','engine':plan['engine'],
            'authorization':{'plan':{'selection':selection}},'databasePlan':{'schema':'ouf.chatbot-cohort-database-plan.v1',
                'postgresRuntimeBinding':pins['postgres'],'modules':[{'module':n,'schema':'ouf_'+n,
                    **{k:v for k,v in self.selected['databaseIdentity'].items()if k!='schema'}}for n in('onboarding','udp','ingestion','mcp')]}}
        def write(file,value):file.write_bytes(c.encoded(value));file.chmod(0o600);return file
        import hashlib
        original_file=write(owner/'original.json',original)
        write(owner/'case.json',{'originalBinding':{'path':str(original_file),'sha256':hashlib.sha256(original_file.read_bytes()).hexdigest()}})
        verified={k:copy.deepcopy(packet[k])for k in('candidate','expectedRuntimeBindings','gatewayConfigBefore','retainedGatewayConfig','dedicatedOwnerKey','retainedClaims')}
        packet['verifiedInputsHash']=c.digest(verified)
        case={'schema':'ouf.ingestion-rollout-retained-case.v1','purpose':'EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT',
            'budgetReset':False,'runtimeAuthorityIssued':False}
        for key,value in zip(('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'),(packet,verified,plan,completed)):
            file=write(owner/(key+'.json'),value);case[key]={'path':str(file),'sha256':c.digest(value)}
        captured=self.root/'ingestion-native-inputs-ABCDEFGH';captured.mkdir(mode=0o700)
        logical=c.digest({'profile':native_inputs.PROFILE,'packetHash':c.digest(packet),'containerIds':{n:v['containerId']for n,v in pins.items()}})
        write(self.root/('ingestion-native-inputs-'+logical+'.claim.json'),{'contextPath':str(captured),'logicalRef':logical,'sourceClosureHash':'c'*64})
        Journal(captured).initialize({'schema':native_inputs.PROFILE,'sourceClosureHash':'c'*64,'logicalRef':logical,
            'complete':True,'phase':'COMPLETE','engineGetsReserved':12,'maximumEngineGets':12,'budgetReset':False})
        metadata={}
        for n in actual:
            metadata[n]={'networkNamespace':namespaces[n],'tcpProcessOwnershipProven':True,
                'tcpListeners':[{'family':4,'addressHex':'0100007F','port':29180 if n=='gateway'else 18080}]}
            write(captured/(n+'.json'),{'container':actual[n],'bindingProfile':rb.SORTED,'processMetadata':metadata[n]})
        write(captured/'inputs.json',{'schema':'ouf.ingestion-private-native-input-snapshot.v1','sourceClosureHash':'c'*64,
            **{k:case[k]for k in('packetBinding','ownerPlanBinding','ownerResultBinding')},'databaseIdentity':self.selected['databaseIdentity'],
            'processMetadata':metadata,'bindingProfiles':dict.fromkeys(actual,rb.SORTED)})
        case['nativeProfilePreparation']={'schema':'ouf.retained-native-profile-preparation-input.v1',
            'captureContext':str(captured),'captureSourceClosureHash':'c'*64,'observedNamespaces':namespaces,
            'publishedProjection':{k:self.environment['projection'][k]for k in('path','sha256')},'allowedAncestorOwners':{}}
        raw,_=profile_delivery.generate(ROOT,case);script=self.root/'actual-sealed-preparation.py';script.write_bytes(raw)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'prepare'],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);result=json.loads(run.stdout)
        self.assertTrue(result['complete']);self.assertEqual(result['engineRequests'],0);self.assertFalse(result['serviceReachabilityProven'])
        profiles=json.loads((Path(result['contextPath'])/'profiles.json').read_text())
        self.assertEqual(profiles['databaseControlProfile']['unixSocketDirectory'],'/s')
        self.assertEqual(profiles['databaseControlProfile']['identity']['postgresPort'],45454)
        self.assertEqual(profiles['databaseControlProfile']['containerPrograms'],{'env':'/bin/env','timeout':'/bin/timeout','psql':'/bin/psql'})
        inspect=subprocess.run([sys.executable,'-I','-B','-S',str(script),'inspect',result['contextPath']],capture_output=True,text=True,timeout=30)
        self.assertEqual(inspect.returncode,0,inspect.stdout+inspect.stderr)

if __name__=='__main__':unittest.main()
