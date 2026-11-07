import copy,http.server,importlib.util,json,os,socketserver,stat,tempfile,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('provider_runtime_contract',ROOT/'tools/m2_discovery_installation_profile/provider_runtime_contract.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class UnixHTTP(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True

class Contract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rc-fixture-',dir=ROOT);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'etc';self.wrappers=self.root/'sbin';self.inputs=self.root/'prior'
        self.source=self.config/'source';self.candidate=self.config/'registry'/m.PROVIDER
        for p in (self.config,self.wrappers,self.inputs,self.source/'scripts',self.candidate):p.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.boot=self.root/'boot';self.boot.write_text('synthetic-boot')
        def put(path,value,mode=0o600):
            path.write_bytes(value if type(value) is bytes else m.encoded(value));path.chmod(mode);return m.sha(path.read_bytes())
        self.put=put
        self.profiles={}
        for role,filename,schema in [('preparerTemplate','preparer-template.json','ouf.semantic-admission-preparer-template.v1'),
            ('attestation','attestation-producer.json','ouf.semantic-node-attestor.v4'),
            ('approval','approval-producer.json','ouf.semantic-installer-approval-producer.v1')]:
            p=self.candidate/filename;h=put(p,{'schema':schema,'signingKeyBinding':{'path':str(self.root/'NEVER-READ-SECRET'),'sha256':'a'*64}})
            self.profiles[role]={'path':str(p),'sha256':h}
        broker={'schema':'ouf.semantic-deployment-broker.v1','sourceRoot':str(self.source),'candidateRoot':str(self.candidate),
            'preparerTemplate':self.profiles['preparerTemplate'],'producers':{k:{'configuration':self.profiles[k]} for k in ('attestation','approval')}}
        broker_hash=put(self.candidate/'broker.json',broker)
        adapter=self.source/'scripts/semantic_provider_docker_runtime.py';adapter_hash=put(adapter,b'# synthetic source: never executed\n')
        self.cfgpath=self.config/'runtime.json'
        self.cfg={'schema':m.ADAPTERS[3],'sourceHash':adapter_hash,'pythonPath':'/usr/bin/python3','registryRoot':str(self.config/'registry'),
            'driverPath':str(self.source/'scripts/semantic_provider_preexec_hook.py'),
            'admissionPath':str(self.source/'scripts/semantic_provider_deployment_broker.py'),
            'candidates':{m.PROVIDER:{'admissionConfiguration':str(self.candidate/'broker.json'),'admissionConfigurationHash':broker_hash}}}
        put(self.cfgpath,self.cfg)
        self.wrapper=self.wrappers/'ouf-test-runtime';put(self.wrapper,
            ('#!/bin/sh\nexec /usr/bin/python3 -I -B '+str(adapter)+' --configuration '+str(self.cfgpath)+' "$@"\n').encode(),0o755)
        self.info={'ID':'synthetic-engine','ServerVersion':'29.8.1','Driver':'overlayfs','CgroupDriver':'systemd','DockerRootDir':'/synthetic',
            'Runtimes':{'ouf-test':{'path':str(self.wrapper)}}}
        self.provider={'Id':m.PROVIDER,'Image':m.IMAGE,'Config':{'Env':['PRIVATE_ENV_DO_NOT_PRINT=secret']},
            'HostConfig':{'Runtime':'ouf-test'},'Mounts':[],'State':{'Pid':0,'Running':False,'Paused':False,'Restarting':False,'StartedAt':'retained'}}
        self.calls=[];test=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                test.calls.append(('GET',self.path))
                value=copy.deepcopy(test.info if self.path=='/v1.44/info' else test.provider)
                if self.path=='/v1.44/info':value['SystemTime']=time.time()
                raw=m.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.socket=self.root/'engine.sock';self.server=UnixHTTP(str(self.socket),Handler)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        def close():self.server.shutdown();self.server.server_close();thread.join()
        self.addCleanup(close);s=self.socket.stat()
        binding={'socketPath':str(self.socket),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],
            'peerCredentials':[os.getpid(),0,0]}
        self.private={'schema':'ouf.m2-discovery-stopped-provider-installation-inputs.v1','bootId':'synthetic-boot',
            'engineBinding':binding,'currentStoppedProvider':copy.deepcopy(self.provider),**m.FLAGS}
        self.refresh()
    def refresh(self):
        self.put(self.inputs/'installation-inputs.private.json',self.private);self.input_hash=m.digest(self.private)
        result={'schema':'ouf.m2-stopped-provider-inputs-result.v1','status':'STOPPED_PROVIDER_INSTALLATION_INPUTS_PREPARED_NOT_ADMITTED',
            'scope':str(self.inputs),'installationInputsHash':self.input_hash,'complete':True,'scopeConsumed':True}
        self.put(self.inputs/'result.json',result);self.result_hash=m.digest(result)
    def run_collect(self,c=None):
        self.capture=c or m.Capture(self.root/'capture')
        return m.collect(self.capture,input_root=self.inputs,input_hash=self.input_hash,result_hash=self.result_hash,
            boot_path=self.boot,configuration_root=self.config,wrapper_root=self.wrappers)
    def test_actual_unix_peer_four_gets_and_custody_rechecks_no_secret_traversal(self):
        result=self.run_collect();self.assertEqual(result['counts']['engineGets'],4)
        self.assertEqual(result['counts']['metadataReads'],18);self.assertTrue(result['sourceCustodyRechecked'])
        self.assertEqual(result['contract']['classification'],'BOUND_NAMED_RUNTIME_AND_RETAINED_PROVIDER_PROFILE_METADATA')
        self.assertEqual(result['contract']['profileSchemas']['attestation'],'ouf.semantic-node-attestor.v4')
        text=json.dumps(result);self.assertNotIn('PRIVATE_ENV_DO_NOT_PRINT',text);self.assertNotIn(str(self.candidate),text)
        self.assertFalse(result['contract']['signingKeyBindingsFollowed']);self.assertEqual(result['counts']['privateKeyReads'],0)
        self.assertTrue(all(not result[k] for k in m.FLAGS));self.assertEqual(len(self.calls),4)
    def test_existing_scope_never_replays_or_changes_claim(self):
        self.run_collect();p=self.root/'capture/capture.claim.json';before=p.read_bytes(),p.stat().st_mtime_ns
        with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Capture(self.root/'capture')
        self.assertEqual(before,(p.read_bytes(),p.stat().st_mtime_ns));self.assertEqual(len(self.calls),4)
    def test_prior_hash_drift_stops_before_engine(self):
        self.put(self.inputs/'installation-inputs.private.json',{**self.private,'bootId':'changed'})
        with self.assertRaisesRegex(m.Stop,'METADATA_HASH'):self.run_collect()
        self.assertEqual(self.calls,[])
    def test_boot_drift_stops_before_engine(self):
        self.boot.write_text('different')
        with self.assertRaisesRegex(m.Stop,'BOOT_CHANGED'):self.run_collect()
        self.assertEqual(self.calls,[])
    def test_running_provider_cannot_be_treated_as_stopped(self):
        self.provider['State']['Running']=True
        with self.assertRaisesRegex(m.Stop,'SAME_STOPPED_PROVIDER'):self.run_collect()
    def test_provider_configuration_drift_stops(self):
        self.provider['HostConfig']['Unexpected']=True
        with self.assertRaisesRegex(m.Stop,'SAME_STOPPED_PROVIDER'):self.run_collect()
    def test_socket_peer_mismatch_stops_without_fallback(self):
        self.private['engineBinding']['peerCredentials'][0]+=1;self.refresh()
        with self.assertRaisesRegex(m.Stop,'PEER_CREDENTIAL_DRIFT'):self.run_collect()
        self.assertEqual(self.calls,[])
    def test_shell_wrapper_is_parsed_never_executed(self):
        self.put(self.wrapper,b'#!/bin/sh\ntouch /not-permitted\n',0o755)
        with self.assertRaisesRegex(m.Stop,'CLOSED_REVIEWED_RUNTIME_WRAPPER'):self.run_collect()
    def test_metadata_symlink_is_rejected(self):
        target=self.config/'original.json';self.cfgpath.rename(target);self.cfgpath.symlink_to(target)
        with self.assertRaises(OSError):self.run_collect()
    def test_unreviewed_configuration_location_stops_before_read(self):
        self.put(self.wrapper,self.wrapper.read_bytes().replace(str(self.cfgpath).encode(),b'/root/private-key.json'),0o755)
        with self.assertRaisesRegex(m.Stop,'OUTSIDE_REVIEWED_ROOT'):self.run_collect()
    def test_profile_hash_or_schema_drift_cannot_grant_a_contract(self):
        self.put(self.candidate/'attestation-producer.json',{'schema':'arbitrary-secret-value'})
        with self.assertRaisesRegex(m.Stop,'METADATA_HASH'):self.run_collect()
    def test_source_drift_is_not_executed_or_admitted(self):
        self.put(self.source/'scripts/semantic_provider_docker_runtime.py',b'raise SystemExit(0)\n')
        with self.assertRaisesRegex(m.Stop,'SOURCE_DRIFT'):self.run_collect()
    def test_absent_retained_entry_is_bounded_result_no_directory_search(self):
        self.cfg['candidates']={};self.put(self.cfgpath,self.cfg);r=self.run_collect()
        self.assertFalse(r['contract']['retainedProviderEntryPresent']);self.assertEqual(r['counts']['metadataReads'],10)
    def test_builtin_runtime_reports_missing_contract_without_guessing(self):
        self.provider['HostConfig']['Runtime']='runc';self.private['currentStoppedProvider']=copy.deepcopy(self.provider);self.refresh()
        r=self.run_collect();self.assertEqual(r['contract']['classification'],'NO_NAMED_PROVIDER_ADAPTER')
        self.assertEqual(r['counts']['metadataReads'],4)
    def test_source_inode_drift_during_final_read_is_rejected(self):
        c=m.Capture(self.root/'capture');original=c.recheck
        def changed():
            p=self.candidate/'preparer-template.json';raw=p.read_bytes();p.unlink();self.put(p,raw);original()
        c.recheck=changed
        with self.assertRaisesRegex(m.Stop,'SOURCE_DRIFT'):self.run_collect(c)
    def test_no_engine_operation_outside_two_closed_get_paths(self):
        c=m.Capture(self.root/'capture');e=m.Engine(c,self.private['engineBinding'],m.PROVIDER)
        with self.assertRaisesRegex(m.Stop,'CLOSED_RUNTIME_CONTRACT_ENGINE_GET'):e.get('/v1.44/containers/json')
        self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
