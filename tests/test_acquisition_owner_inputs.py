import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

SOURCE=Path(__file__).resolve().parents[1]/'scripts/read-acquisition-owner-inputs-20261025.py'
spec=importlib.util.spec_from_file_location('acquisition_inputs',SOURCE);reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
SECRET='fixture-credential-must-not-appear-in-public-output'

class Fixture:
    def __init__(self,base):
        self.base=base;self.socket=base/'engine.sock';self.root=base/'scope';self.seed=base/'seed.json';self.calls=[];self.mutate=False;self.substitute=False
        self.values={}
        for n,role in enumerate(reader.ROLES,1):
            cid=('%064x'%n);env=['PRIVATE_FIXTURE='+SECRET]
            if role=='mcp':env+=['MCP_OIDC_TOKEN_ENDPOINT=https://fixture.invalid/token','MCP_OIDC_CLIENT_ID=fixture','MCP_OIDC_CLIENT_SECRET_FILE=/private/fixture-key']
            self.values[cid]={'Id':cid,'Image':'sha256:'+'a'*64,'Config':{'Env':env,'Labels':{}},'HostConfig':{},'Mounts':[],
                'NetworkSettings':{'Networks':{}},'RestartCount':0,'State':{'Running':True,'Pid':1000+n,'StartedAt':'2026-10-25T00:00:00Z','Paused':False,'Restarting':False,'Dead':False,'OOMKilled':False,'Error':''}}
        fixture=self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.0'
            def do_GET(self):
                fixture.calls.append(('GET',self.path));cid=self.path.split('/')[-2]
                value=copy.deepcopy(fixture.values[cid])
                if fixture.mutate and len(fixture.calls)>5:value['Config']['Env'].append('CHANGED=1')
                if fixture.substitute:value['Id']='f'*64
                raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*_):pass
        class Server(socketserver.UnixStreamServer):allow_reuse_address=False
        self.server=Server(str(self.socket),Handler);os.chmod(self.socket,0o600);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.rewrite_seed()
    def rewrite_seed(self,stale_socket=False):
        ids=list(self.values)
        binding=reader.socket_binding(str(self.socket));binding[1]+=1 if stale_socket else 0
        value={'schema':'ouf.onboarding-finite-session-private-inputs.v1','engineBinding':{'socketPath':str(self.socket),'socketBinding':binding},
            'currentBindings':{role:{'containerId':ids[n],'imageId':self.values[ids[n]]['Image'],'pid':self.values[ids[n]]['State']['Pid'],'startedAt':self.values[ids[n]]['State']['StartedAt']}for n,role in enumerate(reader.ROLES)}}
        if self.seed.exists():os.chmod(self.seed,0o600)
        self.seed.write_bytes(reader.encoded(value));os.chmod(self.seed,0o400);self.hash=reader.sha(self.seed.read_bytes())
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()

@unittest.skipUnless(os.geteuid()==os.getegid()==0,'root-only Unix/custody fixture; mandatory in dedicated gate')
class InputCaptureTest(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='acquisition-input-test-',dir=os.environ.get('OUF_CAPTURE_TEST_PARENT',str(SOURCE.parents[1]))));os.chmod(self.base,0o700)
        self.fixture=Fixture(self.base);reader.PROGRESS.update(engineGetAttempts=0,privateMetadataReadPasses=0)
        original_text=Path.read_text;original_bytes=Path.read_bytes;original_stat=Path.stat
        def read_text(path,*args,**kwargs):
            if str(path)=='/proc/sys/kernel/random/boot_id':return 'synthetic-stable-boot'
            return original_text(path,*args,**kwargs)
        def read_bytes(path,*args,**kwargs):
            if re.fullmatch('/proc/[0-9]+/stat',str(path)):return ('100 (fixture) '+' '.join(['S']+['0']*18+['10000'])).encode()
            return original_bytes(path,*args,**kwargs)
        def path_stat(path,*args,**kwargs):
            if re.fullmatch('/proc/[0-9]+/ns/(net|mnt)',str(path)):return types.SimpleNamespace(st_dev=17,st_ino=31 if str(path).endswith('net')else 32)
            return original_stat(path,*args,**kwargs)
        self.patches=[mock.patch.object(Path,'read_text',read_text),mock.patch.object(Path,'read_bytes',read_bytes),mock.patch.object(Path,'stat',path_stat)]
        for patch in self.patches:patch.start()
    def tearDown(self):
        for patch in reversed(self.patches):patch.stop()
        self.fixture.close();shutil.rmtree(self.base)
    def run_capture(self):return reader.capture(self.fixture.root,self.fixture.seed,self.fixture.hash)
    def test_private_capture_has_ten_gets_and_no_public_credentials_or_executable_authority(self):
        result=self.run_capture();self.assertEqual(result['engineGetAttempts'],10);self.assertEqual(len(self.fixture.calls),10)
        self.assertEqual({method for method,_ in self.fixture.calls},{'GET'})
        public=json.dumps(result);self.assertNotIn(SECRET,public);self.assertNotIn('https://fixture.invalid',public);self.assertNotIn('/private/fixture-key',public)
        self.assertTrue(result['mcpAuthenticationDeclaration']['clientCredentialsDeclared']);self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['applicationE2EProven'])
        self.assertEqual(result['privateInputsHash'],hashlib.sha256((self.fixture.root/'inputs.json').read_bytes()).hexdigest())
        for p in self.fixture.root.iterdir():self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o400)
        self.assertIn(SECRET,(self.fixture.root/'response-01.json').read_text())
    def test_consumed_scope_cannot_be_reopened_and_old_evidence_stays_byte_identical(self):
        self.run_capture();before={p.name:p.read_bytes()for p in self.fixture.root.iterdir()}
        with self.assertRaisesRegex(reader.Stop,'INPUT_SCOPE_ALREADY_CONSUMED_NO_REPLAY'):self.run_capture()
        self.assertEqual(len(self.fixture.calls),10);self.assertEqual(before,{p.name:p.read_bytes()for p in self.fixture.root.iterdir()})
    def test_drift_does_not_make_a_complete_result_or_restart_a_role(self):
        self.fixture.mutate=True
        with self.assertRaisesRegex(reader.Stop,'CURRENT_OWNER_COHORT_CHANGED_DURING_READ'):self.run_capture()
        self.assertTrue((self.fixture.root/'claim.json').exists());self.assertFalse((self.fixture.root/'complete.json').exists());self.assertLessEqual(len(self.fixture.calls),10)
    def test_id_substitution_fails_closed(self):
        self.fixture.substitute=True
        with self.assertRaisesRegex(reader.Stop,'SELECTED_CONTAINER_SUBSTITUTED'):self.run_capture()
        self.assertEqual(len(self.fixture.calls),1)
    def test_paused_role_is_not_restarted_or_treated_as_running(self):
        next(iter(self.fixture.values.values()))['State']['Paused']=True
        with self.assertRaisesRegex(reader.Stop,'RUNNING_STABLE_ROLE_REQUIRED'):self.run_capture()
        self.assertEqual(len(self.fixture.calls),1);self.assertFalse((self.fixture.root/'complete.json').exists())
    def test_wrong_seed_hash_stops_before_engine_io_and_consumes_the_new_scope(self):
        self.fixture.hash='0'*64
        with self.assertRaisesRegex(reader.Stop,'EXACT_RETAINED_INPUT_REFERENCE_REQUIRED'):self.run_capture()
        self.assertEqual(self.fixture.calls,[]);self.assertTrue((self.fixture.root/'claim.json').exists())
    def test_current_socket_can_be_observed_without_rebinding_old_runtime_authority(self):
        self.fixture.rewrite_seed(stale_socket=True);result=self.run_capture()
        self.assertFalse(result['currentSocketMatchesRetainedSeed']);self.assertFalse(result['newBindingAcceptedForRuntime']);self.assertFalse(result['runtimeAuthorityIssued'])
    def test_mixed_declarations_stay_metadata_not_token_or_secret_file_reads(self):
        mcp=self.fixture.values[list(self.fixture.values)[2]]
        mcp['Config']['Env']+=['MCP_WORKLOAD_TOKEN='+SECRET,'MCP_WORKLOAD_TOKEN_FILE=/private/nonexistent-token','JAVA_TOOL_OPTIONS=-Dfixture='+SECRET]
        result=self.run_capture();hints=result['mcpAuthenticationDeclaration']
        self.assertTrue(hints['multipleAuthenticationDeclarations']);self.assertTrue(hints['effectiveConfigurationNotResolvedByThisReader'])
        self.assertEqual(result['serviceCredentialFilesOpened'],0);self.assertEqual(result['oauthRequests'],0);self.assertNotIn(SECRET,json.dumps(result))
    def test_world_readable_private_seed_is_refused(self):
        os.chmod(self.fixture.seed,0o644)
        with self.assertRaisesRegex(reader.Stop,'PROTECTED_BOUNDED_METADATA_REQUIRED'):self.run_capture()
        self.assertEqual(self.fixture.calls,[])
    def test_symbolic_private_seed_is_not_followed(self):
        other=self.base/'seed-original';self.fixture.seed.rename(other);self.fixture.seed.symlink_to(other)
        with self.assertRaises(OSError):self.run_capture()
        self.assertEqual(self.fixture.calls,[])
    def test_actual_main_exceptional_path_is_safe_without_isolated_flags(self):
        child=subprocess.run([sys.executable,str(SOURCE)],capture_output=True,text=True)
        self.assertEqual(child.returncode,2);self.assertEqual(child.stderr,'')
        result=json.loads(child.stdout);self.assertEqual(result['reasonCode'],'ONE_ISOLATED_ROOT_CAPTURE_REQUIRED');self.assertFalse(result['complete']);self.assertNotIn(SECRET,child.stdout)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_ENGINE')=='1','dedicated native Docker gate required')
class NativeEngineInputTest(unittest.TestCase):
    def test_real_engine_process_pins_and_private_capture_without_runtime_writes(self):
        self.assertEqual(os.geteuid(),0);base=Path(tempfile.mkdtemp(prefix='ouf-acquisition-native-',dir='/run'));os.chmod(base,0o700)
        ids=[]
        def docker(*args):return subprocess.check_output(['docker',*args],text=True).strip()
        try:
            docker('pull','busybox:1.37.0')
            for role in reader.ROLES:ids.append(docker('run','-d','--name','ouf-acquisition-ci-'+role+'-'+str(os.getpid()),'--label','ouf.fixture.role='+role,'--env','PRIVATE_FIXTURE='+SECRET,'busybox:1.37.0','sleep','300'))
            values={cid:json.loads(docker('inspect',cid))[0]for cid in ids};socket_path=str(Path('/var/run/docker.sock').resolve())
            seed={'schema':'ouf.onboarding-finite-session-private-inputs.v1','engineBinding':{'socketPath':socket_path,'socketBinding':reader.socket_binding(socket_path)},
                'currentBindings':{role:{'containerId':cid,'imageId':values[cid]['Image'],'pid':values[cid]['State']['Pid'],'startedAt':values[cid]['State']['StartedAt']}for role,cid in zip(reader.ROLES,ids)}}
            path=base/'seed.json';path.write_bytes(reader.encoded(seed));os.chmod(path,0o400)
            reader.PROGRESS.update(engineGetAttempts=0,privateMetadataReadPasses=0)
            result=reader.capture(base/'scope',path,reader.sha(path.read_bytes()))
            self.assertTrue(result['complete']);self.assertEqual(result['engineGetAttempts'],10);self.assertTrue(result['currentCohortStable']);self.assertNotIn(SECRET,json.dumps(result))
            for cid in ids:
                after=json.loads(docker('inspect',cid))[0]
                self.assertEqual(reader.stable(values[cid]),reader.stable(after));self.assertEqual(values[cid]['State']['Pid'],after['State']['Pid'])
        finally:
            for cid in ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,check=False)
            shutil.rmtree(base)

if __name__=='__main__':unittest.main()
