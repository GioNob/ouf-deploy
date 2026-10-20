"""Exact Unix Engine GET fixture; private state, crash fence, sealed delivery."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_preparation import native_inputs as n,input_delivery
from tools.ingestion_rollout_execution import contract as c,runtime_bindings as rb
from tools.semantic_lease_recovery.recovery_journal import Journal

class Capture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.owner=self.root/'owner';self.owner.mkdir(mode=0o700)
        # Keep AF_UNIX pathname below108 bytes even in the CI copy.
        self.socktemp=tempfile.TemporaryDirectory(prefix='ouf-ni-',dir='/var/lib'if Path('/var/lib').is_dir()else str(self.root))
        self.addCleanup(self.socktemp.cleanup);self.sockpath=Path(self.socktemp.name)/'e.sock'
        self.seen=[];self.fail_at=None;self.drift_at=None;fixture=self
        self.actual={}
        for i,name in enumerate(sorted(n.APP_NAMES|{'postgres'}),1):
            self.actual[str(i)*64]={'Id':str(i)*64,'Image':'sha256:'+'a'*64,'Config':{'Env':['PRIVATE_FIXTURE=never-print']},
                'HostConfig':{'Memory':123},'Mounts':[],'NetworkSettings':{'Networks':{}},'RestartCount':0,
                'State':{'Running':True,'Paused':False,'Restarting':False,'Pid':os.getpid(),'StartedAt':'fixture-generation'}}
        class Server(socketserver.UnixStreamServer):pass
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):raise AssertionError('Mutation forbidden in capture fixture')
            def do_GET(self):
                fixture.seen.append((self.command,self.path));index=len(fixture.seen)
                if index==fixture.fail_at:self.connection.shutdown(socket.SHUT_RDWR);return
                cid=self.path.split('/')[-2]
                value=copy.deepcopy(fixture.actual[cid])
                if index==fixture.drift_at:value['RestartCount']+=1
                raw=c.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        try:self.server=Server(str(self.sockpath),Handler)
        except PermissionError:
            if os.environ.get('GITHUB_ACTIONS')=='true':raise
            self.skipTest('Sandbox denies Unix sockets; real socket qualification mandatory in root CI')
        self.sockpath.chmod(0o600)
        self.thread=threading.Thread(target=lambda:self.server.serve_forever(poll_interval=.02),daemon=True);self.thread.start()
        def stop():self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        self.addCleanup(stop)
        s=self.sockpath.stat();engine={'socketPath':str(self.sockpath),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
        pins={name:rb.observed(self.actual[str(i)*64],rb.SORTED)for i,name in enumerate(sorted(n.APP_NAMES|{'postgres'}),1)}
        self.selection={'issuer':'https://fixture.invalid','tenant':'fixture','subject':'fixture','extraIdentity':'must-be-included'}
        original={'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1','engine':engine,
            'authorization':{'plan':{'selection':self.selection}},'databasePlan':{
                'schema':'ouf.chatbot-cohort-database-plan.v1','postgresRuntimeBinding':pins['postgres'],
                'modules':[{'module':v,'schema':'ouf_'+v,'database':'db_'+v,'user':'role_'+v,'databaseOid':100+i}
                    for i,v in enumerate(sorted(n.APP_NAMES-{'gateway'}))]}}
        self.original=self.write(self.owner/'original.json',original)
        self.write(self.owner/'case.json',{'originalBinding':{'path':str(self.original),'sha256':hashlib.sha256(self.original.read_bytes()).hexdigest()}})
        plan={'engine':engine,'authorityDirectory':str(self.owner),'humanBinding':{'selectionHash':c.digest(self.selection)},
            'currentApplications':{k:v for k,v in pins.items()if k!='postgres'}}
        inputs={'privateFixture':True}
        packet={'schema':'ouf.ingestion-rollout-private-packet.v3','kind':'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY',
            'verifiedInputsHash':c.digest(inputs),'ownerPlanSha256':c.digest(plan),
            'expectedRuntimeBindings':{k:pins[k]for k in('ingestion','gateway')},
            **{k:False for k in('runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset','newLoginAllowed')}}
        result={'complete':True,'planHash':c.digest(plan)}
        self.case={'schema':'ouf.ingestion-rollout-retained-case.v1','purpose':'EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT',
            'runtimeAuthorityIssued':False,'budgetReset':False}
        for key,value in zip(('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'),(packet,inputs,plan,result)):
            p=self.write(self.owner/(key+'.json'),value);self.case[key]={'path':str(p),'sha256':c.digest(value)}
        self.closure='b'*64
        self.ns={'networkNamespace':{'device':12,'inode':34},'tcpListeners':[],'tcpProcessOwnershipProven':False}
    def write(self,p,v):p.write_bytes(c.encoded(v));p.chmod(0o600);return p
    def run_capture(self):
        with patch.object(n,'process_metadata',return_value=copy.deepcopy(self.ns)):
            return n.execute('capture',None,self.case,None,self.closure)
    def test_twelve_exact_gets_private_snapshots_no_auth_or_secret_output(self):
        before={p:p.read_bytes()for p in self.owner.iterdir()}
        result=self.run_capture();self.assertEqual(len(self.seen),12)
        expected={v['Id']for v in self.actual.values()}
        self.assertEqual({path.split('/')[-2]for _,path in self.seen},expected)
        self.assertTrue(all(method=='GET'and path.startswith('/v1.44/containers/')and path.endswith('/json')for method,path in self.seen))
        self.assertEqual(result['engineGetsReserved'],12);self.assertEqual(result['oauthRequests'],0)
        self.assertFalse(result['nativeProfilesCompiled']);self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertNotIn('never-print',json.dumps(result));self.assertEqual({p:p.read_bytes()for p in self.owner.iterdir()},before)
        context=Path(result['contextPath']);self.assertEqual(stat.S_IMODE(context.stat().st_mode),0o700)
        for p in context.iterdir():self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        self.assertIn('never-print',(context/'gateway.json').read_text())
        observed=n.execute('inspect',str(context),self.case,None,self.closure)
        self.assertTrue(observed['complete']);self.assertEqual(len(self.seen),12)
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):self.run_capture()
        self.assertEqual(len(self.seen),12)
    def test_lost_get_reservation_and_partial_context_retained_no_replay(self):
        self.fail_at=3
        with self.assertRaises(Exception):self.run_capture()
        context=n.CHECKPOINT['contextPath'];self.assertEqual(Journal(context).read()['engineGetsReserved'],3)
        result=n.execute('inspect',context,self.case,None,self.closure)
        self.assertFalse(result['complete']);self.assertEqual(result['engineGetsThisInvocation'],0)
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):self.run_capture()
        self.assertEqual(len(self.seen),3)
    def test_second_pass_restart_drift_does_not_finish(self):
        self.drift_at=8
        with self.assertRaisesRegex(c.Denied,'CAPTURE_RUNTIME_RESTART_CHANGED'):self.run_capture()
        row=Journal(n.CHECKPOINT['contextPath']).read();self.assertFalse(row['complete']);self.assertEqual(row['engineGetsReserved'],8)
    def test_full_original_selection_drift_before_any_get_or_new_context(self):
        original=json.loads(self.original.read_text());original['authorization']['plan']['selection'].pop('extraIdentity')
        self.write(self.original,original);capsule=self.owner/'case.json'
        self.write(capsule,{'originalBinding':{'path':str(self.original),'sha256':hashlib.sha256(self.original.read_bytes()).hexdigest()}})
        with self.assertRaisesRegex(c.Denied,'FULL_ORIGINAL_CAPTURE_SELECTION'):self.run_capture()
        self.assertFalse(self.seen);self.assertFalse(list(self.root.glob('ingestion-native-inputs-*')))
    def test_foreign_context_claim_cannot_be_used_for_inspection(self):
        result=self.run_capture();claim=next(self.root.glob('*.claim.json'));row=json.loads(claim.read_text());row['contextPath']=str(self.root/'foreign')
        self.write(claim,row)
        with self.assertRaisesRegex(c.Denied,'EXACT_CONSUMED_CAPTURE_CLAIM'):n.observe(result['contextPath'],self.case,self.closure)
        self.assertEqual(len(self.seen),12)
    def test_invalid_mode_context_shape_has_no_effects(self):
        for mode,context in[('capture','/foreign'),('inspect',None),('step',None)]:
            with self.subTest(mode=mode),self.assertRaises(c.Denied):n.execute(mode,context,self.case,None,self.closure)
        self.assertFalse(self.seen)
    def test_sealed_actual_capture_and_inspection_without_disk_imports(self):
        if not Path('/proc/self/ns/net').exists():self.skipTest('Actual proc namespace required; mandatory root Linux CI')
        raw,declaration=input_delivery.generate(ROOT,self.case);script=self.write(self.root/'sealed.py',{})
        script.write_bytes(raw)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'capture'],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);result=json.loads(run.stdout)
        self.assertTrue(result['complete']);self.assertEqual(len(self.seen),12)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'inspect',result['contextPath']],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertEqual(len(self.seen),12)
        self.assertNotIn('never-print',run.stdout);self.assertFalse(declaration['humanSessionImplementationIncluded'])
    def test_sealed_loader_denies_changed_case_before_any_read(self):
        raw,_=input_delivery.generate(ROOT,self.case)
        changed=raw.replace(b"'purpose': 'EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT'",b"'purpose': 'changed'",1)
        self.assertNotEqual(raw,changed);script=self.root/'changed.py';script.write_bytes(changed)
        run=subprocess.run([sys.executable,'-I','-B','-S',str(script),'capture'],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,2);self.assertEqual(json.loads(run.stdout)['reasonCode'],'CAPTURE_CASE_CHANGED')
        self.assertFalse(self.seen)
    def test_reproducible_delivery_and_no_auth_or_signing_sources(self):
        artifact=ROOT/'scripts/capture-ingestion-native-inputs-20261020.py'
        if artifact.exists():
            case=next(ast.literal_eval(v.value)for v in ast.parse(artifact.read_bytes()).body
                if isinstance(v,ast.Assign)and isinstance(v.targets[0],ast.Name)and v.targets[0].id=='CASE')
            raw,_=input_delivery.generate(ROOT,case);self.assertEqual(artifact.read_bytes(),raw)
        raw,declaration=input_delivery.generate(ROOT,self.case)
        self.assertEqual(input_delivery.generate(ROOT,self.case)[0],raw)
        self.assertFalse(any(v in ' '.join(declaration['sourceHashes'])for v in('human_session','signing','operator','window')))
        self.assertEqual(len(declaration['sourceHashes']),7)
    def test_owned_tcp_listener_metadata_is_exact_process_scoped(self):
        if not Path('/proc/self/ns/net').exists():self.skipTest('Actual proc namespace required; mandatory root Linux CI')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            observed=n.process_metadata(os.getpid());self.assertTrue(observed['tcpProcessOwnershipProven'])
            self.assertIn({'family':4,'addressHex':'0100007F','port':listener.getsockname()[1]},observed['tcpListeners'])

if __name__=='__main__':unittest.main()
