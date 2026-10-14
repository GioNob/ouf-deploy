"""Actual signatures, private Journal and Unix-socket Engine; disposable Docker fixture.

This is failure/reconciliation qualification, not evidence from the VPS. Docker
and health state below are explicit test fixtures; no target runtime is touched.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

ROOT=Path(__file__).resolve().parents[1]
def component(path, sibling):
    return ROOT if (ROOT/path).is_file() else ROOT.parent/sibling
APP=component('tools/semantic_application_cutover/file_only_profile.py','file-profile-work')
TOKEN=component('tools/semantic_policy_token_owner/owner_installation.py','token-owner-installer-work')
sys.path[:0]=[str(ROOT),str(TOKEN),str(APP),str(ROOT/'tests'),str(APP/'tests'),
    str(TOKEN/'tools/semantic_policy_token_owner'),str(APP/'tools/semantic_application_cutover'),
    str(APP/'tools/semantic_database_cutover'),str(APP/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from tools.chatbot_file_cohort import containers as c, plan as p
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from engine_creation import Engine,CreationDenied
from tools.semantic_lease_recovery.recovery_journal import Journal
from test_chatbot_cohort_plan import fixture as container_fixture

class DockerFixture:
    """Native HTTP/Unix transport with in-memory Docker effects and ACK loss."""
    def __init__(self, root, originals, plan):
        self.state=copy.deepcopy(originals)
        self.plan=plan;self.calls=[];self.lose_ack=None;self.omit_effect=None
        self.serial=8
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.handle_request()
            def do_POST(self):self.handle_request()
            def handle_request(self):
                length=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(length)) if length else None
                status,result,drop=owner.request(self.command,self.path,body)
                if drop:
                    self.close_connection=True
                    return
                raw=json.dumps(result).encode() if result is not None else b''
                self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers()
                if raw:self.wfile.write(raw)
        self.socket_directory=tempfile.TemporaryDirectory(prefix='cs-',dir=ROOT.parent)
        self.path=Path(self.socket_directory.name)/'docker.sock'
        try:self.server=socketserver.UnixStreamServer(str(self.path),Handler)
        except PermissionError:
            if os.environ.get('OUF_NATIVE_SOCKETS')=='1':raise
            # Restricted local sandbox forbids AF_UNIX. CI sets the above
            # flag and therefore cannot silently substitute this I/O fixture.
            self.server=None;self.engine=Engine.__new__(Engine);self.engine.path=str(self.path)
            self.engine.check_socket=lambda:None
            def simulated(method,path,body=None):
                status,result,drop=self.request(method,path,body)
                if drop:raise CreationDenied('ENGINE_OUTCOME_REQUIRES_RECONCILIATION')
                return status,result
            self.engine.request=simulated
            return
        self.path.chmod(0o600)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        s=self.path.lstat()
        self.engine=Engine(str(self.path),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
    def close(self):
        if self.server is not None:
            self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        self.socket_directory.cleanup()
    def find(self,identity):
        return next((v for v in self.state.values() if v['Id']==identity or v['Name']=='/'+identity),None)
    def request(self,method,path,body):
        path=urlsplit(path);parts=path.path.split('/');identity=unquote(parts[3]);stage=parts[-1]
        if method=='GET':
            value=self.find(identity)
            return (200,copy.deepcopy(value),False) if value is not None else (404,None,False)
        if identity=='create':stage='create'
        self.calls.append((stage,identity,copy.deepcopy(body)))
        if self.omit_effect==stage:
            self.omit_effect=None
            return 500,None,False
        if stage=='rename':
            self.find(identity)['Name']='/'+parse_qs(path.query)['name'][0];status,result=204,None
        elif stage=='create':
            name=parse_qs(path.query)['name'][0]
            row=next(r for r in self.plan['replacements'] if r['name']==name)
            self.serial+=1;cid=format(self.serial,'064x')
            network=copy.deepcopy(body['NetworkingConfig']['EndpointsConfig']['ouf-backend'])
            network.update(IPAddress='172.20.0.'+str(self.serial),IPAMConfig=None)
            actual={'Id':cid,'Name':'/'+name,'Image':body['Image'],
                'Config':{k:copy.deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')},
                'HostConfig':copy.deepcopy(body['HostConfig']),'Mounts':copy.deepcopy(row['oldMounts']),
                'NetworkSettings':{'Networks':{'ouf-backend':network}},'RestartCount':0,
                'State':{'Status':'created','Running':False,'Paused':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}}
            actual['Config']['Hostname']=cid[:12]
            self.state[cid]=actual;status,result=201,{'Id':cid}
        elif stage=='start':
            self.find(identity)['State'].update(Status='running',Running=True,Pid=2000+self.serial,
                StartedAt='2026-10-14T03:00:%02dZ'%self.serial)
            status,result=204,None
        elif stage=='update':
            self.find(identity)['HostConfig']['RestartPolicy']=copy.deepcopy(body['RestartPolicy'])
            status,result=200,{}
        else:raise AssertionError(path)
        drop=self.lose_ack==stage
        if drop:self.lose_ack=None
        return status,result,drop

class CohortRuntime(unittest.TestCase):
    def fixture(self):
        f=crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        observed,images,packages={},{},{}
        for idx,name in enumerate(p.MODULES):
            old,image,package=container_fixture(name)
            old['Id']=str(idx+1)*64
            old['Config']['Hostname']=old['Id'][:12]
            old['RestartCount']=0
            observed[name],images[name],packages[name]=old,image,package
        for name in ('semantic','gateway'):packages[name]={'module':name,'cohortSourceLockSha256':'f'*64}
        manifest={'schema':'ouf.chatbot-file-cohort-package.v1','cohortId':'fixture','sourceLockSha256':'f'*64,
                  'modules':[dict(v,files={}) for v in packages.values()]}
        plan=p.compile_cohort(manifest,observed,images,packages,{n:{} for n in p.MODULES},'1'*64,'2'*64,'3'*64)
        raw=json.loads(f.authority);raw['applicationCohortInstallation']=c.installation_scope(plan)
        f.authority=crypto.encoded(raw);f.approval['executionAuthorityHash']=crypto.sha(f.authority)
        f.write(f.mandate,crypto.encoded(f.approval));f.approved=crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        # The preceding Registry quiescence owner stopped exactly the reviewed old generations.
        for old in observed.values():
            old['HostConfig']['RestartPolicy']=copy.deepcopy(p.NO_RESTART)
            old['State'].update(Running=False,Pid=0,Status='exited')
        native=DockerFixture(f.root,{x['Id']:x for x in observed.values()},plan)
        self.addCleanup(native.close)
        directory=f.root/'cohort-journal';directory.mkdir(mode=0o700)
        now=[10000.0]
        owner=c.CohortContainers(action,native.engine,Journal(directory),plan,lambda:now[0])
        owner.initialize()
        for name,key in (('registry','registryModulePackageHash'),('database','databasePlanHash'),
                         ('authorization','authorizationPlanHash'),('gateway','gatewayPlanHash')):
            owner.accept_owner_gate(name,plan[key],p.digest({'fixtureOwner':name}))
        owner.health=lambda row,actual:{'fixtureReadiness':row['module']}
        return owner,native,f,now

    def restart(self,owner):
        other=c.CohortContainers(owner.action,owner.engine,Journal(owner.journal.root),owner.plan,owner.clock)
        other.health=owner.health
        return other

    def test_four_replacements_preserve_data_and_secrets_retire_olds_and_do_not_replay(self):
        owner,native,_,_=self.fixture()
        result=owner.run_until('onboarding')
        self.assertEqual(result['completedEffects'],10)
        result=self.restart(owner).run_until('mcp')
        self.assertTrue(result['allFourReplacementsVerified']);self.assertTrue(result['notReleaseAcceptance'])
        self.assertEqual(len(native.calls),16)
        owner.run_until('mcp');self.assertEqual(len(native.calls),16)
        self.assertEqual(len(owner.verify_all()['members']),4)
        for row in owner.plan['replacements']:
            old=native.find(row['oldRuntimeBinding']['containerId']);new=native.find(row['name'])
            self.assertFalse(old['State']['Running']);self.assertEqual(old['HostConfig']['RestartPolicy'],p.NO_RESTART)
            self.assertEqual(new['Mounts'],row['oldMounts'])
            self.assertIn('PASSWORD=private-value',new['Config']['Env'])
            self.assertEqual(new['HostConfig']['RestartPolicy'],row['restoreRestartPolicy'])
        self.assertNotIn('private-value',json.dumps(result))

    def test_lost_mutation_ack_reconciles_each_effect_without_replay(self):
        for stage in ('rename','create','start','update'):
            with self.subTest(stage=stage):
                owner,native,_,_=self.fixture();native.lose_ack=stage
                with self.assertRaises(CreationDenied):owner.run_until('onboarding')
                self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')
                self.restart(owner).run_until('onboarding')
                self.assertEqual([x[0] for x in native.calls].count(stage),2)
                self.assertEqual(len(native.calls),8)

    def test_crash_after_effect_before_observation_never_repeats_native_mutation(self):
        owner,native,_,_=self.fixture();observe=owner.observe
        def crash(row,stage):
            if stage=='start':raise RuntimeError('disposable crash after acknowledged start')
            return observe(row,stage)
        owner.observe=crash
        with self.assertRaisesRegex(RuntimeError,'disposable crash'):owner.run_until('onboarding')
        restarted=self.restart(owner);restarted.run_until('onboarding')
        self.assertEqual(len(native.calls),8)

    def test_unknown_mutation_does_not_retry_or_restore_old_data(self):
        owner,native,_,_=self.fixture();native.omit_effect='create'
        with self.assertRaisesRegex(p.PlanDenied,'CREATION_REQUIRES'):owner.run_until('onboarding')
        calls=copy.deepcopy(native.calls)
        with self.assertRaises(c.CohortPaused):self.restart(owner).run_until('onboarding')
        self.assertEqual(native.calls,calls)
        old=native.find('1'*64);self.assertFalse(old['State']['Running'])
        self.assertEqual(old['Mounts'][0]['Source'],'/private/data')

    def test_transient_readiness_and_crash_preserve_budget_and_retry_time(self):
        owner,native,_,now=self.fixture();reads=[]
        def transient(row,actual):reads.append(row['module']);return None
        owner.health=transient
        with self.assertRaisesRegex(c.CohortPaused,'TRANSIENT'):owner.run_until('onboarding')
        budget=owner.record()['readiness']['udp'];self.assertEqual(budget['attempts'],1)
        restarted=self.restart(owner)
        with self.assertRaisesRegex(c.CohortPaused,'WAIT'):restarted.run_until('onboarding')
        self.assertEqual(reads,['udp']);self.assertEqual(len(native.calls),3)
        now[0]=budget['nextAttemptAt']
        def interrupted(row,actual):raise RuntimeError('fixture interrupted GET')
        restarted.health=interrupted
        with self.assertRaises(RuntimeError):restarted.run_until('onboarding')
        budget=restarted.record()['readiness']['udp'];self.assertEqual(budget['attempts'],2)
        resumed=self.restart(restarted)
        with self.assertRaisesRegex(c.CohortPaused,'WAIT'):resumed.run_until('onboarding')
        self.assertEqual(len(native.calls),3)
        now[0]=budget['nextAttemptAt'];resumed.health=lambda r,a:{'fixture':'UP'}
        resumed.run_until('onboarding');self.assertEqual(resumed.record()['readiness']['udp']['attempts'],3)
        self.assertEqual(len(native.calls),8)

    def test_readiness_attempt_cap_elapsed_cap_and_response_duration_are_durable(self):
        for kind in ('attempts','elapsed','duration'):
            with self.subTest(kind=kind):
                owner,native,_,now=self.fixture();owner.health=lambda r,a:None
                with self.assertRaises(c.CohortPaused):owner.run_until('onboarding')
                previous=owner.record();following=copy.deepcopy(previous)
                budget=following['readiness']['udp']
                if kind=='attempts':budget['attempts']=128;now[0]=budget['nextAttemptAt']
                else:now[0]=budget['firstAttemptAt']+3599+(kind=='elapsed')
                owner.journal.compare_and_save(previous,following)
                if kind=='duration':
                    def slow(r,a):now[0]+=2;return {'fixture':'UP'}
                    owner.health=slow
                with self.assertRaisesRegex(c.CohortPaused,'BUDGET_EXHAUSTED'):owner.run_until('onboarding')
                self.assertEqual(len(native.calls),3)
                with self.assertRaises(c.CohortPaused):self.restart(owner).run_until('onboarding')
                self.assertEqual(owner.record()['nextStep'],3)

    def test_matching_name_replacement_or_restarted_process_cannot_be_adopted(self):
        for kind in ('container','process'):
            with self.subTest(kind=kind):
                owner,native,_,_=self.fixture();original=owner.observe
                stop='create' if kind=='container' else 'start'
                def crash(row,stage):
                    if stage==stop:
                        proof=original(row,stage)
                        prior=owner.record();following=copy.deepcopy(prior)
                        following['effects'][-1].update(state='APPLIED',evidence=proof,evidenceHash=p.digest(proof))
                        following['nextStep']+=1;owner.save(prior,following)
                        raise RuntimeError('fixture crash after durable effect')
                    return original(row,stage)
                owner.observe=crash
                with self.assertRaises(RuntimeError):owner.run_until('onboarding')
                candidate=native.find('ouf-udp')
                if kind=='container':candidate['Id']='f'*64
                else:candidate['State']['Pid']+=1;candidate['State']['StartedAt']='2026-10-14T04:00:00Z'
                calls=copy.deepcopy(native.calls)
                with self.assertRaisesRegex(p.PlanDenied,'GENERATION_CHANGED'):self.restart(owner).run_until('onboarding')
                self.assertEqual(native.calls,calls)

    def test_revoked_or_corrupt_signed_authority_denies_before_effect(self):
        for kind in ('human','signature','scope'):
            with self.subTest(kind=kind):
                owner,native,f,_=self.fixture()
                if kind=='human':f.approval['state']='REVOKED';f.write(f.mandate,crypto.encoded(f.approval))
                elif kind=='signature':
                    path=f.signatures/(crypto.sha(f.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')
                    value=json.loads(path.read_bytes());value['signature']='0'*128;f.write(path,crypto.encoded(value))
                else:owner.plan['replacements'][0]['creationRequest']['Env'].append('DRIFT=yes')
                with self.assertRaises(Exception):owner.run_until('onboarding')
                self.assertEqual(native.calls,[])

    def test_retained_intent_or_evidence_drift_is_not_silently_accepted(self):
        for field in ('intentHash','evidenceHash'):
            with self.subTest(field=field):
                owner,native,_,_=self.fixture();owner.run_until('onboarding')
                prior=owner.record();following=copy.deepcopy(prior);following['effects'][0][field]='0'*64
                owner.journal.compare_and_save(prior,following);calls=len(native.calls)
                with self.assertRaisesRegex(p.PlanDenied,'RETAINED_.*DRIFT'):owner.run_until('mcp')
                self.assertEqual(len(native.calls),calls)

    def test_incomplete_owner_gates_block_the_dependent_cohort(self):
        owner,native,_,_=self.fixture();prior=owner.record();following=copy.deepcopy(prior)
        following['gates'].pop('gateway');owner.journal.compare_and_save(prior,following)
        owner.run_until('onboarding')
        with self.assertRaisesRegex(p.PlanDenied,'OWNER_NOT_RECONCILED'):owner.run_until('mcp')
        self.assertEqual(len(native.calls),8)

if __name__=='__main__':unittest.main()
