"""Durable finite Registry waits; clocks and remote observations are synthetic.

The actual delivery functions are compiled from source and use real private
Journal files. Native Docker effects/signatures are qualified separately.
"""
import ast
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover')]
import test_chatbot_cohort_containers as fixture_bootstrap
from tools.chatbot_file_cohort.containers import RegistryReadinessBudget,REGISTRY_READINESS_POLICY
from tools.chatbot_file_cohort.plan import digest,require,PlanDenied
from tools.semantic_lease_recovery.recovery_journal import Journal
from cutover_executor import CutoverDenied

class RegistryWait(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700);self.now=[1000000.,1000.]
        self.scope={'readinessPolicy':copy.deepcopy(REGISTRY_READINESS_POLICY)}
        self.journal=Journal(self.root)
    def budget(self,**kw):
        return RegistryReadinessBudget(self.journal,digest(self.scope),'a'*64,1003600,
            clock=lambda:tuple(self.now),boot=kw.pop('boot','fixture-boot'),**kw)
    def advance(self,seconds):self.now[:]=[v+seconds for v in self.now]
    def functions(self):
        source=ast.parse((ROOT/'tools/chatbot_file_cohort/delivery.py').read_text())
        transient=next(x for x in source.body if isinstance(x,ast.FunctionDef) and x.name=='transient_registry_observation')
        cls=next(x for x in source.body if isinstance(x,ast.ClassDef) and x.name=='Delivery')
        wait=next(x for x in cls.body if isinstance(x,ast.FunctionDef) and x.name=='await_registry')
        def budget(journal,*args):return RegistryReadinessBudget(journal,*args,clock=lambda:tuple(self.now),boot='fixture-boot')
        ns={'CutoverDenied':CutoverDenied,'digest':digest,'require':require,'RegistryReadinessBudget':budget,
            'REGISTRY_READINESS_POLICY':REGISTRY_READINESS_POLICY,'Journal':Journal,
            'evidence':types.SimpleNamespace(decode=json.loads)}
        exec(compile(ast.Module(body=[transient,wait],type_ignores=[]),'actual-registry-delivery-functions','exec'),ns)
        return ns
    def test_verified_running_recovery_waits_read_only_with_retry_after(self):
        from tools.chatbot_file_cohort.backup_recovery import RegistryRecoveryReadinessPending,PROFILE
        ns=self.functions();owner,app,*rest=self.fixture(phases=())
        row={'state':'READY','nextPhase':10,'effects':[]}
        app.executor.t.read=lambda:row
        app.executor.aggregate_scope={'postGrantRecovery':{'profile':PROFILE}}
        app.executor.adapters['VERIFY_APPLICATION'].channel=types.SimpleNamespace(retry_after_seconds=0)
        calls=[]
        def verify():
            calls.append(self.now[0])
            if len(calls)<3:raise RegistryRecoveryReadinessPending(45)
            return {'freshReadiness':True}
        app.verify_registry_and_hold=verify
        result=ns['await_registry'](owner,app,str(self.root))
        self.assertEqual(result,{'freshReadiness':True})
        self.assertEqual(len(calls),3)
        self.assertTrue(all(b-a>=45 for a,b in zip(calls,calls[1:])))

    def test_running_readiness_error_is_not_retryable_at_other_boundaries(self):
        from tools.chatbot_file_cohort.backup_recovery import RegistryRecoveryReadinessPending,PROFILE
        ns=self.functions();_,app,*_=self.fixture(phases=())
        app.executor.aggregate_scope={'postGrantRecovery':{'profile':PROFILE}}
        for state,cursor in [('IN_FLIGHT',10),('READY',9),('COMPLETED',11)]:
            app.executor.t.read=lambda:{'state':state,'nextPhase':cursor}
            self.assertIsNone(ns['transient_registry_observation'](app,RegistryRecoveryReadinessPending(0)))

    def fixture(self,phases=('START_REPLACEMENT','VERIFY_APPLICATION')):
        row={'state':'READY','effects':[]};calls=[];side_effects=[];reports=[];revoked=[False]
        native={'State':{'Running':True,'Paused':False,'Status':'running'}}
        process={'processKind':'GATE_WAITING'}
        def current(intent):
            if intent=='START_REPLACEMENT':return row,copy.deepcopy(native),copy.deepcopy(process)
            return {'sameGeneration':True}
        executor=types.SimpleNamespace(t=types.SimpleNamespace(read=lambda:copy.deepcopy(row)),
            adapters={phase:types.SimpleNamespace(current=current) for phase in ('START_REPLACEMENT','VERIFY_APPLICATION')},
            intents={phase:phase for phase in ('START_REPLACEMENT','VERIFY_APPLICATION')})
        def verify():
            calls.append('observe')
            if len(calls)==1:side_effects.extend(('create','start','SIGUSR1'))
            if len(calls)<=len(phases):
                phase=phases[len(calls)-1]
                evidence=({'preapplicationReleaseUnproven':True,'unpauseReplayAllowed':False,'signalReplayAllowed':False}
                    if phase=='START_REPLACEMENT' else {'applicationReadinessUnproven':True,
                        'readOnlyReconciliationRequired':True,'dependentProducersRemainQuiesced':True})
                row.update(state='IN_FLIGHT',effects=[{'phase':phase,'nativeEvidenceHash':digest(evidence)}])
                raise CutoverDenied('NATIVE_AMBIGUITY_OR_NO_EFFECT_STOPS_CUTOVER')
            return {'verified':True}
        app=types.SimpleNamespace(executor=executor,verify_registry_and_hold=verify)
        def guard(active):
            if revoked[0]:raise ValueError('CURRENT_FULL_ACTION_AUTHORITY_REQUIRED')
        owner=types.SimpleNamespace(review={'scopes':{'applicationRegistryCutover':self.scope}},
            action=types.SimpleNamespace(authority_hash='a'*64,raw=b'{"expiresAt":1003600}'),
            current=guard,wait=lambda delay,active:self.advance(delay),report=lambda phase,**facts:reports.append((phase,facts)))
        return owner,app,calls,side_effects,reports,revoked,native,process
    def test_exec_and_http_startup_waits_share_durable_budget_without_repeating_effects(self):
        ns=self.functions();owner,app,calls,effects,reports,*_=self.fixture()
        self.assertEqual(ns['await_registry'](owner,app,self.root),{'verified':True})
        self.assertEqual(effects,['create','start','SIGUSR1']);self.assertEqual(len(calls),3)
        row=self.journal.read();self.assertEqual(row['attempts'],3);self.assertEqual(row['state'],'COMPLETE')
        self.assertEqual([x[1]['registryPhase'] for x in reports],['START_REPLACEMENT','VERIFY_APPLICATION'])
        self.assertGreaterEqual(self.now[0],1000020);self.assertLessEqual(self.now[0],1000024)
    def test_authority_revoked_while_waiting_prevents_another_observation_or_effect(self):
        ns=self.functions();owner,app,calls,effects,reports,revoked,*_=self.fixture()
        def wait(delay,active):self.advance(delay);revoked[0]=True
        owner.wait=wait
        with self.assertRaisesRegex(ValueError,'CURRENT_FULL_ACTION_AUTHORITY_REQUIRED'):ns['await_registry'](owner,app,self.root)
        self.assertEqual(len(calls),1);self.assertEqual(effects,['create','start','SIGUSR1'])
        self.assertEqual(self.journal.read()['state'],'RETRY_WAIT')
    def test_unknown_outcome_paused_generation_or_integrity_error_never_enters_wait(self):
        for scenario in ('unknown','paused','integrity'):
            ns=self.functions();owner,app,calls,effects,reports,revoked,native,process=self.fixture()
            if scenario=='unknown':
                app.verify_registry_and_hold=lambda:(_ for _ in ()).throw(CutoverDenied('OTHER_NATIVE_FAILURE'))
            elif scenario=='paused':native['State']['Paused']=True
            else:
                app.executor.adapters['START_REPLACEMENT'].current=lambda intent:(_ for _ in ()).throw(ValueError('UNCLASSIFIED_PROCESS_INTEGRITY_ERROR'))
            with self.subTest(scenario=scenario),self.assertRaises((ValueError,CutoverDenied)):ns['await_registry'](owner,app,self.root)
            self.assertEqual(reports,[])
            # Distinct fixture directory; consumed ATTEMPTING is never reset.
            self.assertEqual(self.journal.read()['state'],'ATTEMPTING')
            for p in self.root.iterdir():p.unlink()
    def test_crash_does_not_refund_attempt_or_reinitialize_budget(self):
        b=self.budget();b.initialize();b.reserve();raw=self.journal.record.read_bytes()
        restarted=self.budget();restarted.initialize()
        with self.assertRaisesRegex(PlanDenied,'NO_REPLAY'):restarted.reserve()
        self.assertEqual(self.journal.record.read_bytes(),raw)
        with self.assertRaises(PlanDenied):self.budget(boot='another-boot').initialize()
    def test_hours_of_outage_exhausts_same_deadline_and_cannot_reset_on_restart(self):
        b=self.budget();row=b.initialize();deadline=row['expiresAt'];attempts=0
        while True:
            try:b.reserve()
            except PlanDenied as error:
                self.assertIn('BUDGET_EXHAUSTED',str(error));break
            attempts+=1
            try:b.schedule('VERIFY_APPLICATION')
            except PlanDenied:break
            self.advance(b.wait_seconds())
        self.assertEqual(self.journal.read()['state'],'PAUSED_EXHAUSTED')
        self.assertEqual(self.journal.read()['expiresAt'],deadline);self.assertLessEqual(attempts,128)
        restarted=self.budget();restarted.initialize()
        with self.assertRaises(PlanDenied):restarted.reserve()
        self.assertEqual(self.journal.read()['attempts'],attempts)
    def test_retry_after_is_respected_and_never_shortened_to_fit_authority(self):
        from application_verification_adapter import ApplicationReadinessChannel,retry_after_delay
        from unittest.mock import patch
        delay=retry_after_delay('90',self.now[0]);self.assertEqual(delay,90)
        b=self.budget();b.initialize();b.reserve();b.schedule('VERIFY_APPLICATION',delay)
        self.assertEqual(b.wait_seconds(),90)
        self.advance(90);b.reserve()
        with self.assertRaisesRegex(PlanDenied,'RETRY_AFTER_EXCEEDS_BUDGET'):b.schedule('VERIFY_APPLICATION',3600)
        self.assertEqual(self.journal.read()['state'],'PAUSED_EXHAUSTED')
        self.assertEqual(retry_after_delay('Thu, 01 Jan 1970 00:00:00 GMT',self.now[0]),0)
        for value in ('invalid','NaN','-1','1'*129):
            with self.assertRaises(ValueError):retry_after_delay(value,self.now[0])
        class Reply:
            status=503
            def read(self,limit):return b'{}'
            def getheader(self,name):return '90'
        class Client:
            def __init__(self,*args,**kw):self.closed=False
            def request(self,*args,**kw):pass
            def getresponse(self):return Reply()
            def close(self):self.closed=True
        channel=object.__new__(ApplicationReadinessChannel)
        channel.scope={'health':{'address':'192.168.1.1','port':8080,'path':'/actuator/health','timeoutSeconds':5}}
        channel.exact=lambda:None
        with patch('application_verification_adapter.http.client.HTTPConnection',Client):
            self.assertIsNone(channel.health());self.assertEqual(channel.retry_after_seconds,90)

    def test_cas_conflict_clock_regression_and_expired_success_are_not_repaired(self):
        b=self.budget();b.initialize();before=b.record();b.reserve()
        with self.assertRaises(ValueError):b.save(before,state='RETRY_WAIT')
        self.now[1]-=1
        with self.assertRaises(PlanDenied):b.record()
        self.now[1]+=1;self.advance(3601)
        with self.assertRaisesRegex(PlanDenied,'DEADLINE'):b.complete()

if __name__=='__main__':unittest.main()
