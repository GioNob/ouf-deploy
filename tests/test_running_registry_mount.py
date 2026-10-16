"""Native hardened running process, read-only mount and real signed TLS owner.

Docker effect receipts are synthetic fixture observations; process identity,
mount namespace, current token admission and revocation are native.
"""
import copy,os,signal,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_containers as bootstrap
import test_policy_token_mount_owner_integration as prior
import gated_process_observation as process_module
from engine_creation import Engine
from transition_journal import Transition,digest
from native_evidence_store import NativeEvidenceStore
from gated_creation_plan import ENTRY
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation

class RunningMount(unittest.TestCase):
    def setUp(self):
        h=prior.MountedOwnerIntegration();self.addCleanup(h.doCleanups)
        command=['/usr/bin/python3','-I','-B','-c','import signal\nwhile True: signal.pause()']
        argv=['/usr/bin/setpriv','--reuid=10001','--regid=10001','--clear-groups','--bounding-set=-all','--no-new-privs',*command]
        helper=prior.HELPER.replace('print(os.getpid(),flush=True)',
            'signal.signal(signal.SIGUSR1,lambda *_:os.execv("/usr/bin/setpriv",'+repr(argv)+'))\nprint(os.getpid(),flush=True)')
        with patch.object(prior,'HELPER',helper):h.setUp()
        self.h=h;pid=h.generation['pid'];os.kill(pid,signal.SIGCONT);os.kill(pid,signal.SIGUSR1)
        request={'User':'10001:10001','Entrypoint':ENTRY,'Cmd':command}
        observer=process_module.GatedProcessObservation(request);deadline=time.monotonic()+5
        while True:
            try:
                observed=observer.observe(pid)
                if observed['processKind']=='APPLICATION_RUNNING':break
            except ValueError:pass
            if time.monotonic()>=deadline:self.fail('hardened running fixture did not exec')
            time.sleep(.02)
        self.state={'Id':'1'*64,'Image':'sha256:'+'2'*64,'Config':request,'HostConfig':{},'Mounts':[],
            'NetworkSettings':{},'RestartCount':0,'State':{'Pid':pid,'StartedAt':'synthetic-docker-receipt',
                'Running':True,'Paused':False,'Status':'running'}}
        engine=Engine.__new__(Engine);engine.inspect=lambda _:copy.deepcopy(self.state)
        engine.matching_configuration=lambda t,r,a:a
        self.transition=Transition.__new__(Transition)
        self.row={'nextPhase':10,'creationRequestHash':digest(request),'effects':[
            {'phase':'START_REPLACEMENT','state':'APPLIED','nativeEvidenceHash':'a'*64},
            {'phase':'VERIFY_APPLICATION','state':'APPLIED','nativeEvidenceHash':'b'*64}]}
        self.transition.read=lambda:copy.deepcopy(self.row)
        store=NativeEvidenceStore.__new__(NativeEvidenceStore)
        release={'runtimeBinding':engine.runtime_binding(self.state),'generation':observed['generation']}
        store.read=lambda phase,hash:copy.deepcopy(release)
        self.binding=process_module.RunningWorkloadBinding(engine,self.transition,request,store)
        self.generation=generation(pid,allow_frozen=True)
    def observe(self):
        h=self.h
        return RenewableTokenMountObservation(h.policy,h.reader,time.monotonic()+20,running_binding=self.binding).observe(self.generation)
    def test_running_mount_requires_typed_verified_binding_and_current_owner(self):
        result=self.observe();self.assertTrue(result['currentOwnerAdmissionObserved']);self.h.unchanged()
        with self.assertRaisesRegex(ValueError,'PAUSED_PROCESS_REQUIRED'):
            RenewableTokenMountObservation(self.h.policy,self.h.reader,time.monotonic()+20).observe(self.generation)
        with self.assertRaises(Exception):
            RenewableTokenMountObservation(self.h.policy,self.h.reader,time.monotonic()+20,running_binding=SimpleNamespace(observe=self.binding.observe))
    def test_restarted_unverified_or_changed_process_is_denied(self):
        self.state['RestartCount']=1
        with self.assertRaises(Exception):self.observe()
        self.state['RestartCount']=0;self.row['nextPhase']=9
        with self.assertRaises(Exception):self.observe()
        self.h.unchanged()
    def test_current_human_revocation_during_introspection_denies_running_mount(self):
        def revoke():self.h.f.mandate.write_bytes(b'{}')
        self.h.server.after=revoke
        with self.assertRaises(Exception):self.observe()
        self.h.unchanged()
    def test_process_stopped_during_introspection_denies_running_mount(self):
        def stop():os.kill(self.generation['pid'],signal.SIGSTOP)
        self.h.server.after=stop
        with self.assertRaises(Exception):self.observe()
        self.h.unchanged()

if __name__=='__main__':unittest.main()
