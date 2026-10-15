"""Masked failed timer and explicit pregrant continuation with real custody.

Systemctl/IAM-admin boundaries are simulated. Native Ed25519, filesystem fencing,
group10001 custody and issuer TLS/token publication are real in hosted CI.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch

import test_file_only_preparation
import test_policy_token_owner_installation as installation_fixture
import legacy_retirement as recovery
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence
from tools.semantic_policy_token_owner.owner_installation import AggregateAction,OwnerInstallation
from tools.semantic_policy_token_owner.producer import Binding
import legacy_retirement as legacy
import migration_root_custody as custody
import test_chatbot_cohort_predecessor as predecessor_fixture
from tools.chatbot_file_cohort import action_process as process
from tools.chatbot_file_cohort.gateway_runtime import PROFILE as GATEWAY_PROFILE,STEPS,runtime_scope
from image_custody import archive,native_identity,runtime_image_id,loaded
from image_import import Import
from engine_creation import Engine

class CompletedInfrastructure(unittest.TestCase):
    write=predecessor_fixture.Predecessor.write
    def setUp(self):
        predecessor_fixture.ImagePredecessor.setUp(self)
        self.engine_class=__import__('engine_creation').Engine
        self.engine_class.runtime_binding.side_effect=Engine.runtime_binding
        self.by_id={}
        for row in self.image_plan['images']:
            old=row['audit']
            with open(row['archivePath'],'rb') as stream:
                audit=archive(stream,old['archiveSha256'],old['imageId'],old['sourceCommit'])
            audit['nativeIdentity']=native_identity(audit);row['audit']=audit
            native={'Id':runtime_image_id(audit),'Os':'linux','Architecture':'amd64',
                'Config':copy.deepcopy(audit['imageConfig']),
                'RootFS':{'Type':'layers','Layers':[layer['diffId'] for layer in audit['layers']]}}
            self.by_id['/v1.44/images/'+native['Id']+'/json']=native
            record=Import.initial(audit,self.authority_hash)
            count=0 if row['module']=='semantic' else 1
            record.update(state='VERIFIED',version=1+count,effectAttemptCount=count,imageCustodyProven=True,
                nativeEvidenceHash=process.digest(loaded(audit,native)))
            self.write(Path(self.paths['image'+row['module'].capitalize()])/'recovery.json',record)
        self.old_gateway={'Id':'1'*64,'Image':'sha256:'+'2'*64,'Name':'/ouf-apisix-before-fixture',
            'Config':{'Env':['PRIVATE_GATEWAY_VALUE']},'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},
            'State':{'Running':False,'Paused':False,'Pid':0,'StartedAt':'old'},'Mounts':[],'NetworkSettings':{}}
        self.new_gateway=copy.deepcopy(self.old_gateway)
        self.new_gateway.update(Id='3'*64,Name='/ouf-apisix',RestartCount=0,
            State={'Running':True,'Paused':False,'Pid':42,'StartedAt':'new'})
        self.runtime={'schema':GATEWAY_PROFILE,'sameExistingImageRequired':True,
            'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False,
            'oldRuntimeBinding':Engine.runtime_binding(self.old_gateway),'oldName':'ouf-apisix',
            'retiredName':'ouf-apisix-before-fixture','oldHostConfig':copy.deepcopy(self.old_gateway['HostConfig']),
            'proposalKeyHash':'4'*64}
        scope=runtime_scope(self.runtime);self.review['scopes']['gatewayRuntimeInstallation']=scope
        self.review['scopes']['cohortImageImport']=predecessor_fixture.image_import_scope(self.image_plan)
        self.gateway={'schema':GATEWAY_PROFILE,'authorityHash':self.authority_hash,'planHash':scope['planHash'],
            'budgetReset':False,'version':19,'nextStep':8,'effects':[{'step':step,'state':'APPLIED',
                'intentHash':process.digest({'planHash':scope['planHash'],'step':step}),
                'evidence':{'containerId':self.new_gateway['Id'],'runtimeBinding':Engine.runtime_binding(self.new_gateway)}}
                for step in STEPS]}
        path=Path(self.paths['gatewayRuntime'])/'recovery.json';self.write(path,self.gateway)
        p=patch.object(recovery,'GATEWAY_RECORD_HASH',recovery.binding.sha(path.read_bytes()));p.start();self.addCleanup(p.stop)
        prepared={'imagePlan':self.image_plan,'gatewayRuntimePlan':self.runtime,
            'engine':{'socketPath':'/fixture-socket','socketBinding':[]}}
        self.review['privateInputHashes']['preparedInputs']=process.digest(prepared)
        bundle={'declaration':self.review['sourceClosure']['declaration'],'prepared':prepared}
        path=Path(self.plan['bundle']['path']);self.write(path,bundle)
        self.plan['bundle']['sha256']=recovery.binding.sha(path.read_bytes())
        self.by_id['/v1.44/containers/'+self.old_gateway['Id']+'/json']=self.old_gateway
        self.by_id['/v1.44/containers/'+self.new_gateway['Id']+'/json']=self.new_gateway
        def get(method,path):
            self.assertEqual(method,'GET');return (200,copy.deepcopy(self.by_id[path]))
        self.engine.request=get

    def test_all_completed_native_effects_are_read_without_modifying_old_files(self):
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        images,gateway,bindings=process.pregrant_native_readback(self.review,self.authority_hash)
        self.assertEqual([r['effectAttemptCount'] for r in images],[0,1,1,1,1])
        self.assertEqual(gateway['completedSteps'],list(STEPS));self.assertEqual(len(bindings),7)
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_changed_gateway_generation_denies_reuse(self):
        self.new_gateway['State']['Pid']+=1
        with self.assertRaisesRegex(Exception,'APISIX_GENERATION_DRIFT'):
            process.pregrant_native_readback(self.review,self.authority_hash)

    def test_changed_image_execution_config_denies_reuse(self):
        for path,native in self.by_id.items():
            if path.startswith('/v1.44/images/'):
                native['Config']['Env']=['UNREVIEWED_OVERRIDE'];break
        with self.assertRaisesRegex(Exception,'EXECUTION_CONFIG_DRIFT'):
            process.pregrant_native_readback(self.review,self.authority_hash)

    def test_incomplete_or_second_attempt_image_journal_is_not_replayed(self):
        path=Path(self.paths['imageUdp'])/'recovery.json';record=json.loads(path.read_bytes())
        record['effectAttemptCount']=2;self.write(path,record)
        with self.assertRaisesRegex(Exception,'STATE_INVALID'):
            process.pregrant_native_readback(self.review,self.authority_hash)

class Quiescence(unittest.TestCase):
    def rows(self):
        return {u:{'Id':u,'LoadState':'masked','UnitFileState':'masked','Job':'',
            'ActiveState':'failed' if u.endswith('.timer') else 'inactive',
            'SubState':'failed' if u.endswith('.timer') else 'dead',
            **({'MainPID':'0'} if u.endswith('.service') else {})} for u in legacy.UNITS}

    def test_actual_observed_terminal_failed_timer_is_quiescent_and_worker_uses_same_fence(self):
        rows=self.rows();self.assertTrue(legacy.quiescent(rows))
        with patch.object(LegacyWriterFence,'read_units',return_value=rows):self.assertTrue(LegacyWriterFence().guard())

    def test_active_pending_runtime_mask_missing_fields_or_service_pid_are_rejected(self):
        timer,service=legacy.UNITS
        for unit,key,value in ((timer,'ActiveState','active'),(timer,'SubState','waiting'),
            (timer,'Job','42'),(timer,'UnitFileState','masked-runtime'),(timer,'LoadState','loaded'),
            (service,'MainPID','123'),(service,'ActiveState','failed'),(service,'Job','9')):
            rows=self.rows();rows[unit][key]=value
            with self.subTest(unit=unit,key=key,value=value):self.assertFalse(legacy.quiescent(rows))
            self.assertEqual(legacy.quiescent(rows),LegacyWriterFence.quiescent(rows,legacy.UNITS))
        rows=self.rows();rows[timer].pop('Job');self.assertFalse(legacy.quiescent(rows))
        rows=self.rows();rows[service].pop('MainPID');self.assertFalse(legacy.quiescent(rows))

    def test_native_metadata_parser_requires_exact_units_and_retains_failed_state(self):
        raw='\n\n'.join('\n'.join(key+'='+value for key,value in row.items()) for row in self.rows().values())+'\n'
        def command(argv,**kwargs):
            self.assertEqual(argv[:2],['/usr/bin/systemctl','show'])
            self.assertIn('Job',argv[-1]);kwargs['stdout'].write(raw.encode())
            return subprocess.CompletedProcess(argv,0)
        with patch.object(legacy.subprocess,'run',side_effect=command):
            rows=legacy.read_units();self.assertEqual(rows,self.rows());self.assertTrue(legacy.quiescent(rows))

class SignedPregrantContinuation(installation_fixture.OwnerInstallationTest):
    # Keep the original full installer tests in their original suite only.
    def setUp(self):
        super().setUp()
        self.old=self.installation
        with patch.object(legacy,'quiescent',return_value=False),self.assertRaisesRegex(Exception,'RETIREMENT_QUIESCENCE_UNPROVEN'):
            self.old.install()
        self.f.state[legacy.UNITS[0]]=dict(self.f.state[legacy.UNITS[0]],ActiveState='failed',SubState='failed')
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)
        self.old_records={}
        root=self.f.f.root;context=root/'pregrant-fixture';context.mkdir(mode=0o700)
        self.old_scopes=self.old.scopes()
        self.old_scopes['finiteActionProcess']={'authorityDirectory':str(context)}
        review={'sourceClosure':{'declaration':{'sourceCommit':recovery.SOURCE}},'scopes':self.old_scopes}
        self.f.f.write(context/'review.json',recovery.binding.encoded(review))
        authority=self.old.action.authority_hash
        code=Path(self.f.r.paths['reviewedCode']);closure=self.old.scope['stageManifestHash']
        paths=recovery.names(self.old_scopes)
        hashes={key:recovery.binding.sha(paths[key].read_bytes()) for key in ('installation','retirement','output')}
        hashes['stageIntent']=recovery.binding.sha((code/('policy-token-source-stage-'+closure+'.intent')).read_bytes())
        hashes['stageIntake']=recovery.binding.sha((code/('semantic-native-v11-intake-'+closure)/'intake.json').read_bytes())
        roots={'ownerRecovery':(self.f.r.paths['durableRecovery'],0,0o700),
            'credential':(self.f.r.paths['ownerCredential'],0,0o700),
            'output':(str(self.old.output.path),10001,0o750)}
        for p in (patch.object(recovery,'REVIEW',recovery.digest(review)),patch.object(recovery,'AUTHORITY',authority),
            patch.object(recovery,'CONTEXT',context.name),patch.object(recovery,'CODE',code),
            patch.object(recovery,'RECORD_HASHES',hashes),patch.object(recovery,'ROOTS',roots)):
            p.start();self.addCleanup(p.stop)
        self.proof=recovery.observe(review,authority)
        self.old_records={binding['path']:Path(binding['path']).read_bytes()
            for binding in self.proof['recordBindings'].values()}
        # Distinct current source/authority; the predecessor's start/grant is
        # never used as a credential or execution authorization.
        self.f.f.expected['sourceClosureHash']='9'*64
        value=json.loads(self.f.f.authority);value['sourceClosureHash']='9'*64
        self.f.f.authority=recovery.binding.encoded(value)
        planned=self.successor()
        value.update(planned.scopes());self.f.f.authority=recovery.binding.encoded(value)
        self.f.f.approval['sourceClosureHash']='9'*64
        self.f.f.approval['executionAuthorityHash']=recovery.binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
        self.f.f.approved=recovery.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.continued=self.successor()

    def successor(self):
        f=self.f;action=AggregateAction(f.f.gate(),f.f.authority,f.f.expected['sourceClosureHash'])
        binding=Binding(f.server.profile.token_endpoint,'fixture-client','authorization.bundle.read',
            str(self.old.output.path),'token.jwt',10001)
        return OwnerInstallation(action,f.r.f.raw,f.root_hash,f.root_source,f.registration,binding,
            f.server.profile,f.transport,'b'*40,self.files,self.policy,'3'*64,'4'*64,60,f.clock,
            pregrant_recovery=self.proof)

    def test_completed_output_expired_creation_budget_and_retirement_are_observed_without_replay(self):
        before=len(self.f.commands)
        output=self.continued.output
        # Explicit observation has no mkdir or new creation deadline. The exact
        # original timestamps and consumed attempt are preserved in its receipt.
        old_output=json.loads(Path(self.proof['recordBindings']['output']['path']).read_bytes())
        with patch.object(custody,'time',types.SimpleNamespace(
                monotonic=lambda:old_output['expiresMonotonic']+1)):
            worker=self.continued.install()
        self.assertEqual(len(self.f.commands),before)
        self.assertEqual(self.grants(),1);self.assertEqual(self.f.calls.count(('create','/client-secret')),1)
        row=json.loads((self.f.f.root/output.name).read_bytes())
        self.assertEqual(row['createdMonotonic'],old_output['createdMonotonic'])
        self.assertEqual(row['expiresMonotonic'],old_output['expiresMonotonic'])
        self.assertEqual(output.scope['maximumMkdirAttempts'],0)
        self.assertEqual(self.continued.first.transaction.retirement.scope['maximumCommandAttempts'],0)
        self.assertEqual(self.continued.journal.read()['controlledCumulativeGrantAttempts'],1)
        for path,raw in self.old_records.items():self.assertEqual(Path(path).read_bytes(),raw)
        self.assertEqual(worker.tick()['state'],'ACTIVE')
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(self.grants(),1)

    def test_revoked_current_human_denies_before_continuation_or_grant(self):
        self.f.f.approval['state']='REVOKED'
        self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
        with self.assertRaises(Exception):self.continued.install()
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)
        self.assertFalse((self.f.f.root/self.continued.intent_name).exists())

    def test_changed_predecessor_or_consumed_grant_slot_cannot_be_adopted(self):
        path=Path(self.proof['recordBindings']['retirement']['path']);raw=path.read_bytes()
        self.f.f.write(path,raw+b'\n')
        with self.assertRaisesRegex(Exception,'PREGRANT_RETAINED_RECORD_DRIFT'):self.continued.install()
        self.f.f.write(path,raw)
        slot=Path(next(path for path in self.proof['absentRecords'] if 'first-gap-session-' in path))
        self.f.f.write(slot,b'{"attemptSlotsConsumed":1}')
        with self.assertRaisesRegex(Exception,'HISTORY_PRESENT'):self.continued.install()
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)

    def test_parallel_continuation_is_fenced_and_does_not_consume_slot(self):
        import fcntl
        path=self.f.f.root/(self.continued.intent_name+'.lock')
        fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.continued.install()
        finally:os.close(fd)
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)

    def test_new_queued_job_or_unmask_denies_before_continuation(self):
        timer=legacy.UNITS[0];before=dict(self.f.state[timer])
        for key,value in (('Job','42'),('UnitFileState','enabled'),('ActiveState','active')):
            self.f.state[timer]={**before,key:value}
            with self.subTest(key=key),self.assertRaisesRegex(Exception,'QUIESCENCE_REQUIRED'):
                self.continued.install()
            self.assertFalse((self.f.f.root/self.continued.intent_name).exists())
        self.f.state[timer]=before
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)

    def test_revocation_after_output_observation_preserves_receipts_without_issuer_effects(self):
        original=self.continued.pregrant_recovery.publish
        def publish(name,row):
            value=original(name,row)
            self.f.f.approval['state']='REVOKED'
            self.f.f.write(self.f.f.mandate,recovery.binding.encoded(self.f.f.approval))
            return value
        with patch.object(self.continued.pregrant_recovery,'publish',side_effect=publish),self.assertRaises(Exception):
            self.continued.install()
        self.assertTrue((self.f.f.root/self.continued.intent_name).exists())
        self.assertTrue((self.f.f.root/self.continued.output.name).exists())
        self.assertEqual(self.grants(),0);self.assertFalse(self.f.calls)
        for path,raw in self.old_records.items():self.assertEqual(Path(path).read_bytes(),raw)

# unittest otherwise repeats all inherited installer methods against the
# deliberately partially consumed fixture, obscuring their original contract.
for _name in list(installation_fixture.OwnerInstallationTest.__dict__):
    if _name.startswith('test_') and _name not in SignedPregrantContinuation.__dict__:
        setattr(SignedPregrantContinuation,_name,None)

if __name__=='__main__':unittest.main()
