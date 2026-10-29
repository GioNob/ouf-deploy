import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('composition',ROOT/'compose.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def setUp(self):
        self.case=json.loads((ROOT/'case.json').read_text())
        self.rid='a'*64;self.gid='b'*64;self.iid='sha256:'+'c'*64
        self.registry={'Id':self.rid,'Image':self.iid,'Config':{'User':'10001:10001'},'HostConfig':{},
            'State':{'Status':'exited','Running':False,'Pid':0},'NetworkSettings':{},'RestartCount':0}
        self.bindings=[{'source':'/fixture/'+name,'target':'/run/'+name,'readOnly':True} for name in ('key','receipt','db','token')]
        self.registry['Mounts']=[{'Source':b['source'],'Destination':b['target'],'RW':False,'Type':'bind'} for b in self.bindings]
        self.gateway=copy.deepcopy(self.registry)
        self.gateway.update(Id=self.gid,State={'Status':'running','Running':True,'Pid':22,'StartedAt':'fixture'})
        pin={'containerId':self.rid,'imageId':self.iid,'stableMetadataHash':m.digest(m.stable_fields(self.registry)),
            'mountsHash':m.digest(sorted(self.registry['Mounts'],key=lambda x:x['Destination']))}
        gpin={'containerId':self.gid,'imageId':self.iid,'pid':22,'startedAt':'fixture'}
        for actual,dest in ((self.registry,pin),(self.gateway,gpin)):
            for field,key in [('Config','configHash'),('HostConfig','hostConfigHash'),('NetworkSettings','networkSettingsHash')]:
                dest[key]=m.digest(actual[field])
        proposal={'schema':'ouf.semantic-registry-blocked-recovery-proposal.v1','registry':pin,
            'requiredGates':list(m.GATES),'unresolvedGateCount':8,'gatewayBinding':gpin,
            'engineBinding':{'socketPath':'/fixture/engine.sock','socketBinding':[1,2,0,0,0o660]},
            **{k:False for k in ('nativeExecutorQualified','runtimeAuthorityIssued','targetApplyAuthorized',
                                'providerRecoveryProposed','automaticReplayAllowed','budgetReset')}}
        history={'historicalDeploymentChainBound':True,'proposalConfigHashMatchesHistoricalVerified':True,
            'finiteProcessClaimRemainsConsumed':True,'historicalAuthorityReactivated':False,'oldProcessGenerationReusable':False}
        self.audit={'imageId':self.iid,'configSha256':'c'*64,'configBytes':420,'layers':[
            {'blobSha256':'d'*64,'diffId':'sha256:'+'e'*64,'archiveBytes':1234}],
            'sourceCommit':'f'*40,'archiveSha256':'1'*64,'imageConfig':{'User':'10001:10001'}}
        self.image={'Id':self.iid,'Os':'linux','Architecture':'amd64','Config':copy.deepcopy(self.audit['imageConfig']),
                    'RootFS':{'Type':'layers','Layers':[r['diffId'] for r in self.audit['layers']]}}
        recipe={'launch':{'sources':self.bindings[:2],'manifest':{'mounts':copy.deepcopy(self.bindings)}},
                'renewableToken':{k:self.bindings[3][k] for k in ('source','target')}}
        self.inputs={'schema':'ouf.semantic-registry-recovery-private-historical-inputs.v1',
            'kind':'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY','proposal':proposal,
            'proposalHash':m.digest(proposal),'historicalBinding':history,
            'historicalTransition':{'predecessorIncidentRef':'2'*64},
            'registryInputs':{'imageAudit':self.audit,'nodeRecipe':recipe,'configtree':self.bindings[2]},
            'historicalGateReconciled':m.GATES[0],'unresolvedGateCount':7,
            **{k:False for k in ('nativeExecutorQualified','runtimeAuthorityIssued','targetApplyAuthorized',
                'currentRegistryIdentityEstablished','oldAuthorityIsCurrent','providerRecoveryProposed',
                'automaticReplayAllowed','budgetReset','releaseAcceptance')},
            **{k:0 for k in ('oauthRequests','engineGets','databaseCalls','credentialFilesOpened')}}
        self.inputs['candidateContract']=m.candidate_contract(proposal,m.digest(history),'2'*64)
        self.repin()

    def repin(self):
        self.case['proposalHash']=self.inputs['proposalHash']=m.digest(self.inputs['proposal'])
        self.case['inputsHash']=m.digest(self.inputs)

    def run_capture(self,change=None,read_change=False):
        self.paths=[];reads=[0]
        sequence=[self.gateway,self.registry,self.image,self.image,self.registry,self.gateway]
        if change:sequence[change[0]]=copy.deepcopy(sequence[change[0]]);change[1](sequence[change[0]])
        def get(engine,path):
            self.paths.append(path);engine.calls+=1
            return m.encoded(sequence[engine.calls-1])
        def read(path):
            reads[0]+=1
            return self.inputs,m.encoded(self.inputs)+(b' ' if read_change and reads[0]==2 else b'')
        with patch.object(m.BaseEngine,'get',get),patch.object(m,'private_json',read):return m.capture(self.case)

    def test_six_gets_and_seven_gates_remain(self):
        result,calls=self.run_capture()
        self.assertEqual(calls,6)
        self.assertEqual(self.paths,[f'/v1.44/containers/{self.gid}/json',f'/v1.44/containers/{self.rid}/json',
            f'/v1.44/images/{self.iid}/json',f'/v1.44/images/{self.iid}/json',
            f'/v1.44/containers/{self.rid}/json',f'/v1.44/containers/{self.gid}/json'])
        self.assertEqual(result['unresolvedGateCount'],7)
        for key in ('nativeExecutorQualified','runtimeAuthorityIssued','targetApplyAuthorized','completeCurrentOciProven',
                    'currentRegistryIdentityEstablished','currentTokenAdmissionProven','imageLayerBytesReaudited'):
            self.assertIs(result[key],False)
        self.assertNotIn('/fixture/key',json.dumps(result))

    def test_mismatched_retained_hash_stops_before_engine(self):
        self.case['inputsHash']='0'*64
        with self.assertRaisesRegex(m.Stop,'RETAINED_INPUT_BYTES_CHANGED'):self.run_capture()
        self.assertEqual(self.paths,[])

    def test_case_path_rejected_before_private_metadata_open(self):
        self.case['inputsPath']='/etc/credential.json'
        with patch.object(m,'private_json',side_effect=AssertionError('must not open')):
            with self.assertRaisesRegex(m.Stop,'EXACT_RETAINED_INPUT_PATH_REQUIRED'):m.capture(self.case)

    def test_consumed_generation_and_authority_flags_cannot_be_adopted(self):
        for key in ('oldAuthorityIsCurrent','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset'):
            with self.subTest(key=key):
                self.inputs[key]=True;self.repin()
                with self.assertRaisesRegex(m.Stop,'HISTORY_ONLY'):m.compile_composition(self.case,self.inputs)
                self.inputs[key]=False

    def test_contract_stage_mutation_rejected_even_with_rehashed_dossier(self):
        self.inputs['candidateContract']['stages'][7]['name']='RELEASE_BOTH'
        self.repin()
        with self.assertRaisesRegex(m.Stop,'CANDIDATE_CONTRACT_CHANGED'):m.compile_composition(self.case,self.inputs)

    def test_contract_still_matches_pinned_history_producer(self):
        spec=importlib.util.spec_from_file_location('history_contract',ROOT.parent/'semantic_registry_history_capture'/'capture.py')
        other=importlib.util.module_from_spec(spec);spec.loader.exec_module(other)
        proposal=self.inputs['proposal'];history=self.inputs['historicalBinding']
        self.assertEqual(m.candidate_contract(proposal,m.digest(history),'2'*64),
                         other.candidate_contract(proposal,m.digest(history),'2'*64))

    def test_missing_or_duplicate_component_pin_rejected(self):
        self.case['componentPins'][-1]=self.case['componentPins'][0]
        with self.assertRaisesRegex(m.Stop,'COMPONENT_SOURCE_PINS'):m.compile_composition(self.case,self.inputs)

    def test_current_running_registry_cannot_be_reinterpreted(self):
        with self.assertRaisesRegex(m.Stop,'EXACT_STOPPED_REGISTRY'):
            self.run_capture((1,lambda r:r['State'].update(Running=True,Pid=88)))

    def test_stopped_config_drift_rejected(self):
        with self.assertRaisesRegex(m.Stop,'BASELINE_CHANGED'):
            self.run_capture((4,lambda r:r['Config'].update(User='0')))

    def test_gateway_generation_drift_rejected(self):
        with self.assertRaisesRegex(m.Stop,'GATEWAY_GENERATION_CHANGED'):
            self.run_capture((5,lambda r:r['State'].update(Pid=99)))

    def test_image_rootfs_and_launch_drift_rejected(self):
        for edit,reason in ((lambda r:r['RootFS']['Layers'].append('sha256:'+'0'*64),'NATIVE_ROOTFS_CUSTODY_DRIFT'),
                            (lambda r:r['Config'].update(Entrypoint=['sh']),'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT')):
            with self.subTest(reason=reason),self.assertRaisesRegex(m.Stop,reason):self.run_capture((3,edit))

    def test_native_manifest_identity_exact_and_not_configuration_id(self):
        audit=copy.deepcopy(self.audit);audit['nativeIdentity']=m.native_identity(audit)
        native=copy.deepcopy(self.image);native['Id']=audit['nativeIdentity']['nativeImageId']
        self.assertNotEqual(native['Id'],self.iid)
        self.assertTrue(m.loaded(audit,native)['imageByteCustodyProven'])
        audit['nativeIdentity']['manifestBytes']+=1
        with self.assertRaisesRegex(m.Stop,'EXACT_NATIVE_MANIFEST_IDENTITY'):m.loaded(audit,native)

    def test_readwrite_extra_and_shadowing_mounts_rejected(self):
        for mode in ('rw','extra','shadow'):
            r=copy.deepcopy(self.registry);recipe=copy.deepcopy(self.inputs['registryInputs']['nodeRecipe'])
            tree=copy.deepcopy(self.bindings[2])
            if mode=='rw':r['Mounts'][0]['RW']=True
            if mode=='extra':r['Mounts'].append(copy.deepcopy(r['Mounts'][0]))
            if mode=='shadow':
                recipe['launch']['sources'][1]['target']='/run/key/nested'
                recipe['launch']['manifest']['mounts'][1]['target']='/run/key/nested'
            with self.subTest(mode=mode),self.assertRaises(m.Stop):m.mount_declarations(r,recipe,tree)

    def test_metadata_only_does_not_open_credentials(self):
        with patch('builtins.open',side_effect=AssertionError('no key/token open')):
            result,_=self.run_capture()
        self.assertIs(result['mountDeclarations']['hostFileCustodyProven'],False)

    def test_retained_bytes_changed_after_inspects_stops(self):
        with self.assertRaisesRegex(m.Stop,'RETAINED_INPUTS_CHANGED_DURING_PREFLIGHT'):self.run_capture(read_change=True)

    def test_closed_transport_rejects_paths_and_budget_before_socket(self):
        engine=m.Engine(self.inputs['proposal']['engineBinding'],[self.gid,self.rid],self.iid)
        for path,calls in (('/v1.44/containers/json?all=1',0),(engine.image_path,6)):
            engine.calls=calls
            with patch.object(engine,'check',side_effect=AssertionError('should not touch socket')):
                with self.assertRaisesRegex(m.Stop,'CLOSED_SIX_GET_BUDGET'):engine.get(path)

    def test_new_private_publication_preserves_prior_directory(self):
        if os.geteuid()!=0:self.fail('qualification needs current root workspace')
        with tempfile.TemporaryDirectory() as directory:
            # /tmp ancestry is writable; isolate publish ancestry policy for this fixture only.
            real_lstat=Path.lstat
            def ancestry(path,*args,**kwargs):
                info=real_lstat(path,*args,**kwargs)
                if str(path)=='/tmp':
                    values=list(info);values[0]=stat.S_IFDIR|0o755;return os.stat_result(values)
                return info
            prior=Path(directory)/'prior';prior.write_text('preserve')
            with patch.object(Path,'lstat',ancestry):
                path,sha=m.publish({'privateParent':directory},{'fixture':'sealed'})
            self.assertEqual(Path(path).read_bytes(),m.encoded({'fixture':'sealed'}))
            self.assertEqual(sha,m.digest({'fixture':'sealed'}))
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode),0o400)
            self.assertEqual(stat.S_IMODE(Path(path).parent.stat().st_mode),0o700)
            self.assertEqual(prior.read_text(),'preserve')

    def test_public_error_does_not_echo_private_exception(self):
        self.assertNotIn('SECRET',json.dumps(m.stopped(ValueError('SECRET /private'))))
        self.assertNotIn('/private',json.dumps(m.stopped(m.Stop('SECRET /private'))))


if __name__=='__main__':unittest.main()
