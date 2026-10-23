import copy
import importlib.util
import json
import tempfile
import stat
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('history',ROOT/'capture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def setUp(self):
        self.case=json.loads((ROOT/'case.json').read_text());case=self.case
        h=case['historicalContext'];r='/etc/ouf/deploy-snapshots/fixture-registry'
        self.runtime={'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'configHash':'c'*64,'pid':123}
        self.registry={'schema':'ouf.semantic-file-only-installation-inputs.v1',
            'creationRequest':{'Image':self.runtime['imageId']},'intents':{p:{'fixture':p} for p in m.PHASES},
            'readinessScope':{'fixture':'PRIVATE_METADATA'},'directoryPlan':{'root':r,'transition':r+'/transition','evidence':r+'/evidence'},
            'nodeRecipe':{'private':'PRIVATE_METADATA'}}
        self.payloads={'CREATE_REPLACEMENT':{'Id':self.runtime['containerId'],'Image':self.runtime['imageId']},
            'ATTEST_NEW_OCI_PEER':{'fixture':'historical-attestation'},
            'START_REPLACEMENT':{'runtimeBinding':self.runtime},
            'VERIFY_APPLICATION':{'runtimeBinding':copy.deepcopy(self.runtime),
                'creationRequestHash':m.digest(self.registry['creationRequest']),
                'readinessScopeHash':m.digest(self.registry['readinessScope'])}}
        self.effects=[{'phase':p,'state':'APPLIED','intentHash':m.digest(self.registry['intents'][p]),
                       'authorityEvidenceHash':'e'*64,'nativeEvidenceHash':m.digest(self.payloads[p]) if p in self.payloads else 'f'*64}
                      for p in m.PHASES[:10]]
        self.transition={'schema':'ouf.semantic-cutover-journal.v2','deploymentProfile':'ouf.semantic-file-only-native-proposal.v1',
            'executionProfileHash':'d'*64,'creationRequestHash':m.digest(self.registry['creationRequest']),
            'predecessorHistoryHash':'e'*64,'predecessorIncidentRef':'f'*64,'transitionAuthorityEvidenceHash':'1'*64,
            'nextPhase':10,'effects':self.effects,'state':'READY','automaticReplayAllowed':False,
            'preMigrationRestoreAllowed':False,'databaseMayHaveChanged':True,'applicationWritesMayHaveOccurred':True}
        fields=('creationRequestHash','predecessorHistoryHash','predecessorIncidentRef','transitionAuthorityEvidenceHash',
                'deploymentProfile','executionProfileHash')
        self.transition['contextHash']=m.digest({k:self.transition[k] for k in fields})
        self.proposal={'schema':'ouf.semantic-registry-blocked-recovery-proposal.v1',
            'kind':'REVIEW_INPUTS_ONLY_NOT_EXECUTABLE_AUTHORITY','registry':self.runtime,
            'requiredGates':list(m.GATES),'unresolvedGateCount':8,
            **{k:False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','nativeExecutorQualified','providerRecoveryProposed',
                                'newOAuthBudgetProposed','newHumanWindowProposed','automaticReplayAllowed','budgetReset')}}
        self.prepared={'registry':self.registry};declaration={'sourceCommit':case['historicalSourceCommit']}
        self.bundle={'declaration':declaration,'prepared':self.prepared};self.bundle_path=h+'/fixture-bundle.json'
        self.scope={'creationRequestHash':m.digest(self.registry['creationRequest']),'preparedHash':m.digest(self.registry),
                    'phaseIntentHashes':{p:m.digest(v) for p,v in self.registry['intents'].items()}}
        self.review={'sourceClosure':{'declaration':declaration},'privateInputHashes':{'preparedInputs':m.digest(self.prepared)},
                     'scopes':{'finiteActionProcess':{'unit':case['historicalUnit'],'authorityDirectory':h,
                          'logicalOperationHash':h.rsplit('-',1)[1],'maximumElapsedSeconds':3600,
                          'bundle':{'path':self.bundle_path,'sha256':m.digest(self.bundle)}},
                               'applicationRegistryCutover':self.scope}}
        self.authority={**self.review['scopes'],'issuedAt':1,'expiresAt':2}
        self.claim={'schema':'ouf.chatbot-file-cohort-process-claim.v1','planHash':m.digest(self.review['scopes']['finiteActionProcess']),
                    'authorityHash':m.digest(self.authority),'state':'START_CONSUMED_OUTCOME_UNPROVEN',
                    'automaticReplayAllowed':False,'runtimeMaxSeconds':900}
        self.data={case['proposalPath']:self.proposal,h+'/review.json':self.review,h+'/authority.json':self.authority,
                   self.bundle_path:self.bundle,r+'/transition/recovery.json':self.transition,
                   **{r+'/evidence/'+p+'.json':v for p,v in self.payloads.items()}}
        self.data[case['privateParent']+'/chatbot-file-cohort-process-'+h.rsplit('-',1)[1]+'.claim.json']=self.claim
        self.repin()

    def repin(self):
        self.scope['preparedHash']=m.digest(self.registry)
        self.review['privateInputHashes']['preparedInputs']=m.digest(self.prepared)
        self.review['scopes']['finiteActionProcess']['bundle']['sha256']=m.digest(self.bundle)
        self.case.update(proposalHash=m.digest(self.proposal),historicalReviewHash=m.digest(self.review),
                         historicalAuthorityHash=m.digest(self.authority))
        self.claim.update(planHash=m.digest(self.review['scopes']['finiteActionProcess']),authorityHash=m.digest(self.authority))

    def run_capture(self,drift=False):
        count=[0]
        def read(path):
            count[0]+=1
            return self.data[path],m.encoded(self.data[path])+(b' ' if drift and count[0]>10 else b'')
        with patch.object(m,'private_json',read):return m.capture(self.case)

    def test_exact_lineage_and_expired_authority_are_history_only(self):
        inputs,reads=self.run_capture()
        self.assertEqual(reads,20)
        self.assertTrue(inputs['historicalBinding']['historicalDeploymentChainBound'])
        self.assertEqual(inputs['unresolvedGateCount'],7)
        self.assertFalse(inputs['oldAuthorityIsCurrent'])
        self.assertFalse(inputs['currentRegistryIdentityEstablished'])
        self.assertFalse(inputs['runtimeAuthorityIssued'])
        self.assertEqual(inputs['registryInputs'],self.registry)

    def test_retained_prefix_bridge_does_not_rewrite_old_intents(self):
        self.effects[6]['intentHash']='0'*64
        bridge={'appliedPrefixPhaseCount':10,'registryPhaseReplayAllowed':False,'appliedPrefixHash':m.digest(self.effects)}
        self.scope['postGrantRecovery']=bridge;self.registry['postGrantRecovery']=copy.deepcopy(bridge);self.repin()
        self.assertTrue(self.run_capture()[0]['historicalBinding']['historicalDeploymentChainBound'])
        self.scope['postGrantRecovery']['appliedPrefixHash']='1'*64;self.repin()
        with self.assertRaisesRegex(m.Stop,'RETAINED_PREFIX_BRIDGE'):self.run_capture()

    def test_bad_proposal_hash_stops_without_authority_use(self):
        self.case['proposalHash']='0'*64
        with self.assertRaisesRegex(m.Stop,'METADATA_HASH_CHANGED'):self.run_capture()

    def test_scope_bundle_and_source_bindings_cannot_be_guessed(self):
        for mutation in ('source','unit','preparedHash'):
            self.setUp()
            if mutation=='source':self.case['historicalSourceCommit']='0'*40
            elif mutation=='unit':self.case['historicalUnit']='other.service'
            else:self.scope['preparedHash']='0'*64;self.case['historicalReviewHash']=m.digest(self.review);self.case['historicalAuthorityHash']=m.digest(self.authority)
            with self.assertRaises(m.Stop):self.run_capture()

    def test_inflight_or_reordered_or_replayable_history_stops(self):
        for mutation in ('inflight','order','replay'):
            self.setUp()
            if mutation=='inflight':self.effects[-1]['state']='IN_FLIGHT'
            elif mutation=='order':self.effects[1],self.effects[2]=self.effects[2],self.effects[1]
            else:self.transition['automaticReplayAllowed']=True
            with self.assertRaisesRegex(m.Stop,'COMPLETED_HISTORICAL_REGISTRY_PREFIX'):self.run_capture()

    def test_consumed_process_claim_scope_and_budget_are_immutable(self):
        for key,value in [('state','READY'),('authorityHash','0'*64),('planHash','0'*64),('runtimeMaxSeconds',0),('automaticReplayAllowed',True)]:
            before=copy.deepcopy(self.claim);self.claim[key]=value
            with self.assertRaisesRegex(m.Stop,'CONSUMED_HISTORICAL_PROCESS_CLAIM'):self.run_capture()
            self.claim.clear();self.claim.update(before)

    def test_payload_hash_and_registry_id_are_not_adopted_by_name(self):
        self.payloads['CREATE_REPLACEMENT']['Id']='d'*64
        with self.assertRaisesRegex(m.Stop,'METADATA_HASH_CHANGED'):self.run_capture()
        self.effects[4]['nativeEvidenceHash']=m.digest(self.payloads['CREATE_REPLACEMENT'])
        with self.assertRaisesRegex(m.Stop,'CONTAINER_AND_VERIFICATION'):self.run_capture()

    def test_current_config_mismatch_does_not_adopt_historical_generation(self):
        self.proposal['registry']=dict(self.runtime,configHash='d'*64);self.repin()
        with self.assertRaisesRegex(m.Stop,'CURRENT_PROPOSAL_CONFIG_DIFFERS'):self.run_capture()

    def test_change_between_metadata_reads_stops(self):
        with self.assertRaisesRegex(m.Stop,'HISTORICAL_INPUT_CHANGED'):self.run_capture(drift=True)

    def test_candidate_contract_separates_each_effect_and_preserves_blockers(self):
        contract=self.run_capture()[0]['candidateContract'];stages=contract['stages']
        self.assertEqual(len(stages),12)
        self.assertEqual([s['name'] for s in stages if s['kind']=='EFFECT'],
            ['START_NEW_WAIT_GATE','PAUSE_NEW_WAIT_GATE','ATTEST_NEW_GENERATION','UNPAUSE_ATTESTED_GENERATION','RELEASE_SAME_GENERATION_SIGUSR1'])
        self.assertTrue(all(s['intentHash']==m.digest(s['intent']) for s in stages))
        self.assertEqual(contract['remainingGates'],list(m.GATES[1:]))
        for key in ('newRuntimeBudgetGranted','newOAuthBudgetProposed','providerRecoveryAllowed','gatewayWritesAllowed',
                    'databaseMigrationAllowed','automaticAuthenticationAllowed','sourceActivationAllowed','nativeExecutorQualified',
                    'runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset'):
            self.assertFalse(contract[key])

    def test_no_network_subprocess_dynamic_source_or_issuer_dependencies(self):
        import ast
        tree=ast.parse((ROOT/'capture.py').read_text())
        imports=[alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names]
        self.assertFalse(set(imports)&{'socket','http.client','subprocess','ssl','urllib','importlib'})
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {'exec','eval','compile','__import__'} for n in ast.walk(tree)))

    def test_case_pins_match_the_original_qualified_reader_selection(self):
        fixture={}
        exec((ROOT/'tests/fixtures/historical_selection.py').read_text(),fixture)
        case=json.loads((ROOT/'case.json').read_text())
        for field,key in [('historicalContext','CONTEXT'),('historicalReviewHash','REVIEW'),
                          ('historicalAuthorityHash','AUTHORITY'),('historicalSourceCommit','SOURCE'),('historicalUnit','UNIT')]:
            self.assertEqual(case[field],str(fixture[key]))

    def test_actual_private_dossier_publication_preserves_prior_files(self):
        inputs,reads=self.run_capture()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            previous=Path(directory)/'retained.json';previous.write_text('{"retained":true}')
            before=previous.read_bytes();case={'privateParent':directory}
            path,sha=m.publish(case,inputs)
            self.assertEqual(Path(path).name,'inputs.json')
            self.assertEqual(sha,m.digest(inputs));self.assertEqual(json.loads(Path(path).read_bytes()),inputs)
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode),0o400)
            self.assertEqual(previous.read_bytes(),before)
            self.assertFalse(inputs['candidateContract']['nativeExecutorQualified'])

if __name__=='__main__':unittest.main()
