"""Pure fixture contracts: no keys, target files, IAM or authority calls."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT))
from tools.semantic_registry_operational_owner import core, contract, installation


class Contract(unittest.TestCase):
    def setUp(self):
        self.policy=core.RenewalPolicy(60,240,15,30,3,10,(5,15,60))
        first={'syntheticFixtureFirstGrant':True}
        owner_inputs={'syntheticFixtureOwnerInputs':True}
        scope={'journalPath':'/fixture/old-owner','policy':{'finite':True},'ownerInputsHash':core.digest(owner_inputs),
               'firstGrantReceiptHash':core.digest(first),'currentSessionBootId':'fixture-boot',
               'fenceBinding':{'syntheticFence':True}}
        native={'nextStage':11,'effects':[{'state':'APPLIED'} for _ in range(11)]+[{'state':'CLAIMED'}],
                'originalSemanticGetSucceeded':False,'bootId':'fixture-boot','newGeneration':{'pid':123},'authorityHash':'a'*64}
        owner={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','controlledPredecessorGrantAttempts':320,
               'attempts':1,'controlledCumulativeGrantAttempts':321,'workerSessionHash':core.digest(scope),
               'policyHash':core.digest(scope['policy']),'firstGrantReceiptHash':core.digest(first),
               'bootId':'fixture-boot','gateGeneration':native['newGeneration']}
        prepared={'nativeContext':{'executionRoot':'/fixture/native','originalRequest':{'ca':{'path':'/fixture/caller-ca','sha256':'1'*64}}},
                  'ownerContext':{'ownerInputs':owner_inputs}}
        review={'currentContext':prepared['nativeContext'],'ownerContext':prepared['ownerContext'],
                'scopes':{'semanticRegistryPostbootOwner':scope,'semanticRegistryRecoveryReads':{'syntheticReadScope':True}}}
        self.inputs={'schema':contract.INPUT_SCHEMA,'runtimeAuthorityIssued':False,'newRuntimeBudgetGranted':False,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'grantAttemptAllowance':0,
            'retainedControlledGrantAttempts':321,'oldClaimsRemainConsumed':True,'prepared':prepared,'review':review,
            'retainedNativeJournal':native,'retainedNativeReads':{'counts':{'databaseSessions':18,'gatewayAdminGets':18,'semanticGets':0},
                'scopeHash':core.digest(review['scopes']['semanticRegistryRecoveryReads']),'authorityHash':'a'*64},
            'retainedOwnerRecords':{'recovery.json':owner,'owner-session.json':scope,'owner-first-grant.json':first,
                'owner-admission.json':{'state':'BLOCKED'}},'retainedFence':scope['fenceBinding'],
            'identity':{'nativeJournalHash':core.digest(native),'ownerJournalHash':core.digest(owner)}}
        self.manifest={'schema':'ouf.registry-operational-owner-sources.v1','sourceCommit':'a'*40,
            'sourceHashes':{name:'b'*64 for name in contract.SOURCE_NAMES},'dependencyClosureHash':'c'*64,'bootstrapHash':'d'*64}
        self.dest={'installationRoot':'/fixture/new-install','ledgerRoot':'/fixture/new-ledger',
                   'commonInvocationLock':'/fixture/old-owner/invocation.lock'}
        self.ca={'path':'/fixture/iam-ca','sha256':'e'*64}

    def proposal(self):
        return contract.compile_proposal(self.inputs,{'path':'/fixture/inputs.json','sha256':core.digest(self.inputs)},
                                         self.manifest,self.policy,self.dest,self.ca)

    def test_proposal_keeps_all_predecessor_records_and_grants_no_authority(self):
        before=copy.deepcopy(self.inputs);proposal=self.proposal()
        self.assertEqual(self.inputs,before)
        self.assertEqual(proposal['priorControlledGrantAttempts'],321)
        self.assertFalse(proposal['legacyFiniteBudgetExtended'])
        self.assertFalse(proposal['nativeRecoveryEffectReplayAllowed'])
        self.assertFalse(proposal['runtimeAuthorityIssued'])
        self.assertFalse(proposal['targetApplyAuthorized'])

    def test_iam_ca_is_independent_of_caller_api_ca(self):
        proposal=self.proposal()
        self.assertEqual(proposal['publicTlsCaBinding'],self.ca)
        self.assertNotEqual(self.ca,self.inputs['prepared']['nativeContext']['originalRequest']['ca'])

    def test_missing_executing_module_or_ambiguous_source_hash_denied(self):
        self.manifest['sourceHashes'].pop(next(iter(contract.SOURCE_NAMES)))
        with self.assertRaisesRegex(core.Denied,'SOURCE_DECLARATION'):self.proposal()

    def test_native_prefix_or_counter_rewrite_denied(self):
        for change in ('effect','read','owner'):
            saved=copy.deepcopy(self.inputs)
            if change=='effect':self.inputs['retainedNativeJournal']['effects'][0]['state']='CLAIMED'
            elif change=='read':self.inputs['retainedNativeReads']['counts']['semanticGets']=False
            else:self.inputs['retainedOwnerRecords']['recovery.json']['controlledCumulativeGrantAttempts']=320
            with self.assertRaises(core.Denied):self.proposal()
            self.inputs=saved

    def test_common_lock_or_native_directory_replacement_denied(self):
        self.dest['commonInvocationLock']='/fixture/another.lock'
        with self.assertRaises(core.Denied):self.proposal()
        self.dest['commonInvocationLock']='/fixture/old-owner/invocation.lock'
        self.dest['installationRoot']='/fixture/native/overwrite'
        with self.assertRaises(core.Denied):self.proposal()

    def test_configuration_compiler_copies_values_without_issuing_or_installing(self):
        proposal=self.proposal();sources=[{'path':'/fixture/capsule.py','sha256':'f'*64,'maximumBytes':1048576}]
        result=installation.configuration(proposal,sources=sources,
            fence_binding={'path':'/fixture/fence','value':{'newOwner':'fixture'}},
            common_lock_identity=[1]*9,verification={'trustPolicy':{},'openssl':{},'context':{}},
            service_unit_path='/fixture/owner.service')
        self.assertEqual(result['predecessorInputsHash'],core.digest(self.inputs))
        self.assertEqual(result['tlsCa'],self.ca)
        sources[0]['path']='/fixture/changed'
        self.assertEqual(result['sources'][0]['path'],'/fixture/capsule.py')


if __name__=='__main__':unittest.main()
