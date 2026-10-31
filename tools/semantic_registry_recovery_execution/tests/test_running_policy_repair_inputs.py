import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('running_repair_inputs',ROOT/'scripts/prepare-registry-running-policy-inputs-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class Prefix(unittest.TestCase):
    def setUp(self):
        first={'originalGrant':'retained'}
        self.scope={'firstGrantReceiptHash':d.digest(first),'currentSessionBootId':'same-boot','contextRef':'same-context','generationRef':'same-gen'}
        self.j={'authorityHash':d.AUTHORITY_HASH,'nextStage':11,'effects':[{'state':'APPLIED'}for _ in range(11)]+[{'state':'CLAIMED'}],
                'originalSemanticGetSucceeded':False,'bootId':'same-boot','newGeneration':{'pid':123}}
        self.o={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','controlledPredecessorGrantAttempts':320,'attempts':1,
                'controlledCumulativeGrantAttempts':321,'workerSessionHash':d.digest(self.scope),'firstGrantReceiptHash':d.digest(first),
                'bootId':'same-boot','gateGeneration':{'pid':123},'contextRef':'same-context','generationRef':'same-gen'}
        self.records={'owner-session.json':self.scope,'owner-first-grant.json':first,
                      'owner-admission.json':{'state':'BLOCKED','contextRef':'same-context','generationRef':'same-gen'}}
        self.reads={'authorityHash':d.AUTHORITY_HASH,'counts':{'databaseSessions':18,'gatewayAdminGets':18,'semanticGets':0}}
    def validate(self):return d.validate_repair_prefix(self.j,self.o,self.scope,self.records,self.reads)
    def test_exact_stage11_cancelled321_is_metadata_input_not_runtime_admission(self):
        before=copy.deepcopy((self.j,self.o,self.scope,self.records,self.reads));self.validate()
        self.assertEqual(before,(self.j,self.o,self.scope,self.records,self.reads))
    def test_old_checkpoint_cannot_enter_running_repair(self):
        self.j['nextStage']=4
        with self.assertRaisesRegex(ValueError,'EXACT_UNCOMPLETED_STAGE_ELEVEN_PREFIX_REQUIRED'):self.validate()
    def test_prefix_effect_or_claim_rewrite_refused(self):
        self.j['effects'][7]['state']='CLAIMED'
        with self.assertRaises(ValueError):self.validate()
    def test_grant_reset_refused(self):
        self.o['controlledCumulativeGrantAttempts']=320
        with self.assertRaisesRegex(ValueError,'EXACT_CANCELLED321'):self.validate()
    def test_active_owner_refused(self):
        self.o['state']='ACTIVE'
        with self.assertRaisesRegex(ValueError,'EXACT_CANCELLED321'):self.validate()
    def test_native_count_reset_and_bool_zero_refused(self):
        self.reads['counts']['semanticGets']=False
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_NATIVE18_18_0'):self.validate()
    def test_different_running_generation_refused(self):
        self.o['gateGeneration']={'pid':124}
        with self.assertRaisesRegex(ValueError,'EXACT_CANCELLED321'):self.validate()
    def test_original_first_grant_must_be_preserved(self):
        self.records['owner-first-grant.json']={'different':'grant'}
        with self.assertRaisesRegex(ValueError,'EXACT_CANCELLED321'):self.validate()
    def test_publication_is_private_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp)/'inputs.json';d.publish_private(p,{'safe':'metadata'})
            self.assertEqual(p.stat().st_mode&0o777,0o400)
            before=p.read_bytes()
            with self.assertRaises(FileExistsError):d.publish_private(p,{'overwritten':True})
            self.assertEqual(p.read_bytes(),before)

if __name__=='__main__':unittest.main()
