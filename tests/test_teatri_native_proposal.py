import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('proposal',ROOT/'tools/prepare_teatri_native_proposal.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class NativeProposal(unittest.TestCase):
    def setUp(self):
        self.profile=json.loads((ROOT/'evidence/teatri-authorized-profile-20261011.json').read_text())
    def proposal(self):return module.prepare(self.profile,'fixture-owner','fixture-authority')
    def test_complete_scoped_definition_and_explicit_limitations(self):
        result=self.proposal();commands=result['nativeDraftCommands'];fields=result['mappingBlueprint']['fields']
        self.assertEqual(len(commands),21);self.assertEqual(len(fields),20)
        self.assertEqual({f['fieldName'] for f in fields},{c['name'] for c in self.profile['columns']})
        self.assertTrue(all(f['extractionDecision']=='INCLUDE' and f['dataAccessLabel']=='RESTRICTED' for f in fields))
        properties={c['semanticId']:c for c in commands[1:]}
        for field in fields:
            p=properties[field['targetPropertyIri']]
            self.assertEqual(p['definition']['domainRefs'],[module.CLASS])
        self.assertTrue(result['mappingBlueprint']['notExecutableOnboardingRequest'])
        self.assertFalse(any(result['effects'].values()))
        self.assertNotIn('publicationSetId',json.dumps(result));self.assertNotIn('revisionId',json.dumps(result))
        self.assertNotIn('schema.org',json.dumps(result));self.assertNotIn('/cinema#',json.dumps(commands))
        self.assertEqual(result,self.proposal())
    def test_foreign_asset_profile_version_and_column_drift_block(self):
        for change in ('assetId','profileId','profileVersion','columns'):
            with self.subTest(change=change):
                row=copy.deepcopy(self.profile)
                if change=='columns':row['columns'][1]['name']=row['columns'][0]['name']
                else:row[change]='foreign'
                with self.assertRaises(ValueError):module.prepare(row,'owner','authority')
    def test_identity_nullable_and_unsupported_type_block(self):
        for key,value in [('nullable',True),('distinctValues',12),('dataType','BINARY')]:
            row=copy.deepcopy(self.profile);row['columns'][0][key]=value
            with self.assertRaises(ValueError):module.prepare(row,'owner','authority')
    def test_owner_is_explicit_and_does_not_create_authority(self):
        for owner in ('','owner\nheader'):
            with self.assertRaises(ValueError):module.prepare(self.profile,owner,'authority')
        self.assertFalse(self.proposal()['proposedOwnership']['authorityInheritedFromOtherArtifacts'])

if __name__=='__main__':unittest.main()
