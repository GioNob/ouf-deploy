"""Offline continuation arithmetic with canonical schema; no target authority."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.chatbot_file_cohort.gateway_recovery_plan import compile_remaining, digest


class RemainingPlan(unittest.TestCase):
    def fixture(self):
        gateway=Path(os.environ['OUF_GATEWAY_SOURCE'])
        schema=json.loads((gateway/'schemas/mcp-gateway-onboarding-review-prepare-dispatch-v1.json').read_text())
        before={'unrelated':{'id':'unrelated','uri':'/retained','host':'ente.example'}}
        changes=[];target=copy.deepcopy(before)
        ids=[f'a-{i}' for i in range(9)]+['mcp-managed-file-review-prepare']+[f'z-{i}' for i in range(27)]
        for i,rid in enumerate(ids):
            row={'id':rid,'uri':'/synthetic/'+str(i),'upstream':{'nodes':{'private.ente.example:9443':1}}}
            if i==9:row['plugins']={'request-validation':{'body_schema':schema}}
            changes.append({'id':rid,'before':None,'after':row});target[rid]=copy.deepcopy(row)
        plan={'previousRoutes':before,'proposedRoutes':target,'changes':changes,
              'previousRuntimeHash':digest(before),'proposedRuntimeHash':digest(target)}
        current=copy.deepcopy(before);effects=[]
        for i,c in enumerate(changes[:10]):
            effect={'routeId':c['id'],'intentHash':digest(c),'state':'APPLIED' if i<9 else 'CLAIMED'}
            if i<9:
                current[c['id']]=copy.deepcopy(c['after']);effect['observedMapHash']=digest(current)
            effects.append(effect)
        journal={'planHash':digest(plan),'budgetReset':False,'nextStep':9,'effects':effects}
        return plan,journal,current

    def compile(self,p,j,r):
        return compile_remaining(p,j,r,copy.deepcopy(r),{'newGenerationRequiresAuthority':True},'a'*64)

    def test_preserves_history_and_bindings_and_only_changes_qualified_metadata(self):
        p,j,r=self.fixture();original=copy.deepcopy((p,j,r));new=self.compile(p,j,r)
        self.assertEqual((p,j,r),original)
        self.assertEqual(len(new['changes']),28)
        self.assertEqual(new['previousRoutes'],r)
        marker=new['governedReprocessing']
        self.assertEqual(marker['historicalAppliedEffects'],j['effects'][:9])
        self.assertEqual(marker['historicalUnresolvedClaim'],j['effects'][9])
        self.assertFalse(marker['runtimeAuthorityIssued'])
        self.assertFalse(marker['executionIntegrationQualified'])
        self.assertNotEqual(marker['newIntentHash'],j['effects'][9]['intentHash'])
        target=copy.deepcopy(p['proposedRoutes'])
        del target['mcp-managed-file-review-prepare']['plugins']['request-validation']['body_schema']['properties']['Arguments']['properties']['executionProposal']['$id']
        self.assertEqual(new['proposedRoutes'],target)

    def test_stale_unstable_or_foreign_route_map_is_denied(self):
        p,j,r=self.fixture();bad=copy.deepcopy(r);bad['unrelated']['host']='changed.example'
        with self.assertRaisesRegex(ValueError,'BEFORE_CLAIM_MAP'):
            compile_remaining(p,j,r,bad,{},'a'*64)
        with self.assertRaisesRegex(ValueError,'BEFORE_CLAIM_MAP'):
            self.compile(p,j,bad)

    def test_completed_or_tampered_claim_is_not_reprocessed(self):
        for field,value in [('state','APPLIED'),('intentHash','f'*64),('routeId','different')]:
            with self.subTest(field=field):
                p,j,r=self.fixture();j['effects'][-1][field]=value
                with self.assertRaisesRegex(ValueError,'HISTORY_DRIFT'):self.compile(p,j,r)

    def test_prefix_evidence_and_schema_or_limit_changes_are_denied(self):
        p,j,r=self.fixture();j['effects'][0]['observedMapHash']='f'*64
        with self.assertRaisesRegex(ValueError,'PREFIX_EVIDENCE'):self.compile(p,j,r)
        p,j,r=self.fixture()
        p['changes'][9]['after']['plugins']['request-validation']['body_schema']['properties']['Arguments']['properties']['expectedVersion']['maximum']=42
        p['proposedRoutes'][p['changes'][9]['id']]=copy.deepcopy(p['changes'][9]['after'])
        p['proposedRuntimeHash']=digest(p['proposedRoutes']);j['planHash']=digest(p)
        j['effects'][9]['intentHash']=digest(p['changes'][9])
        with self.assertRaisesRegex(ValueError,'ORIGINAL_SCHEMA'):self.compile(p,j,r)

    def test_complete_plan_and_numeric_runtime_binding_are_required(self):
        p,j,r=self.fixture();p['proposedRoutes']['foreign']={'id':'foreign'};j['planHash']=digest(p)
        with self.assertRaisesRegex(ValueError,'COMPLETE_ROUTE_PLAN'):self.compile(p,j,r)
        p,j,r=self.fixture()
        with self.assertRaisesRegex(ValueError,'NUMERIC_RUNTIME'):
            compile_remaining(p,j,r,r,{},None)


if __name__=='__main__':unittest.main()
