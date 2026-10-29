"""Exercise the real route stage adapter with explicit in-memory APISIX state.

The fixture is a transport, never an authority substitute in production.
"""
import copy
from pathlib import Path
import sys
import types
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.source_revision_update.native import NativePorts
from tools.source_revision_update.owner import UpdateDenied


class Transport:
    def __init__(self, routes):
        self.current = copy.deepcopy(routes); self.writes = []
    def routes(self): return copy.deepcopy(self.current)
    def request(self, method, path, body):
        self.writes.append((method,path)); self.current[body['id']] = copy.deepcopy(body)
        return 200, {}


class Routes(unittest.TestCase):
    def setUp(self):
        self.ports = object.__new__(NativePorts)
        before = {'retained':{'id':'retained','uri':'/retained','methods':['GET']}}
        additions = {m:{'id':'mcp-source-revision-'+m,'uri':'/revision/'+m} for m in ('prepare','read')}
        self.ports.plan = {'gateway':{'beforeRoutes':before,'afterRoutes':{**before,**{r['id']:r for r in additions.values()}},
                                      'additions':additions}}
        self.effects = []
        self.ports.journal = types.SimpleNamespace(read=lambda:{'effects':copy.deepcopy(self.effects)})
        self.ports.gateway = Transport(before)

    def test_each_claim_allows_only_the_exact_before_or_after_map(self):
        for mode in ('prepare','read'):
            stage = 'GATEWAY_'+mode.upper()+'_ROUTE'
            self.effects.append({'stage':stage,'state':'CLAIMED'})
            self.ports.guard_current = lambda _:None
            self.assertEqual(self.ports.observe(stage),('UNKNOWN',{}))
            self.ports.apply(stage)
            status, proof = self.ports.observe(stage)
            self.assertEqual(status,'APPLIED'); self.assertIn('routeMapHash',proof)
            self.effects[-1]['state'] = 'APPLIED'
        self.assertEqual(len(self.ports.gateway.writes),2)
        self.assertEqual(self.ports.route_inventory(True), self.ports.plan['gateway']['afterRoutes'])
        self.assertEqual(self.ports.gateway.current['retained'],self.ports.plan['gateway']['beforeRoutes']['retained'])

    def test_existing_claim_does_not_authorize_repeated_put(self):
        self.effects.append({'stage':'GATEWAY_PREPARE_ROUTE','state':'CLAIMED'})
        self.ports.apply('GATEWAY_PREPARE_ROUTE')
        with self.assertRaises(UpdateDenied): self.ports.apply('GATEWAY_PREPARE_ROUTE')
        self.assertEqual(len(self.ports.gateway.writes),1)

    def test_any_other_route_or_retained_mutation_blocks_reconciliation(self):
        for change in ('foreign','retained'):
            self.ports.gateway.current = copy.deepcopy(self.ports.plan['gateway']['beforeRoutes'])
            self.effects[:] = [{'stage':'GATEWAY_PREPARE_ROUTE','state':'CLAIMED'}]
            self.ports.gateway.current[change] = {'id':change,'uri':'/changed'}
            with self.subTest(change=change),self.assertRaises(UpdateDenied):
                self.ports.observe('GATEWAY_PREPARE_ROUTE')
            self.assertFalse(self.ports.gateway.writes)


if __name__ == '__main__': unittest.main()
