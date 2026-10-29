"""Retained route-read boundary; pure stage predicates, no native acceptance."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import retained_gateway as r,contract as c
import test_ingestion_rollout_runtime_guard as model

class RetainedReadBoundary(unittest.TestCase):
    def test_retained_transport_rejects_every_write_or_non_inventory_get_before_io(self):
        obj=r.RetainedGatewayMap.__new__(r.RetainedGatewayMap)
        for method,path,body in(('PUT','/apisix/admin/routes/mcp-ingestion-status',{}),
                                ('POST','/apisix/admin/routes',{}),('DELETE','/apisix/admin/routes/x',None),
                                ('GET','/apisix/admin/routes/x',None),('GET','/apisix/admin/routes',{})):
            with self.subTest(method=method,path=path),self.assertRaises(c.Denied):obj._request(method,path,body)
        self.assertFalse(hasattr(obj,'put'))
    def pin(self,actual,row,case):
        pin=r.RetainedGatewayPin.__new__(r.RetainedGatewayPin)
        pin.reader=type('FixtureReader',(),{'container':lambda _,cid:copy.deepcopy(actual)})()
        pin.journal=type('FixtureJournal',(),{'read':lambda _:copy.deepcopy(row)})()
        pin.runtime_profile=case.profile;pin.packet=case.packet;pin.review=case.review
        pin.binding={'device':1,'inode':2};pin.fd=None
        return pin
    def fixture(self):
        case=model.OldGeneration('test_exact_two_replaced_three_unchanged_apps_and_distinct_ids');case.setUp()
        actual=copy.deepcopy(case.profile['beforeContainers']['gateway'])
        actual['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        return case,actual
    def test_stopped_retained_gateway_is_denied_before_opening_or_checking_namespace(self):
        case,actual=self.fixture();actual['State'].update(Running=False,Pid=0)
        row=case.row('gateway.STOP_OLD',True);pin=self.pin(actual,row,case)
        with patch.object(r.os,'stat',side_effect=AssertionError('stopped namespace must not be read')):
            with self.assertRaises(c.Denied):pin.check()
    def test_predecessor_config_drift_blocks_before_namespace_access(self):
        case,actual=self.fixture();actual['Config']['Env'].append('FOREIGN=1')
        row=case.row('gateway.STOP_OLD');pin=self.pin(actual,row,case)
        with patch.object(r.os,'stat',side_effect=AssertionError('foreign process must not be used')):
            with self.assertRaises(c.Denied):pin.check()
    def test_closed_retained_fd_is_released_and_not_rebound_by_name(self):
        pin=r.RetainedGatewayPin.__new__(r.RetainedGatewayPin);pin.fd=os.open(__file__,os.O_RDONLY)
        fd=pin.fd;pin.close();self.assertIsNone(pin.fd)
        with self.assertRaises(OSError):os.fstat(fd)
        pin.close()

if __name__=='__main__':unittest.main()
