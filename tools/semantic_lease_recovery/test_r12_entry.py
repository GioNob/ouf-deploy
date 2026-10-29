import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import activate_resilient_r12 as m

class Tests(unittest.TestCase):
    def test_parked_receipt_exit_is_two_and_retains_reason(self):
        value={'externalTrafficNowPermittedForApprovedFlows':False,'status':'RESILIENT_WORKER_PARKED_REQUIRES_ATTENTION','workerReason':'PROCESS_METADATA_PERMISSION_DENIED'}
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'flags',SimpleNamespace(isolated=1)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.sys,'argv',['entry','--apply',m.APPROVAL_REF]),patch.object(m,'apply',return_value=value),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(),2)
        self.assertIn(value['workerReason'],out.getvalue())
    def test_active_receipt_exit_is_zero(self):
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'flags',SimpleNamespace(isolated=1)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.sys,'argv',['entry','--apply',m.APPROVAL_REF]),patch.object(m,'apply',return_value={'externalTrafficNowPermittedForApprovedFlows':True}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(),0)
    def test_old_claims_and_units_are_distinct_and_time_window_bounded(self):
        self.assertNotEqual(m.CLAIM,m.R11_CLAIM)
        self.assertNotEqual(m.UNIT,m.R11_UNIT)
        m.approval_live(m.APPROVAL_REF,lambda:m.ISSUED_AT)
        with self.assertRaises(ValueError):m.approval_live(m.APPROVAL_REF,lambda:m.EXECUTION_EXPIRES_AT)

if __name__=='__main__':unittest.main()
