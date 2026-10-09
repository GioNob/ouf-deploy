"""R6 diagnosis must expose symbolic reasons only and retain exact generation."""
import importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_r6_broker_denial.py'))
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
class ReaderTests(unittest.TestCase):
    def test_exact_consumed_r6_paths(self):
        self.assertEqual(reader.CONTEXT.name,'semantic-provider-v2-approved-context-aj1j95xl')
        self.assertEqual(reader.ROOT.name,'semantic-provider-v2-transaction-aj1j95xl')
    def test_only_public_exception_projection(self):
        value={'schema':'ouf.semantic-broker-phase-denial.v1','secretValuesPrinted':False,'notReleaseAcceptance':True,'phase':'prepare','reason':'AUTHENTICATION_DEADLINE_MISSED','errorType':'PreexecDenied','exceptionPoints':[{'file':'broker.py','function':'prepare','line':42}],'diagnosisSaved':True,'privateValue':'SECRET_CANARY'}
        self.assertNotIn('SECRET_CANARY',json.dumps(reader.safe_denial(value)))
        for field,bad in [('reason','token=SECRET_CANARY'),('errorType','/private/path')]:
            changed={**value,field:bad}
            with self.assertRaises(AssertionError):reader.safe_denial(changed)
        value['exceptionPoints'][0]['file']='/private/path'
        with self.assertRaises(AssertionError):reader.safe_denial(value)
    def test_journal_summary_never_prints_values(self):
        result=reader.journal_summary(json.dumps({'state':'DELETING','runtimeRoot':'/private/path','token':'SECRET_CANARY'}).encode())
        self.assertEqual(result['state'],'DELETING')
        self.assertTrue(result['runtimeRootPresent'])
        self.assertNotIn('SECRET_CANARY',json.dumps(result))
        self.assertNotIn('/private/path',json.dumps(result))
if __name__=='__main__':unittest.main()
