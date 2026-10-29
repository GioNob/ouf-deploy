import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import iam_admin_get_diagnostic as diagnostic
import iam_binding_candidate as binding

class AdminGetDiagnosticTest(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temporary.cleanup)
        parent=Path(temporary.name);parent.chmod(0o700)
        client={k:'PRIVATE-FIXTURE' for k in diagnostic.FIELDS.split(',')};client['id']='11111111-1111-1111-1111-111111111111'
        snapshot={'schema':'ouf.policy-token-existing-iam-metadata.v1','client':client}
        raw=binding.encoded(snapshot);path=parent/'retained.json';path.write_bytes(raw);path.chmod(0o600)
        patches=[patch.object(binding,'PARENT',parent),patch.object(diagnostic,'SNAPSHOT',path.name),patch.object(diagnostic,'SNAPSHOT_HASH',binding.sha(raw))]
        for p in patches:p.start();self.addCleanup(p.stop)
        return parent,path,client
    def test_authentication_permission_transport_and_unknown_categories_do_not_disclose_raw_values(self):
        for raw,expected in [(b'PRIVATE-TOKEN Session has expired','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
                             (b'PRIVATE-TOKEN Forbidden HTTP 403','FORBIDDEN_TEXT_OBSERVED'),
                             (b'PRIVATE-TOKEN Connection refused','CONNECTION_REFUSED_TEXT_OBSERVED'),
                             (b'PRIVATE-TOKEN arbitrary error','UNCLASSIFIED_CLI_FAILURE')]:
            self.assertIn(expected,diagnostic.categories(raw));self.assertNotIn('PRIVATE-TOKEN',json.dumps(diagnostic.categories(raw)))
    def test_one_failed_exact_get_no_login_secret_or_other_resource_and_no_writes(self):
        parent,path,client=self.fixture();before=path.read_bytes();report={}
        with patch.object(diagnostic,'command',side_effect=[(0,b'true\n',b''),(1,b'',b'PRIVATE-TOKEN Session has expired')])as run:
            diagnostic.observe(report)
        self.assertEqual(run.call_count,2);args=run.call_args_list[1].args[0]
        self.assertEqual(args[3:6],['/opt/keycloak/bin/kcadm.sh','get','clients/'+client['id']])
        self.assertFalse(any(v in args for v in ('credentials','client-secret','create','update','delete')))
        self.assertEqual(report['iamMetadataGetAttempts'],1);self.assertNotIn('PRIVATE',json.dumps(report))
        self.assertEqual(path.read_bytes(),before);self.assertEqual(list(parent.iterdir()),[path])
    def test_stopped_container_and_hash_drift_deny_before_iam_get(self):
        _,path,_=self.fixture();report={}
        with patch.object(diagnostic,'command',return_value=(0,b'false',b''))as run:diagnostic.observe(report)
        self.assertEqual(run.call_count,1);self.assertEqual(report['reason'],'SELECTED_CONTAINER_NOT_RUNNING')
        path.write_bytes(b'CHANGED')
        with patch.object(diagnostic,'command')as run:
            with self.assertRaises(binding.CandidateDenied):diagnostic.observe({})
            self.assertFalse(run.called)
    def test_successful_get_only_reports_availability_without_replaying_preparation(self):
        _,_,client=self.fixture();report={}
        with patch.object(diagnostic,'command',side_effect=[(0,b'true',b''),(0,binding.encoded(client),b'')])as run:
            diagnostic.observe(report)
        self.assertEqual(run.call_count,2);self.assertTrue(report['exactSelectedClientGetSucceeded'])
        self.assertIn('NO_AUTOMATIC_PREPARATION_REPLAY',report['reason']);self.assertNotIn('PRIVATE',json.dumps(report))
    def test_actual_child_stderr_capture_is_bounded_and_remains_private(self):
        status,out,err=diagnostic.command([sys.executable,'-I','-B','-c',
            "import sys;sys.stderr.write('PRIVATE-DIAGNOSTIC'*5000);sys.exit(1)"],5)
        self.assertEqual(status,1);self.assertEqual(out,b'');self.assertEqual(len(err),65537)
        self.assertEqual(diagnostic.categories(err[:65536]),['UNCLASSIFIED_CLI_FAILURE'])

if __name__=='__main__':unittest.main()
