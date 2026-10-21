import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import install_provider_network_guard as installer

class DiagnosisTest(unittest.TestCase):
 def test_existing_root_owned_sticky_tmp_report_can_be_read(self):
  with tempfile.TemporaryDirectory(prefix='ouf-selected-report-',dir='/tmp') as directory:
   root=Path(directory);root.chmod(0o700);path=root/'report.json';path.write_bytes(b'{}');path.chmod(0o600)
   with patch.object(installer,'NETWORK_REPORT',path):self.assertEqual(installer.private(path),b'{}')
   root.chmod(0o777)
   with patch.object(installer,'NETWORK_REPORT',path),self.assertRaisesRegex(installer.MigrationDenied,'ANCESTOR_REQUIRED'):installer.private(path)
 def test_unexpected_error_is_classified_without_private_raw_content(self):
  output=io.StringIO()
  with (patch.object(installer,'install',side_effect=RuntimeError('DO_NOT_PRINT_PRIVATE_CONFIGURATION')),
   patch.object(installer,'SNAPSHOT',None),patch.object(installer,'STAGE','ORIGINAL_BOOT_COHORT'),
   patch('sys.argv',['installer','--source-directory','/root/source','--manifest-sha256','a'*64]),contextlib.redirect_stdout(output)):
   self.assertEqual(installer.main(),1)
  row=json.loads(output.getvalue().split('=',1)[1])
  self.assertEqual(row['stage'],'ORIGINAL_BOOT_COHORT');self.assertEqual(row['errorClass'],'RuntimeError')
  self.assertNotIn('DO_NOT_PRINT',output.getvalue());self.assertFalse(row['startAuthorized'])
 def test_sealed_source_drift_identifies_expected_and_actual_hash(self):
  with tempfile.TemporaryDirectory(prefix='ouf-hash-diagnosis-',dir='/root') as directory:
   root=Path(directory);root.chmod(0o700);path=root/'source.py';path.write_bytes(b'changed');path.chmod(0o600)
   with self.assertRaises(installer.MigrationDenied) as error:installer.private(path,'0'*64)
   details=error.exception.diagnosis
   self.assertEqual(details['inputName'],'source.py');self.assertEqual(details['expectedSha256'],'0'*64)
   self.assertEqual(details['actualSha256'],installer.sha(b'changed'))
if __name__=='__main__':unittest.main()
