"""Deny wrong application artifacts and incomplete or failed owner test reports."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gateway_candidate', ROOT/'scripts/package-m2-gateway-owner-candidate-20261101.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OwnerCandidate(unittest.TestCase):
    def test_missing_empty_failed_errored_or_skipped_owner_reports_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with self.assertRaises(ValueError): m.tests_passed(folder)
            for tests, failure, error, skip in ((0,0,0,0),(3,0,0,0),(4,1,0,0),(4,0,1,0),(4,0,0,1)):
                (folder/'TEST-one.xml').write_text(f'<testsuite tests="{tests}" failures="{failure}" errors="{error}" skipped="{skip}"/>')
                with self.subTest(tests=tests, failure=failure, error=error, skip=skip), self.assertRaises(ValueError):
                    m.tests_passed(folder)
            (folder/'TEST-one.xml').write_text('<testsuite tests="4" failures="0" errors="0" skipped="0"/>')
            self.assertEqual(m.tests_passed(folder)['tests'], 4)

    def test_only_the_actual_owner_application_and_receipt_filter_form_this_candidate(self):
        first = 'BOOT-INF/classes/it/comune/trieste/ouf/gateway/GatewayOperationalApplication.class'
        second = 'BOOT-INF/classes/it/comune/trieste/ouf/receipt/SummaryReceiptFilter.class'
        for names, allowed in (([first,second],True),([first],False),([second],False),(['BOOT-INF/classes/semantic.class'],False)):
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, 'w') as archive:
                for name in names: archive.writestr(name, b'class fixture')
            if allowed: self.assertEqual(set(m.jar_contract(raw.getvalue())), {first,second})
            else:
                with self.assertRaisesRegex(ValueError, 'ACTUAL_GATEWAY_OWNER'): m.jar_contract(raw.getvalue())

    def test_build_is_denied_outside_hosted_ci_before_source_engine_or_output_access(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.dict(m.os.environ, {'GITHUB_ACTIONS':'false'}):
            output = Path(tmp)/'absent'
            with self.assertRaisesRegex(ValueError, 'ISOLATED_CI'): m.build(Path('/not-read'), output)
            self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
