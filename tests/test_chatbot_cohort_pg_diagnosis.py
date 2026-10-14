"""Diagnostic redaction qualification; not a target PostgreSQL observation."""
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1]/'scripts/diagnose-file-cohort-postgres.py'
spec = importlib.util.spec_from_file_location('pg_diagnosis', path)
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class DiagnosisRedaction(unittest.TestCase):
    def test_verbose_sqlstate_does_not_reveal_server_detail_or_query(self):
        raw = b'ERROR:  42501: permission denied private-table\nDETAIL: private-secret\nSTATEMENT: SELECT private-payload;'
        result = d.safe_reply(3, b'private-result', raw, 'MIGRATION_HISTORY')
        self.assertEqual(result['sqlstate'], '42501')
        self.assertEqual(result['classification'], 'INSUFFICIENT_PRIVILEGE')
        self.assertFalse(result['automaticRetry'])
        self.assertNotIn('private', json.dumps(result))

    def test_missing_sqlstate_is_unknown_and_never_guessed_from_error_text(self):
        for raw in (b'password authentication failed private-secret', b'permission denied', b''):
            result = d.failure(raw, 1)
            self.assertIsNone(result['sqlstate'])
            self.assertEqual(result['classification'], 'UNCLASSIFIED_CHANNEL_FAILURE')
            self.assertFalse(result['automaticRetry'])

    def test_only_migration_count_and_allowlisted_admin_facts_are_public(self):
        result = d.safe_reply(0, b'{"value":[{"script":"private-secret","checksum":123}]}', b'', 'MIGRATION_HISTORY')
        self.assertEqual(result['migrationCount'], 1)
        self.assertNotIn('private', json.dumps(result))
        raw = json.dumps({'value':{'adminSuperuser':True, 'serverVersion':170011,
                                   'auditRoleAbsent':'private-secret', 'private-secret':True}}).encode()
        result = d.safe_reply(0, raw, b'', 'ADMIN_OWNERSHIP')
        self.assertEqual(result['facts'], {'adminSuperuser':True, 'serverVersion':170011})

    def test_invalid_or_excessive_reply_stays_blocked(self):
        for raw in (b'private-secret', b'{}', b'[]', json.dumps({'value':[0]*257}).encode()):
            result = d.safe_reply(0, raw, b'', 'MIGRATION_HISTORY')
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertNotIn('private', json.dumps(result))

    def test_identity_injection_is_rejected(self):
        for value in ('x; DROP DATABASE target', 'x"', '', None, '-hremote'):
            with self.assertRaises(ValueError): d.ident(value)


if __name__ == '__main__': unittest.main()
