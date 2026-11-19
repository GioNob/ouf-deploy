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

    def test_preconnection_fatal_errors_are_classified_without_exposing_identities(self):
        cases = ((b'FATAL:  role "private-user" does not exist\n', 'ROLE_NOT_FOUND'),
                 (b'FATAL:  password authentication failed for user "private-user"\n', 'PASSWORD_AUTHENTICATION_FAILED'),
                 (b'FATAL:  Peer authentication failed for user "private-user"\n', 'PEER_AUTHENTICATION_FAILED'),
                 (b'FATAL:  database "private-db" does not exist\n', 'DATABASE_NOT_FOUND'))
        for raw, expected in cases:
            result = d.failure(b'psql: connection to server failed: '+raw, 2)
            self.assertEqual(result['classification'], expected)
            self.assertIsNone(result['sqlstate'])
            self.assertFalse(result['automaticRetry'])
            self.assertNotIn('private', json.dumps(result))

    def test_admin_selector_is_explicit_without_password_reads_or_default_role(self):
        self.assertEqual(d.bootstrap_admin({'Config':{'Env':['POSTGRES_USER=fixture_admin',
                         'POSTGRES_PASSWORD=private-secret']}}), 'fixture_admin')
        for env in ([], ['POSTGRES_USER=']):
            self.assertIsNone(d.bootstrap_admin({'Config':{'Env':env}}))
        with self.assertRaisesRegex(ValueError, 'AMBIGUOUS'):
            d.bootstrap_admin({'Config':{'Env':['POSTGRES_USER=a','POSTGRES_USER=b']}})
        with self.assertRaises(ValueError):
            d.bootstrap_admin({'Config':{'Env':['POSTGRES_USER=admin;DROP DATABASE x']}})

    def test_role_catalogue_redacts_private_fields(self):
        raw = json.dumps({'value':{'postgresRoleExists':False, 'bootstrapRoleSuperuser':True,
                                   'roleName':'private-user'}}).encode()
        result = d.safe_reply(0, raw, b'', 'ADMIN_ROLE_METADATA')
        self.assertEqual(result['facts'], {'postgresRoleExists':False, 'bootstrapRoleSuperuser':True})
        self.assertNotIn('private', json.dumps(result))


if __name__ == '__main__': unittest.main()
