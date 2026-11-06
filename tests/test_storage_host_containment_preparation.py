"""Preparation boundary tests: no service mutations, privacy, lineage and no overwrite."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = load('containment_preparation', 'scripts/prepare-storage-host-containment-20261106.py')
b = load('backup_io_definitions', 'scripts/storage-cold-backup.py')


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name) / 'new-preparation'
        self.calls = []
        self.secret = 'EXAMPLE_PRIVATE_UNIT_VALUE_NOT_FOR_PUBLIC_OUTPUT'
        self.rows = []
        self.files = {}
        legacy = {'sources': ['/data/source-' + str(i) for i in range(34)],
                  'runtimeSources': {'/run/example-' + str(i): {} for i in range(5)},
                  'validUntilEpoch': 1794081219}
        for i, path in enumerate(p.PRIOR):
            self.files[path] = b.canonical(legacy if i == 0 else {'fixture': i})
        self.prior = {path: b.digest(raw) for path, raw in self.files.items()}
        for name in sorted(p.EXPECTED):
            row = {key: [''] for key in p.PROPS}
            row.update(Id=[name], Names=[name], LoadState=['masked' if name in p.MASKED else 'loaded'],
                       ActiveState=['inactive' if name in p.MASKED or name in p.SERVICES else 'active'],
                       NeedDaemonReload=['no'], MainPID=['0'], Type=['oneshot'], Restart=['no'],
                       ReadWritePaths=['/data/source-1'], ExecStart=[self.secret],
                       FragmentPath=['/etc/systemd/system/' + name])
            self.rows.append(row)
            if name not in p.MASKED:
                self.files[row['FragmentPath'][0]] = ('[Service]\nEnvironment=' + self.secret + '\n').encode()
        self.unavailable = set()
        self.extra_unit = False
        self.h = {name: getattr(b, name) for name in ('digest', 'decode', 'canonical', 'new', 'Held')}
        self.h['protected'] = self.read

    def read(self, path, **_kwargs):
        if str(path) in self.unavailable:
            raise b.Held('PROTECTED_REGULAR_INPUT_REQUIRED')
        return self.files[str(path)]

    def systemctl(self, argv, until):
        self.calls.append(argv)
        if argv[0] in ('list-unit-files', 'list-units'):
            names = p.EXPECTED | ({'ouf-unreviewed-token.service'} if self.extra_unit else set())
            return '\n'.join(name + ' enabled' for name in sorted(names))
        if argv[0] == 'show':
            return '\n\n'.join('\n'.join(k + '=' + v for k, values in row.items() for v in values
                                        if v or '--all' in argv)
                               for row in self.rows)
        raise AssertionError('Mutating or unapproved command: ' + str(argv))

    def prepare(self):
        with patch.object(p, 'AREA', self.area), patch.object(p, 'PRIOR', self.prior):
            return p.prepare(self.h, run=self.systemctl)

    def test_private_draft_public_redaction_and_no_operational_effect(self):
        result = self.prepare()
        self.assertNotIn(self.secret, json.dumps(result))
        draft = (self.area / 'draft.private.json').read_bytes()
        self.assertIn(self.secret.encode(), draft)
        self.assertEqual(result['candidateSha256'], b.digest(draft))
        self.assertEqual(result['serviceMutations'], 0)
        self.assertFalse(result['executorImplemented'])
        self.assertEqual(len(result['proposedServiceUnits']), 6)
        self.assertEqual(stat.S_IMODE(self.area.stat().st_mode), 0o700)
        self.assertEqual({stat.S_IMODE(f.stat().st_mode) for f in self.area.iterdir()}, {0o600})
        self.assertEqual([c[0] for c in self.calls], ['list-unit-files', 'list-units', 'show'])
        self.assertEqual(result['legacyValidUntilEpoch'], 1794081219)

    def test_existing_preparation_denied_before_any_read_command(self):
        self.prepare()
        before = (self.area / 'draft.private.json').read_bytes()
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'PREPARATION_ALREADY_EXISTS'):
            self.prepare()
        self.assertEqual(self.calls, [])
        self.assertEqual((self.area / 'draft.private.json').read_bytes(), before)

    def test_prior_attempt_tamper_denied_before_commands_or_output(self):
        self.files[next(iter(self.prior))] += b' '
        with self.assertRaisesRegex(ValueError, 'PRIOR_ATTEMPT_BINDING'):
            self.prepare()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.area.exists())

    def test_additional_token_unit_never_silently_ignored(self):
        self.extra_unit = True
        with self.assertRaisesRegex(ValueError, 'TOKEN_UNIT_SET_CHANGED'):
            self.prepare()
        self.assertFalse(self.area.exists())

    def test_unreadable_configuration_retains_review_finding_not_false_success(self):
        self.unavailable.add('/etc/systemd/system/' + p.REGISTRY)
        result = self.prepare()
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['unit'], p.REGISTRY)
        self.assertEqual(result['findings'][0]['reason'], 'UNIT_CONFIGURATION_CUSTODY_OR_ENCODING_UNPROVEN')
        self.assertFalse(result['targetStopOrCaptureAuthorized'])

    def test_external_fragment_arbitrary_filename_keeps_protected_read_and_redaction(self):
        path = '/var/lib/ouf-private-installation/current/unit.runtime'
        row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
        row['FragmentPath'] = [path]
        self.files[path] = ('[Service]\nEnvironment=' + self.secret + '\n').encode()
        result = self.prepare()
        report = next(r for r in result['units'] if r['Id'] == p.REGISTRY)
        self.assertEqual(report['externalConfigurationFilesBound'], 1)
        self.assertNotIn(path, json.dumps(result))
        self.assertNotIn(self.secret, json.dumps(result))
        self.assertEqual(result['findings'], [])

    def test_external_fragment_custody_failure_cannot_be_admitted_by_location(self):
        path = '/opt/ouf-unprotected/unit.runtime'
        row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
        row['FragmentPath'] = [path]
        self.unavailable.add(path)
        result = self.prepare()
        self.assertEqual(result['findings'][0]['locationKind'], 'EXTERNAL_MANAGER_REPORTED_LOCATION')
        self.assertEqual(result['findings'][0]['reason'], 'UNIT_CONFIGURATION_CUSTODY_OR_ENCODING_UNPROVEN')
        self.assertEqual(next(r for r in result['units'] if r['Id'] == p.REGISTRY)['configurationFilesBound'], 0)

    def test_invalid_path_is_reported_without_reading_it_or_losing_other_units(self):
        for path in ('', '../unit', '/etc/../root/unit', '/proc/1/environ', '/dev/zero', '/sys/example'):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temp:
                self.area = Path(temp) / 'preparation'
                row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
                row['FragmentPath'] = [path]
                result = self.prepare()
                self.assertEqual(result['findings'][0]['reason'], 'UNIT_CONFIGURATION_PATH_REQUIRES_REVIEW')
                self.assertFalse(result['findings'][0]['bodyReadAttempted'])
                self.assertEqual(result['unitConfigurationFilesBound'], 10)

    def test_repeated_identity_property_denied_without_new_files(self):
        self.rows[0]['Id'].append(self.rows[0]['Id'][0])
        with self.assertRaisesRegex(ValueError, 'UNIT_ID_CARDINALITY'):
            self.prepare()
        self.assertFalse(self.area.exists())

    def test_show_explicitly_requests_empty_properties(self):
        result = self.prepare()
        self.assertIn('--all', self.calls[-1])
        self.assertEqual(result['findings'], [])
        self.assertTrue(all(r['execStopPresent'] is False for r in result['units'] if 'execStopPresent' in r))

    def test_missing_optional_field_is_unknown_and_other_units_are_preserved(self):
        row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
        for key in ('PropagatesStopTo', 'ExecStop', 'ReadWritePaths', 'DropInPaths'):
            del row[key]
        result = self.prepare()
        report = next(r for r in result['units'] if r['Id'] == p.REGISTRY)
        self.assertIsNone(report['stopPropagationPresent'])
        self.assertIsNone(report['execStopPresent'])
        self.assertIsNone(report['declaredWritablePathsOverlapSourceCount'])
        self.assertEqual({f['property'] for f in result['findings']},
                         {'PropagatesStopTo', 'ExecStop', 'ReadWritePaths', 'DropInPaths'})
        self.assertEqual(result['unitConfigurationFilesBound'], 11)

    def test_multiple_exec_stop_commands_preserved_without_exporting_arguments(self):
        row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
        row['ExecStop'] = [self.secret + ' first', self.secret + ' second']
        row['Restart'] = ['no', 'always']
        result = self.prepare()
        report = next(r for r in result['units'] if r['Id'] == p.REGISTRY)
        self.assertTrue(report['execStopPresent'])
        self.assertEqual(report['execStopPropertyLines'], 2)
        self.assertIsNone(report['Restart'])
        self.assertEqual(result['findings'][0]['property'], 'Restart')
        self.assertEqual(result['findings'][0]['occurrences'], 2)
        self.assertNotIn(self.secret, json.dumps(result))

    def test_critical_cardinality_failure_identifies_unit_and_key_without_values(self):
        row = next(r for r in self.rows if r['Id'] == [p.REGISTRY])
        row['LoadState'] = ['loaded', self.secret]
        with self.assertRaises(p.PropertyIssue) as caught:
            self.prepare()
        self.assertEqual(caught.exception.details, {'unit': p.REGISTRY, 'property': 'LoadState',
            'occurrences': 2, 'reason': 'PROPERTY_CARDINALITY'})
        self.assertFalse(self.area.exists())


if __name__ == '__main__':
    unittest.main()
