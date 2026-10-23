"""Configuration source precedence, custody and mounted-view identity."""
import copy
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.semantic_registry_recovery_execution import caller_configuration as c

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "tests")]
import test_file_only_preparation  # supplies the repo standard flat-module aliases


class CallerConfiguration(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.file = self.root / 'ingestion-summary.properties'
        self.file.write_text('ouf.ingestion.activation.gateway-url=http://192.0.2.1:9080\n'
                             'ouf.ingestion.activation.token-file=/run/service.jwt\n')
        self.file.chmod(0o440)
        self.actual = {'Config': {'Env': ['SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:' + c.INGESTION_CONFIG_TARGET],
                                 'Entrypoint': ['java'], 'Cmd': ['-jar', '/app/app.jar']},
                       'Mounts': [{'Destination': c.INGESTION_CONFIG_TARGET,
                                   'Source': str(self.file), 'Type': 'bind', 'RW': False}],
                       'State': {'Pid': os.getpid()}}

    def test_legacy_environment_remains_explicit_and_guarded(self):
        self.actual['Config']['Env'] = [c.ENV_KEYS[0] + '=http://192.0.2.1:9080', c.ENV_KEYS[1] + '=/run/service.jwt']
        origin, target, binding = c.configuration(self.actual)
        c.verify(self.actual, {'origin': origin, 'tokenTarget': target, 'callerConfiguration': binding})
        self.actual['Config']['Env'][0] += '/changed'
        with self.assertRaisesRegex(Exception, 'CONFIGURATION_CHANGED'):
            c.configuration(self.actual, binding)

    def test_properties_and_activation_environment_are_ambiguous(self):
        self.actual['Config']['Env'].append(c.ENV_KEYS[0] + '=http://192.0.2.2')
        with self.assertRaisesRegex(Exception, 'AMBIGUOUS'):
            c.configuration(self.actual)

    def test_overlay_channels_fail_before_any_file_read(self):
        for key in sorted(c.CHANNELS):
            actual = copy.deepcopy(self.actual); actual['Config']['Env'].append(key + '=override')
            with self.subTest(key=key), patch.object(c, 'ingestion_properties') as reader:
                with self.assertRaisesRegex(Exception, 'OVERLAY'): c.configuration(actual)
                reader.assert_not_called()

    def test_command_overrides_including_shell_or_relaxed_spelling_fail(self):
        for arg in ('--ouf.ingestion.activation.gateway-url=http://evil',
                    'exec java -Dspring.config.location=/tmp/evil -jar app.jar',
                    '--ouf_ingestion_activation_token_file=/tmp/evil'):
            actual = copy.deepcopy(self.actual); actual['Config']['Cmd'].append(arg)
            with self.subTest(arg=arg), self.assertRaisesRegex(Exception, 'COMMAND_CONFIGURATION'):
                c.configuration(actual)

    def test_read_write_and_multiple_properties_mounts_fail(self):
        for mounts in ([dict(self.actual['Mounts'][0], RW=True)], self.actual['Mounts'] * 2):
            actual = copy.deepcopy(self.actual); actual['Mounts'] = mounts
            with self.subTest(mounts=mounts), self.assertRaisesRegex(Exception, 'PROPERTIES_MOUNT'):
                c.configuration(actual)

    def test_governed_reader_rejects_symlink_writable_file_and_duplicate(self):
        link = self.root / 'link'; link.symlink_to(self.file)
        actual = copy.deepcopy(self.actual); actual['Mounts'][0]['Source'] = str(link)
        with self.assertRaises(Exception): c.configuration(actual)
        self.file.chmod(0o666)
        with self.assertRaisesRegex(Exception, 'ROOT_CONTROLLED'): c.configuration(self.actual)
        self.file.chmod(0o440)
        self.file.chmod(0o640)
        self.file.write_text(self.file.read_text() + 'ouf_ingestion_activation_gateway_url=http://evil\n')
        with self.assertRaisesRegex(Exception, 'DUPLICATE'): c.configuration(self.actual)

    def test_missing_activation_property_fails_without_token_read(self):
        self.file.chmod(0o640)
        self.file.write_text('unrelated.property=literal\n')
        with self.assertRaisesRegex(Exception, 'CALLER_PROPERTIES_REQUIRED'): c.configuration(self.actual)

    def test_properties_profile_must_be_bound_to_signed_request(self):
        with patch.object(c, 'configuration', return_value=('origin', 'token', {'mode': 'SPRING_PROPERTIES'})):
            with self.assertRaisesRegex(Exception, 'SIGNED_ORIGINAL'):
                c.verify(self.actual, {'origin': 'origin', 'tokenTarget': 'token'})

    def mounted_view(self):
        # Same-process mount view for descriptor identity; full Docker bind
        # coverage is additionally exercised by native_jvm_postboot.
        actual = copy.deepcopy(self.actual)
        actual['Mounts'][0]['Destination'] = str(self.file)
        return actual

    def test_actual_process_view_same_inode_and_guarded_atomic_replacement(self):
        actual = self.mounted_view()
        with patch.object(c, 'INGESTION_CONFIG_TARGET', str(self.file)), \
             patch('tools.chatbot_file_cohort.preparation.INGESTION_CONFIG_TARGET', str(self.file)):
            actual['Config']['Env'] = ['SPRING_CONFIG_ADDITIONAL_LOCATION=file:' + str(self.file)]
            origin, target, binding = c.configuration(actual)
            self.assertEqual(binding['mode'], 'SPRING_PROPERTIES')
            c.verify(actual, {'origin': origin, 'tokenTarget': target, 'callerConfiguration': binding})
            replacement = self.root / 'replacement'; replacement.write_bytes(self.file.read_bytes()); replacement.chmod(0o440)
            os.replace(replacement, self.file)
            with self.assertRaisesRegex(Exception, 'CHANGED'):
                c.configuration(actual, binding)

    def test_host_and_process_mounted_inode_must_match(self):
        actual = self.mounted_view()
        other = self.root / 'other'; other.write_bytes(self.file.read_bytes()); other.chmod(0o440)
        actual['Mounts'][0]['Source'] = str(other)
        with patch.object(c, 'INGESTION_CONFIG_TARGET', str(self.file)), \
             patch('tools.chatbot_file_cohort.preparation.INGESTION_CONFIG_TARGET', str(self.file)):
            actual['Config']['Env'] = ['SPRING_CONFIG_ADDITIONAL_LOCATION=file:' + str(self.file)]
            with self.assertRaisesRegex(Exception, 'SAME_PROCESS_MOUNTED_PROPERTIES'):
                c.configuration(actual)


if __name__ == '__main__': unittest.main()
