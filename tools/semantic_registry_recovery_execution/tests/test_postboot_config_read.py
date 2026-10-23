"""Classify retained caller configuration; no runtime, property or credential read."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/read-registry-postboot-config-20261023.py'
spec = importlib.util.spec_from_file_location('caller_config_probe_fixture', SCRIPT)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class RetainedCallerConfiguration(unittest.TestCase):
    def file_config(self):
        return {'Env': ['SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:' + p.TARGET],
                'Cmd': ['--spring.flyway.enabled=false', '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']}

    def test_properties_selection_exposes_exact_legacy_lookup_failure_without_values(self):
        value = p.configuration_shape(self.file_config(), {'Binds': ['/private/PRIVATE_SOURCE:' + p.TARGET + ':ro']})
        self.assertTrue(value['knownPropertiesFileSelected'])
        self.assertTrue(value['knownPropertiesReadOnlyBindPresent'])
        self.assertTrue(value['legacyEnvironmentLookupWouldRaiseKeyError'])
        self.assertFalse(any(value['commandLineOverridesPresent'].values()))
        self.assertNotIn('PRIVATE_SOURCE', json.dumps(value))
        self.assertNotIn(p.TARGET, json.dumps(value))

    def test_explicit_environment_reports_both_keys_without_printing_values(self):
        config = {'Env': [name + '=PRIVATE_VALUE' for name in p.EXPECTED_ENV.values()]}
        value = p.configuration_shape(config, {})
        self.assertFalse(value['legacyEnvironmentLookupWouldRaiseKeyError'])
        self.assertFalse(value['knownPropertiesFileSelected'])
        self.assertNotIn('PRIVATE_VALUE', json.dumps(value))

    def test_empty_environment_value_is_distinguished_from_absent_key(self):
        value = p.configuration_shape({'Env': [name + '=' for name in p.EXPECTED_ENV.values()]}, {})
        self.assertFalse(value['legacyEnvironmentLookupWouldRaiseKeyError'])
        self.assertTrue(value['legacyEnvironmentLookupWouldFail'])

    def test_ambiguous_selectors_or_non_readonly_bind_are_not_proven(self):
        config = self.file_config(); config['Env'].append('SPRING_CONFIG_LOCATION=file:' + p.TARGET)
        self.assertFalse(p.configuration_shape(config, {})['knownPropertiesFileSelected'])
        self.assertFalse(p.configuration_shape(self.file_config(), {'Binds': ['PRIVATE:' + p.TARGET + ':rw']})[
            'knownPropertiesReadOnlyBindPresent'])

    def test_command_line_and_jvm_channels_are_reported_as_booleans(self):
        config = self.file_config()
        config['Cmd'] += ['--ouf.ingestion.activation.gateway-url=PRIVATE_URL',
                          '--ouf.ingestion.activation.token-file=PRIVATE_PATH']
        config['Env'].append('JAVA_TOOL_OPTIONS=PRIVATE_JVM_OPTIONS')
        value = p.configuration_shape(config, {})
        self.assertTrue(value['commandLineOverridesPresent']['gatewayUrl'])
        self.assertTrue(value['commandLineOverridesPresent']['tokenFile'])
        self.assertTrue(value['additionalConfigurationChannelsPresent']['JAVA_TOOL_OPTIONS'])
        self.assertNotIn('PRIVATE_', json.dumps(value))

    def test_duplicate_environment_is_rejected_without_private_value_in_error(self):
        with self.assertRaises(ValueError) as error:
            p.configuration_shape({'Env': ['KEY=PRIVATE_A', 'KEY=PRIVATE_B']}, {})
        self.assertEqual(error.exception.args, ())

    def test_only_exact_retained_reader_bytes_are_loaded_and_symlinks_are_refused(self):
        reader = (ROOT / 'scripts/read-registry-postboot-stop-20261023.py').read_bytes()
        self.assertEqual(hashlib.sha256(reader).hexdigest(), p.READER_HASH)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'reader.py'; path.write_bytes(reader)
            self.assertEqual(p.read_verified_reader(str(path)), reader)
            path.write_bytes(b'raise RuntimeError("PRIVATE_EXECUTED")')
            with self.assertRaises(ValueError):
                p.read_verified_reader(str(path))
            path.unlink(); path.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                p.read_verified_reader(str(path))

    def test_no_application_or_native_or_write_dispatch(self):
        denied = {'execute', 'prepare', '_prepare', 'request', 'Popen', 'run', 'mkdir',
                  'write', 'write_bytes', 'write_text', 'unlink', 'rename'}
        for node in ast.walk(ast.parse(SCRIPT.read_bytes())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, denied)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'os':
                self.assertNotIn(node.attr, {'O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC'})

    def test_selected_file_metadata_never_reads_or_projects_contents_or_paths(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'PRIVATE_CONFIG'; path.write_text('PRIVATE_CONTENT_NOT_JSON')
            info = path.stat()
            binding = {'path': str(path), 'metadata': [info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]}
            value = p.file_metadata(binding)
            self.assertTrue(value['present']); self.assertTrue(value['metadataMatchesRetained'])
            self.assertFalse(value['hashVerified'])
            self.assertNotIn('PRIVATE_', json.dumps(value)); self.assertNotIn(directory, json.dumps(value))
            missing = p.file_metadata({'path': str(path) + '-absent'})
            self.assertEqual(missing['exceptionClass'], 'FileNotFoundError')
            self.assertFalse(missing['present'])


if __name__ == '__main__':
    unittest.main()
