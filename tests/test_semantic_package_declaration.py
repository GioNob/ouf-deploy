import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('rebase', Path(__file__).resolve().parents[1] / 'scripts/rebase-semantic-package-declaration.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageDeclarationTests(unittest.TestCase):
    def fixture(self):
        old = {'User': '10001:10001', 'Entrypoint': ['java', '-jar', '/app/application.jar'],
               'WorkingDir': '/app', 'Env': ['JAVA_HOME=/opt/java/openjdk', 'JAVA_VERSION=old',
                                            'PATH=/old/bin', 'OUF_SCHEMA_GOV_ENABLED=true',
                                            'JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/run/trust']}
        declaration = {'schema': 'ouf.discovery.private-replacement-runtime-declaration.v1',
                       'candidateImageId': module.OLD_IMAGE,
                       'inputBindings': {'applicationContractHash': module.CONTRACT_HASH},
                       'candidateConfig': old, 'roleOwnedReadOnlyMounts': [{'source': '/protected/key', 'readOnly': True}],
                       'proposedHostConfig': {'Memory': 9123456, 'Binds': ['/protected/key:/key:ro'],
                                              'RestartPolicy': {'Name': 'no'}, 'SecurityOpt': ['no-new-privileges']},
                       'retainedNativeCreationFrame': {'Id': 'retained', 'network': {'aliases': ['semantic']}},
                       'requiredBeforeMutation': ['EXPLICIT_COORDINATED_TRANSITION_AUTHORITY_NO_R9_REPLAY'],
                       'observationsAreHistorical': True, 'secretBytesFreshlyVerified': False,
                       'productionApplyReady': False, 'applicationCutoverAuthorized': False,
                       'completeReplacementOciProven': False}
        contract = {k: copy.deepcopy(v) for k, v in declaration.items()
                    if k in ('candidateConfig', 'roleOwnedReadOnlyMounts', 'productionApplyReady',
                             'applicationCutoverAuthorized', 'completeReplacementOciProven')}
        contract['schema'] = 'ouf.discovery.private-application-input-contract.v1'
        new = copy.deepcopy(old)
        new['Env'] = ['JAVA_HOME=/opt/java/openjdk', 'JAVA_VERSION=new', 'PATH=/new/bin']
        new['Labels'] = {'org.opencontainers.image.revision': module.SOURCE}
        return declaration, contract, new

    def test_preserve_host_and_approved_application_replace_image_defaults(self):
        d, c, new = self.fixture()
        before = copy.deepcopy(d)
        result, public = module.rebase(d, c, new)
        self.assertEqual(d, before)
        for key in ('proposedHostConfig', 'retainedNativeCreationFrame', 'roleOwnedReadOnlyMounts'):
            self.assertEqual(result[key], d[key])
        env = module.environment(result['candidateConfig']['Env'])
        self.assertEqual(env['JAVA_VERSION'], 'new')
        self.assertEqual(env['PATH'], '/new/bin')
        self.assertEqual(env['OUF_SCHEMA_GOV_ENABLED'], 'true')
        self.assertEqual(env['JAVA_TOOL_OPTIONS'], '-Djavax.net.ssl.trustStore=/run/trust')
        self.assertEqual(result['candidateImageId'], module.IMAGE)
        for key in ('productionApplyReady', 'applicationCutoverAuthorized', 'completeReplacementOciProven', 'freshRuntimeCustodyProven'):
            self.assertFalse(public[key])
        self.assertNotIn('candidateConfig', public)

    def test_execution_default_changes_require_review(self):
        for key in ('Entrypoint', 'Cmd', 'User', 'WorkingDir', 'ExposedPorts', 'Volumes', 'StopSignal', 'Healthcheck', 'Shell'):
            with self.subTest(key=key):
                d, c, new = self.fixture()
                new[key] = 'changed'
                with self.assertRaises(ValueError):
                    module.rebase(d, c, new)

    def test_historical_authority_and_image_cannot_be_promoted(self):
        for key in ('productionApplyReady', 'applicationCutoverAuthorized', 'completeReplacementOciProven'):
            for which in (0, 1):
                values = self.fixture()
                values[which][key] = True
                with self.assertRaises(ValueError):
                    module.rebase(*values)
        d, c, new = self.fixture()
        d['candidateImageId'] = module.IMAGE
        with self.assertRaises(ValueError):
            module.rebase(d, c, new)

    def test_contract_drift_and_unreviewed_environment_denied(self):
        d, c, new = self.fixture()
        c['roleOwnedReadOnlyMounts'][0]['source'] = '/different'
        with self.assertRaises(ValueError):
            module.rebase(d, c, new)
        d, c, new = self.fixture()
        d['candidateConfig']['Env'].append('LD_PRELOAD=/unknown')
        c['candidateConfig'] = copy.deepcopy(d['candidateConfig'])
        with self.assertRaisesRegex(ValueError, 'UNREVIEWED_ENVIRONMENT_SETTING'):
            module.rebase(d, c, new)

    def test_duplicate_environment_denied(self):
        d, c, new = self.fixture()
        new['Env'].append('PATH=/other')
        with self.assertRaisesRegex(ValueError, 'UNIQUE_ENVIRONMENT_KEYS_REQUIRED'):
            module.rebase(d, c, new)

    def archive(self, path, *, duplicate=False, escape=False, architecture='amd64', config_link=False):
        config = module.encoded({'architecture': architecture, 'os': 'linux', 'config': self.fixture()[2]})
        image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode='w') as archive:
            members = [('manifest.json', json.dumps([{'Config': 'config.json', 'Layers': []}]).encode()),
                       ('config.json', config)]
            if duplicate:
                members.append(members[0])
            for name, raw in members:
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                if config_link and name == 'config.json':
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '/etc/shadow', 0
                archive.addfile(member, io.BytesIO(raw))
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('../image.docker.tar' if escape else 'semantic/image.docker.tar', tar.getvalue())
        return hashlib.sha256(path.read_bytes()).hexdigest(), image_id

    def test_archive_reads_exact_config_without_extracting_host_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            digest, image = self.archive(path)
            self.assertEqual(module.package_config(path, digest, image), self.fixture()[2])
            self.assertEqual(sorted(v.name for v in Path(directory).iterdir()), ['package.zip'])

    def test_wrong_zip_or_image_hash_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            digest, image = self.archive(path)
            for expected_zip, expected_image in [('0' * 64, image), (digest, 'sha256:' + '0' * 64)]:
                with self.assertRaises(ValueError):
                    module.package_config(path, expected_zip, expected_image)

    def test_duplicate_escape_and_metadata_link_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            for options in ({'duplicate': True}, {'escape': True}, {'config_link': True}, {'architecture': 'arm64'}):
                with self.subTest(options=options):
                    digest, image = self.archive(path, **options)
                    with self.assertRaises(ValueError):
                        module.package_config(path, digest, image)

    def test_symlink_and_hardlinked_package_denied(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            digest, image = self.archive(path)
            linked = Path(directory) / 'link.zip'
            linked.symlink_to(path)
            with self.assertRaises(OSError):
                module.package_config(linked, digest, image)
            linked.unlink()
            os.link(path, linked)
            with self.assertRaises(ValueError):
                module.package_config(path, digest, image)


if __name__ == '__main__':
    unittest.main()
