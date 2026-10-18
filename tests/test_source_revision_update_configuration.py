"""Real private files/JAR, source-selected endpoints and Spring override denial."""
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.source_revision_update import configuration as c
from tools.source_revision_update.owner import UpdateDenied


class Configuration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/root'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        yaml = b'spring:\n  flyway:\n    schemas: ouf_onboarding\n'
        jar = self.root/'application.jar'
        with zipfile.ZipFile(jar,'w') as archive:
            archive.writestr('BOOT-INF/classes/application.yml',yaml)
            archive.writestr('BOOT-INF/lib/flyway-core-fixture.jar',b'fixture')
        jar.chmod(0o600)
        self.candidate = {'jar':{'path':str(jar),'sha256':hashlib.sha256(jar.read_bytes()).hexdigest()}}
        self.yaml_sha = hashlib.sha256(yaml).hexdigest()
        self.actual = {'Config':{'Env':['OUF_ONB_DB_USER=fixture_app','OUF_ONB_DB_PASSWORD=fixture-secret',
            'OUF_ONB_DB_URL=jdbc:postgresql://postgres.fixture:5433/fixture_db?currentSchema=ouf_onboarding'],
            'Entrypoint':['java','-jar','/app/application.jar'],'Cmd':[],'WorkingDir':'/app'},
            'Mounts':[],'State':{'Pid':123}}
        self.postgres = {'Name':'/fixture-postgres','Config':{'Hostname':'fixture-pg'},
            'NetworkSettings':{'Networks':{'fixture':{'Aliases':['postgres.fixture'],'IPAddress':'10.1.1.3'}}}}
        self.binding = {'user':'fixture_app','database':'fixture_db','schema':'ouf_onboarding'}
        self.process_root = self.root/'filesystem'; (self.process_root/'app').mkdir(parents=True)

    def verify(self):
        return c.verify(self.actual,self.candidate,self.postgres,self.binding,5433,self.yaml_sha,root=self.process_root)

    def test_exact_retained_native_binding_and_jar_succeed_without_secret_output(self):
        result = self.verify()
        self.assertTrue(result['sameDatasourceAsApplication']); self.assertTrue(result['nativeFlywayEnabledByDefault'])
        self.assertNotIn('fixture-secret',str(result)); self.assertFalse(result['configurationValuesPrinted'])

    def test_wrong_database_role_endpoint_port_or_source_jar_fail(self):
        valid = copy.deepcopy(self.actual)
        for old,new in [('fixture_app','wrong_app'),('postgres.fixture','unapproved.fixture'),
                        (':5433/',':5432/'),('/fixture_db','/other_db')]:
            self.actual = copy.deepcopy(valid)
            self.actual['Config']['Env'] = [v.replace(old,new) for v in self.actual['Config']['Env']]
            with self.subTest(new=new),self.assertRaises(UpdateDenied): self.verify()
        self.actual = valid; self.yaml_sha = 'a'*64
        with self.assertRaises(UpdateDenied): self.verify()

    def test_higher_priority_spring_and_java_channels_fail_before_start(self):
        valid = copy.deepcopy(self.actual)
        for value in ('SPRING_FLYWAY_ENABLED=false','SPRING_APPLICATION_JSON={}',
                      'JAVA_TOOL_OPTIONS=-Dspring.flyway.url=jdbc:unapproved','SPRING_PROFILES_ACTIVE=other'):
            self.actual = copy.deepcopy(valid); self.actual['Config']['Env'].append(value)
            with self.subTest(value=value),self.assertRaises(UpdateDenied): self.verify()
        self.actual = valid; self.actual['Config']['Cmd'] = ['--spring.flyway.enabled=false']
        with self.assertRaises(UpdateDenied): self.verify()

    def test_existing_readonly_owner_overlay_is_hashed_and_retained(self):
        overlay = self.root/'owner.yaml'; overlay.write_bytes(b'ouf:\n  onboarding:\n    issuer: https://auth.fixture.invalid\n')
        overlay.chmod(0o600)
        self.actual['Config']['Env'].append('SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:/run/owner.yaml')
        self.actual['Mounts'] = [{'Destination':'/run/owner.yaml','Source':str(overlay),'Type':'bind','RW':False}]
        result = self.verify(); self.assertEqual(len(result['ownerOverlays']),1)
        self.assertEqual(result['ownerOverlays'][0]['binding']['path'],str(overlay))
        self.assertTrue(result['ownerOverlays'][0]['metadata']['nonSpringOwnerOverlay'])
        overlay.write_bytes(b'spring:\n  flyway:\n    enabled: false\n')
        with self.assertRaisesRegex(UpdateDenied,'MIGRATION_OVERRIDE'): self.verify()

    def test_overlay_mount_must_be_exact_readonly_single_file(self):
        self.actual['Config']['Env'].append('SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/owner.yaml')
        with self.assertRaises(UpdateDenied): self.verify()
        for value in ('file:/run/one.yaml,file:/run/two.yaml','classpath:other.yml','file:../other.yaml',
                      'optional:file:/run/*/owner.yaml'):
            with self.subTest(value=value),self.assertRaises(UpdateDenied): c.additional_location(value)

    def test_aliases_complex_keys_and_flow_documents_are_not_accepted_as_absent_overrides(self):
        for raw in (b'<<: *override\n',b'owner: &override value\n',b'{spring: {flyway: {enabled: false}}}',
                    b'"spring":\n  flyway.enabled: false\n',b'spring.flyway.enabled: false\n'):
            with self.subTest(raw=raw),self.assertRaises(UpdateDenied): c.overlay_text(raw)

    def test_default_external_configuration_and_config_mounts_fail(self):
        external = self.process_root/'app/application.properties'; external.write_text('spring.flyway.enabled=false')
        with self.assertRaises(UpdateDenied): self.verify()
        external.unlink()
        self.actual['Mounts'] = [{'Destination':'/app/config','Source':'/retained','Type':'bind','RW':False}]
        with self.assertRaises(UpdateDenied): self.verify()


if __name__ == '__main__': unittest.main()
