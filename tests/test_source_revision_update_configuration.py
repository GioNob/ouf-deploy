"""Real private files/JAR, source-selected endpoints and Spring override denial."""
import copy
import hashlib
import json
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
        for value in ('SPRING_FLYWAY_ENABLED=false','SPRING_FLYWAY_ENABLED=','SPRING_APPLICATION_JSON={"spring.flyway.enabled":false}',
                      'JAVA_TOOL_OPTIONS=-Dspring.flyway.url=jdbc:unapproved','SPRING_PROFILES_ACTIVE=other'):
            self.actual = copy.deepcopy(valid); self.actual['Config']['Env'].append(value)
            with self.subTest(value=value),self.assertRaises(UpdateDenied): self.verify()
        self.actual = valid; self.actual['Config']['Cmd'] = ['--spring.flyway.enabled=false']
        with self.assertRaises(UpdateDenied): self.verify()

    def test_retained_root_empty_json_has_no_override_and_is_preserved(self):
        self.actual['Config']['Env'].append('SPRING_APPLICATION_JSON= {} ')
        before=copy.deepcopy(self.actual)
        result=self.verify()
        self.assertEqual(result['applicationJson']['propertyOverrides'],0)
        self.assertFalse(result['applicationJson']['migrationOverridePresent'])
        self.assertEqual(self.actual,before)

    def test_nonempty_duplicate_malformed_and_nonobject_json_stay_blocked(self):
        for raw in ('[]','null','true','invalid','{"ouf":{"setting":true}}',
                    '{"spring":{"flyway":{"enabled":false}}}',
                    '{"spring.flyway.enabled":true,"spring.flyway.enabled":false}'):
            with self.subTest(raw=raw),self.assertRaises(UpdateDenied):c.application_json_metadata(raw)

    def test_observed_owner_json_keeps_values_and_literal_oauth_identity(self):
        value={'ouf.authorization.ths.enabled':True,
            'ouf.managed-file-picker.gateway-upload-url':'https://fixture.invalid/PRIVATE_CANARY',
            'ouf.onboarding.udp-identity.gateway-url':'https://fixture.invalid/PRIVATE_CANARY',
            'ouf.onboarding.udp-identity.token-file':'/run/PRIVATE_CANARY',
            'ouf.resolution.ths.gateway-base-url':'https://fixture.invalid/PRIVATE_CANARY',
            'ouf.workflow.ths.gateway-base-url':'https://fixture.invalid/PRIVATE_CANARY',
            'spring.security.oauth2.client.registration.ouf-ths.scope':['openid','PRIVATE_CANARY']}
        raw=json.dumps(value);self.actual['Config']['Env'].append('SPRING_APPLICATION_JSON='+raw)
        before=copy.deepcopy(self.actual);result=self.verify()
        self.assertEqual(result['applicationJson']['propertyOverrides'],7)
        self.assertEqual(result['applicationJson']['rawSha256'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(self.actual,before);self.assertNotIn('PRIVATE_CANARY',json.dumps(result))

    def test_json_contract_rejects_type_alias_map_identity_and_migration_drift(self):
        for raw in ('{"ouf.authorization.ths.enabled":"true"}',
            '{"ouf.onboarding.udp-identity.gateway-url":"one","ouf.onboarding.udpIdentity.gatewayUrl":"two"}',
            '{"spring.security.oauth2.client.registration.oufths.scope":["openid"]}',
            '{"spring.security.oauth2.client.registration.ouf-ths.client-secret":"PRIVATE_CANARY"}',
            '{"spring.security.oauth2.client.registration.ouf-ths.scope":[true]}',
            '{"spring.datasource.url":"PRIVATE_CANARY"}','{"spring":{}}',
            '{"ouf.authorization.ths.enabled":NaN}',
            '{"ouf.authorization-ths.enabled":true}'):
            with self.subTest(raw=raw),self.assertRaises(UpdateDenied):c.application_json_metadata(raw)

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

class OwnerJson(unittest.TestCase):
    def test_retained_ths_json_accepts_owner_and_oauth_without_values(self):
        raw=json.dumps({'ouf':{'authorization':{'ths':{'enabled':True,'public-origin':'https://fixture.invalid'}}},'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'client-id':'PRIVATE_CANARY','client-secret':'SECRET_CANARY','authorization-grant-type':'authorization_code','provider':'fixture','scope':['openid','profile']}},'provider':{'fixture':{'issuer-uri':'https://fixture.invalid/realms/test'}}}}}}}).encode()
        result=c.overlay_text(raw);self.assertEqual(result['format'],'STRICT_JSON');self.assertFalse(result['migrationOverridePresent']);self.assertNotIn('CANARY',json.dumps(result))
    def test_spring_loader_datasource_profile_import_sql_and_env_aliases_denied(self):
        for key in ('spring.flyway.enabled','spring.datasource.url','spring.config.import','spring.profiles.active','spring.sql.init.mode','loader.path','SPRING_FLYWAY_ENABLED','springFlywayEnabled','ouf.onb.db.password','OUF_ONB_DB_PASSWORD','java.tool.options'):
            with self.subTest(key=key),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps({key:'CANARY'}).encode())
    def test_duplicate_canonical_and_prefix_conflicts_denied(self):
        for raw in (b'{"ouf":{"a":true,"a":false}}',b'{"ouf":{"a-b":1,"ab":2}}',b'{"ouf.a":1,"ouf":{"a":{"b":2}}}',b'{"ouf..a":1}',b'{"ouf":{"a":NaN}}'):
            with self.subTest(raw=raw),self.assertRaises(UpdateDenied):c.overlay_text(raw)
    def test_interpolation_lists_objects_null_and_unknown_oauth_denied(self):
        for value in ('${spring.flyway.enabled}','#{secret}',None,[{'spring.flyway.enabled':True}]):
            with self.subTest(value=value),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps({'ouf':{'value':value}}).encode())
        for key in ('spring.security.oauth2.client.registration.other.client-id','spring.security.oauth2.client.registration.ouf-ths.unknown','spring.security.oauth2.client.provider.fixture.loader.path'):
            with self.subTest(key=key),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps({key:'CANARY'}).encode())
    def test_json_does_not_enable_yaml_tags_merges_or_multi_documents(self):
        for raw in (b'{"ouf":{"a":1}}\n---\nspring: {}',b'{"ouf":{<<: *alias}}',b'{"ouf":{"a":!tag value}}'):
            with self.subTest(raw=raw),self.assertRaises(UpdateDenied):c.overlay_text(raw)
    def test_json_depth_and_property_limits(self):
        value={'a':True}
        for _ in range(18):value={'a':value}
        for value in ({'ouf':value},{'ouf':{str('a'+str(i)):True for i in range(513)}}):
            with self.assertRaises(UpdateDenied):c.overlay_text(json.dumps(value).encode())

class SessionJson(unittest.TestCase):
    def properties(self):
        return {'server.servlet.session.cookie.http-only':True,'server.servlet.session.cookie.secure':True,'server.servlet.session.cookie.same-site':'lax','server.servlet.session.timeout':'30m'}
    def test_exact_four_properties_validate_without_values(self):
        for duration in ('30m','1800','PT30M','P1D','PT0.5S'):
            value=self.properties();value['server.servlet.session.timeout']=duration
            result=c.overlay_text(json.dumps(value).encode());self.assertTrue(result['retainedSessionSecurityValidated']);self.assertEqual(result['propertyCount'],4);self.assertNotIn(duration,json.dumps(result))
    def test_weakened_or_wrongly_typed_cookie_settings_denied(self):
        for key,value in (('http-only',False),('secure',False),('secure','true'),('http-only',1),('same-site','unknown'),('same-site',None)):
            props=self.properties();props['server.servlet.session.cookie.'+key]=value
            with self.subTest(key=key,value=value),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps(props).encode())
    def test_incomplete_security_quartet_and_unrelated_server_channels_denied(self):
        for key in self.properties():
            props=self.properties();del props[key]
            with self.subTest(key=key),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps(props).encode())
        for key in ('server.port','server.servlet.context-path','server.servlet.session.store-dir','server.servlet.session.cookie.domain','spring.session.timeout'):
            props=self.properties();props[key]='secret'
            with self.subTest(key=key),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps(props).encode())
    def test_timeout_infinite_zero_invalid_interpolated_and_wrong_type_denied(self):
        for value in ('0','0s','-1','PT0S','P','PT','P1DT','${SECRET}','infinite','999999999999s',30,True):
            props=self.properties();props['server.servlet.session.timeout']=value
            with self.subTest(value=value),self.assertRaises(UpdateDenied):c.overlay_text(json.dumps(props).encode())
    def test_json_session_overlay_keeps_native_jar_datasource_and_custody_checks(self):
        fixture=Configuration();fixture.setUp();self.addCleanup(fixture.doCleanups)
        path=fixture.root/'owner.yaml';path.write_bytes(json.dumps({'server':{'servlet':{'session':{'cookie':{'http-only':True,'same-site':'lax','secure':True},'timeout':'30m'}}}}).encode());path.chmod(0o600)
        fixture.actual['Config']['Env'].append('SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/owner.yaml');fixture.actual['Mounts']=[{'Destination':'/run/owner.yaml','Source':str(path),'Type':'bind','RW':False}]
        result=fixture.verify();self.assertTrue(result['sameDatasourceAsApplication']);self.assertTrue(result['ownerOverlays'][0]['metadata']['retainedSessionSecurityValidated'])
        fixture.actual['Config']['Env'].append('SPRING_FLYWAY_ENABLED=false')
        with self.assertRaises(UpdateDenied):fixture.verify()
