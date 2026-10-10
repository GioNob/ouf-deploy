import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest

s=importlib.util.spec_from_file_location('prepare',Path(__file__).resolve().parents[1]/'scripts/prepare-current-semantic-cutover-inputs.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class CurrentInputTests(unittest.TestCase):
    def fixture(self):
        current={'Id':'a'*64,'Image':'sha256:'+'b'*64,
            'Config':{'Env':['OUF_SEM_DB_PASSWORD=fixture-private-value','OUF_SEM_DB_USER=fixture']},
            'HostConfig':{'Binds':['/auth:/auth:ro'],'Memory':123456,'RestartPolicy':{'Name':'no'}},
            'Mounts':[{'Destination':'/auth','Source':'/auth','RW':False}],
            'NetworkSettings':{'Networks':{'ouf':{'IPAddress':'172.18.0.6'}}},
            'State':{'Pid':1234,'StartedAt':'fixed','Running':True,'Status':'running','Health':{'counter':1}}}
        declaration={'schema':'ouf.discovery.private-qualified-package-runtime-declaration.v1',
            'candidateImageId':m.IMAGE,'candidateConfig':{'User':'10001:10001','Env':['JAVA_HOME=/opt/java/openjdk','OUF_SEM_DB_PASSWORD=fixture-private-value','OUF_SEM_DB_USER=fixture']},
            'retainedNativeCreationFrame':copy.deepcopy(current),'proposedHostConfig':copy.deepcopy(current['HostConfig']),
            'roleOwnedReadOnlyMounts':[{'target':'/run/key'}],
            'hostDelta':{'appendedReadOnlyBinds':[]},'inputBindings':{},'requiredBeforeMutation':[],
            'productionApplyReady':False,'applicationCutoverAuthorized':False,'completeReplacementOciProven':False}
        return declaration,current
    def test_password_file_bind_and_explicit_restart_policy_are_only_changes(self):
        d,c=self.fixture();before=copy.deepcopy(d)
        private,public,credential=m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
        self.assertEqual(d,before)
        self.assertEqual(credential,b'fixture-private-value')
        env=m.environment(private['candidateConfig'])
        self.assertNotIn('OUF_SEM_DB_PASSWORD',env)
        self.assertEqual(env['SPRING_CONFIG_IMPORT'],'configtree:/run/ouf-semantic-db/')
        self.assertEqual(env['OUF_SEM_DB_USER'],'fixture')
        for k,v in d['proposedHostConfig'].items():
            if k not in ('Binds','RestartPolicy'):self.assertEqual(private['proposedHostConfig'][k],v)
        self.assertEqual(private['proposedHostConfig']['RestartPolicy'],{'Name':'no','MaximumRetryCount':0})
        self.assertTrue(public['candidateAutomaticRestartDisabled'])
        self.assertEqual(private['proposedHostConfig']['Binds'][:-1],d['proposedHostConfig']['Binds'])
        self.assertTrue(private['proposedHostConfig']['Binds'][-1].endswith(':/run/ouf-semantic-db:ro'))
        self.assertEqual(private['databaseSecretProjection']['file']['sha256'],hashlib.sha256(credential).hexdigest())
        self.assertNotIn('fixture-private-value',json.dumps(public))
        for k in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven','freshRuntimeCustodyProven','platformSecretManagerIntegrationProven'):
            self.assertFalse(public[k])
    def test_live_config_mount_network_or_generation_drift_denied(self):
        mutations=[lambda c:c['Config']['Env'].append('OUF_OTHER=changed'),
                   lambda c:c['HostConfig'].update(Memory=999),
                   lambda c:c['Mounts'][0].update(RW=True),
                   lambda c:c['NetworkSettings']['Networks']['ouf'].update(IPAddress='172.18.0.99'),
                   lambda c:c['State'].update(Pid=9999),lambda c:c['State'].update(Running=False)]
        for mutation in mutations:
            d,c=self.fixture();mutation(c)
            with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
    def test_dynamic_health_counter_is_observational_only(self):
        d,c=self.fixture();c['State']['Health']['counter']=99
        m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
    def test_credential_drift_or_invalid_bytes_denied(self):
        for password in ('other','', 'newline\nvalue','null\x00value','x'*4097):
            d,c=self.fixture();d['candidateConfig']['Env'][1]='OUF_SEM_DB_PASSWORD='+password
            with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
    def test_config_import_and_direct_spring_password_overrides_require_review(self):
        for env in ('SPRING_CONFIG_IMPORT=optional:configtree:/other/','SPRING_DATASOURCE_PASSWORD=other'):
            d,c=self.fixture();d['candidateConfig']['Env'].append(env)
            with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
    def test_parent_mount_shadowing_or_unsafe_snapshot_denied(self):
        d,c=self.fixture();d['roleOwnedReadOnlyMounts'][0]['target']='/run'
        with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
        for path in ('relative','/etc/../tmp/x','/etc/ouf/x:bad','/etc/ouf/x\ninvalid'):
            d,c=self.fixture()
            with self.assertRaises(ValueError):m.compile_file_secret(d,c,path)
    def test_no_authority_promotion_or_different_image(self):
        for field in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven'):
            d,c=self.fixture();d[field]=True
            with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
        d,c=self.fixture();d['candidateImageId']='different'
        with self.assertRaises(ValueError):m.compile_file_secret(d,c,'/etc/ouf/deploy-snapshots/fixture')
    def test_mutating_native_operations_denied_before_execution(self):
        reader=types.SimpleNamespace(SEMANTIC_ID='exact')
        for docker,args in [(True,['start','exact']),(True,['inspect','--type','container','other']),
                            (False,['stop',m.UNIT]),(False,['restart',m.UNIT])]:
            with self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_NATIVE_SCOPE_REQUIRED'):
                m.native(reader,{},args,docker)

    @unittest.skipUnless(os.geteuid()==0 and os.environ.get('OUF_POSIX_FIXTURE_ROOT'),
                         'Native UID10001 custody runs on isolated hosted root fixture')
    def test_actual_posix_projection_and_wrong_mode_owner_link_denials(self):
        s=importlib.util.spec_from_file_location('custody',Path(__file__).resolve().parents[1]/'tools/semantic_target_review/prepare_application_runtime_inputs.py')
        c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_POSIX_FIXTURE_ROOT',str(Path.cwd()))) as directory:
            root=Path(directory);root.chmod(0o700)
            credential=b'nonproduction-custody-fixture'
            m.create_secret_projection(c,root,credential)
            secret=root/'database-secret';file=secret/'OUF_SEM_DB_PASSWORD'
            self.assertEqual((secret.stat().st_uid,secret.stat().st_gid,stat.S_IMODE(secret.stat().st_mode)),(10001,10001,0o500))
            self.assertEqual((file.stat().st_uid,file.stat().st_gid,stat.S_IMODE(file.stat().st_mode)),(10001,10001,0o400))
            file.chmod(0o600)
            with self.assertRaises(ValueError):c.file_bytes(file,10001,{0o400})
            file.chmod(0o400);os.chown(file,0,0)
            with self.assertRaises(ValueError):c.file_bytes(file,10001,{0o400})
            os.chown(file,10001,10001)
            link=secret/'alias';os.link(file,link)
            with self.assertRaises(ValueError):c.file_bytes(file,10001,{0o400})
            link.unlink();link.symlink_to(file)
            with self.assertRaises(OSError):c.file_bytes(link,10001,{0o400})

if __name__=='__main__':unittest.main()
