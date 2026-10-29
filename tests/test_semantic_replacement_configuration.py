import copy,importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('plan',Path('scripts/plan-semantic-replacement-configuration.py'))
plan=importlib.util.module_from_spec(spec);spec.loader.exec_module(plan)
class Configuration(unittest.TestCase):
    def setUp(self):
        self.old={'Id':plan.OLD_IMAGE,'Config':{'Env':['JAVA_HOME=/old/java','PATH=/old/java/bin:/usr/bin'],'User':'10001:10001','Cmd':['old.jar'],'Entrypoint':['java'],'WorkingDir':'/app'}}
        self.new={'Id':plan.NEW_IMAGE,'Config':{'Env':['JAVA_HOME=/new/java','PATH=/new/java/bin:/usr/bin'],'User':'10001:10001','Cmd':['new.jar'],'Entrypoint':['java'],'WorkingDir':'/app'}}
        self.container={'Id':plan.CID,'Image':plan.OLD_IMAGE,'Config':copy.deepcopy(self.old['Config']), 'Mounts':[{'Destination':p,'RW':False} for p in ('/run/ouf-semantic-auth','/run/secrets/semantic-read-owner.key')]}
        self.container['Config']['Env']+=['OUF_SEM_DB_PASSWORD=DO_NOT_PRINT','PORT=8080']
    def test_candidate_runtime_defaults_replace_inherited_old_java(self):
        result=plan.configuration_delta(self.container,self.old,self.new)
        env=plan.environment(result['candidateConfig']['Env'])
        self.assertEqual(env['JAVA_HOME'],'/new/java');self.assertEqual(env['PATH'],'/new/java/bin:/usr/bin')
        self.assertEqual(env['OUF_SEM_DB_PASSWORD'],'DO_NOT_PRINT');self.assertEqual(result['candidateConfig']['Cmd'],['new.jar'])
        self.assertNotIn('DO_NOT_PRINT',json.dumps(result['public']));self.assertFalse(result['public']['cutoverApplyReady'])
    def test_explicit_runtime_override_is_flagged_for_review(self):
        self.container['Config']['Env'][0]='JAVA_HOME=/deliberate/java'
        self.container['Config']['Cmd']=['custom.jar']
        result=plan.configuration_delta(self.container,self.old,self.new)['public']
        self.assertIn('JAVA_HOME',result['unreviewedEnvironmentOverrideNames']);self.assertEqual(result['explicitCommandOrUserOverrideNames'],['Cmd'])
    def test_duplicate_or_malformed_environment_denied(self):
        for entries in (['X=one','X=two'],['X'],['bad-key=value']):
            with self.assertRaises(ValueError):plan.environment(entries)
    def test_wrong_candidate_cannot_be_promoted(self):
        self.new['Id']=plan.OLD_IMAGE
        with self.assertRaisesRegex(ValueError,'EXACT_IMAGE_AND_CONTAINER_REQUIRED'):plan.configuration_delta(self.container,self.old,self.new)
    def test_writable_owner_key_mount_denied(self):
        self.container['Mounts'][1]['RW']=True
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_READ_ONLY_AUTH_MOUNTS_REQUIRED'):plan.configuration_delta(self.container,self.old,self.new)
    def test_old_java_version_label_does_not_override_candidate(self):
        self.container['Config']['Env'].append('JAVA_VERSION=old-release')
        self.new['Config']['Env'].append('JAVA_VERSION=new-release')
        result=plan.configuration_delta(self.container,self.old,self.new)
        self.assertEqual(plan.environment(result['candidateConfig']['Env'])['JAVA_VERSION'],'new-release')
        self.assertEqual(result['public']['ignoredLegacyRuntimeMetadataOverrideNames'],['JAVA_VERSION'])
if __name__=='__main__':unittest.main()
