import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('plan', Path(__file__).resolve().parents[1]/'tools/chatbot_file_cohort/plan.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def fixture(module='onboarding'):
    old = {'Id':'a'*64, 'Name':'/ouf-'+module, 'Image':'sha256:'+'b'*64,
           'Config':{'Image':'old:tag','User':p.USERS[module], 'Env':['PASSWORD=private-value', 'KEEP=present'],
                     'Entrypoint':['java'], 'Cmd':['old.jar'], 'WorkingDir':'/app', 'Hostname':'a'*12,
                     'Labels':{'existing':'preserved'}},
           'HostConfig':{'OomKillDisable':None,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
                         'NetworkMode':'ouf-backend', 'Memory':536870912,
                         'Mounts':[{'Type':'bind','Source':'/private/data','Target':'/data','ReadOnly':False}]},
           'Mounts':[{'Type':'bind','Source':'/private/data','Destination':'/data','RW':True}],
           'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'c'*64,'Aliases':['ouf-'+module,'a'*12],
                                                       'IPAddress':'172.20.0.3', 'IPAMConfig':None}}},
           'State':{'Running':True,'Paused':False,'Status':'running','Pid':3456,'StartedAt':'2026-10-14T00:00:00Z'}}
    image = {'Id':'sha256:'+'d'*64,'Config':{'User':p.USERS[module], 'Entrypoint':['java','-jar','/app/new.jar'],
                                                          'Cmd':None,'WorkingDir':'/app','Volumes':{}}}
    package = {'module':module,'sourceCommit':'e'*40,'artifactKind':'DOCKER_SAVE',
               'imageId':image['Id'],'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
               'cohortSourceLockSha256':'f'*64}
    return old, image, package


class PlanTests(unittest.TestCase):
    def test_new_image_preserves_existing_configuration_and_data_mounts(self):
        old, image, package = fixture()
        before = copy.deepcopy(old)
        row = p.compile_replacement('onboarding',old,image,package,'chatbot-file-20261014',{'set':{'EXTRA':'yes'}})
        request = row['creationRequest']
        self.assertEqual(old, before)
        self.assertEqual(request['HostConfig']['Mounts'], old['HostConfig']['Mounts'])
        self.assertEqual(request['HostConfig']['Memory'], 536870912)
        self.assertEqual(request['HostConfig']['RestartPolicy'], p.NO_RESTART)
        self.assertEqual(p.environment(request['Env']), {'PASSWORD':'private-value','KEEP':'present','EXTRA':'yes'})
        self.assertEqual(request['Entrypoint'], image['Config']['Entrypoint'])
        self.assertFalse(row['automaticRollbackAllowed'])

    def test_only_observed_null_oom_default_is_made_explicit_for_each_module(self):
        for module in p.MODULES:
            for value in (None,False,True):
                with self.subTest(module=module,value=value):
                    old,image,package=fixture(module);old['HostConfig']['OomKillDisable']=value
                    row=p.compile_replacement(module,old,image,package,'cohort',{})
                    self.assertIs(row['creationRequest']['HostConfig']['OomKillDisable'],False if value is None else value)
                    self.assertIs(row['oldHostConfig']['OomKillDisable'],value)
                    self.assertIs(old['HostConfig']['OomKillDisable'],value)
        with self.assertRaisesRegex(p.PlanDenied,'BOOLEAN_OR_DEFAULT'):
            p.creation_host_config({'OomKillDisable':'false'})

    def test_default_oom_roundtrip_is_equivalent_without_mutating_native_hashes(self):
        for expected in (None,False):
            for actual in (None,False):
                left={'OomKillDisable':expected,'Memory':123};right={'OomKillDisable':actual,'Memory':123}
                hashes=(p.digest(left),p.digest(right))
                self.assertTrue(p.host_config_matches(left,right))
                self.assertEqual(hashes,(p.digest(left),p.digest(right)))
            for actual in (True,0,1,'false'):
                self.assertFalse(p.host_config_matches({'OomKillDisable':expected},{'OomKillDisable':actual}))
            self.assertFalse(p.host_config_matches({'OomKillDisable':expected},{}))
        self.assertFalse(p.host_config_matches({'OomKillDisable':True},{'OomKillDisable':None}))
        self.assertFalse(p.host_config_matches({'OomKillDisable':True},{'OomKillDisable':False}))
        self.assertTrue(p.host_config_matches({'OomKillDisable':True},{'OomKillDisable':True}))
        self.assertFalse(p.host_config_matches({'OomKillDisable':False,'Memory':123},{'OomKillDisable':None,'Memory':124}))

    def test_package_image_identity_not_tag_is_required(self):
        old, image, package = fixture()
        image['Id'] = 'sha256:'+'1'*64
        with self.assertRaisesRegex(p.PlanDenied,'QUALIFIED_IMAGE'):
            p.compile_replacement('onboarding',old,image,package,'cohort',{})

    def test_new_image_anonymous_volume_is_not_silently_created(self):
        old, image, package = fixture()
        image['Config']['Volumes'] = {'/new-data':{}}
        with self.assertRaisesRegex(p.PlanDenied,'NEW_IMAGE_VOLUME'):
            p.compile_replacement('onboarding',old,image,package,'cohort',{})

    def test_stopped_or_foreign_namespace_requires_concrete_review(self):
        old, image, package = fixture()
        old['HostConfig']['PidMode'] = 'container:foreign'
        with self.assertRaisesRegex(p.PlanDenied,'NON_INDEPENDENT'):
            p.compile_replacement('onboarding',old,image,package,'cohort',{})
        old['HostConfig'].pop('PidMode')
        old['State']['Running'] = False
        with self.assertRaisesRegex(p.PlanDenied,'CURRENT_OLD_GENERATION'):
            p.compile_replacement('onboarding',old,image,package,'cohort',{})

    def test_complete_manifest_is_bound_not_merely_six_module_names(self):
        observed, images, packages, changes = {}, {}, {}, {}
        for idx, module in enumerate(p.MODULES):
            old, image, package = fixture(module)
            old['Id'] = str(idx+1)*64
            old['Config']['Hostname'] = old['Id'][:12]
            observed[module], images[module], packages[module], changes[module] = old, image, package, {}
        for module in ('semantic','gateway'):
            packages[module] = {'module':module,'cohortSourceLockSha256':'f'*64}
        manifest = {'schema':'ouf.chatbot-file-cohort-package.v1','cohortId':'cohort',
                    'sourceLockSha256':'f'*64,'modules':[dict(v,files={}) for v in packages.values()]}
        plan = p.compile_cohort(manifest, observed, images, packages, changes, '1'*64,'2'*64,'3'*64)
        self.assertNotIn('private-value',p.encoded(p.public_review(plan)).decode())
        self.assertNotIn('/private/data',p.encoded(p.public_review(plan)).decode())
        packages['mcp']['sourceCommit'] = '9'*40
        with self.assertRaisesRegex(p.PlanDenied,'OUTSIDE_COHORT_MANIFEST'):
            p.compile_cohort(manifest, observed, images, packages, changes, '1'*64,'2'*64,'3'*64)


if __name__ == '__main__':
    unittest.main()
