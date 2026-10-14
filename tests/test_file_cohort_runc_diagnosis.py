import copy
import importlib.util
import json
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'scripts/diagnose-file-cohort-runc.py'
spec=importlib.util.spec_from_file_location('runc_diagnosis',path)
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)


class RuntimeFacts(unittest.TestCase):
    def fixture(self):
        current={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'fixture-generation',
                 'Running':True,'Paused':False,'Status':'running'}}
        recorded={'id':current['Id'],'image':current['Image'],'pid':123,'startedAt':'fixture-generation'}
        state={'id':current['Id'],'pid':123,'status':'running','bundle':d.BUNDLE_PARENT+'/'+current['Id']}
        return current,recorded,state

    def test_running_identity_and_exact_layout_are_reported(self):
        c,r,s=self.fixture();f=d.facts(c,r,s)
        self.assertTrue(f['oldCollectorConditionPassed']);self.assertTrue(f['retainedEngineGenerationMatched'])

    def test_paused_state_is_not_relabelled_running(self):
        c,r,s=self.fixture();c['State'].update(Paused=True,Status='paused');s['status']='paused'
        f=d.facts(c,r,s)
        self.assertFalse(f['oldCollectorConditionPassed']);self.assertTrue(f['enginePaused'])
        self.assertEqual(f['runcStatus'],'paused');self.assertTrue(f['runcPidMatched'])

    def test_alias_and_system_containerd_layout_remain_distinct_from_approved_layout(self):
        for prefix,key in (('/var'+d.BUNDLE_PARENT,'bundleUsesVarRunAlias'),
                           ('/run/containerd/io.containerd.runtime.v2.task/moby','bundleUsesSystemContainerd')):
            c,r,s=self.fixture();s['bundle']=prefix+'/'+c['Id'];f=d.facts(c,r,s)
            self.assertTrue(f[key]);self.assertFalse(f['bundleExactExpected'])
            self.assertFalse(f['oldCollectorConditionPassed'])

    def test_pid_identity_and_retained_generation_drift_are_visible(self):
        c,r,s=self.fixture();s['pid']=321;r['startedAt']='another-generation'
        f=d.facts(c,r,s)
        self.assertFalse(f['runcPidMatched']);self.assertFalse(f['retainedEngineGenerationMatched'])

    def test_untrusted_fields_and_paths_do_not_reach_public_output(self):
        c,r,s=self.fixture();s.update(status='private-secret',bundle='/private-secret/path',private='private-secret')
        c['State']['Status']='private-secret'
        output=json.dumps(d.facts(c,r,s))
        self.assertNotIn('private-secret',output);self.assertNotIn(c['Id'],output)
        self.assertEqual(d.facts(c,r,s)['runcStatus'],'UNKNOWN')


if __name__=='__main__':unittest.main()
