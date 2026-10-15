"""Docker representations across created, paused, released and cohort phases."""
import copy
from pathlib import Path
import sys
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover')]
from engine_creation import Engine,CreationDenied,requested_host_config_matches,started_host_config_matches,digest
from tools.chatbot_file_cohort.plan import host_config_matches

class DockerRepresentations(unittest.TestCase):
    def sample(self):
        transition=types.SimpleNamespace(context='a'*64)
        request={'Image':'sha256:'+'b'*64,'Env':['FIXTURE=retained'],
            'HostConfig':{'Mounts':[],'Binds':['/reviewed/config:/run/config:ro'],
                'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'OomKillDisable':False}}
        actual={'Id':'c'*64,'Name':'/ouf-semantic-cutover-'+transition.context,'Image':request['Image'],
            'Config':{'Image':request['Image'],'Env':request['Env']},
            'HostConfig':copy.deepcopy(request['HostConfig']),
            'State':{'Status':'created','Running':False,'Paused':False,'Pid':0}}
        actual['HostConfig'].pop('Mounts')
        return transition,request,actual
    def test_created_empty_specs_omit_without_changing_raw_hashes_or_binds(self):
        t,request,actual=self.sample();before=copy.deepcopy((request,actual))
        self.assertEqual(Engine.matching_created(object.__new__(Engine),t,request,actual),actual)
        self.assertEqual((request,actual),before)
        actual['HostConfig']['Mounts']=None
        self.assertTrue(requested_host_config_matches(request['HostConfig'],actual['HostConfig']))
    def test_nonempty_specs_missing_specs_or_changed_bind_are_rejected(self):
        t,request,actual=self.sample()
        for changed in ({'Mounts':[{'Type':'bind','Source':'/foreign','Target':'/run/config'}]},
            {'Mounts':{}},{'Binds':['/foreign:/run/config:ro']},{'Binds':['/reviewed/config:/run/config:rw']}):
            value=copy.deepcopy(actual);value['HostConfig'].update(changed)
            with self.subTest(changed=changed),self.assertRaisesRegex(CreationDenied,'HOST_CONFIG_DRIFT'):
                Engine.matching_created(object.__new__(Engine),t,request,value)
        request['HostConfig']['Mounts']=[{'Type':'bind','Source':'/reviewed','Target':'/required','ReadOnly':True}]
        with self.assertRaises(CreationDenied):Engine.matching_created(object.__new__(Engine),t,request,actual)
    def test_paused_and_released_use_same_empty_spec_rule_and_existing_oom_default(self):
        t,request,actual=self.sample();actual['State'].update(Status='paused',Running=True,Paused=True,Pid=12)
        actual['State']['StartedAt']='fixture';actual.update(Mounts=[],NetworkSettings={})
        actual['HostConfig']['OomKillDisable']=None
        engine=object.__new__(Engine)
        intent={'containerId':actual['Id'],'creationRequestHash':digest(request),'createdEvidenceHash':'d'*64}
        self.assertEqual(engine.matching_paused(t,request,intent,actual),actual)
        pin=engine.runtime_binding(actual);actual['State'].update(Status='running',Paused=False)
        self.assertEqual(engine.matching_released(t,request,pin,actual),actual)
    def test_missing_or_nonboolean_oom_is_still_denied_and_true_never_becomes_default(self):
        for actual in ({},{'OomKillDisable':0},{'OomKillDisable':'false'},{'OomKillDisable':True}):
            self.assertFalse(started_host_config_matches({'OomKillDisable':False},actual))
        self.assertFalse(started_host_config_matches({'OomKillDisable':True},{'OomKillDisable':None}))
    def test_cohort_and_gateway_comparator_share_exact_owner_rules(self):
        expected={'Mounts':[],'Binds':['/source:/target:ro'],'OomKillDisable':False}
        for actual in ({'Binds':['/source:/target:ro'],'OomKillDisable':None},
            {'Binds':['/foreign:/target:ro'],'OomKillDisable':False},
            {'Binds':['/source:/target:ro'],'OomKillDisable':True}):
            before=copy.deepcopy((expected,actual))
            self.assertEqual(host_config_matches(expected,actual),started_host_config_matches(expected,actual))
            self.assertEqual((expected,actual),before)

if __name__=='__main__':unittest.main()
