"""Closed runtime profile selection and grouped, redacted preflight failures."""
import copy
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_chatbot_cohort_containers as fixture
sys.path.insert(0,str(fixture.ROOT/'tools/semantic_frame_compiler'))
import file_only_preparation as p


class RuntimeLayout(unittest.TestCase):
    def inputs(self):
        cid='a'*64
        current={'Id':cid,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'fixture-generation',
            'Running':True,'Paused':False,'Status':'running'},'Mounts':[],
            'NetworkSettings':{'SandboxKey':'/var/run/docker/netns/'+'c'*12}}
        state={'id':cid,'status':'running','pid':123,'bundle':p.BUNDLE_PARENTS[1]+'/'+cid}
        return current,state,{'runtimeStateRoot':'/run/docker'}

    def test_observed_system_containerd_selects_only_its_exact_parent(self):
        current,state,adapter=self.inputs();context=p.retained_runtime_context(current,state,adapter)
        self.assertEqual(context['bundleParent'],p.BUNDLE_PARENTS[1])
        self.assertEqual(context['networkNamespaceParent'],'/var/run/docker/netns')
        self.assertEqual(context['storageParent'],'/var/lib/docker')
        self.assertNotIn('expectedOci',context)

    def test_managed_containerd_remains_a_separate_closed_profile(self):
        c,s,a=self.inputs();s['bundle']=p.BUNDLE_PARENTS[0]+'/'+c['Id']
        c['NetworkSettings']['SandboxKey']='/run/docker/netns/'+'c'*12
        self.assertEqual(p.retained_runtime_context(c,s,a)['bundleParent'],p.BUNDLE_PARENTS[0])

    def test_unknown_parent_traversal_and_different_container_are_rejected(self):
        c,s,a=self.inputs()
        for bundle in ('/private/unknown/'+c['Id'],p.BUNDLE_PARENTS[1]+'/../'+c['Id'],
                       p.BUNDLE_PARENTS[1]+'/'+'f'*64):
            with self.subTest(bundle=bundle),self.assertRaises(Exception):
                p.retained_runtime_context(c,{**s,'bundle':bundle},a)

    def test_paused_pid_or_runtime_root_drift_does_not_expand_the_contract(self):
        for kind in ('paused','pid','id','runtimeRoot'):
            c,s,a=self.inputs()
            if kind=='paused':c['State'].update(Paused=True,Status='paused');s['status']='paused'
            if kind=='pid':s['pid']=456
            if kind=='id':s['id']='f'*64
            if kind=='runtimeRoot':a['runtimeStateRoot']='/private/unknown'
            with self.subTest(kind=kind),self.assertRaises(Exception):p.retained_runtime_context(c,s,a)

    def test_namespace_parent_and_exact_name_are_not_inferred_from_any_path(self):
        c,s,a=self.inputs()
        for namespace in ('/private/unknown/'+'c'*12,'/run/docker/netns/../'+'c'*12,
                          '/run/docker/netns/not-an-id'):
            c['NetworkSettings']['SandboxKey']=namespace
            with self.assertRaises(Exception):p.retained_runtime_context(c,s,a)

    def test_namespace_alias_requires_canonical_target_and_current_process_inode(self):
        c,s,a=self.inputs();context=p.retained_runtime_context(c,s,a)
        def info(path,wrong=False):
            if str(path)==context['networkNamespaceParent']:
                return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_ino=1)
            return SimpleNamespace(st_ino=22 if wrong and str(path).startswith('/proc/') else 21)
        with patch.object(Path,'resolve',return_value=Path('/run/docker/netns')):
            with patch.object(Path,'stat',autospec=True,side_effect=lambda path:info(path)):
                p.verify_namespace(c,context)
            with patch.object(Path,'stat',autospec=True,side_effect=lambda path:info(path,True)),self.assertRaises(Exception):
                p.verify_namespace(c,context)
        with patch.object(Path,'resolve',return_value=Path('/private/redirect')),self.assertRaises(Exception):
            p.verify_namespace(c,context)

    def test_grouped_preflight_returns_independent_failures_without_raw_errors(self):
        c,s,a=self.inputs();s['pid']=456
        recorded={'id':c['Id'],'image':c['Image'],'pid':123,'startedAt':'fixture-generation'}
        # Full Engine binding fields are supplied by the existing fixture.
        native,_,_=fixture.container_fixture('mcp')
        for key in ('Config','HostConfig','Mounts'):c[key]=copy.deepcopy(native[key])
        c['Mounts']=[]
        c['NetworkSettings'].update(copy.deepcopy(native['NetworkSettings']))
        class Engine:
            def check_socket(self):pass
            def request(self,method,path):
                if path=='/v1.44/info':return 200,{'ServerVersion':'0.0.0','Driver':'overlay2','CgroupDriver':'systemd','DockerRootDir':'/var/lib/docker'}
                return 200,copy.deepcopy(c)
        class Reader:
            def __init__(self,*args):pass
            def run(self,*args):return json.dumps(s).encode()
        inputs={'installationReview':{'currentRegistry':recorded},'declaration':{'retainedNativeCreationFrame':copy.deepcopy(c)}}
        with patch.object(p,'retained_inputs',return_value=(inputs,{})),\
             patch.object(p,'retained_native_bindings',return_value=(a,{'path':'fixture','sha256':'a'*64},{},[])),\
             patch.object(p,'NodeObservation',Reader),\
             patch.object(p,'consultation_metadata',side_effect=ValueError('private path contains secret')):
            result=p.preflight_retained_runtime(Engine(),{})
        self.assertFalse(result['allRequiredChecksPass'])
        self.assertEqual(set(result['failedChecks']),{'engineBaseline','consultationKeyCustody','runtimeLayoutAndIdentity'})
        self.assertTrue(result['checks']['stableRunc']);self.assertTrue(result['checks']['stableEngine'])
        self.assertNotIn('secret',json.dumps(result));self.assertNotIn(c['Id'],json.dumps(result))

    def test_preflight_reports_full_historical_drift_before_iam(self):
        c,s,a=self.inputs();native,_,_=fixture.container_fixture('mcp')
        for key in ('Config','HostConfig','Mounts'):c[key]=copy.deepcopy(native[key])
        old=copy.deepcopy(c);c['Config']['Env'].append('PRIVATE_INPUT=never-print-this-value')
        values={'installationReview':{'currentRegistry':{'id':c['Id'],'image':c['Image'],'pid':123,'startedAt':'fixture-generation'}},
                'declaration':{'retainedNativeCreationFrame':old}}
        class Engine:
            def check_socket(self):pass
            def request(self,method,path):return (200,copy.deepcopy(c)) if path.endswith('/json') else (200,{})
        with patch.object(p,'retained_inputs',return_value=(values,{})),patch.object(p,'consultation_metadata',return_value=True),\
             patch.object(p,'retained_native_bindings',side_effect=ValueError('NATIVE_FIXTURE_UNAVAILABLE')):
            result=p.preflight_retained_runtime(Engine(),{})
        self.assertFalse(result['allRequiredChecksPass'])
        self.assertEqual(result['failedChecks']['historicalGeneration'],'RETAINED_REGISTRY_NATIVE_GENERATION_CHANGED')
        self.assertNotIn('never-print',json.dumps(result))


if __name__=='__main__':unittest.main()
