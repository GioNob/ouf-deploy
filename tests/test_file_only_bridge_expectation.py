"""Signed launch derivation: Docker default order and fresh bridge namespaces."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_frame_compiler')]
from compile_file_only_frame_policy import docker_bridge_environment,private_bridge_namespace_name,recompile_bridge_proposal

class BridgeExpectation(unittest.TestCase):
    def request(self):
        return {'Env':['LANG=C','OUF_FLAG=false','PATH=/verified/path'],
            'HostConfig':{'NetworkMode':'ouf-backend'},'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':'a'*64}}}}
    def test_default_slots_precede_overrides_and_other_rows_keep_signed_order(self):
        request=self.request();before=copy.deepcopy(request)
        self.assertEqual(docker_bridge_environment(request),['PATH=/verified/path','HOSTNAME=$OUF_HOSTNAME','LANG=C','OUF_FLAG=false'])
        self.assertEqual(request,before)
        self.assertIsNone(private_bridge_namespace_name(request))
    def test_rejects_tty_links_hostname_duplicates_and_missing_path(self):
        for kind in ('tty','links','hostname','duplicate','no-path'):
            request=self.request()
            if kind=='tty':request['Tty']=True
            if kind=='links':request['HostConfig']['Links']=['x:y']
            if kind=='hostname':request['Env'].append('HOSTNAME=unreviewed')
            if kind=='duplicate':request['Env'].append('LANG=other')
            if kind=='no-path':request['Env']=[x for x in request['Env']if not x.startswith('PATH=')]
            if kind=='host':request['HostConfig']['NetworkMode']='host'
            with self.subTest(kind=kind),self.assertRaises(ValueError):docker_bridge_environment(request)
    def test_fresh_namespace_requires_the_same_single_named_bridge(self):
        for mode in ('host','none','bridge','container:'+'c'*64,'unselected'):
            request=self.request();request['HostConfig']['NetworkMode']=mode
            with self.subTest(mode=mode),self.assertRaises(ValueError):private_bridge_namespace_name(request)
        request=self.request();request['HostConfig']['NetworkMode']='a'*64
        self.assertIsNone(private_bridge_namespace_name(request))
    def test_retained_recompilation_preserves_input_and_all_other_policy_fields(self):
        request=self.request();env=request['Env']+['HOSTNAME=$OUF_HOSTNAME']
        template={'expectedOci':{'process':{'env':env,'args':['fixed']},'root':{'readonly':False}}}
        launch={'startup':{'env':copy.deepcopy(env),'uid':10001},'other':'preserved'}
        before=copy.deepcopy((request,template,launch));t,l=recompile_bridge_proposal(template,launch,request)
        self.assertEqual((request,template,launch),before)
        self.assertEqual(t['expectedOci']['process']['args'],['fixed']);self.assertEqual(l['other'],'preserved')
        self.assertEqual(t['expectedOci']['process']['env'],docker_bridge_environment(request))
    def test_value_drift_cannot_be_treated_as_reordering(self):
        request=self.request();env=request['Env']+['HOSTNAME=$OUF_HOSTNAME']
        template={'expectedOci':{'process':{'env':env}}};launch={'startup':{'env':copy.deepcopy(env)}}
        template['expectedOci']['process']['env'][0]='LANG=DIFFERENT'
        with self.assertRaisesRegex(ValueError,'RETAINED_FRAME_ENVIRONMENT_VALUE_DRIFT'):recompile_bridge_proposal(template,launch,request)

if __name__=='__main__':unittest.main()
