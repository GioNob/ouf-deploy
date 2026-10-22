import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('reader',Path(__file__).parents[1]/'reader.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def fixtures(self):
        gateway={'Id':'a'*64,'State':{'Pid':1,'StartedAt':'g','Running':True},'Config':{'Tty':True},
            'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'192.0.2.1'}}}}
        registry={'Id':'b'*64,'State':{'Pid':2,'StartedAt':'r','Running':True},
            'Config':{'ExposedPorts':{'8080/tcp':{}},'Env':['SECRET']},
            'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'192.0.2.2'}}}}
        return gateway,registry
    def line(self,host='192.0.2.2',request='/api/semantic/v1/references:resolve?secret=HIDDEN'):
        return ('2026-10-22T13:13:24.000Z connect() failed (113: No route to host), request: "GET '
            +request+' HTTP/1.1", upstream: "http://'+host+':8080/api/semantic/v1/references:resolve?token=HIDDEN"').encode()
    def test_same_line_and_address_match_without_secrets(self):
        g,r=self.fixtures();out=m.correlated(self.line(),r,g)
        row=out['sameLineSemanticReferenceFailures'][0]
        self.assertTrue(row['upstreamAddressMatchesObservedRegistry'])
        self.assertTrue(row['upstreamPortDeclaredByRegistryImage'])
        self.assertEqual(out['commonNetworkCount'],1)
        for secret in ('HIDDEN','192.0.2','SECRET','http://'):
            self.assertNotIn(secret,json.dumps(out))
    def test_mismatched_address_and_unrelated_request(self):
        g,r=self.fixtures()
        out=m.correlated(self.line('192.0.2.3'),r,g)
        self.assertFalse(out['sameLineSemanticReferenceFailures'][0]['upstreamAddressMatchesObservedRegistry'])
        self.assertEqual(m.correlated(self.line(request='/unrelated'),r,g)['sameLineSemanticReferenceFailures'],[])
    def test_hostname_is_unknown_not_mismatch(self):
        g,r=self.fixtures()
        out=m.correlated(self.line('fixture.invalid'),r,g)
        self.assertIsNone(out['sameLineSemanticReferenceFailures'][0]['upstreamAddressMatchesObservedRegistry'])
    def test_closed_get_budget(self):
        e=m.Engine({}, {'a'*64},1,2)
        with self.assertRaises(m.Stop):e.get('/containers/json')
        e.calls=5
        with self.assertRaises(m.Stop):e.get('/v1.44/containers/'+'a'*64+'/json')
    def test_five_get_path_and_generation_drift(self):
        g,r=self.fixtures();pins={'containerId':g['Id'],'pid':1,'startedAt':'g'}
        review={'executionReview':{'stages':[{}]*12,'engineBinding':{},
            'runtimeGuardProfile':{'unchangedApplications':{'gateway':{'binding':pins}}}}}
        journal={'nextStage':12,'effects':[{'state':'APPLIED'}]*12}
        case={'schema':'ouf.semantic-transport-correlation-case.v1','contextPath':'/fixture',
            'since':1,'until':2,'historicalRegistryId':r['Id']}
        line=self.line()
        class Engine:
            drift=False
            def __init__(self,*_):
                self.calls=0;self.logs={g['Id']:'logs'}
            def inspect(self,cid):
                self.calls+=1
                row=json.loads(json.dumps(g if cid==g['Id'] else r))
                if self.drift and self.calls>3:row['State']['Pid']+=1
                return row
            def get(self,*_):
                self.calls+=1;return line
        def read(path):
            return (review,b'review') if path.endswith('review.json') else (journal,b'journal')
        with patch.object(m,'private_json',read),patch.object(m,'Engine',Engine):
            out=m.run(case);self.assertEqual(out['engineGets'],5)
            self.assertEqual(len(out['sameLineSemanticReferenceFailures']),1)
            self.assertFalse(out['activationResubmitted'])
            Engine.drift=True
            with self.assertRaisesRegex(m.Stop,'RUNTIME_GENERATION_CHANGED'):m.run(case)
            Engine.drift=False;journal['nextStage']=11
            with self.assertRaisesRegex(m.Stop,'COMPLETED_PATCH_REQUIRED'):m.run(case)

if __name__=='__main__':unittest.main()

