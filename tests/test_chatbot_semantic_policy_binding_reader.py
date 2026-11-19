import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binding_reader',ROOT/'scripts/read-chatbot-semantic-policy-binding-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def actual():
    return {'Id':m.REGISTRY,'Image':'sha256:'+'a'*64,
        'State':{'Pid':123,'StartedAt':'fixed','Running':True},
        'Mounts':[{'Destination':'/policy','RW':False}],
        'Config':{'Env':['OUF_AUTHORIZATION_BUNDLE_FILE=/policy/bundle.json',
            'OUF_AUTHORIZATION_BUNDLE_VERSION=40','OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/token',
            'OUF_AUTHORIZATION_REGISTRY_URL=https://SECRET.invalid',
            'PASSWORD=PRIVATE_VALUE','OUF_AUTHORIZATION_BUNDLE_SHA256=d4e2478ce91c0bb2d2d36144dab1305ad137b7ae4c74e218f07e70604ade57bc'],
            'Cmd':['java','PRIVATE_VALUE'],'Entrypoint':[]},'HostConfig':{},'NetworkSettings':{}}

class ReaderTests(unittest.TestCase):
    def test_metadata_redaction_and_longest_mount(self):
        a=actual();a['Mounts'].append({'Destination':'/policy/bundle.json','RW':True})
        r=m.projection(a);raw=json.dumps(r)
        for s in ('PRIVATE_VALUE','SECRET','/token','/policy','d4e247'):self.assertNotIn(s,raw)
        self.assertFalse(r['bundle_fileCoveredByReadOnlyMount'])
        self.assertEqual(r['bundle_version'],40)
        self.assertTrue(r['matchesObservedPolicy40Hash'])
        self.assertFalse(r['loadedSnapshotProven'])

    def test_absent_metadata_stays_unknown(self):
        a=actual();a['Config']['Env']=[]
        r=m.projection(a)
        self.assertNotIn('bundle_version',r)
        self.assertEqual(r['explicitEnvironmentFields'],[])
        self.assertFalse(r['effectivePolicyProven'])

    def test_duplicate_alias_and_generation_are_rejected(self):
        a=actual();a['Config']['Env'].append('OUF_AUTHORIZATION_BUNDLEVERSION=41')
        with self.assertRaises(m.ReadDenied):m.projection(a)
        a=actual();a['Id']='b'*64
        with self.assertRaises(m.ReadDenied):m.projection(a)
        a=actual();a['State']['Running']=False
        with self.assertRaises(m.ReadDenied):m.projection(a)

    def exercise_main(self,drift=False):
        p={'engine':{'socketPath':'/fixture'}};declaration={'sourceCommit':m.SOURCE}
        process={'unit':m.UNIT,'authorityDirectory':str(m.CONTEXT),
            'bundle':{'path':'/fixture/bundle','sha256':'a'*64}}
        scopes={'finiteActionProcess':process}
        rows={'review.json':{'sourceClosure':{'declaration':declaration},'scopes':scopes,
            'privateInputHashes':{'preparedInputs':m.digest(p)}},
            'authority.json':{**scopes,'expiresAt':1},'bundle':{'prepared':p,'declaration':declaration}}
        a=actual();b=copy.deepcopy(a)
        if drift:b['State']['Pid']+=1
        out=io.StringIO()
        with patch.object(m,'read',side_effect=lambda path,*args:rows[Path(path).name]),\
             patch.object(m,'engine_get',side_effect=[a,b])as engine,\
             patch.object(m.os,'geteuid',return_value=0),\
             patch.object(m.sys,'flags',type('Flags',(),{'isolated':1})),\
             patch.object(m.signal,'alarm'),contextlib.redirect_stdout(out):
            if drift:
                with self.assertRaisesRegex(m.ReadDenied,'REGISTRY_GENERATION_DRIFT'):m.main()
            else:m.main()
        self.assertEqual(engine.call_count,2)
        self.assertNotIn('PRIVATE_VALUE',out.getvalue())
        return [json.loads(s)for s in out.getvalue().splitlines()]

    def test_complete_expired_window_requires_no_runtime_renewal(self):
        rows=self.exercise_main()
        self.assertTrue(rows[1]['authorityExpiredAtRead'])
        self.assertTrue(rows[-1]['complete'])
        self.assertFalse(rows[-1]['runtimeAuthorityIssued'])

    def test_midread_replacement_withholds_projection(self):
        rows=self.exercise_main(drift=True)
        self.assertEqual([r['check']for r in rows],['BEGIN'])

if __name__=='__main__':unittest.main()
