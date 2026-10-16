import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.semantic_policy_token_owner.producer import AtomicTokenFile,Binding
spec=importlib.util.spec_from_file_location('refresh_reader',ROOT/'scripts/read-chatbot-semantic-policy-refresh-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def fixture():
    env=['OUF_AUTHORIZATION_REGISTRY_URL=https://policy.invalid/internal/capabilities/v1/authorization/policy-bundle/active',
         'OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/token/current']
    a={'Id':m.REGISTRY,'Image':'sha256:'+'a'*64,'State':{'Running':True,'Pid':123,'StartedAt':'fixed'},
       'Config':{'Env':env,'User':'10001:10001'},'HostConfig':{},'NetworkSettings':{},
       'Mounts':[{'Type':'bind','Source':'/private/token','Destination':'/token','RW':False}]}
    p={'registry':{'creationRequest':{'Env':env[:],'HostConfig':{'Binds':['/private/token:/token:ro']}}},
       'authorization':{'plan':{'selection':{'origin':'https://policy.invalid'}}}}
    return a,p

class Tests(unittest.TestCase):
    def setUp(self):
        self.emitter=patch.object(m,'emit');self.emitter.start();self.addCleanup(self.emitter.stop)

    @contextlib.contextmanager
    def ownership_adapter(self):
        # The Work filesystem cannot chown. Emulate ownership metadata only;
        # open/no-follow/chmod/write/fsync/rename and producer code remain real.
        original_stat,original_fstat=os.stat,os.fstat
        owners={}
        def wrapped(s):
            if (s.st_dev,s.st_ino)not in owners:return s
            values={name:getattr(s,name)for name in dir(s)if name.startswith('st_')}
            values['st_uid'],values['st_gid']=owners[(s.st_dev,s.st_ino)]
            return types.SimpleNamespace(**values)
        def chown(path,uid,gid):
            s=original_stat(path);owners[(s.st_dev,s.st_ino)]=(uid,gid)
        def fchown(fd,uid,gid):
            s=original_fstat(fd);owners[(s.st_dev,s.st_ino)]=(uid,gid)
        with patch.object(os,'stat',side_effect=lambda *a,**k:wrapped(original_stat(*a,**k))),\
             patch.object(os,'fstat',side_effect=lambda *a,**k:wrapped(original_fstat(*a,**k))),\
             patch.object(os,'chown',side_effect=chown),patch.object(os,'fchown',side_effect=fchown):
            yield

    def test_drift_unreviewed_origin_mount_and_url_reject_before_credential(self):
        a,p=fixture();u,s=m.selected(a,p)
        self.assertEqual(s,'/private/token/current')
        for mutate in (
            lambda a,p:a['Config']['Env'].__setitem__(0,'OUF_AUTHORIZATION_REGISTRY_URL=https://evil.invalid/api/active'),
            lambda a,p:p['authorization']['plan']['selection'].__setitem__('origin','https://else.invalid'),
            lambda a,p:a['Mounts'][0].__setitem__('Source','/other'),
            lambda a,p:a['Mounts'][0].__setitem__('RW',True)):
            a,p=fixture();mutate(a,p)
            with self.assertRaises(m.ReadDenied):m.selected(a,p)

    def test_exact_published_gateway_contract_and_canonical_https_port(self):
        a,p=fixture()
        p['authorization']['plan']['selection']['origin']='https://policy.invalid:443'
        m.selected(a,p)
        for path in ('/api/active','/internal/capabilities/v1/authorization/policy-bundle/active/','/unrelated'):
            a,p=fixture()
            row='OUF_AUTHORIZATION_REGISTRY_URL=https://policy.invalid'+path
            a['Config']['Env'][0]=p['registry']['creationRequest']['Env'][0]=row
            with self.assertRaises(m.ReadDenied):m.selected(a,p)

    def test_real_private_file_expiry_and_symlink_rejection(self):
        claims=base64.urlsafe_b64encode(b'{"exp":1,"private":"SECRET"}').decode().rstrip('=')
        with tempfile.TemporaryDirectory(dir=ROOT)as d,self.ownership_adapter():
            os.chown(d,0,10001);os.chmod(d,0o750)
            b=Binding('https://issuer.invalid/token','test','scope',d,'token',10001)
            writer=AtomicTokenFile(b);writer.check_custody()
            writer.publish('header.'+claims+'.signature',lambda:None)
            writer.check_custody();p=Path(d)/'token'
            self.assertEqual((p.stat().st_uid,p.stat().st_gid,p.stat().st_mode&0o777),(0,10001,0o440))
            token,metadata=m.credential(p)
            self.assertTrue(metadata['expiredAtRead']);self.assertFalse(metadata['signatureVerifiedLocally'])
            self.assertNotIn('SECRET',json.dumps(metadata))
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):m.credential(link)
            p.chmod(0o644)
            with self.assertRaises(m.ReadDenied):m.credential(p)

    def test_custody_contract_rejects_wrong_uid_gid_mode_and_directory(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d,self.ownership_adapter():
            os.chown(d,0,10001);os.chmod(d,0o750)
            p=Path(d)/'token';p.write_text('not-read')
            for uid,gid,mode in ((0,0,0o400),(10001,10001,0o400),(0,10001,0o640),(0,10001,0o600)):
                os.chown(p,uid,gid);os.chmod(p,mode)
                with self.assertRaisesRegex(m.ReadDenied,'PRIVATE_WORKLOAD_TOKEN_REQUIRED'):m.credential(p)
            os.chown(p,0,10001);os.chmod(p,0o440);os.chmod(d,0o700)
            with self.assertRaisesRegex(m.ReadDenied,'TOKEN_OUTPUT_DIRECTORY_CUSTODY_REQUIRED'):m.credential(p)

    def response(self,status=401,doc=None):
        class Reply:
            def __init__(self):self.status=status;self.reads=0
            def read(self,n):self.reads+=1;return json.dumps(doc).encode()
        class Connection:
            def __init__(self):self.calls=[];self.reply=Reply();self.closed=False
            def request(self,*args,**kwargs):self.calls.append((args,kwargs))
            def getresponse(self):return self.reply
            def close(self):self.closed=True
        conn=Connection()
        with patch.object(m.http.client,'HTTPSConnection',return_value=conn),patch.object(m.ssl,'create_default_context'):
            result=m.fetch_policy(m.urlsplit('https://policy.invalid/api/active'),'SECRET_TOKEN')
        self.assertEqual(len(conn.calls),1);self.assertEqual(conn.calls[0][0],('GET','/api/active'))
        self.assertTrue(conn.closed);self.assertNotIn('SECRET_TOKEN',json.dumps(result))
        return result,conn

    def test_authentication_rejection_does_not_read_body_or_retry(self):
        result,conn=self.response()
        self.assertEqual(result['httpStatus'],401);self.assertEqual(conn.reply.reads,0)

    def test_valid_envelope_is_projected_without_installing_or_raw_data(self):
        bundle={'bundleId':'SECRET_ID','version':40,'publishedAt':'x','capabilities':[{'capabilityId':'ouf.semantic.propose'}],
                'grants':[{'capabilityId':'ouf.semantic.propose','subjectId':'SECRET_SUBJECT'}]}
        raw=json.dumps(bundle,separators=(',',':'),ensure_ascii=False).encode()
        result,_=self.response(200,{'bundleId':'SECRET_ID','bundleVersion':40,'bundle':bundle,
            'contentHash':m.hashlib.sha256(raw).hexdigest()})
        self.assertTrue(result['compactBundleHashMatchesEnvelope'])
        self.assertFalse(result['registryLoadedSnapshotProven']);self.assertNotIn('SECRET',json.dumps(result))

    def test_unknown_envelope_fields_fail_closed(self):
        with self.assertRaises(m.ReadDenied):self.response(200,{'unexpected':'x'})

    def test_envelope_size_bound(self):
        with self.assertRaisesRegex(m.ReadDenied,'ACTIVE_ENVELOPE_TOO_LARGE'):
            self.response(200,{'bundle':'x'*(5*1024*1024+65536)})

if __name__=='__main__':unittest.main()
