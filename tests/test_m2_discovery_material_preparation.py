"""Real private files/copies, explicitly synthetic peer/Engine observations."""
import copy
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_custody_capture as prior_fixture
from tools.m2_discovery_installation_profile import material_preparation as m
from tools.m2_discovery_installation_profile import custody_capture as old


class MaterialPreparation(unittest.TestCase):
    def fixture(self):
        root,k,inputs,secret,key=prior_fixture.CustodyCapture.fixture(self)
        ca=ssl.DER_cert_to_PEM_cert(b'0'*256).encode('ascii')
        p=k['material_root']/'provider-public-ca.crt';p.write_bytes(ca)
        p=k['material_root']/'private-input-manifest.json';manifest=json.loads(p.read_bytes())
        manifest['publicCaHash']=hashlib.sha256(ca).hexdigest();p.write_bytes(old.encoded(manifest))
        k['manifest_hash']=hashlib.sha256(p.read_bytes()).hexdigest()
        roles=sorted(old.ROLES)+['peer-'+str(i) for i in range(9)]
        peers={}
        for i,role in enumerate(roles):
            peers[role]={'Id':format(i+1,'064x'),'Image':'sha256:'+'1'*64,
                'Config':{'Env':['OUF_GATEWAY_DELEGATION_KEY='+'b'*64,
                    'OUF_SEMANTIC_READ_OWNER_KEY='+'c'*64,'OUF_SEMANTIC_PROPOSAL_OWNER_KEY='+'d'*64]},
                'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{}},
                'State':{'Pid':20+i,'StartedAt':'explicit-synthetic-generation',
                         'Running':True,'Paused':False,'Restarting':False}}
        inputs['observations']={r:copy.deepcopy(peers[r]) for r in old.ROLES}
        inputs['processPins']={r:k['pin'](peers[r]['State']['Pid']) for r in old.ROLES}
        p=k['input_root']/'inputs.json';p.write_bytes(old.encoded(inputs));k['input_hash']=old.digest(inputs)
        custody=old.Capture(root/'prior-custody-consumed');receipt=old.collect(custody,**k)
        cohort={**{name:inputs[name] for name in ('schema','bootId','historicalAuthorityReused',
                   'runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')},
            'schema':'ouf.m2-discovery-current-private-bindings.v1','observations':copy.deepcopy(peers),
            'processPins':{r:k['pin'](v['State']['Pid']) for r,v in peers.items()},
            'rootProcessPins':{'pid1':k['pin'](1),'engine':k['pin'](2)},
            'engineBinding':{'socketPath':'/explicit/fixture/socket','socketBinding':[1,2,0,0,0o600],
                             'peerCredentials':[2,0,0]}}
        folder=root/'cohort';folder.mkdir(mode=0o700)
        p=folder/'inputs.json';p.write_bytes(old.encoded(cohort));p.chmod(0o600)
        calls=[]
        class FakeEngine:
            def __init__(self,c,binding,ids):
                self.c=c;assert len(ids)==13 and len(set(ids))==13
            def get(self,path):
                calls.append(path);self.c.counts['engineGets']+=1
                if path=='/v1.44/info':return {'ServerVersion':'29.8.1'}
                cid=path.split('/')[-2]
                return copy.deepcopy(next(v for v in peers.values() if v['Id']==cid))
        args={'input_root':k['input_root'],'input_hash':k['input_hash'],
            'cohort_root':folder,'cohort_hash':m.digest(cohort),'candidate_root':custody.scope,
            'candidate_hash':receipt['candidateBindingHash'],'pin':k['pin'],'boot_path':k['boot_path'],
            'engine_factory':FakeEngine}
        return root,args,peers,calls,secret,key,ca

    def test_prepares_two_readonly_copies_and_public_certificate_without_mutating_sources(self):
        root,k,peers,calls,secret,key,ca=self.fixture()
        before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        c=m.Preparation(root/'new-preparation');result=m.prepare(c,**k)
        self.assertEqual(len(calls),27);self.assertEqual(result['counts']['metadataReads'],3)
        self.assertEqual(result['counts']['credentialFileReads'],1)
        self.assertEqual(result['counts']['applicationMacKeyReads'],2)
        self.assertEqual(result['counts']['privateCopiesPrepared'],2)
        self.assertEqual(result['counts']['preparedCopyReads'],3)
        for name,raw,gid,mode in [('schema-gov-client-secret',secret,10001,0o440),
             ('semantic-discovery-owner.key',key,10001,0o440),('provider-public-ca.crt',ca,0,0o600)]:
            p=c.scope/name;self.assertEqual(p.read_bytes(),raw)
            self.assertEqual((p.stat().st_uid,p.stat().st_gid,p.stat().st_mode&0o777),(0,gid,mode))
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
        self.assertNotIn(secret.decode(),json.dumps(result));self.assertNotIn(key.decode(),json.dumps(result))
        self.assertNotIn(ca.decode(),json.dumps(result))
        self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['applicationE2EProven'])
        self.assertFalse(result['currentCertificateCaValidityAndTrustProven'])
        self.assertEqual((c.scope/'prepared-inputs.private.json').stat().st_mode&0o777,0o600)

    def test_consumed_scope_stops_before_any_read_and_preserves_copies(self):
        root,k,*_=self.fixture();c=m.Preparation(root/'new-preparation');m.prepare(c,**k)
        before={p:p.read_bytes() for p in c.scope.iterdir()}
        with patch.object(m.Preparation,'read',side_effect=AssertionError('no reads')):
            with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Preparation(c.scope)
        self.assertEqual(before,{p:p.read_bytes() for p in c.scope.iterdir()})

    def test_changed_peer_or_process_stops_before_copy(self):
        for case in ('peer','process','boot'):
            root,k,peers,*_=self.fixture()
            if case=='peer':peers['peer-8']['HostConfig']['changed']=True
            if case=='process':k['pin']=lambda pid:{'pid':pid,'startTicks':999,'namespaces':{}}
            if case=='boot':k['boot_path'].write_text('changed')
            c=m.Preparation(root/'new-preparation')
            with self.subTest(case=case),self.assertRaises(m.Stop):m.prepare(c,**k)
            self.assertEqual(c.counts['privateCopiesPrepared'],0)
            self.assertFalse((c.scope/'prepared-inputs.private.json').exists())

    def test_candidate_replacement_content_mode_and_symlink_are_denied(self):
        for case in ('replacement','content','mode','symlink'):
            root,k,*_=self.fixture()
            candidates=json.loads((k['candidate_root']/'material-candidates.private.json').read_bytes())
            p=Path(candidates['candidates']['registryDiscoveryKey']['path'])
            if case=='content':p.write_bytes(b'e'*64)
            if case=='mode':p.chmod(0o444)
            if case=='replacement':
                raw=p.read_bytes();p.unlink();p.write_bytes(raw);os.chown(p,10001,10001);p.chmod(0o400)
            if case=='symlink':
                p.unlink();p.symlink_to(Path(candidates['candidates']['gatewayDiscoveryKey']['path']))
            c=m.Preparation(root/'new-preparation')
            with self.subTest(case=case),self.assertRaises((m.Stop,OSError)):m.prepare(c,**k)
            self.assertEqual(c.counts['privateCopiesPrepared'],0)

    def test_unrelated_key_collision_and_wrong_existing_discovery_slot_are_denied(self):
        for case in ('collision','wrong-slot'):
            root,k,peers,*_=self.fixture()
            # Bind the observed Env to the provenance too, to exercise the
            # key-purpose check rather than the earlier generation drift guard.
            value='OUF_SEMANTIC_READ_OWNER_KEY='+'a'*64 if case=='collision' else m.KEY_SLOT+'='+'e'*64
            peers['apisix']['Config']['Env']=[r for r in peers['apisix']['Config']['Env'] if not r.startswith(value.split('=')[0]+'=')]+[value]
            for path,hash_key in [(k['input_root']/'inputs.json','input_hash'),(k['cohort_root']/'inputs.json','cohort_hash')]:
                v=json.loads(path.read_bytes());v['observations']['apisix']=copy.deepcopy(peers['apisix'])
                path.write_bytes(m.encoded(v));k[hash_key]=m.digest(v)
            p=k['candidate_root']/'material-candidates.private.json';v=json.loads(p.read_bytes())
            v['installationInputsHash']=k['input_hash'];p.write_bytes(m.encoded(v));k['candidate_hash']=m.digest(v)
            c=m.Preparation(root/'new-preparation')
            with self.subTest(case=case),self.assertRaisesRegex(m.Stop,'KEY_PURPOSE_COLLISION|DIFFERENT_MATERIAL'):
                m.prepare(c,**k)
            self.assertEqual(c.counts['privateCopiesPrepared'],0)

    def test_copy_failure_and_late_peer_drift_preserve_consumed_partial_evidence(self):
        for case in ('copy','late-peer'):
            root,k,peers,*_=self.fixture();c=m.Preparation(root/'new-preparation')
            original=c.copy_once;calls=[]
            def changed(name,raw,**kw):
                calls.append(name)
                if case=='copy' and len(calls)==2:raise OSError('synthetic interrupted copy')
                value=original(name,raw,**kw)
                if case=='late-peer':peers['peer-8']['HostConfig']['changed']=True
                return value
            with patch.object(c,'copy_once',side_effect=changed):
                with self.subTest(case=case),self.assertRaises((m.Stop,OSError)):m.prepare(c,**k)
            self.assertTrue((c.scope/'schema-gov-client-secret').exists())
            self.assertTrue((c.scope/'capture.claim.json').exists())
            self.assertFalse((c.scope/'prepared-inputs.private.json').exists())
            with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Preparation(c.scope)

    def test_private_or_multiple_pem_blocks_are_never_labeled_public_certificate(self):
        for raw in (b'-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n',
                    ssl.DER_cert_to_PEM_cert(b'0'*256).encode()*2,b'public-looking text'):
            with self.subTest(raw=raw[:25]),self.assertRaises(m.Stop):m.public_certificate_only(raw)

    def test_closed_engine_paths_and_budget_are_denied_before_socket_access(self):
        root,k,peers,*_=self.fixture();c=m.Preparation(root/'new-preparation')
        cohort=json.loads((k['cohort_root']/'inputs.json').read_bytes())
        engine=m.ReadOnlyEngine(c,cohort['engineBinding'],[v['Id'] for v in peers.values()])
        for path in ('/v1.44/containers/json','/v1.44/images/json','/internal/execute'):
            with self.subTest(path=path),self.assertRaisesRegex(m.Stop,'CLOSED_MATERIAL_PREPARATION'):
                engine.get(path)
            self.assertEqual(c.counts['engineGets'],0)
        c.counts['engineGets']=27
        with self.assertRaisesRegex(m.Stop,'CLOSED_MATERIAL_PREPARATION'):engine.get('/v1.44/info')
        self.assertEqual(c.counts['engineGets'],27)
        self.assertFalse(list(c.scope.glob('engine-get-*-claim.json')))

if __name__=='__main__':unittest.main()
