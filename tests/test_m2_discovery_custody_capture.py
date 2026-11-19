"""Actual private POSIX candidates; process/boot fixture is explicit, no IAM."""
import copy,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile import custody_capture as m

class CustodyCapture(unittest.TestCase):
    def fixture(self):
        self.assertEqual(os.geteuid(),0)
        t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup);root=Path(t.name);root.chmod(0o700)
        source=root/'input';source.mkdir(mode=0o700);material=root/'material';material.mkdir(mode=0o700)
        boot=root/'boot';boot.write_text('synthetic-boot')
        pin=lambda pid:{'pid':pid,'startTicks':123,'namespaces':{'net':[1,2],'mnt':[3,4]}}
        data={'schema':'ouf.m2-discovery-private-installation-inputs.v1','bootId':'synthetic-boot',
            'processPins':{r:pin(i+20) for i,r in enumerate(sorted(m.ROLES))},
            'observations':{r:{'State':{'Pid':i+20}} for i,r in enumerate(sorted(m.ROLES))},
            'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        p=source/'inputs.json';p.write_bytes(m.encoded(data));p.chmod(0o600)
        secret=b'synthetic-fixture-secret-not-for-target';key=b'a'*64;ca=b'synthetic-fixture-public-ca'
        for name,value,uid,gid,mode in [('schema-gov-client-secret',secret,10001,10001,0o400),
            ('semantic-discovery-owner.key',key,10001,10001,0o400),('gateway-discovery-owner.key',key,636,636,0o400),
            ('provider-public-ca.crt',ca,0,0,0o600)]:
            p=material/name;p.write_bytes(value);os.chown(p,uid,gid);p.chmod(mode)
        manifest={'schema':'ouf.discovery.private-runtime-input-manifest.v1','existingWorkloadCredentialHash':hashlib.sha256(secret).hexdigest(),
            'discoveryMacKeyHash':hashlib.sha256(key).hexdigest(),'publicCaHash':hashlib.sha256(ca).hexdigest(),
            'mountsInstalled':False,'applicationCutoverAuthorized':False,'leaseAuthorityGranted':False}
        raw=m.encoded(manifest);p=material/'private-input-manifest.json';p.write_bytes(raw);p.chmod(0o600)
        kwargs={'input_root':source,'material_root':material,'input_hash':m.digest(data),
            'manifest_hash':hashlib.sha256(raw).hexdigest(),'pin':pin,'boot_path':boot}
        return root,kwargs,data,secret,key

    def test_success_exact_counts_private_candidates_and_no_secret_in_result(self):
        root,k,data,secret,key=self.fixture();before={p:p.read_bytes() for p in list(k['input_root'].iterdir())+list(k['material_root'].iterdir())}
        c=m.Capture(root/'scope');result=m.collect(c,**k)
        self.assertEqual(result['counts']['metadataReads'],2);self.assertEqual(result['counts']['credentialFileReads'],1)
        self.assertEqual(result['counts']['applicationMacKeyReads'],2);self.assertEqual(result['candidateFilesVerified'],4)
        self.assertNotIn(secret.decode(),json.dumps(result));self.assertNotIn(key.decode(),json.dumps(result))
        self.assertNotIn(str(k['material_root']),json.dumps(result))
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
        out=root/'scope/material-candidates.private.json';self.assertEqual(out.stat().st_mode&0o777,0o600)
        self.assertFalse(result['runtimeAuthorityIssued']);self.assertFalse(result['targetApplyAuthorized'])

    def test_consumed_scope_is_refused_before_file_reads(self):
        root,k,*_=self.fixture();m.Capture(root/'scope')
        with patch.object(m.Capture,'read',side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Capture(root/'scope')

    def test_metadata_mode_owner_symlink_and_key_bytes_fail_closed(self):
        for case in ('mode','owner','symlink','content'):
            root,k,*_=self.fixture();p=k['material_root']/'gateway-discovery-owner.key'
            if case=='mode':p.chmod(0o444)
            if case=='owner':os.chown(p,0,0)
            if case=='symlink':p.unlink();p.symlink_to(k['material_root']/'semantic-discovery-owner.key')
            if case=='content':p.write_bytes(b'b'*64)
            with self.subTest(case=case),self.assertRaises((m.Stop,OSError)):m.collect(m.Capture(root/'scope'),**k)

    def test_changed_process_boot_or_input_hash_never_reaches_credentials(self):
        for case in ('process','boot','hash'):
            root,k,*_=self.fixture()
            if case=='process':k['pin']=lambda p:{'pid':p,'startTicks':999,'namespaces':{}}
            if case=='boot':k['boot_path'].write_text('different-boot')
            if case=='hash':k['input_hash']='f'*64
            c=m.Capture(root/'scope')
            with self.subTest(case=case),self.assertRaises(m.Stop):m.collect(c,**k)
            self.assertEqual(c.counts['credentialFileReads'],0);self.assertEqual(c.counts['applicationMacKeyReads'],0)

    def test_changed_manifest_cannot_authorize_arbitrary_new_files(self):
        root,k,*_=self.fixture();p=k['material_root']/'private-input-manifest.json';v=json.loads(p.read_text());v['credentialPath']='/etc/shadow';p.write_bytes(m.encoded(v))
        c=m.Capture(root/'scope')
        with self.assertRaises(m.Stop):m.collect(c,**k)
        self.assertEqual(c.counts['credentialFileReads'],0)

    def test_process_drift_during_hashing_preserves_consumed_scope(self):
        root,k,*_=self.fixture();original=k['pin'];calls=[]
        def changed(pid):
            calls.append(pid);v=original(pid)
            if len(calls)>4:v['startTicks']+=1
            return v
        k['pin']=changed;c=m.Capture(root/'scope')
        with self.assertRaises(m.Stop):m.collect(c,**k)
        self.assertTrue((root/'scope/capture.claim.json').exists())
        self.assertFalse((root/'scope/material-candidates.private.json').exists())

    def test_native_self_process_pin_is_stable_and_namespaced(self):
        before=m.process_pin(os.getpid());after=m.process_pin(os.getpid())
        self.assertEqual(before,after);self.assertEqual(set(before['namespaces']),{'net','mnt'})

if __name__=='__main__':unittest.main()
