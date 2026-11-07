"""Root filesystem staging with synthetic metadata/Engine, never target admission."""
import copy,hashlib,os,shutil,ssl,stat,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_public_truststore as certificates
import test_m2_discovery_trust_inputs as bindings
from tools.m2_discovery_installation_profile import trust_preparation as m


class PublicTrustPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0:raise RuntimeError('Native public trust tests require actual root, no skip')
        certificates.PublicTruststore.setUpClass()
        cls.root=Path(tempfile.mkdtemp(prefix='ouf-public-trust-ci-',dir='/var/lib'))
        cls.root.chmod(0o700)
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root);certificates.PublicTruststore.tearDownClass()

    def fixture(self,name):
        base=self.root/name;base.mkdir(mode=0o700)
        material_root=base/'material';material_root.mkdir(mode=0o700)
        owner_root=base/'owner';owner_root.mkdir(mode=0o700)
        a=list(bindings.BoundTrustInputs().fixture());material,owner=a[0],a[2]
        def write(p,raw):
            p.write_bytes(raw);p.chmod(0o600)
        public=material_root/'provider-public-ca.crt';iam=owner_root/'iam-ca.pem'
        write(public,a[5]);write(iam,a[4])
        material['preparedCopies']['publicProviderCa'].update(path=str(public),metadata=m.attrs(public.lstat()))
        owner['tlsCa']['path']=str(iam);owner['destinations']={'installationRoot':str(owner_root)}
        pins={}
        for i,(alias,row) in enumerate(material['currentObservations'].items()):
            row.update(Image='sha256:'+'a'*64,HostConfig={},Mounts=[],NetworkSettings={})
            row.setdefault('Config',{'Env':[]})
            row['State']={'Pid':100+i,'StartedAt':'synthetic','Running':True,'Paused':False,'Restarting':False}
            pins[alias]={'pid':100+i,'startTicks':i+1000,'namespaces':{'net':[1,i+10],'mnt':[1,i+30]}}
        material.update(processPins=pins,rootProcessPins={
            'pid1':{'pid':1,'startTicks':10},'engine':{'pid':2,'startTicks':20}},
            engineBinding={'peerCredentials':[2,0,0],'socketPath':'/fixture/engine','socketBinding':[]},
            bootId='synthetic-boot')
        material_path=material_root/'prepared-inputs.private.json'
        review={'schema':'ouf.registry-operational-installation-review.v1','configuration':owner,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
        review_path=base/'review.json';configuration_path=owner_root/'configuration.json'
        write(material_path,m.encoded(material) if hasattr(m,'encoded') else
              __import__('json').dumps(material,sort_keys=True,separators=(',',':')).encode())
        write(review_path,__import__('json').dumps(review,sort_keys=True,separators=(',',':')).encode())
        write(configuration_path,__import__('json').dumps(owner,sort_keys=True,separators=(',',':')).encode())
        boot_path=base/'boot-id';write(boot_path,b'synthetic-boot')
        pin_by_pid={p['pid']:p for p in list(pins.values())+list(material['rootProcessPins'].values())}
        class Engine:
            def __init__(self,capture,binding,ids):
                self.c=capture;self.rows={r['Id']:r for r in material['currentObservations'].values()}
                if len(ids)!=13 or set(ids)!=set(self.rows):raise AssertionError('exact scope')
            def get(self,path):
                self.c.counts['engineGets']+=1
                if path=='/v1.44/info':return {'ServerVersion':'29.8.1'}
                return copy.deepcopy(self.rows[path.split('/')[-2]])
        args=dict(material_root=material_root,material_hash=m.digest(material),
            owner_review=review_path,owner_review_hash=m.digest(review),
            owner_configuration_hash=m.digest(owner),pin=lambda pid:copy.deepcopy(pin_by_pid[pid]),
            boot_path=boot_path,engine_factory=Engine,now=time.time)
        return base,material,owner,args,Engine

    def test_current_thirteen_peers_exact_bound_records_and_root_store_readback(self):
        base,material,owner,args,_=self.fixture('positive')
        prior={p:p.read_bytes() for p in base.rglob('*') if p.is_file()}
        c=m.TrustPreparation(base/'new');result=m.prepare(c,**args)
        self.assertEqual(result['counts']['engineGets'],27);self.assertEqual(result['counts']['metadataReads'],3)
        self.assertEqual(result['counts']['publicCertificateReads'],2)
        self.assertEqual(result['counts']['credentialFileReads'],0)
        self.assertEqual(result['counts']['applicationMacKeyReads'],0)
        self.assertEqual(result['counts']['publicTrustStoresPrepared'],1)
        self.assertFalse(result['targetTlsAdmissionProven']);self.assertFalse(result['runtimeAuthorityIssued'])
        record=m.decode((c.scope/'public-trust-inputs.json').read_bytes())
        target=Path(record['publicStore']['path']);s=target.lstat()
        self.assertEqual((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)),(0,10001,0o440))
        self.assertEqual(record['proposal']['sha256'],hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(record['proposal']['certificateCount'],2)
        self.assertEqual({p:p.read_bytes() for p in prior},prior)
        with self.assertRaises(ValueError):m.TrustPreparation(c.scope)

    def test_existing_output_or_claim_is_never_overwritten(self):
        for conflict in ('provider-trust.p12','public-truststore-claim.json'):
            with self.subTest(conflict=conflict):
                base,_,_,args,_=self.fixture('existing-'+conflict)
                c=m.TrustPreparation(base/'new');p=c.scope/conflict;p.write_bytes(b'preserve');p.chmod(0o600)
                with self.assertRaises(FileExistsError):m.prepare(c,**args)
                self.assertEqual(p.read_bytes(),b'preserve');self.assertFalse((c.scope/'public-trust-inputs.json').exists())

    def test_rehashed_metadata_is_not_accepted_under_exact_expected_binding(self):
        for name in ('material','review','configuration'):
            with self.subTest(name=name):
                base,_,_,args,_=self.fixture('drift-'+name)
                p={'material':args['material_root']/'prepared-inputs.private.json',
                   'review':args['owner_review'],'configuration':base/'owner/configuration.json'}[name]
                value=m.decode(p.read_bytes());value['extra']='unbound'
                p.write_bytes(__import__('json').dumps(value).encode())
                c=m.TrustPreparation(base/'new')
                with self.assertRaises(ValueError):m.prepare(c,**args)
                self.assertEqual(c.counts['engineGets'],0);self.assertEqual(c.counts['publicCertificateReads'],0)
                self.assertFalse((c.scope/'provider-trust.p12').exists())

    def test_current_pin_or_engine_drift_blocks_before_ca_read(self):
        for name in ('pin','engine'):
            with self.subTest(name=name):
                base,_,_,args,Engine=self.fixture('generation-'+name)
                if name=='pin':args['pin']=lambda pid:{'pid':pid,'startTicks':-1}
                else:
                    class Drift(Engine):
                        def get(self,path):
                            row=super().get(path)
                            if 'containers/' in path:row['Config']['extra']='drift'
                            return row
                    args['engine_factory']=Drift
                c=m.TrustPreparation(base/'new')
                with self.assertRaises(ValueError):m.prepare(c,**args)
                self.assertEqual(c.counts['publicCertificateReads'],0)
                self.assertFalse((c.scope/'provider-trust.p12').exists())

    def test_late_peer_drift_keeps_consumed_scope_and_partial_public_store(self):
        base,_,_,args,Engine=self.fixture('late-drift')
        class Drift(Engine):
            def get(self,path):
                row=super().get(path)
                if self.c.counts['engineGets']==27:row['State']['Restarting']=True
                return row
        args['engine_factory']=Drift;c=m.TrustPreparation(base/'new')
        with self.assertRaises(ValueError):m.prepare(c,**args)
        self.assertTrue((c.scope/'provider-trust.p12').exists())
        self.assertFalse((c.scope/'public-trust-inputs.json').exists())
        with self.assertRaises(ValueError):m.TrustPreparation(c.scope)

    def test_wrong_custody_links_and_source_change_are_refused(self):
        for name in ('symlink','hardlink','writable','mutated-after-copy'):
            with self.subTest(name=name):
                base,material,_,args,_=self.fixture('custody-'+name)
                p=Path(material['preparedCopies']['publicProviderCa']['path'])
                if name=='symlink':
                    other=base/'original-ca';p.rename(other);p.symlink_to(other)
                if name=='hardlink':os.link(p,base/'extra-link')
                if name=='writable':p.chmod(0o660)
                c=m.TrustPreparation(base/'new')
                if name=='mutated-after-copy':
                    original=c.stage_public_store
                    def change(raw):
                        result=original(raw);p.write_bytes(p.read_bytes()+b'\n');return result
                    c.stage_public_store=change
                with self.assertRaises(ValueError):m.prepare(c,**args)
                self.assertFalse((c.scope/'public-trust-inputs.json').exists())
                if name!='mutated-after-copy':self.assertFalse((c.scope/'provider-trust.p12').exists())

if __name__=='__main__':unittest.main()
