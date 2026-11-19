"""Real root file boundary; native network leaves qualified in Docker CI."""
import ast,copy,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import engine_transport_backend as m
from tools.semantic_provider_lease_coordination import PrivateJournal

class EngineBundle(unittest.TestCase):
    def fixture(self):
        t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup)
        root=Path(t.name);root.chmod(0o700);parent=root/'bundles';parent.mkdir(mode=0o700)
        bundle=parent/('c'*64);bundle.mkdir(mode=0o700);p=bundle/'config.json'
        value={'linux':{'namespaces':[{'type':'network'}]},'synthetic':'full-expected-oci'}
        p.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode());p.chmod(0o644)
        profile={'containerId':'c'*64,'bundlePath':str(bundle),'bundleHash':m.digest(value)}
        backend=object.__new__(m.EngineTransportBackend);backend.profile=copy.deepcopy(profile)
        backend.seal=m.digest(profile);backend.bundle_parent=backend.parent_seal=str(parent)
        return backend,profile,p,value

    def test_original_private_denial_reproduced_and_only_signed_engine_oci_accepted(self):
        b,profile,p,value=self.fixture()
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_FILE_UNPROVEN'):PrivateJournal(p).read()
        self.assertEqual(b.engine_bundle(profile),value)
        p.chmod(0o600);self.assertEqual(b.engine_bundle(profile),value)
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_FILE_UNPROVEN'):
            p.chmod(0o644);PrivateJournal(p).read()

    def test_foreign_cid_parent_hash_modes_and_links_are_denied(self):
        for case in ('cid','parent','hash','mode','symlink','hardlink','writable_parent'):
            with self.subTest(case=case):
                b,profile,p,value=self.fixture()
                if case=='cid':profile['containerId']='d'*64;b.seal=m.digest(profile)
                elif case=='parent':b.bundle_parent=str(p.parent)
                elif case=='hash':profile['bundleHash']='f'*64;b.seal=m.digest(profile)
                elif case=='mode':p.chmod(0o666)
                elif case=='symlink':q=p.with_name('kept');p.rename(q);p.symlink_to(q)
                elif case=='hardlink':os.link(p,p.with_name('extra'))
                elif case=='writable_parent':p.parent.chmod(0o777)
                with self.assertRaises((ValueError,RuntimeError,OSError)):b.engine_bundle(profile)

    def test_atomic_replacement_during_read_is_denied(self):
        b,profile,p,value=self.fixture();read=m.os.read
        def replace(fd,n):
            raw=read(fd,n);q=p.with_name('replacement');q.write_bytes(raw);q.chmod(0o644);q.replace(p);return raw
        with patch.object(m.os,'read',side_effect=replace),self.assertRaisesRegex(ValueError,'CHANGED_DURING_READ'):
            b.engine_bundle(profile)

    def test_only_exact_docker_alias_with_same_name_and_inode_is_canonicalized(self):
        b,profile,p,_=self.fixture();canonical=Path('/run/docker/netns/ci-fixture')
        profile.update(namespacePath='/var/run/docker/netns/ci-fixture',namespaceInode=p.stat().st_ino,namespaceOrigin='PREPARED')
        b.namespace_reference=profile['namespacePath'];b.namespace_generation={'pid':1234,'startTicks':23,'namespaceInode':p.stat().st_ino}
        b.namespace_seal=m.digest([b.namespace_reference,b.namespace_generation]);b.generation=lambda _:copy.deepcopy(b.namespace_generation)
        b.seal=m.digest(profile);before=copy.deepcopy(profile)
        with (patch.object(Path,'resolve',return_value=canonical) as resolve,
            patch.object(Path,'lstat',return_value=p.stat()),patch.object(m,'_ancestors') as ancestors):
            self.assertEqual(b.engine_namespace(profile),canonical)
            self.assertEqual(resolve.call_count,2);ancestors.assert_called_once_with(canonical)
        self.assertEqual(profile,before)
        for original,target,reason in (('/foreign/netns/ci-fixture',canonical,'PARENT_REQUIRED'),
            ('/var/run/docker/netns/ci-fixture',Path('/run/docker/netns/other'),'ALIAS_REQUIRED')):
            profile['namespacePath']=original;b.namespace_reference=original
            b.namespace_seal=m.digest([b.namespace_reference,b.namespace_generation]);b.seal=m.digest(profile)
            with patch.object(Path,'resolve',return_value=target),self.assertRaisesRegex(ValueError,reason):
                b.engine_namespace(profile)
        profile.update(namespacePath='/run/docker/netns/ci-fixture',namespaceInode=p.stat().st_ino+1);b.seal=m.digest(profile)
        with (patch.object(Path,'resolve',return_value=canonical),patch.object(Path,'lstat',return_value=p.stat()),
            patch.object(m,'_ancestors'),self.assertRaisesRegex(ValueError,'IDENTITY_DRIFT')):
            b.engine_namespace(profile)

    def test_all_original_network_and_generation_guards_remain_exact(self):
        old=ROOT/'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py'
        self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(),'ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528')
        def method(path,name):
            c=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.ClassDef) and n.name==name)
            return next(n for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='bindings')
        original=method(old,'NativeBackend');current=method(Path(m.__file__),'EngineTransportBackend')
        original.body[1].value=ast.parse('self.engine_bundle(profile)',mode='eval').body
        namespace=next(n for n in original.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='namespace' for t in n.targets))
        namespace.value=ast.parse('self.engine_namespace(profile)',mode='eval').body
        self.assertEqual(ast.dump(original,include_attributes=False),ast.dump(current,include_attributes=False))

    def test_created_proc_reference_uses_same_docker_inode_without_relaxing_proc_ancestry(self):
        b,profile,p,_=self.fixture();canonical=Path('/run/docker/netns/ci-fixture')
        generation={'pid':1234,'startTicks':23,'namespaceInode':p.stat().st_ino}
        profile.update(namespaceOrigin='OCI_CREATED',namespacePath='/proc/1234/ns/net',namespaceInode=p.stat().st_ino)
        b.seal=m.digest(profile);b.namespace_generation=generation;b.namespace_reference=str(canonical)
        b.namespace_seal=m.digest([b.namespace_reference,generation]);before=copy.deepcopy(profile)
        with (patch.object(Path,'resolve',return_value=canonical),patch.object(Path,'lstat',return_value=p.stat()),
            patch.object(m,'_ancestors') as ancestors,patch.object(b,'generation',return_value=copy.deepcopy(generation)) as current):
            self.assertEqual(b.engine_namespace(profile),canonical)
            self.assertEqual(current.call_count,2);ancestors.assert_called_once_with(canonical)
        self.assertEqual(profile,before)
        profile['namespacePath']='/proc/4321/ns/net';b.seal=m.digest(profile)
        with patch.object(Path,'resolve',return_value=canonical),self.assertRaisesRegex(ValueError,'CREATED_PROCESS_NAMESPACE_REQUIRED'):
            b.engine_namespace(profile)
        profile['namespacePath']='/proc/1234/ns/net';b.seal=m.digest(profile)
        with (patch.object(Path,'resolve',return_value=canonical),patch.object(Path,'lstat',return_value=p.stat()),
            patch.object(m,'_ancestors'),patch.object(b,'generation',side_effect=[generation,{**generation,'startTicks':24}]),
            self.assertRaisesRegex(ValueError,'CHANGED_DURING_READ')):
            b.engine_namespace(profile)

if __name__=='__main__':unittest.main()
