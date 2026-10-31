"""Offline exact parent components; real files/crypto fixtures, no target admission."""
import copy,hashlib,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_private_review as cohort_fixture
import test_m2_provider_profiles as provider_fixture
from test_m2_discovery_native_profile import fixture as registry_fixture
from fixtures.m2_admitted_provider_sealed_worker_native import review as worker_review
from tools.m2_discovery_installation_profile import infrastructure_review as m,provider_profiles
from tools.m2_discovery_installation_profile import infrastructure_review_capsule as capsule
from tools.m2_discovery_installation_profile.frame_inputs import compile_inputs,ENGINE
from tools.m2_discovery_installation_profile.parent_authority import review_scope


class InfrastructureReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cohort_fixture.PrivateReview.setUpClass()
        cls.baseline=cohort_fixture.PrivateReview.baseline
        cls.raw,cls.manifest=capsule.build(ROOT,'b'*40)
    @classmethod
    def tearDownClass(cls):cohort_fixture.PrivateReview.tearDownClass()
    def fixture(self):
        cohort=cohort_fixture.PrivateReview().fixture();reg=cohort['registry']
        profile=m.DiscoveryProfile(reg['request'],**reg['selection'])
        t,l=compile_inputs(self.baseline,reg['request'],execution_profile=profile,engine_profile=ENGINE)
        case=provider_fixture.Profiles();self.addCleanup(case.doCleanups)
        issuer,window,auth,state,calls,opts,*_=case.fixture(
            definition=(reg['request'],reg['selection'],t,l,registry_fixture()[4]),gate_seconds=300)
        cohort.update(sourceClosureHash=issuer.template['sourceClosureHash'],
            installationInputsHash=auth.review['installationInputsHash'],desiredProfileHash=auth.review['desiredProfileHash'])
        root=auth.root/'infrastructure-review';root.mkdir(mode=0o700)
        kernel=root/'kernel';kernel.mkdir(mode=0o700);lock=kernel/'common.lock';auth.write(lock,b'')
        prep=opts['preparer_template'];prep['lockFile']=str(lock)
        prep['coordinationBinding']['configurationHash']=m.digest(prep['kernel'])
        scoped=provider_profiles.profile_scope(issuer.template,issuer.creation.scope,**opts,
            maximum_seconds=300,handoff_window=copy.deepcopy(provider_profiles.FULL_HANDOFF_WINDOW))
        worker,setup=worker_review(auth,root,issuer.template,scoped,reg['request']);dirs=setup['dirs']
        info=lock.stat();inode=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns]
        inputs={'schema':m.SCHEMA,'cohortInputs':cohort,
            'gate':{'journalDirectory':window.scope['journalDirectory'],'maximumSeconds':300},
            'provider':{'template':issuer.template,'profile':scoped,
                'creationJournalDirectory':issuer.creation.scope['journalDirectory'],
                'runtime':{'wrapperBinding':{'path':'/usr/local/sbin/ouf-infrastructure-review-test','sha256':'a'*64},
                    'commonLockIdentity':inode,'nativeReadSeconds':5},
                'sequenceJournalDirectory':str(auth.root/'provider-review-sequence')},
            'worker':{'template':worker,'start':{k:setup['start'][k] for k in ('unitName','manager','journalDirectory')},
                'publicationDirectory':str(dirs['publication']),
                'registration':{'unitDirectory':'/etc/systemd/system','journalDirectory':str(dirs['registration'])},
                'issuance':{'directory':str(dirs['issuance']),'signatureDirectory':str(dirs['signatures']),
                    'observationRoot':str(dirs['observations']),'keyBinding':scoped['keys']['attestor'],
                    'keyRef':scoped['keyRefs']['attestor']},'sequenceDirectory':str(dirs['sequence'])},
            'context':auth.context}
        return m.decode(m.encoded(inputs)),auth,calls
    def compile(self,inputs):return m.assemble(inputs,m.digest(inputs),self.baseline)
    def files(self):
        inputs,auth,calls=self.fixture();root=auth.root/'private-infrastructure-output';root.mkdir(mode=0o700)
        source=auth.root/'private-infrastructure-input.json';auth.write(source,m.encoded(inputs))
        return inputs,source,root,auth

    def test_three_exact_components_are_deterministic_and_not_authority(self):
        inputs,auth,calls=self.fixture();before=copy.deepcopy(inputs);a=self.compile(inputs)
        self.assertEqual(a,self.compile(inputs));self.assertEqual(inputs,before)
        self.assertEqual(set(a['parts']),{'registryGatePeerWindow','providerInstallation','operationalLeaseInstallation'})
        for key in ('completeParentReview','inputsAuthenticated','nativeAcceptancesProven','runtimeAuthorityIssued',
            'targetApplyAuthorized','automaticReplayAllowed','budgetReset','applicationE2EProven','releaseAcceptance'):
            self.assertIs(a[key],False)
        self.assertEqual(a['signaturesIssued'],0)
        with self.assertRaises(ValueError):review_scope(a)
        # Existing real dual-role authentication guards accept the exact parts;
        # other parent components remain explicitly modeled fixture values.
        auth.review['components'].update(a['parts']);parent=auth.fixture()
        for key,value in a['parts'].items():self.assertTrue(parent.guard(key,value))
        self.assertFalse(calls)

    def test_assembly_has_no_content_reads_commands_signatures_engine_or_owner_effects(self):
        inputs,_,calls=self.fixture()
        from contextlib import ExitStack
        from engine_creation import Engine
        from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
        with ExitStack() as stack:
            for obj,name in ((Path,'read_bytes'),(Path,'read_text'),(Path,'open'),(subprocess,'run'),
                (Engine,'request'),(ExistingEd25519Signer,'sign'),(m,'directory'),(m,'new_file')):
                stack.enter_context(patch.object(obj,name,side_effect=AssertionError('OFFLINE_REVIEW_MUST_BE_PURE')))
            self.compile(inputs)
        self.assertFalse(calls)

    def test_same_parent_frame_source_and_profile_bindings_are_required(self):
        inputs,_,_=self.fixture()
        mutations=[lambda v:v['cohortInputs'].__setitem__('sourceClosureHash','f'*64),
            lambda v:v['cohortInputs'].__setitem__('installationInputsHash','f'*64),
            lambda v:v['cohortInputs'].__setitem__('desiredProfileHash','f'*64),
            lambda v:v['context'].__setitem__('attestorRef','different-attestor'),
            lambda v:v['cohortInputs']['registry']['contextTemplate'].__setitem__('storageParent','/different/storage'),
            lambda v:v['gate'].__setitem__('maximumSeconds',301),
            lambda v:v['provider']['profile'].__setitem__('schema',provider_profiles.PROFILE_V1),
            lambda v:v['worker']['issuance'].__setitem__('keyRef','different-key'),
            lambda v:v['worker']['issuance']['keyBinding'].__setitem__('sha256','f'*64)]
        for mutate in mutations:
            v=copy.deepcopy(inputs);mutate(v)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.compile(v)

    def test_worker_native_configuration_and_unmaterialized_lock_are_bound(self):
        inputs,_,_=self.fixture()
        for case in ('kernel','dns','coordination','lock','nativeLock','generation','logicalLock','trust','providerKey'):
            v=copy.deepcopy(inputs);w=v['worker']['template'];r=w['recipeTemplate'];c=w['configurationTemplate']
            if case=='kernel':r['kernel']['tableName']='different_table'
            elif case=='dns':r['dns']['timeoutSeconds']=2
            elif case=='coordination':r['binding']['transactionId']='f'*64
            elif case=='lock':r['leaseCommonLockIdentity'][1]+=1
            elif case=='nativeLock':v['provider']['runtime']['commonLockIdentity'][6]=1
            elif case=='generation':r['scope']['generationRef']='f'*64
            elif case=='logicalLock':c['commonLockIdentity']=[1,2,0,0,stat.S_IFREG|0o600,1]
            elif case=='trust':c['verification']['trustPolicy']['sha256']='f'*64
            else:w['signingKeyPaths']=[]
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(v)

    def test_all_cohort_and_infrastructure_roots_are_nonshadowing(self):
        inputs,_,_=self.fixture()
        for case in ('cohort','parent','key','source','providerLedger'):
            v=copy.deepcopy(inputs)
            if case=='cohort':path=v['cohortInputs']['gateway']['journalDirectory']+'/nested'
            elif case=='parent':path=str(Path(v['worker']['publicationDirectory']).parent)
            elif case=='key':path=v['provider']['profile']['keys']['installer']['path']
            elif case=='source':path=v['provider']['profile']['sourceRoot']+'/nested'
            else:path=v['provider']['profile']['preparerTemplate']['coordinationJournal']
            v['provider']['sequenceJournalDirectory']=path
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(v)

    def test_public_receipt_contains_only_hashes_counts_and_denials(self):
        inputs,auth,_=self.fixture();public=json.dumps(m.receipt(self.compile(inputs)))
        for private in (str(auth.key),auth.context['entityRef'],inputs['worker']['start']['unitName'],str(auth.root)):
            self.assertNotIn(private,public)

    def test_private_publication_inspection_never_overwrites_or_resets(self):
        inputs,source,out,_=self.files();h=m.digest(inputs);first=m.prepare(str(source),h,str(out),self.baseline)
        before={p.name:(p.read_bytes(),p.stat().st_ino) for p in out.iterdir()}
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in out.iterdir()))
        self.assertEqual(first,m.prepare(str(source),h,str(out),self.baseline,inspect=True))
        with self.assertRaises(ValueError):m.prepare(str(source),h,str(out),self.baseline)
        self.assertEqual(before,{p.name:(p.read_bytes(),p.stat().st_ino) for p in out.iterdir()})

    def test_partial_publication_never_resumes(self):
        inputs,source,out,_=self.files();original=m.new_file
        def fail(fd,name,raw):
            if name=='assembly.private.json':raise OSError('PRIVATE_SENTINEL')
            return original(fd,name,raw)
        with patch.object(m,'new_file',side_effect=fail),self.assertRaises(OSError):
            m.prepare(str(source),m.digest(inputs),str(out),self.baseline)
        before={p.name:p.read_bytes() for p in out.iterdir()}
        for inspect in (False,True):
            with self.assertRaises((ValueError,OSError)):
                m.prepare(str(source),m.digest(inputs),str(out),self.baseline,inspect=inspect)
        self.assertEqual(before,{p.name:p.read_bytes() for p in out.iterdir()})

    def test_hash_mode_symlink_output_shadow_and_input_drift_do_not_complete(self):
        inputs,source,out,_=self.files();h=m.digest(inputs)
        for case in ('hash','mode','symlink','shadow'):
            selected=source;dest=out;expected=h
            if case=='hash':expected='f'*64
            elif case=='mode':source.chmod(0o644)
            elif case=='symlink':selected=source.with_name('alias');selected.symlink_to(source)
            else:dest=Path(inputs['provider']['profile']['sourceRoot'])
            with self.subTest(case=case),self.assertRaises((ValueError,RuntimeError,OSError)):
                m.prepare(str(selected),expected,str(dest),self.baseline)
            source.chmod(0o600);self.assertFalse((dest/'preparation.claim.json').exists())
        original=m.new_file
        def drift(fd,name,raw):
            original(fd,name,raw)
            if name=='assembly.private.json':source.write_text('{}');source.chmod(0o600)
        with patch.object(m,'new_file',side_effect=drift),self.assertRaises(ValueError):
            m.prepare(str(source),h,str(out),self.baseline)
        self.assertEqual(set(p.name for p in out.iterdir()),{'preparation.claim.json','assembly.private.json'})

    def test_sealed_cli_prepares_then_inspects_without_repository_imports(self):
        inputs,source,out,_=self.files();program=source.parent/'infrastructure-compiler.py';program.write_bytes(self.raw)
        args=[sys.executable,'-I','-B','-S',str(program),'prepare','--input',str(source),
            '--input-sha256',m.digest(inputs),'--output-directory',str(out)]
        run=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,(run.stdout,run.stderr));self.assertEqual(run.stderr,b'')
        public=json.loads(run.stdout);self.assertEqual(public['parentComponentCount'],3)
        self.assertFalse(public['completeParentReview']);self.assertNotIn(str(source),run.stdout.decode())
        saved={p.name:p.read_bytes() for p in out.iterdir()};args[5]='inspect'
        read=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(read.returncode,0,(read.stdout,read.stderr));self.assertEqual(read.stdout,run.stdout)
        self.assertEqual(saved,{p.name:p.read_bytes() for p in out.iterdir()})

    def test_cli_denies_tampered_payload_missing_isolation_and_private_argument_echo(self):
        inputs,source,out,_=self.files();program=source.parent/'infrastructure-compiler.py'
        for case in ('payload','isolation','arguments'):
            raw=self.raw.replace(b"PAYLOAD='",b"PAYLOAD='!",1) if case=='payload' else self.raw
            program.write_bytes(raw)
            args=[sys.executable]+(['-I','-B','-S'] if case!='isolation' else [])+[str(program),'prepare',
                '--input',str(source),'--input-sha256',m.digest(inputs),'--output-directory',str(out)]
            if case=='arguments':args+=['--PRIVATE_SENTINEL='+str(source)]
            run=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(run.returncode,1);self.assertEqual(run.stderr,b'')
            self.assertNotIn(str(source),run.stdout.decode());self.assertNotIn('PRIVATE_SENTINEL',run.stdout.decode())
            self.assertFalse((out/'preparation.claim.json').exists())

    def test_changed_revision_or_loader_cannot_adopt_completed_private_output(self):
        inputs,source,out,_=self.files();program=source.parent/'infrastructure-compiler.py';program.write_bytes(self.raw)
        args=[sys.executable,'-I','-B','-S',str(program),'prepare','--input',str(source),
            '--input-sha256',m.digest(inputs),'--output-directory',str(out)]
        self.assertEqual(subprocess.run(args,stdout=subprocess.PIPE,timeout=30).returncode,0)
        saved={p.name:p.read_bytes() for p in out.iterdir()}
        for case in ('revision','loader'):
            if case=='revision':other,_=capsule.build(ROOT,'c'*40)
            else:
                alternate=capsule.RUNTIME+'\n'
                with patch.object(capsule,'RUNTIME',alternate),patch.object(capsule,'LOADER_HASH',hashlib.sha256(alternate.encode()).hexdigest()):
                    other,_=capsule.build(ROOT,'b'*40)
            program.write_bytes(other);args[5]='inspect'
            run=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(run.returncode,1);self.assertEqual(run.stderr,b'')
            self.assertEqual(saved,{p.name:p.read_bytes() for p in out.iterdir()})

    def test_packager_rejects_matching_source_and_map_drift_or_changed_loader(self):
        for changed_map in (False,True):
            t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup);alternate=Path(t.name)
            pins=json.loads((ROOT/capsule.SOURCE_MANIFEST).read_bytes())
            for relative in {v['path'] for v in pins.values()}|{capsule.SOURCE_MANIFEST,capsule.BASELINE}:
                p=alternate/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/relative).read_bytes())
            p=alternate/'tools/m2_discovery_installation_profile/infrastructure_review.py';p.write_bytes(p.read_bytes()+b'\n')
            if changed_map:
                pins[capsule.ENTRY]['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
                (alternate/capsule.SOURCE_MANIFEST).write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
            with self.assertRaisesRegex(ValueError,'SOURCE_REQUIRED'):capsule.build(alternate,'b'*40)
        with patch.object(capsule,'RUNTIME',capsule.RUNTIME+'\n'),self.assertRaisesRegex(ValueError,'SOURCE_REQUIRED'):
            capsule.build(ROOT,'b'*40)

    def test_input_schema_and_hash_and_gate_ceiling_cannot_be_bypassed(self):
        inputs,_,_=self.fixture()
        for case in ('extra','schema','hash','gate'):
            v=copy.deepcopy(inputs);h=None
            if case=='extra':v['nativeAdmissionAccepted']=True
            elif case=='schema':v['schema']='ouf.discovery-parent-installation-review.v1'
            elif case=='gate':v['gate']['maximumSeconds']=299
            else:h='f'*64
            with self.subTest(case=case),self.assertRaises(ValueError):m.assemble(v,h or m.digest(v),self.baseline)

    def test_tampered_private_output_is_preserved_and_inspection_denies(self):
        inputs,source,out,_=self.files();h=m.digest(inputs);m.prepare(str(source),h,str(out),self.baseline)
        p=out/'assembly.private.json';p.write_text('{}');p.chmod(0o600)
        with self.assertRaises(ValueError):m.prepare(str(source),h,str(out),self.baseline,inspect=True)
        self.assertEqual(p.read_text(),'{}')

if __name__=='__main__':unittest.main()
