"""All six review parts, real cryptographic guards, modeled native baselines."""
import base64,copy,hashlib,json,os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_infrastructure_review as infra_fixture
import test_m2_discovery_publication_review as pub_fixture
from tools.m2_discovery_installation_profile import parent_review as m,private_review,parent_review_capsule as capsule
from tools.m2_discovery_installation_profile.publication_primitives import PublicationPrimitives
from tools.chatbot_file_cohort.authorization import DISCOVERY_CATALOGUE
from cutover_authority import CutoverAuthority


class ParentReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        infra_fixture.InfrastructureReview.setUpClass();cls.baseline=infra_fixture.InfrastructureReview.baseline
        cls.primitives=PublicationPrimitives.from_directories(os.environ['OUF_PUBLICATION_GATEWAY_ROOT'],
            os.environ['OUF_REVISION_ONBOARDING_ROOT'],ROOT/DISCOVERY_CATALOGUE)
        cls.capsule,cls.manifest=capsule.build(ROOT,'b'*40,os.environ['OUF_PUBLICATION_GATEWAY_ROOT'],
            os.environ['OUF_REVISION_ONBOARDING_ROOT'])
    @classmethod
    def tearDownClass(cls):infra_fixture.InfrastructureReview.tearDownClass()
    def fixture(self):
        publication,cohort=pub_fixture.PublicationReview().fixture()
        case=infra_fixture.InfrastructureReview();self.addCleanup(case.doCleanups)
        with patch.object(infra_fixture.cohort_fixture.PrivateReview,'fixture',return_value=cohort):
            infrastructure,auth,calls=case.fixture()
        cohort=infrastructure['cohortInputs'];publication['cohortInputsHash']=m.digest(cohort)
        base=private_review.assemble(cohort,m.digest(cohort),self.baseline)
        child,raw=auth.child(creation_request_hash=m.digest(cohort['registry']['request']))
        body=m.decode(raw);body.update(m.runtime_sections(base['cohortReviewFragment']));raw=m.encoded(body)
        human=m.decode(Path(child.binding['path']).read_bytes());human['executionAuthorityHash']=hashlib.sha256(raw).hexdigest()
        auth.write(Path(child.binding['path']),m.encoded(human));binding=auth.binding(Path(child.binding['path']))
        child=CutoverAuthority(auth.verifier,binding,binding['sha256'],auth.context,child.expected,lambda:auth.now)
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):auth.sign(raw,role)
        inputs={'schema':m.SCHEMA,'infrastructureInputs':infrastructure,'publicationInputs':publication,
            'registryChild':{'authorityBase64':base64.b64encode(raw).decode(),'humanManifestBinding':binding,
                'expected':child.expected}}
        return inputs,auth,calls,child,raw
    def compile(self,i):return m.assemble(i,m.digest(i),self.baseline,self.primitives)

    def test_all_six_review_parts_are_recompiled_deterministically(self):
        i,*_=self.fixture();before=copy.deepcopy(i);a=self.compile(i)
        self.assertEqual(a,self.compile(i));self.assertEqual(i,before)
        self.assertEqual(set(a['review']['components']),{'registryCutover','providerInstallation',
            'registryGatePeerWindow','operationalLeaseInstallation','cohortInstallation','capabilityPublication'})
        self.assertEqual(a['scope'],m.review_scope(a['review']))
        self.assertTrue(a['completeParentReviewShape'])
        for k in ('inputsAuthenticated','currentNativeAdmissionProven','publicationExecutorIntegrated',
            'runtimeAuthorityIssued','targetApplyAuthorized','capabilitiesPublished','applicationE2EProven','releaseAcceptance'):
            self.assertIs(a[k],False)

    def test_actual_parent_and_child_guards_accept_the_exact_prepared_scopes(self):
        i,auth,calls,child,raw=self.fixture();a=self.compile(i)
        auth.review=copy.deepcopy(a['review']);parent=auth.fixture()
        for name,scope in a['review']['components'].items():self.assertTrue(parent.guard(name,scope))
        self.assertTrue(parent.registry_child(child,raw));self.assertFalse(calls)

    def test_expired_declared_child_does_not_gain_current_authority_through_review(self):
        i,auth,calls,child,raw=self.fixture();a=self.compile(i)
        auth.review=copy.deepcopy(a['review']);parent=auth.fixture();auth.now+=301
        with self.assertRaisesRegex(ValueError,'CURRENT_EXPLICIT_DISCOVERY'):parent.registry_child(child,raw)
        self.assertFalse(calls)

    def test_wrong_source_history_human_hash_or_runtime_scope_is_denied(self):
        for key in ('sourceClosureHash','predecessorHistoryHash','human','runtime','extra','worker','phases','time'):
            i,*_=self.fixture();c=i['registryChild'];body=m.decode(base64.b64decode(c['authorityBase64']))
            if key in ('sourceClosureHash','predecessorHistoryHash'):c['expected'][key]='f'*64
            elif key=='human':c['humanManifestBinding']['sha256']='not-a-sha'
            elif key=='runtime':body['discoveryMcpInstallation']['planHash']='f'*64
            elif key=='extra':body['arbitraryPermission']=True
            elif key=='worker':body['newDistinctLeaseWorkerRequired']=False
            elif key=='phases':body['phaseIntentHashes'].pop('RELEASE_PRODUCERS')
            else:body['expiresAt']=body['issuedAt']+3601
            c['authorityBase64']=base64.b64encode(m.encoded(body)).decode()
            with self.subTest(key=key),self.assertRaises(ValueError):self.compile(i)

    def test_thirteen_original_child_bytes_are_hashed_without_projection(self):
        i,*_=self.fixture();raw=base64.b64decode(i['registryChild']['authorityBase64'])
        # Whitespace is still part of the signed bytes. No parsing and
        # reserialization may silently change the child reviewed by the parent.
        raw=b' '+raw+b'\n';i['registryChild']['authorityBase64']=base64.b64encode(raw).decode()
        a=self.compile(i)
        self.assertEqual(a['review']['components']['registryCutover']['authorityHash'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(a['registryChildReview']['authorityBase64'],i['registryChild']['authorityBase64'])

    def test_publication_roots_cannot_shadow_provider_worker_or_human_custody(self):
        for case in ('provider','worker','human'):
            i,*_=self.fixture();inf=i['infrastructureInputs']
            path={'provider':inf['provider']['sequenceJournalDirectory'],
                'worker':inf['worker']['sequenceDirectory'],'human':i['registryChild']['humanManifestBinding']['path']}[case]
            i['publicationInputs']['journalDirectories']['gateway']=path
            with self.subTest(case=case),self.assertRaisesRegex(ValueError,'SHADOW'):self.compile(i)

    def test_public_receipt_contains_only_hashes_and_explicit_unproven_flags(self):
        i,*_=self.fixture();a=self.compile(i);r=m.receipt(a);raw=m.encoded(r)
        self.assertEqual(len(r['componentScopeHashes']),6)
        self.assertNotIn(b'/workspace/',raw);self.assertNotIn(b'KeyEnvironment',raw)
        self.assertNotIn(b'private',raw);self.assertFalse(r['inputsAuthenticated'])
        self.assertFalse(r['targetApplyAuthorized']);self.assertFalse(r['publicationExecutorIntegrated'])

    def test_modelled_current_requirements_cannot_be_reported_as_native_acceptance(self):
        i,*_=self.fixture();a=self.compile(i)
        current=a['review']['components']['cohortInstallation']['currentAdmission']
        self.assertEqual(current['requiredProofs'],m.REQUIRED_PROOFS)
        self.assertTrue(current['mustBeCurrentAtExecution']);self.assertFalse(current['historicalEvidenceSufficient'])
        self.assertFalse(a['currentNativeAdmissionProven'])

    def files(self):
        i,auth,*_=self.fixture();source=auth.root/'parent-review-input.private.json';auth.write(source,m.encoded(i))
        out=auth.root/'review-output';out.mkdir(mode=0o700);return i,auth,source,out

    def test_private_prepare_and_read_only_inspect_preserve_exact_output_and_never_replay(self):
        i,auth,source,out=self.files()
        expected=m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        pins={p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()}
        self.assertEqual(expected,m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives,inspect=True))
        with self.assertRaisesRegex(ValueError,'NO_REPLAY'):
            m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        self.assertEqual(pins,{p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()})

    def test_partial_publication_is_preserved_and_never_completed_by_inspection(self):
        i,auth,source,out=self.files();real=m.new_file
        def fail(fd,name,raw):
            if name=='receipt.json':raise OSError('injected lost completion')
            return real(fd,name,raw)
        with patch.object(m,'new_file',side_effect=fail),self.assertRaises(OSError):
            m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        pins={p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()}
        for inspect in (False,True):
            with self.assertRaises(ValueError):m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives,inspect=inspect)
        self.assertEqual(pins,{p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()})

    def test_sealed_cli_uses_only_its_closed_sources_and_embedded_public_helpers(self):
        i,auth,source,out=self.files();exe=auth.root/'compiler.py';auth.write(exe,self.capsule)
        args=[sys.executable,'-I','-B','-S',str(exe),'prepare','--input',str(source),
            '--input-sha256',m.digest(i),'--output-directory',str(out)]
        result=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        receipt=json.loads(result.stdout);self.assertTrue(receipt['completeParentReviewShape'])
        self.assertFalse(receipt['inputsAuthenticated']);self.assertFalse(receipt['targetApplyAuthorized'])
        args[5]='inspect';again=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(again.returncode,0,again.stdout.decode()+again.stderr.decode())
        self.assertEqual(result.stdout,again.stdout)

    def test_capsule_payload_drift_and_missing_isolation_fail_without_private_details(self):
        i,auth,source,out=self.files();exe=auth.root/'compiler.py';auth.write(exe,self.capsule)
        args=[sys.executable,'-B','-S',str(exe),'prepare','--input',str(source),
            '--input-sha256',m.digest(i),'--output-directory',str(out)]
        result=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,1);self.assertFalse(list(out.iterdir()))
        self.assertNotIn(str(source).encode(),result.stdout+result.stderr)
        tampered=self.capsule.replace(self.manifest['payloadSha256'].encode(),b'0'*64)
        auth.write(exe,tampered);args.insert(1,'-I')
        result=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,1);self.assertFalse(list(out.iterdir()))
        self.assertNotIn(str(source).encode(),result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
