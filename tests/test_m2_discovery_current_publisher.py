"""Real current parent crypto/protected files; gh verification leaf is modeled.

Tests the closed command/certificate policy/cache. They do not themselves
cryptographically authenticate the deliberately synthetic Sigstore bundles.
"""
import copy,hashlib,os,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_cohort as cohort
from tools.m2_discovery_installation_profile import current_publisher as m


def ref(path,maximum):
    return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'maximumBytes':maximum,
        'metadataHash':m.digest(m.attributes(path.lstat()))}


def response(row):
    identity='https://github.com/'+row['repository']+'/'+row['workflowPath']+'@'+row['sourceRef']
    return [{'verificationResult':{'signature':{'certificate':{'issuer':m.ISSUER,
        'subjectAlternativeName':{'type':'URI','value':identity},'sourceRepositoryURI':'https://github.com/'+row['repository'],
        'sourceRepositoryIdentifier':row['repositoryId'],'sourceRepositoryOwnerIdentifier':row['ownerId'],
        'sourceRepositoryOwnerURI':'https://github.com/'+row['repository'].split('/')[0],
        'sourceRepositoryDigest':row['sourceCommit'],'sourceRepositoryRef':row['sourceRef'],
        'buildSignerURI':identity,'buildSignerDigest':row['signerCommit'],'runnerEnvironment':'github-hosted'}},
        'verifiedTimestamps':[{'type':'Tlog','timestamp':'2026-10-31T00:00:00Z'}],
        'statement':{'_type':'https://in-toto.io/Statement/v1','predicateType':m.PREDICATE,
            'subject':[{'name':'fixture.bin','digest':{'sha256':row['subject']['sha256']}}],
            'predicate':{'userControlledValueIsNotAuthority':True}}}}]


class Publisher(unittest.TestCase):
    setUp=cohort.Cohort.setUp
    native=cohort.Cohort.native
    write=cohort.Cohort.write
    binding=cohort.Cohort.binding
    sign=cohort.Cohort.sign
    authority=cohort.Cohort.authority
    runtime_fixture=cohort.Cohort.owner

    def prepared(self,bad_bytes=False):
        runtime,_,_=self.runtime_fixture();subject=self.root/'fixture.bin';bundle=self.root/'bundle.json';root=self.root/'trusted-root.jsonl'
        for path,raw in ((subject,b'disposable artifact'),(bundle,b'{"syntheticSignature":true}'),(root,b'{"syntheticRoot":true}')):
            self.write(path,raw)
        sha=hashlib.sha256(subject.read_bytes()).hexdigest()
        if bad_bytes:subject.write_bytes(b'different current bytes')
        row={'role':'fixtureArtifact','subject':{**ref(subject,1048576),'sha256':sha},'bundle':ref(bundle,1048576),
            'repository':'GioNob/ouf-deploy','repositoryId':'1409074354','ownerId':'96419716',
            'workflowPath':'.github/workflows/m2-discovery-publisher-native.yml','sourceRef':'refs/heads/fixture',
            'sourceCommit':'1'*40,'signerCommit':'1'*40}
        inputs={k:runtime.inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        executable=Path('/usr/bin/true').resolve()
        inputs.update(schema=m.SCHEMA,ghExecutable=ref(executable,134217728),trustedRoot=ref(root,1048576),artifacts=[row])
        bound=m.bind_publisher_inputs(runtime.inputs,inputs);review=copy.deepcopy(self.review)
        review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        self.review=cohort.m.bind_runtime_review(review,bound);parent=self.authority(seconds=300)
        return m.CurrentPublisherCustody(parent,bound,inputs),row,parent

    def gh_fixture(self,reader,body,version=b'gh version 2.97.0 (fixture)\n'):
        native=m.subprocess.run;calls=[]
        def run(args,**kwargs):
            if args[0]!=reader.inputs['ghExecutable']['path']:return native(args,**kwargs)
            calls.append((args,kwargs))
            return SimpleNamespace(returncode=0,stdout=version if args[1:]==['--version'] else m.encoded(body))
        return run,calls

    def test_current_protected_files_and_exact_offline_certificate_policy_are_cached_only_while_unchanged(self):
        reader,row,_=self.prepared();run,calls=self.gh_fixture(reader,response(row))
        with patch.object(m.subprocess,'run',side_effect=run):
            first=reader.observe();second=reader.observe()
        self.assertEqual(first,second);self.assertEqual(len(calls),2)
        args,kwargs=calls[1];self.assertEqual(args[1:3],['attestation','verify'])
        for flag in ('--bundle','--custom-trusted-root','--cert-identity','--source-digest','--source-ref','--signer-digest','--deny-self-hosted-runners'):
            self.assertIn(flag,args)
        self.assertNotIn('--signer-workflow',args) # mutually exclusive with exact SAN in the pinned CLI
        self.assertFalse(set(kwargs['env'])&{'GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','HTTPS_PROXY'})
        self.assertTrue(first['selectedArtifactPublisherCryptographyVerified'])
        self.assertFalse(first['targetOciOrMigrationArtifactMembershipProvenHere']);self.assertFalse(first['fullCohortProven'])

    def test_cli_success_cannot_override_wrong_exact_certificate_identity_or_repository_ids(self):
        reader,row,_=self.prepared()
        for key,value in [('sourceRepositoryIdentifier','1'),('sourceRepositoryOwnerIdentifier','1'),('issuer','https://elsewhere.invalid'),
            ('sourceRepositoryDigest','2'*40),('buildSignerDigest','2'*40),('runnerEnvironment','self-hosted')]:
            body=response(row);body[0]['verificationResult']['signature']['certificate'][key]=value
            run,_=self.gh_fixture(reader,body)
            with self.subTest(key=key),patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'CERTIFICATE_IDENTITY'):
                reader.observe()
            self.assertIsNone(reader.cache)

    def test_workflow_lookalike_and_predicate_claim_cannot_replace_certificate_scope(self):
        reader,row,_=self.prepared();body=response(row);value=body[0]['verificationResult']
        value['signature']['certificate']['subjectAlternativeName']['value']=value['signature']['certificate']['subjectAlternativeName']['value'].replace('ouf-deploy','oufXdeploy')
        value['statement']['predicate'].update(trusted=True,repository=row['repository'])
        run,_=self.gh_fixture(reader,body)
        with patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'CERTIFICATE_IDENTITY'):reader.observe()

    def test_verified_subject_digest_and_witnessed_timestamp_are_required(self):
        reader,row,_=self.prepared()
        for change,reason in [(lambda v:v.update(verifiedTimestamps=[]),'WITNESSED_SLSA'),
            (lambda v:v['statement'].update(subject=[{'digest':{'sha256':'f'*64}}]),'SUBJECT_DIGEST_MISMATCH')]:
            body=response(row);change(body[0]['verificationResult']);run,_=self.gh_fixture(reader,body)
            with patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,reason):reader.observe()

    def test_changed_artifact_or_cache_denies_without_rerunning_a_mutating_action(self):
        reader,row,_=self.prepared();run,calls=self.gh_fixture(reader,response(row))
        with patch.object(m.subprocess,'run',side_effect=run):reader.observe()
        path=Path(row['subject']['path']);path.chmod(0o400)
        with patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'FILE_CUSTODY_CHANGED'):reader.observe()
        self.assertEqual(len(calls),2);self.assertEqual(path.stat().st_mode&0o777,0o400)

    def test_bad_current_file_bytes_are_denied_before_gh_is_executed(self):
        reader,row,_=self.prepared(bad_bytes=True);run,calls=self.gh_fixture(reader,response(row))
        with patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'FILE_BYTES_CHANGED'):reader.observe()
        self.assertEqual(calls,[])

    def test_old_gh_or_revoked_parent_has_no_positive_publisher_receipt(self):
        reader,row,parent=self.prepared();run,calls=self.gh_fixture(reader,response(row),version=b'gh version 2.96.0\n')
        with patch.object(m.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'PATCHED_GH'):reader.observe()
        self.assertEqual(len(calls),1)
        (self.signatures/(parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink();calls.clear()
        with patch.object(m.subprocess,'run',side_effect=run),self.assertRaises((ValueError,OSError)):reader.observe()
        self.assertEqual(calls,[])

    def test_new_review_is_required_for_any_changed_publisher_input(self):
        reader,*_=self.prepared();bad=copy.deepcopy(reader.inputs);bad['artifacts'][0]['repositoryId']='1'
        with self.assertRaisesRegex(ValueError,'CANNOT_BE_REPLACED'):m.bind_publisher_inputs(reader.runtime_inputs,bad)
        reader.inputs=bad
        with self.assertRaises(ValueError):reader.guard()

if __name__=='__main__':unittest.main()
