"""Real six-part compilers/parent crypto; declared native inputs are fixtures.

No current native observation, private-input authentication or target run.
"""
import base64,copy,json,os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_parent_review as parent_fixture
import test_m2_discovery_current_cohort as cohort_fixture
from tools.m2_discovery_installation_profile import current_review as m
from tools.m2_discovery_installation_profile import current_review_capsule as capsule


class CurrentReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent_fixture.ParentReview.setUpClass()
        cls.baseline=parent_fixture.ParentReview.baseline;cls.primitives=parent_fixture.ParentReview.primitives
        cls.capsule,cls.manifest=capsule.build(ROOT,'b'*40,os.environ['OUF_PUBLICATION_GATEWAY_ROOT'],
            os.environ['OUF_REVISION_ONBOARDING_ROOT'])
    @classmethod
    def tearDownClass(cls):parent_fixture.ParentReview.tearDownClass()

    def fixture(self):
        case=parent_fixture.ParentReview();self.addCleanup(case.doCleanups)
        parent,auth,calls,child,raw=case.fixture();declared=parent['infrastructureInputs']['cohortInputs']
        selection=parent['publicationInputs']['authorization']['selection'];refs=declared['registry']['selection']['references']
        selection['realm']=m.urlsplit(refs['OUF_IAM_ISSUER']).path.removeprefix('/realms/')
        runtime=cohort_fixture.fixture();runtime.update({k:declared[k] for k in m.COMMON})
        runtime['peers']['keycloak']['runtimeBinding']['containerId']=selection['keycloakContainer']
        for role,binding in (('mcp',m.current_databases.Engine.runtime_binding(declared['mcp']['old'])),
            ('apisix',declared['gateway']['plan']['oldRuntimeBinding'])):
            runtime['peers'][role]['runtimeBinding']=copy.deepcopy(binding)
            runtime['peers'][role]['processPin']=cohort_fixture.pin(binding['pid'])
        common={k:declared[k] for k in m.COMMON};docker=copy.deepcopy(selection['docker'])
        ref=lambda path:{'path':path,'sha256':'b'*64,'metadataHash':'c'*64,'maximumBytes':1048576}
        rows=[]
        for index,module in enumerate(m.current_databases.MODULES,1):
            root='/review/'+module+('.jar' if module!='mcp' else '')
            rows.append({'module':module,'database':'fixture_'+module,'user':'fixture_'+module,'databaseOid':index,
                'expectedMigrations':[{'fixture':True}],
                'artifact':{'format':'JAR' if module!='mcp' else 'MCP_SQL','root':root,
                    'files':[{'path':root if module!='mcp' else root+'/internal/adapter/postgres/migrations/001_fixture.sql',
                        'sha256':'d'*64,'maximumBytes':1048576}]}})
        profile=m.DiscoveryProfile(declared['registry']['request'],**declared['registry']['selection'])
        additions={
            'databases':{**common,'schema':m.current_databases.SCHEMA,'dockerBinding':docker,
                'postgresRuntimeBinding':runtime['peers']['postgres']['runtimeBinding'],'modules':rows},
            'custody':{**common,'schema':m.current_publisher.SCHEMA,'ghExecutable':ref('/review/gh'),
                'trustedRoot':ref('/review/trusted-root.jsonl'),'artifacts':[{'role':'fixtureArtifact',
                    'subject':ref('/review/subject'),'bundle':ref('/review/bundle'),'repository':'GioNob/ouf-deploy',
                    'repositoryId':'1409074354','ownerId':'96419716','workflowPath':'.github/workflows/fixture.yml',
                    'sourceRef':'refs/heads/fixture','sourceCommit':'1'*40,'signerCommit':'1'*40}]},
            'tlsIam':{**common,'schema':m.current_tls.SCHEMA,'executionProfileHash':profile.sha256,
                'trustStoreBindingHash':m.digest(declared['registry']['selection']['files']['tlsTrustStore']),
                'caFiles':{r:{'path':'/review/'+r+'.pem','sha256':'b'*64,'maximumBytes':1048576} for r in ('iam','provider')},
                'endpoints':{r:{'peerRole':'caddy' if r=='iam' else 'provider','network':'ouf-backend','port':443,
                    'serverName':r+'.fixture.invalid'} for r in ('iam','provider')}},
            'iamWorkload':{**common,'schema':m.current_iam_workload.SCHEMA,'executionProfileHash':profile.sha256,
                'dockerBinding':docker,'keycloakRuntimeBinding':runtime['peers']['keycloak']['runtimeBinding'],
                'realm':selection['realm'],'clientUuid':'11111111-1111-4111-8111-111111111111',
                'serviceAccountUuid':'22222222-2222-4222-8222-222222222222','expectedScopes':[refs['OUF_SCHEMA_GOV_WORKLOAD_SCOPE']],
                'expectedAudiences':[refs['OUF_IAM_AUDIENCE']],'readOnlyAdmin':{'schema':m.current_iam_workload.readonly_iam_admin.SCHEMA,
                    'python':{'path':'/usr/bin/python3','sha256':'e'*64,'maximumBytes':67108864},
                    'sessionFile':{'containerPath':'/opt/keycloak/.keycloak/kcadm.config','sha256':'1'*64,
                        'metadataHash':'2'*64,'maximumBytes':262144},
                    'sessionServer':'http://localhost:8080','adminRealm':'master','port':8080}},
            'retirementAndBackup':{**common,'schema':m.current_retirement.SCHEMA,
                'retirement':{'mode':m.current_retirement.MODE,'scopeHash':'1'*64,'expectedFinalStateHash':'2'*64,
                    'existingMarkerSha256':'3'*64},'backupIntentHash':m.decode(raw)['phaseIntentHashes']['FENCED_BACKUP']}}
        inputs={'schema':m.SCHEMA,'parentInputs':parent,'runtimeInputs':runtime,'additionalInputs':additions}
        return m.decode(m.encoded(inputs)),auth,calls,child,raw

    def compile(self,i):return m.assemble(i,m.digest(i),self.baseline,self.primitives)

    def test_all_five_current_inputs_bind_one_new_parent_without_mutating_any_input(self):
        i,*_=self.fixture();before=copy.deepcopy(i);a=self.compile(i)
        self.assertEqual(a,self.compile(i));self.assertEqual(i,before)
        self.assertEqual(set(a['runtimeInputs']['additionalInputsHashes']),m.current_cohort.ADDITIONAL_INPUTS)
        for name,value in i['additionalInputs'].items():
            self.assertEqual(a['runtimeInputs']['additionalInputsHashes'][name],m.digest(value))
        self.assertNotEqual(a['scope']['reviewHash'],a['baseParentReviewHash'])
        self.assertEqual(a['review']['components']['cohortInstallation']['currentAdmission']['nativeRuntimeInputsHash'],m.digest(a['runtimeInputs']))

    def test_actual_parent_and_child_guards_accept_new_scope_only_with_new_human_and_role_signatures(self):
        i,auth,calls,child,raw=self.fixture();a=self.compile(i)
        old=m.parent_review.assemble(i['parentInputs'],m.digest(i['parentInputs']),self.baseline,self.primitives)
        auth.review=old['review'];old_parent=auth.fixture()
        with self.assertRaisesRegex(ValueError,'EXACT_SEPARATE'):old_parent.guard('cohortInstallation',a['review']['components']['cohortInstallation'])
        auth.review=copy.deepcopy(a['review']);parent=auth.fixture()
        for name,scope in a['review']['components'].items():self.assertTrue(parent.guard(name,scope))
        self.assertTrue(parent.registry_child(child,raw));self.assertFalse(calls)

    def test_original_child_bytes_and_other_five_components_remain_exact(self):
        i,*_=self.fixture();child=copy.deepcopy(i['parentInputs']['registryChild']);a=self.compile(i)
        original=m.parent_review.assemble(i['parentInputs'],m.digest(i['parentInputs']),self.baseline,self.primitives)
        self.assertEqual(a['registryChildReview'],child)
        self.assertEqual(base64.b64decode(a['registryChildReview']['authorityBase64']),base64.b64decode(child['authorityBase64']))
        for name,scope in original['review']['components'].items():
            if name!='cohortInstallation':self.assertEqual(a['review']['components'][name],scope)

    def test_missing_extra_or_legacy_iam_inputs_are_denied(self):
        original,*_=self.fixture()
        for case in list(m.current_cohort.ADDITIONAL_INPUTS)+['extra','legacy']:
            i=copy.deepcopy(original)
            if case=='extra':i['additionalInputs']['unreviewed']={}
            elif case=='legacy':
                i['additionalInputs']['iamWorkload']['schema']='ouf.discovery-current-iam-workload-inputs.v1'
                del i['additionalInputs']['iamWorkload']['readOnlyAdmin']
            else:del i['additionalInputs'][case]
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(i)

    def test_different_installation_or_prebound_input_hash_cannot_be_substituted(self):
        original,*_=self.fixture()
        for name in m.current_cohort.ADDITIONAL_INPUTS:
            i=copy.deepcopy(original);i['additionalInputs'][name]['installationInputsHash']='f'*64
            with self.subTest(name=name),self.assertRaises(ValueError):self.compile(i)
        i=copy.deepcopy(original);i['runtimeInputs'].update(schema=m.current_cohort.INPUT_SCHEMA_V2,
            additionalInputsHashes={'iamWorkload':'f'*64})
        with self.assertRaisesRegex(ValueError,'CANNOT_BE_REPLACED'):self.compile(i)

    def test_wrong_current_database_iam_mcp_or_gateway_generation_is_denied(self):
        original,*_=self.fixture()
        for role in ('postgres','keycloak','mcp','apisix'):
            i=copy.deepcopy(original);i['runtimeInputs']['peers'][role]['runtimeBinding']['configHash']='f'*64
            with self.subTest(role=role),self.assertRaises(ValueError):self.compile(i)

    def test_cross_owner_profile_truststore_client_and_backup_intent_must_match(self):
        original,*_=self.fixture()
        for name,key in [('tlsIam','executionProfileHash'),('iamWorkload','executionProfileHash'),
            ('tlsIam','trustStoreBindingHash'),('retirementAndBackup','backupIntentHash')]:
            i=copy.deepcopy(original);i['additionalInputs'][name][key]='f'*64
            with self.subTest(name=name,key=key),self.assertRaises(ValueError):self.compile(i)
        i=copy.deepcopy(original);i['additionalInputs']['iamWorkload']['dockerBinding']={'path':'/usr/bin/other','sha256':'f'*64}
        with self.assertRaisesRegex(ValueError,'SAME_REVIEWED_CURRENT_DATABASE_AND_IAM'):self.compile(i)

    def test_wrong_envelope_hash_extra_fields_or_false_boolean_hashes_are_denied(self):
        i,*_=self.fixture()
        with self.assertRaises(ValueError):m.assemble(i,'f'*64,self.baseline,self.primitives)
        i['inputsAuthenticated']=True
        with self.assertRaises(ValueError):self.compile(i)
        del i['inputsAuthenticated'];i['additionalInputs']['tlsIam']['executionProfileHash']=True
        with self.assertRaises(ValueError):self.compile(i)

    def test_publication_and_workload_iam_must_select_same_realm_issuer_scope_and_audience(self):
        original,*_=self.fixture()
        for name in ('realm','expectedScopes','expectedAudiences','authorizationContainer'):
            i=copy.deepcopy(original)
            if name=='authorizationContainer':i['parentInputs']['publicationInputs']['authorization']['selection']['keycloakContainer']='f'*64
            else:i['additionalInputs']['iamWorkload'][name]='elsewhere' if name=='realm' else ['unreviewed']
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'SAME_PUBLICATION_AUTHORIZATION'):
                self.compile(i)

    def test_complete_bindings_never_claim_native_admission_or_expose_private_paths(self):
        i,*_=self.fixture();a=self.compile(i);r=m.receipt(a)
        self.assertTrue(r['currentNativeInputsBound']);self.assertTrue(r['completeParentReviewShape'])
        for k in ('currentNativeInputsAuthenticated','currentNativeAdmissionProven','artifactMembershipProven',
            'actualWorkloadBearerAdmitted','nativeCheckpointControllerIntegrated','publicationExecutorIntegrated',
            'runtimeAuthorityIssued','targetApplyAuthorized','capabilitiesPublished','applicationE2EProven','releaseAcceptance'):
            self.assertIs(r[k],False)
        raw=m.encoded(r)
        for forbidden in (b'/review/',b'/usr/',b'/opt/',b'kcadm.config',b'authorityBase64',b'clientUuid'):
            self.assertNotIn(forbidden,raw)

    def files(self):
        i,auth,*_=self.fixture();source=auth.root/'current-parent-input.private.json';auth.write(source,m.encoded(i))
        out=auth.root/'current-review-output';out.mkdir(mode=0o700);return i,auth,source,out

    def test_private_preparation_is_create_only_and_inspection_preserves_bytes_and_inodes(self):
        i,auth,source,out=self.files();first=m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        pins={p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()}
        self.assertEqual(first,m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives,inspect=True))
        with self.assertRaisesRegex(ValueError,'NO_REPLAY'):m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        self.assertEqual(pins,{p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()})

    def test_partial_preparation_is_preserved_and_never_completed_or_replayed(self):
        i,auth,source,out=self.files();native=m.new_file
        def fail(fd,name,raw):
            if name=='receipt.json':raise OSError('injected completion loss')
            return native(fd,name,raw)
        with patch.object(m,'new_file',side_effect=fail),self.assertRaises(OSError):
            m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives)
        pins={p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()}
        for inspect in (False,True):
            with self.assertRaises(ValueError):m.prepare(str(source),m.digest(i),str(out),self.baseline,self.primitives,inspect=inspect)
        self.assertEqual(pins,{p.name:(p.stat().st_ino,p.read_bytes()) for p in out.iterdir()})

    def test_output_cannot_shadow_any_new_database_publisher_tls_or_engine_reference(self):
        i,auth,source,out=self.files();result=self.compile(i)
        selected=[i['additionalInputs']['databases']['modules'][0]['artifact']['root'],
            i['additionalInputs']['custody']['artifacts'][0]['bundle']['path'],
            i['additionalInputs']['tlsIam']['caFiles']['iam']['path'],
            i['additionalInputs']['iamWorkload']['readOnlyAdmin']['python']['path'],
            i['runtimeInputs']['engineBinding']['socketPath']]
        for path in selected:
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'MUST_NOT_SHADOW'):
                m.prepare(str(source),m.digest(i),path,self.baseline,self.primitives)
        self.assertEqual(list(out.iterdir()),[])

    def test_new_capsule_preserves_all_136_frozen_source_bindings(self):
        frozen=json.loads((ROOT/capsule.PARENT_SOURCES).read_text())
        self.assertEqual(len(frozen),136)
        self.assertTrue(all(self.manifest['sources'].get(k)==v for k,v in frozen.items()))
        self.assertEqual(self.manifest['entryModule'],capsule.ENTRY)
        self.assertFalse(self.manifest['publisherTrustAccepted'])

    def test_closed_cli_runs_in_isolation_with_only_embedded_sources_and_helpers(self):
        i,auth,source,out=self.files();exe=auth.root/'current-compiler.py';auth.write(exe,self.capsule)
        args=[sys.executable,'-I','-B','-S',str(exe),'prepare','--input',str(source),
            '--input-sha256',m.digest(i),'--output-directory',str(out)]
        first=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(first.returncode,0,first.stdout.decode()+first.stderr.decode())
        value=json.loads(first.stdout);self.assertTrue(value['currentNativeInputsBound']);self.assertFalse(value['targetApplyAuthorized'])
        args[5]='inspect';second=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(second.returncode,0,second.stdout.decode()+second.stderr.decode());self.assertEqual(first.stdout,second.stdout)
        assembly=m.decode((out/'assembly.private.json').read_bytes())
        self.assertEqual(assembly['compilerBinding']['profile'],'CLOSED_CURRENT_PARENT_REVIEW_CAPSULE')
        self.assertFalse(assembly['compilerBinding']['publisherTrustAccepted'])

    def test_missing_isolation_and_tampered_payload_deny_without_private_error_output(self):
        i,auth,source,out=self.files();exe=auth.root/'current-compiler-deny.py';auth.write(exe,self.capsule)
        args=[sys.executable,'-I','-B','-S',str(exe),'prepare','--input',str(source),
            '--input-sha256',m.digest(i),'--output-directory',str(out)]
        for case in ('missing-isolation','payload'):
            call=list(args)
            if case=='missing-isolation':call.remove('-I')
            else:
                # Change the payload alone while retaining its signed-by-no-one manifest digest.
                raw=self.capsule.replace(b"PAYLOAD='",b"PAYLOAD='A",1)
                self.assertNotEqual(raw,self.capsule);auth.write(exe,raw)
            reply=subprocess.run(call,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            with self.subTest(case=case):
                self.assertEqual(reply.returncode,1);value=json.loads(reply.stdout)
                self.assertEqual(value['status'],'STOP_RECONCILE');self.assertEqual(reply.stderr,b'')
                self.assertNotIn(str(source).encode(),reply.stdout);self.assertEqual(list(out.iterdir()),[])


if __name__=='__main__':unittest.main()
