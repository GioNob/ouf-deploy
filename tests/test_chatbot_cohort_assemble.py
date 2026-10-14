"""Actual complete scope constructors, retained root custody and private bundle.

No VPS or provider effects. Target observations and program selection are explicit
fixtures; root receipts and Ed25519 are real. The new output directory remains
absent, and the preparation authority cannot authorize any operation.
"""
import copy
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
OWNER=Path(os.environ.get('OUF_CHATBOT_ONBOARDING_ROOT',str(ROOT.parent/'onboarding-review-work')))
PATHS=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_text())
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+sorted({str((ROOT/path).parent)
    for path in PATHS.values() if not path.startswith('ouf-onboarding:')})
for name in ('qualified_owner_authorization_lifecycle','qualified_owner_scope_catalogue'):
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,OWNER/PATHS[name].split(':',1)[1])
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)

import test_policy_token_migration_root_custody as custody_fixture
import test_chatbot_cohort_human_session as human_fixture
from tools.chatbot_file_cohort import assemble as compiler
from tools.chatbot_file_cohort import runtime
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES,digest,encoded
from tools.chatbot_file_cohort.delivery import build_owner
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import Binding
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener
from tools.semantic_lease_recovery.bounded_recovery import Policy
from file_only_profile import FileOnlyProfile,PHASES
from cutover_authority import CutoverAuthority
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator


class CompleteActionAssembly(unittest.TestCase):
    def setUp(self):
        roots=custody_fixture.RootCustodyTest();roots.setUp();self.addCleanup(roots.doCleanups)
        self.roots=roots;self.f=roots.f.f
        creation=roots.action();receipt=creation.run()
        self.root_receipt=(self.f.root/creation.name).read_bytes()
        self.sources={name:((OWNER/path.split(':',1)[1]) if path.startswith('ouf-onboarding:') else ROOT/path).read_bytes()
            for name,path in PATHS.items()}
        self.loader=(ROOT/'tools/chatbot_file_cohort/runtime.py').read_bytes()
        self.bootstrap=(ROOT/'tools/chatbot_file_cohort/child_bootstrap.py').read_bytes()
        program=roots.f.host['executables']['systemctl']
        openssl={**self.f.binding(self.f.openssl),'version':self.f.native('version').decode().split()[1]}
        self.closure={'declaration':runtime.declaration('a'*40,self.sources,self.loader,
            {'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40}),
            'executables':{**{k:program for k in ('python','docker','systemctl','systemdRun')},'openssl':openssl},
            'stdlibHash':digest({'syntheticProgramObservationOnly':True}),'stdlibFileCount':1}
        self.closure_hash=digest(self.closure)
        self.stage=self.f.root/'staging';self.stage.mkdir(mode=0o700)
        self.lineage={'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64}
        self.cohort_id='synthetic-complete-assembly'
        _,self.context=compiler.authority_directory(self.cohort_id,self.closure_hash,'e'*64)
        for p in (patch.object(compiler.governance,'POLICY',self.f.binding(self.f.policy)),
                  patch.object(compiler.governance,'CONTEXT',self.f.context)):
            p.start();self.addCleanup(p.stop)
        issuer='https://iam.fixture.invalid/realms/fixture'
        profile=IamProfile(issuer,issuer+'/protocol/openid-connect/token',issuer+'/protocol/openid-connect/token/introspect',
            'fixture-client','fixture-subject','fixture-tenant','fixture-audience',
            ('authorization.bundle.read',),('authorization.bundle.read',),('127.0.0.1',))
        output=str(Path(roots.paths['durableRecovery'])/'token-output')
        binding=Binding(profile.token_endpoint,profile.client_id,'authorization.bundle.read',output,'token.jwt',10001)
        host_hash=hashlib.sha256(roots.f.raw).hexdigest()
        owner={'hostInputBinding':{'path':str(self.f.root/('policy-token-migration-host-inputs-'+host_hash+'.private.json')),'sha256':host_hash},
            'rootEvidenceHash':digest(receipt),'rootCreationSourceClosureHash':creation.scope['sourceClosureHash'],
            'registration':{'id':'11111111-1111-1111-1111-111111111111','clientId':'fixture-client',
                'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,'protocol':'openid-connect',
                'clientAuthenticatorType':'client-secret','protocolMappers':[],'defaultClientScopes':['fixture-read']},
            'binding':dataclasses.asdict(binding),'iamProfile':dataclasses.asdict(profile),
            'tlsTrustSetHash':PinnedIamOpener(profile).trust_digest(),'sourceCommit':'a'*40,
            'policy':dataclasses.asdict(Policy(max_attempts=2,max_elapsed=300)),
            'contextRef':'1'*64,'generationRef':'2'*64,'intervalSeconds':60}
        tree={'source':'/fixture/db','target':'/run/db','readOnly':True,'uid':10001,'gid':10001,
            'directoryMode':0o500,'fileName':'OUF_SEM_DB_PASSWORD','fileMode':0o400,'maxBytes':4096,'sha256':'b'*64}
        request={'Image':'sha256:'+'a'*64,'User':'10001:10001',
            'Entrypoint':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],
            'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false','SPRING_CONFIG_IMPORT=configtree:/run/db/'],
            'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'NetworkMode':'fixture-bridge',
                'Mounts':[{'Type':'bind','Source':'/fixture/db','Target':'/run/db','ReadOnly':True}]}}
        execution=FileOnlyProfile(request,tree)
        gate=CutoverAuthority(DetachedAuthenticator(self.f.binding(self.f.policy),str(self.stage),openssl),
            {'path':str(Path(self.context)/'unissued-mandate.json'),'sha256':'0'*64},'0'*64,self.f.context,
            {'sourceClosureHash':self.closure_hash,'creationRequestHash':digest(request),'intakeHash':'0'*64,**self.lineage},
            execution_profile=execution)
        self.action=AggregateAction(gate,encoded({'schema':'ouf.preparation-without-authority.v1'}),self.closure_hash)
        self.owner=build_owner(self.action,{'owner':owner},self.sources)
        token={'source':output,'target':'/run/ouf/policy','fileName':'token.jwt','gid':10001,
            'ownerBindingHash':binding.digest(),'directoryCustodyScopeHash':digest(self.owner.output.scope),
            'maxBytes':8192,'minimumRemainingSeconds':30}
        paths={'root':self.context+'/registry',**{k:self.context+'/registry/'+k for k in
            ('transition','evidence','before','retirementBefore','node','backup')}}
        intents={p:{'syntheticTargetObservation':p} for p in PHASES};intents['CREATE_REPLACEMENT']=request
        intents['FENCED_BACKUP']={'directory':paths['backup']}
        cohort={'cohortManifestHash':'e'*64,'replacements':[{'module':m,'oldRuntimeBinding':{'containerId':c*64}}
            for m,c in zip(('udp','onboarding','ingestion','mcp'),'5678')]}
        registry={'schema':'ouf.semantic-file-only-installation-inputs.v1','creationRequest':request,'configtree':tree,
            'intents':intents,'retirementScope':{'syntheticTargetObservation':True},
            'nodeRecipe':{'sourceClosureHash':self.closure_hash,'renewableToken':token},
            'readinessScope':{'databaseContainerId':'b'*64,'databaseUser':'postgres','database':'semantic','databaseOid':4,
                'flywaySchema':'ouf_sem','flywayHistoryHash':'c'*64,
                'health':{'address':'10.1.0.2','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':5}},
            'postgresRuntimeBinding':{'syntheticTargetObservation':True},'imageAudit':{'imageId':request['Image']},
            'commandBindings':{'docker':program},'directoryPlan':paths,'cohortPlanHash':digest(cohort),'adminDatabase':'postgres'}
        self.prepared={'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1','owner':owner,'registry':registry,
            'cohortPlan':cohort,'gatewayRuntimePlan':None,
            'gatewayPlan':{'previousRuntimeHash':'1'*64,'proposedRuntimeHash':'2'*64,
                'transportBinding':{'syntheticTargetObservation':True,'pythonExecutable':program},'proposalKeyBinding':{'sha256':'3'*64}},
            'authorization':{'plan':{'baseline':{'active':{'policyRef':'fixture','contentHash':'4'*64}},
                'registrationAdditions':[],'addedDescriptors':[],'roleProposal':{},'scopeCreations':[],'scopeBindings':[]}},
            'imagePlan':{'schema':'ouf.chatbot-cohort-image-import-plan.v1','cohortManifestHash':'e'*64,
                'images':[{'module':m} for m in ('semantic','udp','onboarding','ingestion','mcp')],
                'maximumImportSecondsPerImage':180,'maximumImportAttemptsPerImage':1,
                'retagAllowed':False,'automaticReplayAllowed':False}}

    def assemble(self):
        return compiler.assemble(prepared=self.prepared,sources=self.sources,loader=self.loader,bootstrap=self.bootstrap,
            closure=self.closure,staging_directory=self.stage,lineage=self.lineage,
            preparation_source_hash='f'*64,cohort_id=self.cohort_id)

    def assert_no_runtime_effects(self):
        self.assertFalse(Path(self.context).exists())
        self.assertFalse(self.owner.output.path.exists())
        self.assertFalse((self.owner.journal.root/'recovery.json').exists())
        self.assertFalse(self.owner.first.credential.path.exists())
        self.assertEqual((self.f.root/self.roots.action().name).read_bytes(),self.root_receipt)
        with self.assertRaises(Exception):self.owner.guard()

    def test_actual_owner_and_eleven_phases_share_one_review_without_authority_or_output(self):
        result=self.assemble();review=result['review']
        self.assertEqual(set(review['scopes']),REQUIRED_SCOPES)
        self.assertEqual(len(review['scopes']),15)
        self.assertEqual(set(review['phaseIntentHashes']),set(PHASES))
        self.assertEqual(review['scopes']['policyTokenOutputCustody'],self.owner.output.scope)
        self.assertEqual(review['scopes']['policyTokenOwnerInstallation']['sourceClosureHash'],self.closure_hash)
        self.assertEqual(review['scopes']['applicationRegistryCutover']['preparedHash'],digest(self.prepared['registry']))
        self.assertEqual(review['privateInputHashes']['preparedInputs'],digest(self.prepared))
        self.assertFalse(review['chatbotEndToEndProven']);self.assertIsNone(review['legacyHistoricalGrantAttempts'])
        self.assertEqual(result['processPlan']['argv'][1:4],['-I','-B','-S'])
        self.assertEqual(len(result['processPlan']['directoryPlan']),19)
        self.assertEqual(json.loads(Path(result['reviewBinding']['path']).read_bytes()),review)
        self.assertEqual(self.assemble()['review'],review)

    def test_operator_review_contains_the_exact_conditional_database_privileges(self):
        database={'modules':[{'module':'mcp','database':'fixture_mcp','user':'fixture_app'}],
                  'mcpAuditRoleAdministration':{'admin':'fixture_admin','temporaryIncidentTrigger':True},
                  'mcpAuditRolePreflight':{'incidentBinding':{'ownerOid':123,'aclHash':'a'*64}}}
        self.prepared['databasePlan']=database
        self.prepared['cohortPlan']['databasePlanHash']=digest(database)
        self.prepared['registry']['cohortPlanHash']=digest(self.prepared['cohortPlan'])
        review=self.assemble()['review']
        self.assertEqual(review['mcpMigrationReview']['administration'],database['mcpAuditRoleAdministration'])
        self.assertEqual(review['mcpMigrationReview']['preflight'],database['mcpAuditRolePreflight'])
        self.assertEqual(review['mcpMigrationReview']['databasePlanHash'],digest(database))
        self.assertEqual(review['mcpMigrationReview']['applicationRole'],'fixture_app')
        self.assert_no_runtime_effects()
        self.assert_no_runtime_effects()

    def test_foreign_custody_or_owner_binding_denied_before_private_bundle(self):
        token=self.prepared['registry']['nodeRecipe']['renewableToken']
        for field in ('directoryCustodyScopeHash','ownerBindingHash'):
            with self.subTest(field=field):
                original=token[field];token[field]='0'*64
                with self.assertRaisesRegex(Exception,'SAME_ACTION_FUTURE_OUTPUT_CUSTODY'):
                    self.assemble()
                token[field]=original
                self.assertEqual(list(self.stage.iterdir()),[])
                self.assert_no_runtime_effects()

    def test_source_drift_and_existing_context_cannot_recompile_an_execution(self):
        name='tools.chatbot_file_cohort.delivery';original=self.sources[name]
        self.sources[name]+=b'\n# different executing source\n'
        with self.assertRaisesRegex(Exception,'EXECUTING_SOURCE_CLOSURE_CHANGED'):self.assemble()
        self.sources[name]=original
        self.assertEqual(list(self.stage.iterdir()),[])
        Path(self.context).mkdir(mode=0o700)
        with self.assertRaisesRegex(Exception,'ALREADY_EXISTS_NO_REPLAY'):self.assemble()
        Path(self.context).rmdir();self.assert_no_runtime_effects()

    def test_approved_decision_survives_refresh_pause_without_new_consent_or_issuance(self):
        human=human_fixture.HumanSessionTest();human.setUp();self.addCleanup(human.doCleanups)
        human.login();human.clock.advance(400)
        decision={'expiresAt':int(human.clock.time()+60)}
        compiled={'review':{'explicitSyntheticReviewOnly':True},'reviewBinding':{'path':str(self.stage/'review.json')},
                  'executionProfile':object()}
        stop=threading.Event();waits=[];issued=[]
        def wait(seconds):
            waits.append(seconds);human.clock.advance(seconds);human.session.refresh_if_due();return False
        class BeforeIssuance(Exception):pass
        def issue(review,actual_decision,profile):
            issued.append(actual_decision)
            self.assertIs(actual_decision,decision)
            raise BeforeIssuance()
        with patch.object(compiler,'time',human.clock),patch.object(stop,'wait',side_effect=wait),\
                patch.object(compiler,'terminal_decision',return_value=decision) as prompt,\
                patch.object(compiler,'issue',side_effect=issue),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(BeforeIssuance):compiler.approve_and_start(compiled,human.session,stop)
        self.assertEqual(prompt.call_count,1);self.assertEqual(len(waits),1)
        self.assertEqual(len(issued),1);self.assertEqual(human.fixture.refreshes,1)
        self.assertTrue(stop.is_set());self.assertLess(human.clock.time(),decision['expiresAt'])
        self.assert_no_runtime_effects()

if __name__=='__main__':unittest.main()
