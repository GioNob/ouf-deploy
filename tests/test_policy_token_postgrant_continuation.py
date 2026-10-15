"""New worker after a real signed first grant; real TLS and private native roots.

Only systemctl/IAM administration are simulated by the existing owner fixture.
Hosted CI makes root/group10001 and native sockets mandatory. No target access.
"""
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_policy_token_owner_installation as existing
from tools.chatbot_file_cohort import postgrant_recovery as p
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
from tools.semantic_lease_recovery.bounded_recovery import Policy,fingerprint
from tools.semantic_policy_token_owner.supervisor import RenewalWorker


class PostGrantOwner(unittest.TestCase):
    def setUp(self):
        harness=existing.OwnerInstallationTest('test_same_action_creates_output_rotates_grants_and_admits_real_owner_with_history')
        self.addCleanup(harness.doCleanups);harness.setUp();self.harness=harness;self.f=harness.f
        self.old=harness.installation;worker=self.old.install()
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED')
        root=self.old.journal.root
        paths={name:root/name for name in ('owner-first-grant.json','owner-session.json','owner-admission.json','recovery.json')}
        paths['completed']=self.f.f.root/(self.old.intent_name+'.completed')
        read=lambda name:json.loads(paths[name].read_bytes())
        self.predecessor={'firstGrant':read('owner-first-grant.json'),'worker':read('recovery.json'),
            'admission':read('owner-admission.json'),'session':read('owner-session.json'),'completed':read('completed'),
            'prepared':{'owner':{'binding':dataclasses.asdict(self.old.first.binding),
                'iamProfile':dataclasses.asdict(self.old.first.profile)}},'review':{'scopes':self.old.scopes()}}
        self.preserved={str(path):path.read_bytes()for path in paths.values()}
        self.secret=self.old.first.credential.path.read_bytes()
        self.admin_before=list(self.f.calls);self.commands_before=list(self.f.commands)
        self.proof={'profile':p.PROFILE,'recordBindings':[{'path':name,'sha256':hashlib.sha256(raw).hexdigest()}for name,raw in self.preserved.items()],
            'cancelledWorkerHash':fingerprint(self.predecessor['worker']),
            'newBudget':{'actor':{'issuer':'https://human.fixture.test','tenant':'fixture','subject':'human'},
                'reason':'SYNTHETIC_POSTGRANT_NATIVE_QUALIFICATION','decisionRef':'NEW_EXACT_SIGNED_DECISION',
                'priorControlledGrantAttempts':1,'priorWorkerGrantAttempts':0,'maximumNewWorkerAttempts':128,
                'maximumSeconds':300,'automaticRenewalAllowed':False}}
        host=self.f.f.root/'postgrant-host-inputs.private.json';self.f.f.write(host,self.f.r.f.raw)
        self.directory=self.f.f.root/'postgrant-new-worker';self.directory.mkdir(mode=0o700)
        self.value={'hostInputBinding':{'path':str(host),'sha256':hashlib.sha256(self.f.r.f.raw).hexdigest()},
            'rootEvidenceHash':self.f.root_hash,'rootCreationSourceClosureHash':self.f.root_source,
            'binding':dataclasses.asdict(self.old.first.binding),'iamProfile':dataclasses.asdict(self.old.first.profile),
            'tlsTrustSetHash':self.f.transport.trust_digest(),'policy':dataclasses.asdict(Policy(max_attempts=128,max_elapsed=300)),
            'contextRef':'9'*64,'generationRef':'8'*64,'intervalSeconds':60,'sourceCommit':'b'*40}
        # This fixture changes its own exact record pin; production target pins
        # remain immutable in the source and are never relaxed by a CLI option.
        override=patch.object(p,'FIRST_HASH',fingerprint(self.predecessor['firstGrant']))
        override.start();self.addCleanup(override.stop)
        self.f.f.expected['sourceClosureHash']='8'*64
        authority=json.loads(self.f.f.authority);authority['sourceClosureHash']='8'*64
        self.f.f.authority=existing.fixture.binding.encoded(authority)
        planned=self.make();authority.update(planned.scopes())
        self.f.f.authority=existing.fixture.binding.encoded(authority)
        self.f.f.approval['sourceClosureHash']='8'*64
        self.f.f.approval['approvalRef']='NEW_POSTGRANT_NATIVE_FIXTURE_DECISION'
        self.f.f.approval['executionAuthorityHash']=existing.fixture.binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,existing.fixture.binding.encoded(self.f.f.approval))
        self.f.f.approved=existing.fixture.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.new=self.make()

    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return ContinuedOwnerInstallation(action,self.value,self.harness.files,self.proof,self.predecessor,
            self.directory,self.f.clock,transport=self.f.transport)

    def unchanged(self):
        for path,raw in self.preserved.items():self.assertEqual(Path(path).read_bytes(),raw)
        self.assertEqual(self.old.first.credential.path.read_bytes(),self.secret)
        self.assertEqual(self.f.calls,self.admin_before);self.assertEqual(self.f.commands,self.commands_before)

    def test_initialization_does_not_adopt_old_token_or_repeat_first_grant(self):
        worker=self.new.install();row=self.new.journal.read()
        self.assertFalse(worker.active_here);self.assertEqual(row['state'],'NEW')
        self.assertEqual(row['attempts'],0);self.assertEqual(row['publicationCount'],0)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],1)
        self.assertEqual(self.harness.grants(),1)
        with self.assertRaises(Exception):self.new.observer.guard(self.new.first.binding.digest())
        self.unchanged()

    def test_new_accounted_tls_grant_is_required_and_old_history_stays_immutable(self):
        worker=self.new.install();row=worker.tick()
        self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],2)
        self.assertEqual(self.harness.grants(),2)
        self.new.observer.guard(self.new.first.binding.digest());self.unchanged()
        restarted=RenewalWorker(worker.r)
        self.assertEqual(restarted.tick()['state'],'RECONCILE_REQUIRED')
        self.assertEqual(self.harness.grants(),2);self.unchanged()

    def test_partial_initialization_is_not_reset_or_replayed(self):
        native_initialize=self.new.journal.initialize
        def crashed(row):
            native_initialize(row)
            raise OSError('synthetic crash after durable journal initialization')
        with patch.object(self.new.journal,'initialize',side_effect=crashed),self.assertRaises(OSError):self.new.install()
        before={path.name:path.read_bytes()for path in self.directory.iterdir()}
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.make().install()
        self.assertEqual(before,{path.name:path.read_bytes()for path in self.directory.iterdir()})
        self.assertEqual(self.harness.grants(),1);self.unchanged()

    def test_retained_history_drift_denies_before_a_new_grant(self):
        path=Path(next(iter(self.preserved)));path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.harness.grants(),1)

    def test_revoked_current_human_denies_and_does_not_reuse_predecessor_mandate(self):
        self.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.harness.grants(),1);self.unchanged()

    def test_active_or_nonzero_prior_worker_cannot_be_relabelled_as_unused(self):
        for field,value in (('state','ACTIVE'),('attempts',1),('controlledCumulativeGrantAttempts',2)):
            predecessor=copy.deepcopy(self.predecessor);predecessor['worker'][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):
                ContinuedOwnerInstallation(self.new.action,self.value,self.harness.files,self.proof,predecessor,
                    self.directory,self.f.clock,transport=self.f.transport)
        self.assertEqual(self.harness.grants(),1);self.unchanged()

    def test_complete_review_compiles_new_worker_with_retained_output_and_backup_without_effects(self):
        # Only the selected target observations are synthetic; constructors,
        # root receipts, output inode, source closure and review are concrete.
        import test_chatbot_cohort_assemble as assembly
        import test_file_only_cutover as file_fixture
        import tools.semantic_policy_token_owner.iam_admission as iam
        compiler=assembly.compiler;root=self.f.f.root
        sources={name:((assembly.OWNER/path.split(':',1)[1])if path.startswith('ouf-onboarding:')
            else assembly.ROOT/path).read_bytes()for name,path in assembly.PATHS.items()}
        loader=(assembly.ROOT/'tools/chatbot_file_cohort/runtime.py').read_bytes()
        program=self.f.r.f.host['executables']['systemctl']
        openssl={**self.f.f.binding(self.f.f.openssl),'version':self.f.f.native('version').decode().split()[1]}
        closure={'declaration':assembly.runtime.declaration('b'*40,sources,loader,
            {'ouf-deploy':'b'*40,'ouf-onboarding':'c'*40}),
            'executables':{**{key:program for key in ('python','docker','systemctl','systemdRun')},'openssl':openssl},
            'stdlibHash':fingerprint({'syntheticProgramObservationOnly':True}),'stdlibFileCount':1}
        stage=root/'complete-postgrant-review';stage.mkdir(mode=0o700)
        backup=root/'preserved-backup';backup.mkdir(mode=0o700)
        proof=copy.deepcopy(self.proof);proof['retainedBackupDirectory']=str(backup)
        _,context=compiler.authority_directory('synthetic-postgrant-complete',fingerprint(closure),'e'*64)
        paths={'root':context+'/registry',**{name:context+'/registry/'+name for name in
            ('transition','evidence','before','retirementBefore','node')}};paths['backup']=str(backup)
        request,tree=file_fixture.inputs();identity=Path(self.value['binding']['output_directory']).stat()
        mounted={'source':self.value['binding']['output_directory'],'target':'/run/ouf/policy','fileName':'token.jwt','gid':10001,
            'ownerBindingHash':self.old.first.binding.digest(),'directoryDevice':identity.st_dev,'directoryInode':identity.st_ino,
            'maxBytes':8192,'minimumRemainingSeconds':30}
        intents={phase:{'syntheticTargetObservation':phase}for phase in file_fixture.PHASES}
        intents['CREATE_REPLACEMENT']=request;intents['FENCED_BACKUP']={'directory':str(backup)}
        cohort={'cohortManifestHash':'e'*64,'replacements':[{'module':module,'oldRuntimeBinding':{'containerId':c*64}}
            for module,c in zip(('udp','onboarding','ingestion','mcp'),'5678')]}
        registry={'schema':'ouf.semantic-file-only-installation-inputs.v1','creationRequest':request,'configtree':tree,
            'intents':intents,'retirementScope':{'syntheticTargetObservation':True},'postGrantRecovery':proof,
            'nodeRecipe':{'sourceClosureHash':fingerprint(closure),'renewableToken':mounted},
            'readinessScope':{'databaseContainerId':'b'*64,'databaseUser':'postgres','database':'semantic','databaseOid':4,
                'flywaySchema':'ouf_sem','flywayHistoryHash':'c'*64,
                'health':{'address':'10.1.0.2','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':5}},
            'postgresRuntimeBinding':{'syntheticTargetObservation':True},'imageAudit':{'imageId':request['Image']},
            'commandBindings':{'docker':program},'directoryPlan':paths,'cohortPlanHash':fingerprint(cohort),'adminDatabase':'postgres'}
        prepared={'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1','owner':self.value,'postGrantRecovery':proof,
            'postGrantWorkerDirectory':str(self.directory),'registry':registry,'cohortPlan':cohort,'gatewayRuntimePlan':None,
            'gatewayPlan':{'previousRuntimeHash':'1'*64,'proposedRuntimeHash':'2'*64,
                'transportBinding':{'syntheticTargetObservation':True,'pythonExecutable':program},'proposalKeyBinding':{'sha256':'3'*64}},
            'authorization':{'plan':{'baseline':{'active':{'policyRef':'fixture','contentHash':'4'*64}},
                'targetRoles':{'issuer':self.f.server.profile.issuer,'roles':[],'assignments':[]},
                'registrationAdditions':[],'addedDescriptors':[],'roleProposal':None,'scopeCreations':[],'scopeBindings':[]}},
            'imagePlan':{'schema':'ouf.chatbot-cohort-image-import-plan.v1','cohortManifestHash':'e'*64,
                'images':[{'module':module}for module in ('semantic','udp','onboarding','ingestion','mcp')],
                'maximumImportSecondsPerImage':180,'maximumImportAttemptsPerImage':1,'retagAllowed':False,'automaticReplayAllowed':False}}
        with (patch.object(p,'read_predecessor',return_value=self.predecessor),
            patch.object(p,'proof_scope',return_value=proof),
            patch.object(compiler.governance,'POLICY',self.f.f.binding(self.f.f.policy)),
            patch.object(compiler.governance,'CONTEXT',self.f.f.context),
            patch.object(iam.ssl,'create_default_context',return_value=self.f.transport.context)):
            compiled=compiler.assemble(prepared=prepared,sources=sources,loader=loader,
                bootstrap=(assembly.ROOT/'tools/chatbot_file_cohort/child_bootstrap.py').read_bytes(),closure=closure,
                staging_directory=stage,lineage={'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64},
                preparation_source_hash='f'*64,cohort_id='synthetic-postgrant-complete')
        review=compiled['review'];self.assertEqual(review['firstControlledGrantMaximumAttempts'],0)
        self.assertEqual(review['postGrantRecoveryReview'],proof)
        self.assertNotIn(str(backup),compiled['processPlan']['directoryPlan'].values())
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertFalse(Path(context).exists())
        self.assertEqual(self.harness.grants(),1);self.unchanged()


if __name__=='__main__':unittest.main()
