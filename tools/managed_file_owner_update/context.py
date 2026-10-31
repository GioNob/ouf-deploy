"""Fresh single-Onboarding admission over the consumed exact V38 preparation."""
import copy,os
from pathlib import Path
TARGET={
 'preparedRoot':'/etc/ouf/deploy-snapshots/managed-file-owner-v38-image-plan-8a4c8475-20261028-v1',
 'executionRoot':'/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1',
 'executionInputsHash':'b03d681a8070b31ab29ab9515846421e98ff55a197e963f447d645b1c824a120',
 'conditionalPlanHash':'05e1398deae80106cbd9be45c04f9d9ffbe94303af882f06accb1f6d1a75b191',
 'preparedResultHash':'f71aa2e89b732312fb31bb3791564c4f1f7d6668dfaf45fdff5f44bc023485e9',
 'inputsHash':'8a4c84756a663c3eb3a6b6c615d5efccf0c67b3c6ac2281ff9633c9a93de6224',
 'ownerOverlayPath':'/opt/ouf/secrets/onboarding-ths.yaml',
 'preparationCounts':{'ciZipReads':1,'containerWrites':0,'engineGets':0,'imageImports':0,'nativeArchivesPrepared':1,'privateMetadataBytes':634542,'privateMetadataReads':3},
 'sources':{'onboarding':'9d19fad3dd750dd5b9e77253d3e7e82029c1aca7'},
 'testedSources':{'onboarding':'73498c17596ae155a3ed9ab36acfd6bb69da9846'},
 'nativeImageIds':{'onboarding':'sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51'},
 'archives':{'onboarding':'3c630445a142c45dfdf7e5ab5d8e2f7054f6e377e0fa15418037eb1c49bf3dc6'},
 'transportHashes':{'retainedEngineBindingHash':'8e3adb93d5874ee423092e7171e501a2fcef3386c44fbe48ee40c7c92ef8bb01','capturedEngineBindingHash':'c17569848d56b8efb49ded7ab94b9e4e307ecb0b80eead2fed42aa34d1ed5718','peerCredentialsHash':'7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772'}}

def bind(base):
    class Context(base.Context):
        def __init__(self,parts,auth,sign,journal,closure,*,case=TARGET,public_authority=None,runtime=None):
            self.core,self.p,self.images,self.mac,self.http,self.ports_module,self.watch,self.engine_helpers,self.terminal=[parts[k]for k in('authority','plan_helper','image_custody','retained_mac','transport','ports','quarantine','engine_creation','terminal')]
            c=self.core;self.auth,self.sign,self.journal_module=auth,sign,journal;self.closure=copy.deepcopy(closure)
            self.case,self.root,self.runtime=copy.deepcopy(case),Path(case['executionRoot']),runtime
            self.serial=0;self.execution=None;self.responses=0;self.receiptBytes=0;self.issueStarted=False;self.counts={k:0 for k in c.LIMITS}
            self.p.ancestry(self.root.parent);c.require(not os.path.lexists(self.root),'OWNER_V38_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
            self.root.mkdir(mode=0o700);self.root.chmod(0o700);self.sync(self.root.parent)
            self.write(self.root,'preparation-claim.json',{'schema':'ouf.managed-file-owner-v38-preflight-claim.v1','executionInputsHash':case['executionInputsHash'],'maximums':c.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
            prepared=Path(case['preparedRoot']);retained={}
            for name,checksum in [('execution-inputs.json',case['executionInputsHash']),('execution-plan.json',case['conditionalPlanHash']),('result.json',case['preparedResultHash'])]:
                self.reserve('ownerConfigurationReads');retained[name]=self.read(prepared/name,checksum)
            native,plan,result=(retained[n]for n in('execution-inputs.json','execution-plan.json','result.json'))
            c.require(native['schema']=='ouf.managed-file-owner-recovery-private-execution-inputs.v1'
                and native['capturedInputsHash']==case['inputsHash']and c.digest(native['currentCapture'])==case['inputsHash']
                and native['conditionalNativePlanHash']==case['conditionalPlanHash']
                and all(native[k]is False for k in('executionEntryQualified','runtimeAuthorityIssued','targetUpdateAuthorized','currentRuntimeRevalidated','automaticReplayAllowed','budgetReset')),
                'EXACT_PREPARED_OWNER_V38_INPUTS_REQUIRED')
            c.require(result['schema']=='ouf.managed-file-owner-recovery-image-plan-result.v1'
                and result['status']=='MANAGED_FILE_OWNER_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED'
                and result['complete']is True and result['executionInputsHash']==case['executionInputsHash']
                and result['conditionalNativePlanHash']==case['conditionalPlanHash']and result['capturedInputsHash']==case['inputsHash']
                and result['counts']==case['preparationCounts']and result['targetRoles']==['onboarding']and result['cohortSize']==13 and result['unchangedPeers']==12
                and result['databaseMigration']=={'from':36,'to':38,'newMigrations':2}
                and all(result[k]is False for k in('runtimeAuthorityIssued','targetUpdateAuthorized','currentRuntimeRevalidated','databaseAdmissionProven','currentJobOrBudgetStateObserved'))
                and result['humanOwnershipReceiptsCreated']==result['humanBudgetsGranted']==result['resumes']==0,'EXACT_SUCCESSFUL_CONSUMED_OWNER_IMAGE_PLAN_REQUIRED')
            capture=native['currentCapture'];self.prepared_inputs=copy.deepcopy(native);self.native=copy.deepcopy(native);self.inputs=copy.deepcopy(capture);self.proposal=copy.deepcopy(plan)
            c.require(plan['schema']=='ouf.managed-file-owner-recovery-conditional-native-plan.v1'and plan['kind']=='FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE'
                and c.digest(plan)==case['conditionalPlanHash']and plan['targetRoles']==['onboarding']
                and set(plan['replacements'])==set(native['nativeArchives'])==set(native['imageAudits'])=={'onboarding'}
                and len(plan['existingApplications'])==13 and len(plan['unchangedApplications'])==12
                and all(plan[k]is False for k in('executionEntryQualified','currentRuntimeRevalidated','databaseAdmissionProven','currentJobOrBudgetStateObserved','runtimeAuthorityIssued','targetApplyAuthorized','imageImportAuthorized','newGrantsAuthorized','humanOwnershipOrBudgetOrResumeAuthorized','sourceActivationAuthorized','databaseRestoreAuthorized','automaticRollbackAllowed','automaticReplayAllowed','budgetReset','applicationE2EProven','releaseAcceptance')),
                'EXACT_UNEXECUTED_SINGLE_OWNER_V38_PLAN_REQUIRED')
            self.proposal['readReplacements']=self.proposal['replacements'];self.proposal['nativeIdentityProfile']='CONFIG_AND_NATIVE_MANIFEST'
            row=self.proposal['readReplacements']['onboarding'];archive=native['nativeArchives']['onboarding'];audit=native['imageAudits']['onboarding']
            c.require(audit==row['imageAudit']and archive==row['nativeArchive']and audit['sourceCommit']==case['testedSources']['onboarding']
                and audit['nativeIdentity']['nativeImageId']==case['nativeImageIds']['onboarding']
                and self.images.runtime_image_id(audit)==row['request']['Image']==case['nativeImageIds']['onboarding']
                and archive['sha256']==case['archives']['onboarding']and Path(archive['path'])==prepared/'onboarding-native.tar'
                and row['oldBinding']==self.p.stable_binding(capture['currentObservations']['onboarding'])and row['request']['Image']!=row['oldBinding']['imageId'],
                'EXACT_NEW_NATIVE_ARCHIVE_AND_RETAINED_OLD_OWNER_REQUIRED')
            self.archives={'onboarding':copy.deepcopy(archive)};self.archive=self.archives['onboarding']
            self.facts={'onboarding':{'audit':copy.deepcopy(audit),'archive':copy.deepcopy(archive),'identity':{'nativeImageId':case['nativeImageIds']['onboarding'],'configurationImageId':audit['imageId']}}}
            self.proposal['onboardingReplacement']=row;self.application_facts=copy.deepcopy(plan['candidateApplicationFacts']);self.migrations=self.application_facts['migrations']
            c.require(len(self.migrations)==38 and plan['databaseMigration']=={'from':36,'to':38,'newMigrations':2,'newMigrationFacts':self.migrations[36:]},'EXACT_PACKAGED_36_TO38_MIGRATION_REQUIRED')
            self.database_profile=copy.deepcopy(plan['boundDatabaseProfile']);self.database,self.fence,self.backup=[parts[k]for k in('database','state_fence','backup')]
            self.transport_compatibility=self.database.retained_transport(c,self.database_profile,capture['engineBinding'],case['transportHashes'])
            self.proposal['operationalSqlHash']=c.sha(self.fence.query(False).encode());self.proposal['operationalSqlAfterHash']=c.sha(self.fence.query(True).encode())
            overlays=plan['nativeFlywayConfiguration']['ownerOverlays'];c.require(len(overlays)==1 and overlays[0]['binding']['path']==case['ownerOverlayPath'],'ONE_RETAINED_OWNER_OVERLAY_REQUIRED')
            self.reserve('ownerConfigurationContentReads');self.owner_overlay_raw,self.owner_overlay_binding=self.p.private_config(case['ownerOverlayPath'],overlays[0]['binding'])
            self.configuration_raw=parts['configuration_raw'];self.native['imageAudit']=copy.deepcopy(audit);self.native['currentOnboarding']=self.inputs['currentObservations']['onboarding'];self.onb_context=parts['onb_context'];self.mcp_http=parts['mcp_transport']
            self.engine=self.http.Engine(self.p,capture['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
            self.public_authority=public_authority or parts['base_context'].public_authority;self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
            self.input_seals={str(prepared/name):list(self.p.frame((prepared/name).lstat()))for name in retained};self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure}
            self.verify_archive();self.application_jar=self.extract_application()
            if runtime is not None:self.runtime_binding=self.runtime_snapshot()
            self.check_sources()
    return Context
