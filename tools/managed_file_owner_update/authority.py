"""Fresh finite intent: one Onboarding image, exact36→38 migrations, no domain decisions."""
import copy
ROLES=('onboarding',)
STAGES=('VERIFY_CURRENT_ADMISSION','IMPORT_ONBOARDING_OWNER','VERIFY_PRESTOP_STATE','DISABLE_OLD_RESTART_ONBOARDING_OWNER',
    'STOP_OLD_ONBOARDING_OWNER','VERIFY_QUIESCED_BACKUP','DETACH_OLD_ONBOARDING_OWNER','RENAME_OLD_ONBOARDING_OWNER',
    'CREATE_ONBOARDING_OWNER','VERIFY_PRESTART_STATE','START_ONBOARDING_OWNER','VERIFY_READINESS_ONBOARDING_OWNER',
    'VERIFY_POSTMIGRATION_STATE','RESTORE_RESTART_ONBOARDING_OWNER','VERIFY_FINAL','VERIFY_FINAL_STATE')
LIMITS={'engineGets':768,'engineWrites':10,'imageLoadAttempts':1,'readinessGets':96,'adminGets':0,'adminPuts':0,
    'ownerConfigurationReads':64,'ownerConfigurationContentReads':1,'serviceCredentialFileReads':0,'quarantineStops':1,'sqlSessions':7,'backupProcesses':2}
def bind(base):
    base.ROLES=ROLES;base.STAGES=STAGES;base.LIMITS=copy.deepcopy(LIMITS)
    base.AUTHORITY_SCHEMA='ouf.managed-file-owner-v38-update-authority.v1';base.HUMAN_SCHEMA='ouf.managed-file-owner-v38-update-mandate.v1'
    base.DECISION='APPROVE_ONE_FINITE_ONBOARDING_36_TO38_MAINTENANCE_ONLY'
    def profile(review):
        base.require(review['schema']=='ouf.managed-file-owner-v38-update-review.v1'and'recovery'not in review and'continuation'not in review,'NEW_SINGLE_OWNER_V38_REVIEW_REQUIRED')
        return base.LIMITS,base.STAGES
    def validate(review):
        profile(review);proposal=review['nativePlan']['proposal'];row=proposal['readReplacements']['onboarding']
        migration=proposal['databaseMigration'];facts=proposal['candidateApplicationFacts']['migrations']
        base.require(len(facts)==38 and [r['version']for r in facts]==[str(i)for i in range(1,39)]
            and migration=={'from':36,'to':38,'newMigrations':2,'newMigrationFacts':facts[36:]},'EXACT_TWO_PACKAGED_OWNER_MIGRATIONS_REQUIRED')
        base.require(review['maximumSeconds']==900 and review['maximums']==base.LIMITS and review['stages']==list(base.STAGES)
            and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1,'disableCandidateRestartFirst':True}
            and review['nativePlanHash']==base.digest(review['nativePlan'])and review['sourceClosureHash']==base.digest(review['sourceClosure'])
            and review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']
            and review['maintenanceSqlAuthorized']is True and review['databaseMigrationAuthorized']is True
            and review['databaseMigration']==migration and review['maximumBackupBytes']==268435456 and review['maximumBackupSeconds']==90
            and review['operationalSqlHash']==proposal['operationalSqlHash']and review['operationalSqlAfterHash']==proposal['operationalSqlAfterHash']
            and review['targetRoles']==['onboarding']and review['sameNativeImageRequired']is False
            and set(proposal['readReplacements'])=={'onboarding'}and row['request']['Image']!=row['oldBinding']['imageId']
            and review['imageImportAuthorized']is True and review['iamMutationAuthorized']is False
            and review['humanOwnershipAuthorized']is False and review['databaseRestoreAuthorized']is False
            and review['humanBudgetOrSourceActivationAuthorized']is False and review['acquisitionCallsAuthorized']is False
            and review['gatewayMutationAuthorized']is False and review['automaticReplayAllowed']is False
            and review['budgetReset']is False and review['releaseAcceptance']is False,'EXACT_FINITE_OWNER36_TO38_MAINTENANCE_REVIEW_REQUIRED')
        return review
    base.review_profile=profile;base.validate_review=validate;return base
