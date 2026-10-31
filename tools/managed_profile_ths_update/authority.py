"""Bind unchanged signing/CAS algorithms to a new single-owner finite intent."""
import copy
ROLES=('onboarding',)
STAGES=('VERIFY_CURRENT_ADMISSION','VERIFY_PRESTOP_STATE','DISABLE_OLD_RESTART_ONBOARDING_OWNER',
    'STOP_OLD_ONBOARDING_OWNER','VERIFY_QUIESCED_BACKUP','DETACH_OLD_ONBOARDING_OWNER',
    'RENAME_OLD_ONBOARDING_OWNER','CREATE_ONBOARDING_OWNER','VERIFY_PRESTART_STATE',
    'START_ONBOARDING_OWNER','VERIFY_READINESS_ONBOARDING_OWNER','VERIFY_POSTSTART_STATE',
    'RESTORE_RESTART_ONBOARDING_OWNER','VERIFY_FINAL','VERIFY_FINAL_STATE')
LIMITS={'engineGets':768,'engineWrites':9,'imageLoadAttempts':0,'readinessGets':96,
    'adminGets':0,'adminPuts':0,'ownerConfigurationReads':64,'ownerConfigurationContentReads':1,
    'serviceCredentialFileReads':0,'quarantineStops':1,'sqlSessions':7,'backupProcesses':2}

def bind(base):
    base.ROLES=ROLES; base.STAGES=STAGES; base.LIMITS=copy.deepcopy(LIMITS)
    base.AUTHORITY_SCHEMA='ouf.ths-owner-request-update-authority.v1'
    base.HUMAN_SCHEMA='ouf.ths-owner-request-update-mandate.v1'
    base.DECISION='APPROVE_ONE_FINITE_SAME_IMAGE_ONBOARDING_REQUEST_UPDATE_ONLY'
    def review_profile(review):
        base.require(review['schema']=='ouf.ths-owner-request-update-review.v1'
            and 'recovery'not in review and 'continuation'not in review,'EXACT_NEW_SINGLE_OWNER_REQUEST_REVIEW_REQUIRED')
        return base.LIMITS,base.STAGES
    def validate_review(review):
        review_profile(review)
        base.require(review['maximumSeconds']==900 and review['maximums']==base.LIMITS
            and review['stages']==list(base.STAGES)
            and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,
                'candidateStopOnly':True,'maximumStops':1,'disableCandidateRestartFirst':True}
            and review['nativePlanHash']==base.digest(review['nativePlan'])
            and review['sourceClosureHash']==base.digest(review['sourceClosure'])
            and review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']
            and review['maintenanceSqlAuthorized']is True
            and review['databaseMigrationAuthorized']is False
            and review['databaseMigration']=={'from':36,'to':36,'newMigrations':0}
            and review['maximumBackupBytes']==268435456 and review['maximumBackupSeconds']==90
            and review['operationalSqlHash']==review['nativePlan']['proposal']['operationalSqlHash']
            and review['targetRoles']==['onboarding'] and review['sameNativeImageRequired']is True
            and set(review['nativePlan']['proposal']['readReplacements'])=={'onboarding'}
            and review['nativePlan']['proposal']['readReplacements']['onboarding']['request']['Image']
                ==review['nativePlan']['proposal']['readReplacements']['onboarding']['oldBinding']['imageId']
            and review['imageImportAuthorized']is False and review['iamMutationAuthorized']is False
            and review['databaseRestoreAuthorized']is False
            and review['humanBudgetOrSourceActivationAuthorized']is False
            and review['acquisitionCallsAuthorized']is False and review['gatewayMutationAuthorized']is False
            and review['automaticReplayAllowed']is False and review['budgetReset']is False
            and review['releaseAcceptance']is False,'EXACT_FINITE_SAME_IMAGE_REQUEST_UPDATE_REQUIRED')
        return review
    base.review_profile=review_profile; base.validate_review=validate_review
    # The existing journal/progress wire schema is a compatibility encoding.
    # The signed NEW authority/review, exclusive root and exact single-owner
    # stage/limit arrays bind its meaning; no predecessor journal is adopted.
    return base
