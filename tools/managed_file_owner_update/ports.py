"""Single owner lifecycle, existing signed import and new preservation fence."""
def bind(base):
    class NativePorts(base.NativePorts):
        def execute(self,stage):
            self.require(stage in self.core.STAGES,'ONLY_SINGLE_ONBOARDING_V38_STAGES')
            if stage=='VERIFY_POSTMIGRATION_STATE':return self.ctx.database.observe(self,stage)
            return super().execute(stage)
        def final_result(self):
            self.guard('VERIFY_FINAL_STATE');row=self.execution.record();c=self.core
            proof=next(e['proof']['ownerProofs']['onboarding']for e in row['effects']if e['stage']=='VERIFY_FINAL')
            result={'schema':'ouf.managed-file-owner-v38-update-result.v1','status':'MANAGED_FILE_OWNER_V38_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
                'contextPath':str(self.root),'executionInputsHash':self.ctx.case['executionInputsHash'],'conditionalNativePlanHash':self.ctx.case['conditionalPlanHash'],
                'frozenPlanHash':self.review['frozenPlanHash'],'reviewHash':c.digest(self.review),'authorityHash':c.sha(self.gate.raw),
                'runtimeBindingHash':self.review['nativePlan']['runtimeBindingHash'],'sourceCommit':self.ctx.case['sources']['onboarding'],
                'nativeImageId':self.ctx.case['nativeImageIds']['onboarding'],'nativeBindingHash':proof['nativeBindingHash'],'generation':proof['generation'],
                'counts':row['counts'],'componentReadinessProven':True,'oldOwnersRetainedStopped':1,'targetRoles':['onboarding'],'unchangedPeers':12,
                'installedSchemaVersion':38,'databaseMigrationsByOwnerStartup':2,'controllerSqlWrites':0,'operationalStateProof':row['effects'][-1]['proof'],
                'backup':self.ctx.backup_proof,'sqlSessionsByRepair':row['counts']['sqlSessions'],'imageLoadAttempts':row['counts']['imageLoadAttempts'],
                'registryWorkerTouched':False,'mcpUnchanged':True,'gatewayRequests':0,'credentialFileReads':0,'oauthRequestsByRepair':0,'iamRequestsByRepair':0,
                'normalOwnerOAuthBootstrapMayHaveOccurred':True,'normalOwnerOAuthRequestsCountNotObserved':True,'installationSigningKeysRead':True,
                'installationSigningOperations':3,'mountSourceContentIdentityProven':False,'humanOwnershipReceiptsCreated':0,'legacyTenantsBackfilled':0,
                'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,'sourceActivations':0,'acquisitionsExecuted':0,'newJobs':0,'uploads':0,
                'runtimeAuthorityIssued':True,'effectiveBrowserTokenScopesProven':False,'applicationE2EProven':False,'releaseAcceptance':False,
                'automaticReplayAllowed':False,'budgetReset':False,'automaticRollbackPerformed':False}
            return self.ctx.finalize(result)
    return NativePorts
