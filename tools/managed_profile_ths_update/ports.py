"""Reuse exact owner lifecycle/SQL ports with no import or second owner stage."""
def bind(base):
    class NativePorts(base.NativePorts):
        def execute(self,stage):
            self.require(stage in self.core.STAGES and not stage.startswith('IMPORT_'),
                'ONLY_NEW_SINGLE_OWNER_NO_IMPORT_STAGES')
            return super().execute(stage)
        def final_result(self):
            self.guard('VERIFY_FINAL_STATE');row=self.execution.record()
            proof=next(e['proof']['ownerProofs']['onboarding']for e in row['effects']if e['stage']=='VERIFY_FINAL')
            c=self.core
            result={'schema':'ouf.ths-owner-request-update-result.v1',
                'status':'THS_OWNER_REQUEST_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
                'contextPath':str(self.root),'executionInputsHash':self.ctx.case['executionInputsHash'],
                'conditionalNativePlanHash':self.ctx.case['conditionalPlanHash'],
                'configurationProfileHash':self.ctx.case['configurationProfileHash'],
                'frozenPlanHash':self.review['frozenPlanHash'],'reviewHash':c.digest(self.review),
                'authorityHash':c.sha(self.gate.raw),'runtimeBindingHash':self.review['nativePlan']['runtimeBindingHash'],
                'sourceCommit':self.ctx.case['sources']['onboarding'],
                'nativeImageId':self.ctx.case['nativeImageIds']['onboarding'],
                'sameNativeImageRequired':True,'targetRoles':['onboarding'],'counts':row['counts'],
                'nativeBindingHash':proof['nativeBindingHash'],'generation':proof['generation'],
                'componentReadinessProven':True,'oldOwnersRetainedStopped':1,'unchangedPeers':12,
                'addedRequestScopes':self.ctx.proposal['scopeRequestDelta']['missingRequestScopes'],
                'preservedRequestedScopeCount':len(self.ctx.proposal['scopeRequestDelta']['requestedScopes']),
                'scopePatchApplied':True,'databaseMigrationsByRepair':0,'installedSchemaVersion':36,
                'operationalStateProof':row['effects'][-1]['proof'],'backup':self.ctx.backup_proof,
                'sqlSessionsByRepair':row['counts']['sqlSessions'],'imageImports':0,
                'registryWorkerTouched':False,'mcpUnchanged':True,'gatewayRequests':0,
                'credentialFileReads':0,'oauthRequestsByRepair':0,'iamRequestsByRepair':0,
                'normalOwnerOAuthBootstrapMayHaveOccurred':True,'normalOwnerOAuthRequestsCountNotObserved':True,
                'installationSigningKeysRead':True,'installationSigningOperations':3,
                'mountSourceContentIdentityProven':False,'newGrantsGranted':0,'humanBudgetsGranted':0,
                'resumes':0,'sourceActivations':0,'acquisitionsExecuted':0,'newJobs':0,'uploads':0,
                'runtimeAuthorityIssued':True,'effectiveBrowserTokenScopesProven':False,
                'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,
                'budgetReset':False,'automaticRollbackPerformed':False}
            return self.ctx.finalize(result)
    return NativePorts
