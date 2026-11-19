# Explicit v7 only in a newly sealed closure. The full stopped272 guard stays frozen.
_PREDECESSOR272_PROFILE=copy.deepcopy(PROFILE)
_PREDECESSOR272_CHECK=types.FunctionType(HumanSession._check_identity_and_budget.__code__,dict(globals(),PROFILE=_PREDECESSOR272_PROFILE))
PROFILE={**_PREDECESSOR272_PROFILE,'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288}
def _explicit_288_identity(self,row):
    binding=row.get('binding',{})
    if binding.get('retryProfile')==_PREDECESSOR272_PROFILE:
        return _PREDECESSOR272_CHECK(self,row)
    require(row.get('schema')=='ouf.chatbot-human-session.private.v1'and binding.get('selectionHash')==digest(self.selection)
        and all(binding.get(k)==self.selection[k]for k in('issuer','subject','tenant'))
        and binding.get('clientId')==CLIENT and binding.get('scopes')==SCOPES
        and binding.get('tokenPath')==str(self.token_path)and binding.get('sessionDirectory')==str(self.directory)
        and binding.get('expiresAt')==self.expires_at and binding.get('retryProfile')==PROFILE
        and row.get('budgetReset')is False and row.get('bootId')==self._boot(),'EXPLICIT288_IDENTITY_OR_BINDING_DRIFT')
    require(type(row.get('attempts'))is int and 272<=row['attempts']<=288,'EXPLICIT288_CUMULATIVE_BUDGET_DRIFT')
    receipt=row.get('governedWindowRenewal',{});review=receipt.get('review',{});decision=receipt.get('decision',{})
    require(review.get('schema')=='ouf.human-ingestion-owner-recovery-budget-review.v7'and review.get('purpose')=='CONFIGURATION_AND_VALIDATION'
        and review.get('predecessorMaximumCumulativeOAuthAttempts')==272 and review.get('priorOAuthAttempts')==272
        and review.get('maximumCumulativeOAuthAttempts')==288 and review.get('requestedScopes')==SCOPES
        and review.get('predecessorWindowExpiresAt')==1792446208 and review.get('newWindowSeconds')==7200
        and review.get('budgetReset')is False and review.get('oldCredentialsReusable')is False
        and review.get('automaticRenewalAllowed')is False and review.get('freshIssuerAuthenticationRequired')is True
        and review.get('browserConfirmationPerPollRequired')is True and review.get('verificationBudgetReserved')is True
        and review.get('predecessorPackageHash')=='afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5'
        and review.get('draftPlanHash')=='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
        and decision.get('schema')=='ouf.human-ingestion-owner-recovery-budget-decision.v7'
        and decision.get('decision')=='APPROVE_EXACT288_AND_NEW7200_WINDOW_PROTECTED_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'
        and decision.get('reviewHash')==digest(review)and decision.get('expiresAt')==binding['expiresAt']
        and decision.get('approvedAt')==binding.get('createdAt')and decision['expiresAt']-decision['approvedAt']==7200,
        'EXPLICIT288_NATIVE_CONSENT_AND_HISTORY_REQUIRED')
HumanSession._check_identity_and_budget=_explicit_288_identity
