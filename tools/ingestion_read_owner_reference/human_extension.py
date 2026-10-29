# Explicit v6 sealed successor only. Preserve all frozen264 history checks.
_PREDECESSOR264_PROFILE=copy.deepcopy(PROFILE)
_PREDECESSOR264_CHECK=types.FunctionType(HumanSession._check_identity_and_budget.__code__,dict(globals(),PROFILE=_PREDECESSOR264_PROFILE))
_BASE_HUMAN_REQUEST=_RETAINED_REQUEST
PROFILE={**_PREDECESSOR264_PROFILE,'id':'ouf.human.ingestion-owner-rollout272.v6','maximumAttempts':272}
def _explicit_272_identity(self,row):
    binding=row.get('binding',{})
    if binding.get('retryProfile')==_PREDECESSOR264_PROFILE:
        return _PREDECESSOR264_CHECK(self,row)
    require(row.get('schema')=='ouf.chatbot-human-session.private.v1'and binding.get('selectionHash')==digest(self.selection)
        and all(binding.get(k)==self.selection[k]for k in('issuer','subject','tenant'))
        and binding.get('clientId')==CLIENT and binding.get('scopes')==SCOPES
        and binding.get('tokenPath')==str(self.token_path)and binding.get('sessionDirectory')==str(self.directory)
        and binding.get('expiresAt')==self.expires_at and binding.get('retryProfile')==PROFILE
        and row.get('budgetReset')is False and row.get('bootId')==self._boot(),'EXPLICIT272_IDENTITY_OR_BINDING_DRIFT')
    require(type(row.get('attempts'))is int and 259<=row['attempts']<=272,'EXPLICIT272_CUMULATIVE_BUDGET_DRIFT')
    receipt=row.get('governedWindowRenewal',{});review=receipt.get('review',{});decision=receipt.get('decision',{})
    require(review.get('schema')=='ouf.human-ingestion-owner-rollout-budget-review.v6'and review.get('purpose')=='CONFIGURATION_AND_VALIDATION'
        and review.get('predecessorMaximumCumulativeOAuthAttempts')==264 and review.get('priorOAuthAttempts')==259
        and review.get('maximumCumulativeOAuthAttempts')==272 and review.get('requestedScopes')==SCOPES
        and review.get('predecessorWindowExpiresAt')==1792436155 and review.get('newWindowSeconds')==7200
        and review.get('budgetReset')is False and review.get('oldCredentialsReusable')is False
        and review.get('automaticRenewalAllowed')is False and review.get('freshIssuerAuthenticationRequired')is True
        and review.get('draftPlanHash')=='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
        and decision.get('schema')=='ouf.human-ingestion-owner-rollout-budget-decision.v6'
        and decision.get('decision')=='APPROVE_EXACT272_AND_NEW7200_WINDOW_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'
        and decision.get('reviewHash')==digest(review)and decision.get('expiresAt')==binding['expiresAt']
        and decision.get('approvedAt')==binding.get('createdAt')and decision['expiresAt']-decision['approvedAt']==7200,
        'EXPLICIT272_NATIVE_CONSENT_AND_HISTORY_REQUIRED')
def _explicit_272_request(self,row,operation,url,values=None,bearer=None):
    require(row.get('binding',{}).get('retryProfile')==PROFILE,'PREDECESSOR264_OAUTH_DISPATCH_FORBIDDEN')
    self._check(row)
    return _BASE_HUMAN_REQUEST(self,row,operation,url,values,bearer)
HumanSession._check_identity_and_budget=_explicit_272_identity
HumanSession._request=_explicit_272_request
