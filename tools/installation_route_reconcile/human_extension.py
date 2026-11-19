# Explicit sealed v5 profile extension; evaluated only in the new action process.
import types
_RETAINED_256_PROFILE=copy.deepcopy(PROFILE)
_RETAINED_256_CHECK=types.FunctionType(HumanSession._check_identity_and_budget.__code__,dict(globals(),PROFILE=_RETAINED_256_PROFILE))
_RETAINED_REQUEST=HumanSession._request
PROFILE={**_RETAINED_256_PROFILE,'id':'ouf.human.installation-route-reconciliation264.v5','maximumAttempts':264}
def _explicit_264_identity(self,row):
    binding=row.get('binding',{})
    if binding.get('retryProfile')==_RETAINED_256_PROFILE:
        return _RETAINED_256_CHECK(self,row)
    require(row.get('schema')=='ouf.chatbot-human-session.private.v1'and binding.get('selectionHash')==digest(self.selection)
        and all(binding.get(k)==self.selection[k]for k in('issuer','subject','tenant'))
        and binding.get('clientId')==CLIENT and binding.get('scopes')==SCOPES
        and binding.get('tokenPath')==str(self.token_path)and binding.get('sessionDirectory')==str(self.directory)
        and binding.get('expiresAt')==self.expires_at==1792436155 and binding.get('retryProfile')==PROFILE
        and row.get('budgetReset')is False and row.get('bootId')==self._boot(),'EXPLICIT264_IDENTITY_OR_BINDING_DRIFT')
    require(type(row.get('attempts'))is int and 255<=row['attempts']<=264,'EXPLICIT264_CUMULATIVE_BUDGET_DRIFT')
    receipt=row.get('governedWindowRenewal',{});review=receipt.get('review',{});decision=receipt.get('decision',{})
    require(review.get('schema')=='ouf.human-installation-route-budget-review.v5'and review.get('purpose')=='CONFIGURATION_AND_VALIDATION'
        and review.get('predecessorMaximumCumulativeOAuthAttempts')==256 and review.get('priorOAuthAttempts')==255
        and review.get('maximumCumulativeOAuthAttempts')==264 and review.get('requestedScopes')==SCOPES
        and review.get('preservedWindowExpiresAt')==1792436155 and review.get('budgetReset')is False
        and review.get('oldCredentialsReusable')is False and review.get('automaticRenewalAllowed')is False
        and review.get('freshIssuerAuthenticationRequired')is True and review.get('remainingBudgetInsufficientForVerifiedRefresh')is True
        and decision.get('schema')=='ouf.human-installation-route-budget-decision.v5'
        and decision.get('decision')=='APPROVE_EXACT264_BUDGET_WITH_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'
        and decision.get('reviewHash')==digest(review)and decision.get('expiresAt')==binding['expiresAt']
        and decision.get('approvedAt')==binding.get('createdAt')and 0<decision['expiresAt']-decision['approvedAt']<=7200,
        'EXPLICIT264_NATIVE_CONSENT_AND_HISTORY_REQUIRED')
def _explicit_264_request(self,row,operation,url,values=None,bearer=None):
    # Legacy sessions remain readable, never allowed to spend the predecessor's last request.
    require(row.get('binding',{}).get('retryProfile')==PROFILE,'PREDECESSOR256_OAUTH_DISPATCH_FORBIDDEN')
    self._check(row)
    return _RETAINED_REQUEST(self,row,operation,url,values,bearer)
HumanSession._check_identity_and_budget=_explicit_264_identity
HumanSession._request=_explicit_264_request
