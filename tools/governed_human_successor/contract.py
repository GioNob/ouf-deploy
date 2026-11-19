"""Public review of one expired READY session, preserving cumulative history.

All installation identities are inputs. This module neither opens a credential
file nor issues a window, OAuth request, approval, or runtime authority.
"""
import copy
import math
from urllib.parse import urlsplit
from tools.ingestion_rollout_execution.contract import require,digest,hashed,path
from tools.chatbot_file_cohort.human_session import CLIENT,PROFILE,SCOPES

SCHEMA='ouf.human-expired-ready-successor-review.v1'
REVIEW_FIELDS={'schema','predecessorDirectory','predecessorPublicHistoryHash','predecessorBindingHash',
    'selectionHash','bootId','priorOAuthAttempts','maximumCumulativeOAuthAttempts',
    'maximumRemainingOAuthAttempts','requestedScopes','newWindowSeconds','retainedOwnerHistory',
    'operationBinding','sourceClosureHash','predecessorWindowExpiresAt','freshIssuerAuthenticationRequired',
    'oldCredentialsReusable','oldRefreshReplayAllowed','browserConfirmationPerPollRequired',
    'automaticRenewalAllowed','automaticReplayAllowed','budgetReset','runtimeAuthorityIssued'}
PUBLIC_FIELDS=('schema','binding','bootId','monotonicDeadline','lastObservedAt',
               'attempts','state','budgetReset','accessExpiresAt','governedWindowRenewal')

def public_history(row):
    require(type(row)is dict and all(k in row for k in PUBLIC_FIELDS),
            'EXACT_RETAINED_READY_PUBLIC_HISTORY_REQUIRED')
    return {k:copy.deepcopy(row[k])for k in PUBLIC_FIELDS}

def finite(value):
    return type(value)in(int,float)and math.isfinite(value)

def validate_review(review):
    require(type(review)is dict and set(review)==REVIEW_FIELDS and review.get('schema')==SCHEMA,
            'EXACT_EXPIRED_READY_SUCCESSOR_REVIEW_REQUIRED')
    for key in('predecessorPublicHistoryHash','predecessorBindingHash','selectionHash','sourceClosureHash'):
        require(hashed(review.get(key)),'EXACT_SUCCESSOR_REVIEW_HASH_BINDINGS_REQUIRED')
    path(review.get('predecessorDirectory'))
    prior,maximum=review.get('priorOAuthAttempts'),review.get('maximumCumulativeOAuthAttempts')
    require(type(prior)is type(maximum)is type(review.get('maximumRemainingOAuthAttempts'))is int
        and 0<=prior<maximum<=4096 and review['maximumRemainingOAuthAttempts']==maximum-prior
        and maximum-prior>=4,'EXACT_SUCCESSOR_CUMULATIVE_LIMIT_AND_RESERVE_REQUIRED')
    history=review.get('retainedOwnerHistory')
    require(type(history)is dict and set(history)=={'minimumRetainedOAuthAttempts',
        'maximumCumulativeOAuthAttempts','ownerPlanHash','completedResultHash'}
        and type(history.get('minimumRetainedOAuthAttempts'))is int
        and 0<=history['minimumRetainedOAuthAttempts']<=prior
        and history.get('maximumCumulativeOAuthAttempts')==maximum
        and all(hashed(history[k])for k in('ownerPlanHash','completedResultHash')),
        'SAME_COMPLETED_OWNER_HISTORY_REQUIRED')
    scopes=review.get('requestedScopes');operation=review.get('operationBinding')
    require(type(scopes)is list and 1<=len(scopes)<=64
        and all(type(s)is str and s and not any(c.isspace()for c in s)for s in scopes)
        and len(set(scopes))==len(scopes)and set(SCOPES)<=set(scopes)
        and type(operation)is dict and operation
        and all(type(k)is str and k and hashed(v)for k,v in operation.items()),
        'EXACT_SUCCESSOR_SCOPES_AND_OPERATION_REQUIRED')
    require(type(review.get('newWindowSeconds'))is int and review['newWindowSeconds']==7200
        and type(review.get('predecessorWindowExpiresAt'))is int
        and type(review.get('bootId'))is str and review['bootId']
        and all(review.get(k)is False for k in('oldCredentialsReusable','oldRefreshReplayAllowed',
            'automaticRenewalAllowed','automaticReplayAllowed','budgetReset','runtimeAuthorityIssued'))
        and review.get('freshIssuerAuthenticationRequired')is True
        and review.get('browserConfirmationPerPollRequired')is True,
        'EXPLICIT_FRESH_AUTHENTICATION_NO_RESET_OR_RUNTIME_AUTHORITY_REQUIRED')
    return review

def qualify(selection,row,history,*,now,monotonic,boot_id):
    p=public_history(row);b=p['binding']
    require(type(selection)is dict and type(b)is dict
        and all(type(selection.get(k))is str and selection[k] and b.get(k)==selection[k]
                for k in('issuer','subject','tenant'))
        and b.get('selectionHash')==digest(selection)and b.get('clientId')==CLIENT,
        'EXACT_RETAINED_HUMAN_SELECTION_REQUIRED')
    issuer=urlsplit(selection['issuer'])
    require(issuer.scheme=='https'and issuer.hostname and not issuer.username and not issuer.password
        and not issuer.query and not issuer.fragment and not issuer.path.endswith('/'),
        'PINNED_HTTPS_PREDECESSOR_ISSUER_REQUIRED')
    require(type(history)is dict and set(history)=={'minimumRetainedOAuthAttempts',
        'maximumCumulativeOAuthAttempts','ownerPlanHash','completedResultHash'}
        and all(hashed(history[k])for k in('ownerPlanHash','completedResultHash')),
        'COMPLETED_OWNER_HISTORY_BINDING_REQUIRED')
    low,maximum=history['minimumRetainedOAuthAttempts'],history['maximumCumulativeOAuthAttempts']
    require(type(low)is type(maximum)is type(p['attempts'])is int
        and 0<=low<=p['attempts']<=maximum<=4096,
        'SAME_RETAINED_CUMULATIVE_ATTEMPTS_REQUIRED')
    retry=b.get('retryProfile')
    require(type(retry)is dict and set(retry)==set(PROFILE)and retry.get('maximumAttempts')==maximum
        and type(retry.get('id'))is str and retry['id']
        and all(retry.get(k)==v for k,v in PROFILE.items()if k not in('id','maximumAttempts')),
        'SAME_EXISTING_FINITE_RETRY_POLICY_REQUIRED')
    scopes=b.get('scopes')
    require(type(scopes)is list and 1<=len(scopes)<=64
        and all(type(s)is str and s and not any(c.isspace()for c in s)for s in scopes)
        and len(set(scopes))==len(scopes)and set(SCOPES)<=set(scopes),
        'SAME_RETAINED_HUMAN_SCOPES_REQUIRED')
    require(type(b.get('createdAt'))is type(b.get('expiresAt'))is int
        and 0<b['expiresAt']-b['createdAt']<=PROFILE['maximumElapsedSeconds']
        and type(b.get('sessionId'))is str and b['sessionId'],
        'EXACT_RETAINED_FINITE_WINDOW_REQUIRED')
    directory=path(b.get('sessionDirectory'));token=path(b.get('tokenPath'))
    require(token==directory+'/human-access.jwt','SAME_RETAINED_HUMAN_TOKEN_REFERENCE_REQUIRED')
    require(p['schema']=='ouf.chatbot-human-session.private.v1'and p['state']=='READY'
        and p['budgetReset']is False and p['bootId']==boot_id
        and finite(now)and finite(monotonic)and finite(p['lastObservedAt'])
        and finite(p['monotonicDeadline'])and finite(p['accessExpiresAt'])
        and now>=b['expiresAt']and monotonic>=p['monotonicDeadline']
        and now+2>=p['lastObservedAt']and p['accessExpiresAt']<=now,
        'EXPIRED_READY_SESSION_WITHOUT_CLOCK_OR_AUTHENTICATION_AMBIGUITY_REQUIRED')
    receipt=p['governedWindowRenewal']
    require(type(receipt)is dict and set(receipt)=={'review','decision'},
            'EXACT_RETAINED_GOVERNED_WINDOW_RECEIPT_REQUIRED')
    review,decision=receipt['review'],receipt['decision']
    require(type(review)is dict and type(decision)is dict
        and review.get('maximumCumulativeOAuthAttempts')==maximum
        and type(review.get('priorOAuthAttempts'))is int
        and 0<=review['priorOAuthAttempts']<=p['attempts']
        and review.get('requestedScopes')==scopes and review.get('budgetReset')is False
        and review.get('automaticRenewalAllowed')is False
        and review.get('oldCredentialsReusable')is False
        and review.get('freshIssuerAuthenticationRequired')is True
        and decision.get('reviewHash')==digest(review)
        and decision.get('approvedAt')==b['createdAt']and decision.get('expiresAt')==b['expiresAt'],
        'SAME_PREDECESSOR_CONSENT_SCOPES_AND_CUMULATIVE_LIMIT_REQUIRED')
    require(maximum-p['attempts']>=4,'FRESH_LOGIN_AND_PROVIDER_VERIFICATION_RESERVE_REQUIRED')
    return p

def compile_review(selection,row,history,operation_binding,source_closure_hash,*,now,monotonic,boot_id):
    p=qualify(selection,row,history,now=now,monotonic=monotonic,boot_id=boot_id)
    require(type(operation_binding)is dict and operation_binding
        and all(type(k)is str and k and hashed(v)for k,v in operation_binding.items())
        and hashed(source_closure_hash),'EXACT_SUCCESSOR_OPERATION_AND_SOURCE_BINDINGS_REQUIRED')
    b=p['binding'];maximum=history['maximumCumulativeOAuthAttempts']
    return validate_review({'schema':SCHEMA,'predecessorDirectory':b['sessionDirectory'],
        'predecessorPublicHistoryHash':digest(p),'predecessorBindingHash':digest(b),
        'selectionHash':digest(selection),'bootId':boot_id,
        'priorOAuthAttempts':p['attempts'],'maximumCumulativeOAuthAttempts':maximum,
        'maximumRemainingOAuthAttempts':maximum-p['attempts'],
        'requestedScopes':copy.deepcopy(b['scopes']),
        'newWindowSeconds':PROFILE['maximumElapsedSeconds'],
        'retainedOwnerHistory':copy.deepcopy(history),'operationBinding':copy.deepcopy(operation_binding),
        'sourceClosureHash':source_closure_hash,'predecessorWindowExpiresAt':b['expiresAt'],
        'freshIssuerAuthenticationRequired':True,'oldCredentialsReusable':False,
        'oldRefreshReplayAllowed':False,'browserConfirmationPerPollRequired':True,
        'automaticRenewalAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
        'runtimeAuthorityIssued':False})
