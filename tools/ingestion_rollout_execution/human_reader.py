"""Read an explicitly selected existing HUMAN journal without changing history.

Compatibility with reviewed cumulative profiles (including retained 278/288)
does not replay their extension/login code. The returned concrete HumanSession
keeps its original current/claims checks; all authentication/network/write
methods are disabled. An expired selection fails before credential bytes open.
"""
import copy
import json
from pathlib import Path
import time
import types
from tools.ingestion_rollout_execution import contract as c,private_file
from tools.chatbot_file_cohort import human_session as existing

SCHEMA='ouf.ingestion-rollout-existing-human-read-only.v1'

def validate(profile):
    c.require(type(profile)is dict and set(profile)=={'schema','selection','expectedBinding','journal',
        'minimumCumulativeAttempts','maximumCumulativeAttempts','expectedBootId','expectedMonotonicDeadline',
        'governedWindowReceiptHash','readOnly','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset'},
        'EXACT_READ_ONLY_EXISTING_HUMAN_PROFILE_REQUIRED')
    c.require(profile['schema']==SCHEMA and profile['readOnly']is True
        and all(profile[k]is False for k in('runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),
        'NO_HUMAN_AUTHENTICATION_OR_RENEWAL_AUTHORITY_ALLOWED')
    binding=profile['expectedBinding'];selection=profile['selection']
    c.require(type(binding)is dict and type(selection)is dict and binding.get('selectionHash')==c.digest(selection)
        and all(type(selection.get(k))is str and selection[k]and binding.get(k)==selection[k]for k in('issuer','subject','tenant'))
        and binding.get('clientId')==existing.CLIENT
        and type(binding.get('scopes'))is list and 1<=len(binding['scopes'])<=64
        and all(type(v)is str and v for v in binding['scopes'])
        and len(set(binding['scopes']))==len(binding['scopes'])and set(existing.SCOPES)<=set(binding['scopes'])
        and type(binding.get('sessionId'))is str and binding['sessionId'],'EXACT_RETAINED_HUMAN_IDENTITY_REQUIRED')
    for key in('sessionDirectory','tokenPath'):c.path(binding[key])
    c.require(Path(binding['tokenPath'])==Path(binding['sessionDirectory'])/'human-access.jwt',
              'SAME_RETAINED_HUMAN_BEARER_PATH_REQUIRED')
    retry=binding.get('retryProfile')
    c.require(type(retry)is dict and retry.get('automaticBudgetRenewalAllowed')is False
        and type(retry.get('maximumElapsedSeconds'))is int and 1<=retry['maximumElapsedSeconds']<=7200
        and type(binding.get('createdAt'))is int and type(binding.get('expiresAt'))is int
        and 0<binding['expiresAt']-binding['createdAt']<=retry['maximumElapsedSeconds'],
        'EXACT_EXISTING_FINITE_HUMAN_WINDOW_REQUIRED')
    low,high=profile['minimumCumulativeAttempts'],profile['maximumCumulativeAttempts']
    c.require(type(low)is type(high)is int and 0<=low<=high<=4096
              and type(retry.get('maximumAttempts'))is int and retry['maximumAttempts']==high,
              'EXPLICIT_RETAINED_CUMULATIVE_HUMAN_BOUNDS_REQUIRED')
    c.require(type(profile['expectedBootId'])is str and profile['expectedBootId']
        and type(profile['expectedMonotonicDeadline'])in(int,float)
        and 0<profile['expectedMonotonicDeadline']<float('inf'),'EXACT_RETAINED_HUMAN_BOOT_AND_DEADLINE_REQUIRED')
    receipt=profile['governedWindowReceiptHash']
    c.require(receipt is None or c.hashed(receipt),'EXACT_RETAINED_WINDOW_RECEIPT_HASH_REQUIRED')
    c.require(high<=existing.PROFILE['maximumAttempts']or receipt is not None,'EXTENDED_HISTORY_CANNOT_BE_DISCARDED')
    private_file.validate(profile['journal'])
    c.require(profile['journal']['path']==str(Path(binding['sessionDirectory'])/'recovery.json'),
              'SAME_RETAINED_HUMAN_PRIVATE_JOURNAL_REQUIRED')
    return profile

def _deny(self,*args,**kwargs):raise c.Denied('READ_ONLY_HUMAN_READER_AUTHENTICATION_OR_WRITE_FORBIDDEN')

def _read(self):
    p=self._ingestion_read_profile;validate(p)
    c.require(c.digest(p)==self._ingestion_read_profile_hash,'READ_ONLY_HUMAN_PROFILE_CHANGED')
    def unique(pairs):
        result={}
        for k,v in pairs:c.require(k not in result,'DUPLICATE_RETAINED_HUMAN_JOURNAL_FIELD');result[k]=v
        return result
    return json.loads(private_file.read(p['journal']),object_pairs_hook=unique)

def _identity(self,row):
    p=self._ingestion_read_profile;b=p['expectedBinding']
    c.require(c.encoded(row.get('binding'))==c.encoded(b)
        and row.get('schema')=='ouf.chatbot-human-session.private.v1'and row.get('budgetReset')is False
        and row.get('state')=='READY'and row.get('bootId')==p['expectedBootId']==self._boot()
        and row.get('monotonicDeadline')==p['expectedMonotonicDeadline']
        and type(row.get('attempts'))is int
        and p['minimumCumulativeAttempts']<=row['attempts']<=p['maximumCumulativeAttempts'],
        'RETAINED_HUMAN_BINDING_CUMULATIVE_HISTORY_OR_CLOCK_CHANGED')
    receipt=row.get('governedWindowRenewal')
    if p['governedWindowReceiptHash']is None:
        c.require(receipt is None,'UNREVIEWED_HUMAN_WINDOW_RECEIPT')
    else:
        c.require(type(receipt)is dict and c.digest(receipt)==p['governedWindowReceiptHash'],
                  'RETAINED_HUMAN_WINDOW_RECEIPT_CHANGED')
        review,decision=receipt.get('review',{}),receipt.get('decision',{})
        c.require(review.get('budgetReset')is False and review.get('automaticRenewalAllowed')is False
            and review.get('oldCredentialsReusable')is False and review.get('freshIssuerAuthenticationRequired')is True
            and review.get('maximumCumulativeOAuthAttempts')==p['maximumCumulativeAttempts']
            and type(review.get('priorOAuthAttempts'))is int and 0<=review['priorOAuthAttempts']<=p['minimumCumulativeAttempts']
            and review.get('requestedScopes')==b['scopes']and decision.get('reviewHash')==c.digest(review)
            and decision.get('expiresAt')==b['expiresAt']and decision.get('approvedAt')==b['createdAt'],
            'EXACT_RETAINED_HUMAN_CONSENT_AND_CUMULATIVE_LIMIT_REQUIRED')

def open_existing(profile):
    p=copy.deepcopy(validate(profile));b=p['expectedBinding']
    # No credential file, bearer or old login script is opened for a closed window.
    c.require(time.time()<b['expiresAt']and time.monotonic()<p['expectedMonotonicDeadline'],
              'RETAINED_HUMAN_WINDOW_EXPIRED_NO_LOGIN_OR_RENEWAL')
    h=existing.HumanSession(p['selection'],b['sessionDirectory'],b['tokenPath'],b['expiresAt'])
    h._ingestion_read_profile=p;h._ingestion_read_profile_hash=c.digest(p)
    allowed={'_read','_boot','binding','_check_identity_and_budget','_check','_claims','current'}
    for name,method in existing.HumanSession.__dict__.items():
        if callable(method)and name not in allowed:setattr(h,name,types.MethodType(_deny,h))
    h._read=types.MethodType(_read,h);h._check_identity_and_budget=types.MethodType(_identity,h)
    h.current();return h

def require_profile(human,review):
    c.require(type(human)is existing.HumanSession,'CONCRETE_EXISTING_HUMAN_SESSION_REQUIRED')
    profile=review.get('humanReadProfile')
    if profile is None:
        c.require(not hasattr(human,'_ingestion_read_profile_hash'),'UNREVIEWED_HUMAN_READ_ADAPTER')
    else:
        validate(profile)
        c.require(profile['expectedBinding']==review['humanBinding']
            and getattr(human,'_ingestion_read_profile_hash',None)==c.digest(profile),
            'SAME_SIGNED_READ_ONLY_HUMAN_PROFILE_REQUIRED')
    history=review.get('retainedOwnerHistory')
    if history is not None:
        row=human._read()
        c.require(type(row.get('attempts'))is int
            and history['minimumRetainedOAuthAttempts']<=row['attempts']<=history['maximumCumulativeOAuthAttempts'],
            'CURRENT_HUMAN_CANNOT_RESET_RETAINED_OAUTH_HISTORY')
