"""Explicit successor login and worker fence handoff; never resets budgets.

These operations require exact local consent or the fresh typed dual-role
AggregateAction respectively. Old credential journals and worker records stay
unchanged. A consumed or ambiguous handoff is reconciliation-only.
"""
import copy,fcntl,json,os,stat,time,uuid
from pathlib import Path
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import read_private
from tools.semantic_mcp_update.owner import require,digest,encoded
from iam_owner_action import publish


def expired_login_review(previous,operation_binding):
 require(type(previous)is HumanSession and previous.action is None,'RETAINED_REAL_PRE_AUTHORITY_HUMAN_SESSION_REQUIRED')
 row=previous._read();previous._check_identity_and_budget(row);now=time.time()
 require(row.get('state')=='READY' and row.get('operation')=='USERINFO'
  and now>=previous.expires_at and time.monotonic()>=row['monotonicDeadline']
  and now+2>=row['lastObservedAt'],'EXPIRED_KNOWN_COMPLETED_HUMAN_LOGIN_REQUIRED')
 require(row['attempts']<PROFILE['maximumAttempts'],'HUMAN_CUMULATIVE_OAUTH_BUDGET_EXHAUSTED')
 require(type(operation_binding)is dict and operation_binding and all(type(k)is str and type(v)is str
  and len(v)==64 and all(c in '0123456789abcdef'for c in v)for k,v in operation_binding.items()),
  'EXACT_SUCCESSOR_OPERATION_BINDING_REQUIRED')
 return {'schema':'ouf.human-expired-successful-window-review.v1','predecessorDirectory':str(previous.directory),
  'predecessorRowHash':digest(row),'predecessorBindingHash':digest(row['binding']),
  'predecessorExpiredAt':previous.expires_at,'priorOAuthAttempts':row['attempts'],
  'maximumCumulativeOAuthAttempts':128,'maximumRemainingOAuthAttempts':128-row['attempts'],
  'newWindowSeconds':7200,'selectionHash':digest(previous.selection),'bootId':row['bootId'],
  'operationBinding':copy.deepcopy(operation_binding),'automaticRenewalAllowed':False,'budgetReset':False,
  'runtimeAuthorityIssued':False}


def open_approved_login(previous,review,decision):
 require(type(previous)is HumanSession,'REAL_HUMAN_SESSION_REQUIRED')
 with previous.journal.invocation():
  require(review==expired_login_review(previous,review['operationBinding']),'SUCCESSOR_HUMAN_PREDECESSOR_CHANGED')
  now=time.time()
  require(set(decision)=={'schema','reviewHash','decision','approvedAt','expiresAt'}
   and decision['schema']=='ouf.human-login-window-terminal-consent.v1'
   and decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
   and type(decision['approvedAt'])is int and type(decision['expiresAt'])is int
   and decision['approvedAt']<=now<decision['approvedAt']+60
   and decision['expiresAt']-decision['approvedAt']==7200,'EXACT_CURRENT_SUCCESSOR_LOGIN_CONSENT_REQUIRED')
  destination=previous.directory.parent/('human-successor-'+digest(review))
  claim={'schema':'ouf.human-successor-window-claim.v1','reviewHash':digest(review),
   'decisionHash':digest(decision),'destination':str(destination),'budgetReset':False,'automaticReplayAllowed':False}
  with protected_directory(previous.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded(claim)),'SUCCESSOR_LOGIN_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
  with protected_directory(destination.parent)as directory:
   os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(previous.selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  # Keep the existing governor's receipt shape and checks. The predecessor row
  # and its older receipts remain referenced through the sealed row hash.
  binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(previous.selection),
   **{k:previous.selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
   'bootId':previous._boot(),'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,
   'lastObservedAt':now,'attempts':review['priorOAuthAttempts'],'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':copy.deepcopy(review),'decision':copy.deepcopy(decision)}})
  following._check(following._read());return following


from tools.chatbot_file_cohort.continued_owner import advance_worker_fence
