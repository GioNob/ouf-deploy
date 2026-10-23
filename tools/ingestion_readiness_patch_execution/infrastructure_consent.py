"""Existing scoped infrastructure consent, extracted without its rollout/login entrypoint.

Exact functions retained from source_revision_update.authority af1172ba4127a78cb42a812a90bab3c3c60cb159.
No consent is requested at import; no token or runtime operation is performed.
"""
import os,re,stat,termios,time
from tools.ingestion_readiness_patch_execution.contract import require,digest,encoded
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.review import terminal_line,terminal_answer

def terminal_consent(review,summary,*,login=False):
 require(type(summary)is str and len(summary)<8192,'BOUNDED_TERMINAL_SUMMARY_REQUIRED')
 review_hash=digest(review);phrase=('RIAPRO LOGIN 'if login else'APPROVO ')+review_hash
 fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
 try:
  require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
  termios.tcflush(fd,termios.TCIFLUSH)
  os.write(fd,('\n'+summary+'\nRevisione SHA256: '+review_hash+'\nScrivi: '+phrase+'\n> ').encode())
  accepted=False
  for attempt in range(1,4):
   raw,count=terminal_line(fd);accepted,detail=terminal_answer(raw,phrase.encode('ascii'),count)
   if accepted:break
   os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
  require(accepted,'EXACT_CURRENT_TERMINAL_CONSENT_NOT_GIVEN')
 finally:os.close(fd)
 now=int(time.time())
 if login:return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':review_hash,
  'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
 return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':review_hash,
  'approvalRef':'mcp-scoped-'+review_hash[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
  'humanSessionHash':digest(review['authenticatedHuman']),'approvedAt':now,
  'expiresAt':min(now+review['maximumElapsedSeconds'],review.get('absoluteExpiresAt',now+review['maximumElapsedSeconds'])),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}


def decision_valid(review,decision,human,now):
 require(type(human)is HumanSession and human.current()==review['authenticatedHuman'],
  'CURRENT_SAME_AUTHENTICATED_HUMAN_REQUIRED')
 require(type(decision)is dict and set(decision)=={'schema','reviewHash','approvalRef','sourceClosureHash',
  'humanSessionHash','approvedAt','expiresAt','decision','state'}
  and decision['schema']=='ouf.semantic-scoped-terminal-decision.v1'and decision['state']=='ACTIVE'
  and decision['decision']=='APPROVE_EXACT_FINITE_SCOPED_ACTION'
  and decision['reviewHash']==digest(review)and decision['sourceClosureHash']==review['sourceClosureHash']
  and decision['humanSessionHash']==digest(review['authenticatedHuman'])
  and re.fullmatch('mcp-scoped-[0-9a-f]{24}-[0-9]+',decision['approvalRef'])
  and type(decision['approvedAt'])is int and type(decision['expiresAt'])is int
  and decision['approvedAt']<=now<decision['expiresAt']
  and decision['expiresAt']==min(decision['approvedAt']+review['maximumElapsedSeconds'],
   review.get('absoluteExpiresAt',decision['approvedAt']+review['maximumElapsedSeconds']))
  and decision['expiresAt']<=human.expires_at,'EXACT_CURRENT_SCOPED_DECISION_REQUIRED')
