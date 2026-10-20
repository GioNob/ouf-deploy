"""Build a self-contained READ-ONLY inspection, never a login launcher.

Only the three public policy constants are taken from human_session; no OAuth,
refresh, journal writer, initialization or signing implementation is included.
The resulting installation-specific diagnostic has a separately pinned digest.
"""
import ast
import hashlib
import json
from pathlib import Path

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def generate(root,case):
    root=Path(root)
    names=('tools.ingestion_rollout_execution.contract','tools.ingestion_rollout_execution.private_file',
           'tools.governed_human_successor.contract','tools.governed_human_successor.inspection')
    sources={n:(root/('/'.join(n.split('.'))+'.py')).read_text()for n in names}
    policy=ast.parse((root/'tools/chatbot_file_cohort/human_session.py').read_bytes())
    constants={}
    for node in policy.body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in('CLIENT','SCOPES','PROFILE'):constants[key]=ast.literal_eval(node.value)
    if set(constants)!={'CLIENT','SCOPES','PROFILE'}:raise ValueError('EXACT_EXISTING_PUBLIC_HUMAN_POLICY_REQUIRED')
    sources['tools.chatbot_file_cohort.human_session']='\n'.join(k+'='+repr(v)for k,v in constants.items())+'\n'
    sources['tools.governed_human_successor.window']="from pathlib import Path\ndef boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()\n"
    hashes={n:hashlib.sha256(v.encode()).hexdigest()for n,v in sorted(sources.items())}
    declaration={'schema':'ouf.human-successor-read-only-closure.v1','sourceHashes':hashes,
        'caseHash':hashlib.sha256(encoded(case)).hexdigest(),'readOnly':True,'runtimeAuthorityIssued':False}
    closure_hash=hashlib.sha256(encoded(declaration)).hexdigest()
    safe_reasons=set()
    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name):
                index=1 if node.func.id=='require'else 0 if node.func.id=='ValueError'else None
                if index is not None and len(node.args)>index and isinstance(node.args[index],ast.Constant):
                    value=node.args[index].value
                    if type(value)is str:safe_reasons.add(value)
    header='SOURCES='+repr(sources)+'\nCASE='+repr(case)+'\nDECLARATION='+repr(declaration)+'\nCLOSURE_HASH='+repr(closure_hash)+'\nSAFE_REASONS='+repr(sorted(safe_reasons))+'\n'
    body='''
import hashlib,importlib.abc,importlib.util,json,os,signal,sys
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
PACKAGES={'tools','tools.chatbot_file_cohort','tools.ingestion_rollout_execution','tools.governed_human_successor'}
class ClosedReader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in SOURCES or fullname in PACKAGES:return importlib.util.spec_from_loader(fullname,self,is_package=fullname in PACKAGES)
  if fullname=='tools'or fullname.startswith('tools.'):raise ValueError('READ_ONLY_SOURCE_FALLBACK_DENIED')
  return None
 def create_module(self,spec):return None
 def exec_module(self,module):
  if module.__name__ in PACKAGES:module.__path__=[]
  else:exec(compile(SOURCES[module.__name__],'<sealed-read-only:'+module.__name__+'>','exec'),module.__dict__)
def main():
 if not(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('ISOLATED_ROOT_READ_ONLY_PROCESS_REQUIRED')
 if any(n in sys.modules for n in [*SOURCES,*PACKAGES]):raise ValueError('PRELOADED_READ_ONLY_MODULE_DENIED')
 if hashlib.sha256(encoded(DECLARATION)).hexdigest()!=CLOSURE_HASH:raise ValueError('READ_ONLY_CLOSURE_CHANGED')
 if hashlib.sha256(encoded(CASE)).hexdigest()!=DECLARATION['caseHash']:raise ValueError('READ_ONLY_CASE_CHANGED')
 if {n:hashlib.sha256(v.encode()).hexdigest()for n,v in sorted(SOURCES.items())}!=DECLARATION['sourceHashes']:raise ValueError('READ_ONLY_SOURCES_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('READ_ONLY_DEADLINE')));signal.alarm(45)
 sys.meta_path.insert(0,ClosedReader())
 from tools.governed_human_successor.inspection import inspect_retained
 review,private=inspect_retained(CASE,CLOSURE_HASH)
 result={'schema':'ouf.human-expired-ready-successor-inspection.v1','status':'REVIEW_COMPILED_NO_AUTHORITY',
  'complete':True,'readOnly':True,'reviewHash':hashlib.sha256(encoded(review)).hexdigest(),
  'priorOAuthAttempts':review['priorOAuthAttempts'],'maximumCumulativeOAuthAttempts':review['maximumCumulativeOAuthAttempts'],
  'remainingAttempts':review['maximumRemainingOAuthAttempts'],'proposedWindowSeconds':review['newWindowSeconds'],
  'expiredReadyHistoryReconciled':True,'freshTerminalConsentStillRequired':True,
  'oauthRequests':0,'databaseCalls':0,'engineRequests':0,'gatewayRequests':0,'ownerRequests':0,
  'journalWrites':0,'bearerFilesOpened':0,'credentialJournalsOpened':1,
  'credentialValuesPrinted':False,'credentialHashesPrinted':False,'runtimeAuthorityIssued':False,
  'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,'windowExtended':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
 print(encoded(result).decode(),flush=True)
if __name__=='__main__':
 try:main()
 except (Exception,KeyboardInterrupt)as error:
  reason=str(error)if type(error).__name__ in ('Denied','ValueError')and str(error)in SAFE_REASONS else 'EXACT_CURRENT_HISTORY_OR_CUSTODY_NOT_PROVEN_PRIVATE_DETAILS_REDACTED'
  module=sys.modules.get('tools.governed_human_successor.inspection')
  phase=getattr(module,'CHECKPOINT',{'phase':'SEALED_READ_ONLY_ENTRY'})['phase']
  print(encoded({'schema':'ouf.human-expired-ready-successor-inspection.v1','status':'STOP_RECONCILE',
   'reasonCode':reason,'checkpoint':{'phase':phase},
   'complete':False,'readOnly':True,'automaticReplayAllowed':False,'budgetReset':False,
   'runtimeAuthorityIssued':False}).decode(),flush=True)
  raise SystemExit(2)
'''
    return (header+body).encode(),declaration
