"""Installation-specific child of the successful preflight. Never replay a claim.

Only private preparation occurs here. Execution uses a fresh isolated interpreter,
the original closed loader, and a newly sealed entry/case. No login or IAM recovery.
"""
import base64,hashlib,json,os,re,signal,sys,tempfile,time
from pathlib import Path

PREFLIGHT=Path('/etc/ouf/deploy-snapshots/ingestion-read-preflight-0jvu7qzh')
PLAN='9216f0bae1056f1a6f8c8bf8627915d9a70f126e476fe6700e65f0d58112b53b'
DIAGNOSTIC='661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))

def validate_preflight(report,plan,observed,claim,receipt,context):
 require(report['schema']=='ouf.ingestion-administrative-existing-session-preflight.v1'
  and report['preflightPassed']is True and report['phase']=='PREFLIGHT_COMPILED_NO_AUTHORITY'
  and report['planHash']==digest(plan)==PLAN and report['diagnosticContextPath']==str(PREFLIGHT)
  and report['oauthAttemptsAfter']==212 and report['oauthAttemptsBefore']==210
  and report['maximumCumulativeOAuthAttempts']==256 and report['originalHumanWindowExpiresAt']==1792405963
  and all(report[k]is False for k in ('newHumanLoginAllowed','budgetReset','automaticReplayAllowed',
   'ownerMutationsAllowed','iamMutationsAllowed','runtimeAuthorityIssued','sourceActivated'))
  and plan['baseline']==observed,'EXACT_SUCCESSFUL_PREFLIGHT_REQUIRED')
 require(claim['schema']=='ouf.ingestion-read-existing-session-preflight-claim.v1'
  and claim['sourceHash']==DIAGNOSTIC and claim['originalContext']==str(context)
  and claim['packageHash']==receipt['packageHash']and claim['context']==str(PREFLIGHT)
  and claim['priorOAuthAttempts']==210 and claim['humanBindingHash']==digest(plan['sessionBinding'])
  and claim['maximumCumulativeOAuthAttempts']==256 and claim['budgetReset']is False
  and claim['automaticReplayAllowed']is False,'EXACT_SUCCESSFUL_PREFLIGHT_CLAIM_REQUIRED')

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(re.fullmatch('[0-9a-f]{40}',commit)and set(delivery)=={'prepare','entry','diagnostic'},'EXACT_QUALIFIED_DELIVERY_REQUIRED')
 require(sha(delivery['diagnostic'])==DIAGNOSTIC,'QUALIFIED_PREFLIGHT_HELPERS_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_PREPARATION_DEADLINE_EXHAUSTED')))
 signal.alarm(180)
 ns={'__name__':'qualified_preflight_helpers'}
 exec(compile(delivery['diagnostic'],'<qualified-preflight-helpers>','exec'),ns)
 read,raw_read,write_new=ns['read'],ns['raw_read'],ns['write_new']
 entry,sources,case,original,package,receipt,_=ns['load_capsule']()
 context=ns['CONTEXT'];root=ns['ROOT']
 report=read(PREFLIGHT/'diagnostic-result.json');plan=read(PREFLIGHT/'candidate-authorization-plan.json')
 observed=read(PREFLIGHT/'observed-owner-baseline.json')
 claim_name='ingestion-read-preflight-'+digest({'context':str(context),'packageHash':receipt['packageHash']})+'.claim.json'
 claim=read(root/claim_name,65536)
 validate_preflight(report,plan,observed,claim,receipt,context)
 entry.validate_plan(plan,case['sourceId'])
 original_claim=read(root/('ingestion-read-authorization-'+digest({'sourceId':case['sourceId'],
  'predecessor':case['preparedPlanBinding']['sha256']})+'.claim.json'),65536)
 require(original_claim['context']==str(context)and original_claim['sourceCommit']==receipt['sourceCommit']
  and original_claim['automaticReplayAllowed']is False and original_claim['budgetReset']is False,'ORIGINAL_LOGICAL_CLAIM_REQUIRED')
 human,row=ns['existing_human'](entry,case,original['authorization']['plan']['selection'],package['closure'])
 require(row['binding']==plan['sessionBinding']and 212<=row['attempts']<=256
  and human.expires_at==1792405963,'EXACT_UNEXTENDED_EXISTING_HUMAN_REQUIRED')
 require(human.expires_at-time.time()>=650,'HUMAN_WINDOW_TOO_SHORT_FOR_ADMINISTRATIVE_ACTION')
 bindings={str(p):sha(raw_read(p))for p in (PREFLIGHT/'diagnostic-result.json',
  PREFLIGHT/'candidate-authorization-plan.json',PREFLIGHT/'observed-owner-baseline.json',
  root/claim_name,context/'login-review.json',context/'login-window-receipt.json',
  root/('ingestion-read-authorization-'+digest({'sourceId':case['sourceId'],
   'predecessor':case['preparedPlanBinding']['sha256']})+'.claim.json'),
  context/'runtime.claim.json')}
 # The live HUMAN journal is deliberately not frozen: its cumulative counter can
 # advance through the native fenced refresh implementation.
 sources['tools.ingestion_read_authorization.entry']=delivery['entry']
 loader=raw_read(context/'runtime.py',expected=package['fileHashes']['runtime.py'])
 memory={'__name__':'qualified_child_loader'};exec(compile(loader,'<qualified-child-loader>','exec'),memory)
 memory['compile_sources'](sources)
 child=Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-',dir=root))
 child_claim='ingestion-read-preflight-continuation-'+digest({'originalContext':str(context),'planHash':PLAN})+'.claim.json'
 write_new(root,child_claim,encoded({'schema':'ouf.ingestion-existing-session-child-claim.v1',
  'originalContext':str(context),'preflightContext':str(PREFLIGHT),'planHash':PLAN,'context':str(child),
  'sourceCommit':commit,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'budgetReset':False,'automaticReplayAllowed':False}))
 new_case={**case,'humanBinding':row['binding'],'priorOAuthAttempts':row['attempts'],
  'predecessorHistoryHash':digest({'originalPackageHash':receipt['packageHash'],'preflightClaim':claim,
   'originalHistoryHash':case['predecessorHistoryHash'],'planHash':PLAN}),
  'existingSessionContinuation':{'schema':'ouf.ingestion-existing-session-continuation.v1',
   'planHash':PLAN,'planPath':str(PREFLIGHT/'candidate-authorization-plan.json'),
   'preflightContext':str(PREFLIGHT),'originalContext':str(context),'fileBindings':bindings,
   'claimBinding':{'path':str(root/child_claim),'sha256':sha(raw_read(root/child_claim))},
   'newHumanLoginAllowed':False,'budgetReset':False,'maximumCumulativeOAuthAttempts':256}}
 members={'case.json':encoded(new_case),'bootstrap.py':raw_read(context/'bootstrap.py',expected=package['fileHashes']['bootstrap.py']),
  'runtime.py':loader,'reader.py':raw_read(context/'reader.py',expected=package['fileHashes']['reader.py']),
  'sources.json':encoded({n:base64.b64encode(b).decode('ascii')for n,b in sorted(sources.items())})}
 for name,raw in members.items():write_new(child,name,raw)
 pins={**package['sourcePins'],'ouf-deploy':commit}
 execution={'executorSha256':sha(members['bootstrap.py']),'caseSha256':digest(new_case),'mode':'INGESTION_READ_AUTHORIZATION'}
 declaration=memory['declaration'](commit,sources,loader,pins,execution)
 closure={**package['closure'],'declaration':declaration}
 new_package={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,
  'closure':closure,'declarationHash':digest(declaration),'fileHashes':{n:sha(v)for n,v in members.items()},
  'predecessorPackageHash':receipt['packageHash'],'runtimeAuthorityIssued':False}
 write_new(child,'package.json',encoded(new_package))
 prepared={'schema':'ouf.ingestion-existing-session-preparation.v1','contextPath':str(child),
  'packageHash':digest(new_package),'sourceCommit':commit,'sourceClosureHash':digest(closure),'planHash':PLAN,
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'newHumanLoginAllowed':False,
  'budgetReset':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(child,'preparation-result.json',encoded(prepared))
 print('OUF_INGESTION_EXISTING_SESSION_PREPARED='+encoded(prepared).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(child/'bootstrap.py'),str(child),digest(new_package)])
