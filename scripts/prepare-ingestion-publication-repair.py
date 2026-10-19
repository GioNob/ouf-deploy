"""Installation-specific child of the successful preflight. Never replay a claim.

Only private preparation occurs here. Execution uses a fresh isolated interpreter,
the original closed loader, and a newly sealed entry/case. No login or IAM recovery.
"""
import ast,base64,hashlib,json,os,re,signal,sys,tempfile,time
from pathlib import Path

PREFLIGHT=Path('/etc/ouf/deploy-snapshots/ingestion-read-preflight-0jvu7qzh')
PLAN='9216f0bae1056f1a6f8c8bf8627915d9a70f126e476fe6700e65f0d58112b53b'
DIAGNOSTIC='661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'
STOPPED=Path('/etc/ouf/deploy-snapshots/ingestion-read-authorization-execution-ojz9hai3')
STOPPED_PACKAGE='b2b01238a1c760a5e0334f0ed7770b4d03746ee9fdfc271a96798ff282327e84'
STOPPED_CLOSURE='4152ca6bcd44e745ea3a03dc884b67a948d1f91536a80c752a82c27afd9fc657'
STOPPED_ENTRY='4d3f8df210dee1c1c838474a86569bce6f7af81c003ae4dd51c4e8b81d7a3e76'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))

def publisher_guard_proof(raw):
 tree=ast.parse(raw);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='publish_json']
 require(len(functions)==1,'EXACT_FROZEN_PUBLISHER_REQUIRED')
 guard=functions[0].body[1]if isinstance(functions[0].body[0],ast.Expr)and isinstance(functions[0].body[0].value,ast.Constant)else functions[0].body[0]
 require(isinstance(guard,ast.Expr)and isinstance(guard.value,ast.Call)
  and isinstance(guard.value.func,ast.Name)and guard.value.func.id=='require'
  and len(guard.value.args)==2 and not guard.value.keywords
  and isinstance(guard.value.args[1],ast.Constant)and guard.value.args[1].value=='EXACT_ROLLOUT_DOCUMENT_REQUIRED',
  'EXACT_PUBLISHER_NAME_GUARD_REQUIRED')
 condition=guard.value.args[0]
 require(isinstance(condition,ast.Compare)and isinstance(condition.left,ast.Name)and condition.left.id=='name'
  and len(condition.ops)==len(condition.comparators)==1 and isinstance(condition.ops[0],ast.In)
  and isinstance(condition.comparators[0],ast.Tuple)
  and all(isinstance(n,ast.Constant)and type(n.value)is str for n in condition.comparators[0].elts),
  'PURE_LITERAL_PUBLISHER_NAME_GUARD_REQUIRED')
 expression=compile(ast.Expression(condition),'<verified-frozen-publisher-name-guard>','eval')
 rejected=['authorization-plan.json','administrative-result.json']
 for name in rejected:
  try:require(eval(expression,{'__builtins__':{}},{'name':name}),'EXACT_ROLLOUT_DOCUMENT_REQUIRED')
  except ValueError as error:require(str(error)=='EXACT_ROLLOUT_DOCUMENT_REQUIRED','EXACT_PUBLISHER_FAILURE_REQUIRED')
  else:raise ValueError('EXPECTED_PRIVATE_PUBLISHER_FAILURE_NOT_REPRODUCED')
 return {'schema':'ouf.ingestion-administrative-publisher-repair.v1','sourceHash':sha(raw),
  'guardCode':'EXACT_ROLLOUT_DOCUMENT_REQUIRED','rejectedNames':rejected,'predecessorContext':str(STOPPED)}

def reconcile_stopped_child(read,raw_read,root,original_context,sources,plan):
 package=read(STOPPED/'package.json',expected=STOPPED_PACKAGE)
 require(package['sourceCommit']=='37184220c2a565367a194d41e862a704f87dbdb8'
  and package['schema']=='ouf.ingestion-read-administrative-package.v1'
  and digest(package['closure'])==STOPPED_CLOSURE,'EXACT_STOPPED_CHILD_PACKAGE_REQUIRED')
 files={n:raw_read(STOPPED/n,expected=h)for n,h in package['fileHashes'].items()}
 require(set(files)=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'},'EXACT_STOPPED_CHILD_FILES_REQUIRED')
 child_case=json.loads(files['case.json']);require(digest(child_case)==package['executionPins']['caseSha256']
  and child_case['humanBinding']==plan['sessionBinding'],'EXACT_STOPPED_CHILD_CASE_REQUIRED')
 child_sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(files['sources.json']).items()}
 require({n:sha(v)for n,v in child_sources.items()}==package['closure']['declaration']['sourceHashes']
  and sha(child_sources['tools.ingestion_read_authorization.entry'])==STOPPED_ENTRY
  and child_sources['tools.linked_property_rollout.preparation']==sources['tools.linked_property_rollout.preparation'],
  'EXACT_STOPPED_SOURCE_CLOSURE_REQUIRED')
 for name in ('authority.json','review.json','authorization-plan.json','issuance.claim.json','decision.json',
   'human.json','administrative-result.json','authorization'):
  require(not os.path.lexists(STOPPED/name),'STOPPED_CHILD_EFFECT_RECONCILIATION_REQUIRED')
 require(read(STOPPED/'runtime.claim.json',65536)=={'packageHash':STOPPED_PACKAGE,'automaticReplayAllowed':False},
  'EXACT_CONSUMED_STOPPED_RUNTIME_CLAIM_REQUIRED')
 continuation=child_case['existingSessionContinuation'];binding=continuation['claimBinding']
 claim=read(binding['path'],65536,expected=binding['sha256'])
 require(continuation['originalContext']==str(original_context)and continuation['planHash']==PLAN
  and claim['context']==str(STOPPED)and claim['sourceCommit']==package['sourceCommit']
  and claim['originalContext']==str(original_context)and claim['budgetReset']is False
  and claim['maximumCumulativeOAuthAttempts']==256 and claim['automaticReplayAllowed']is False,
  'EXACT_CONSUMED_PARENT_CONTINUATION_CLAIM_REQUIRED')
 for path,expected in continuation['fileBindings'].items():raw_read(path,expected=expected)
 proof=publisher_guard_proof(child_sources['tools.linked_property_rollout.preparation'])
 bindings={str(STOPPED/n):sha(raw)for n,raw in files.items()if n=='case.json'}
 for p in (STOPPED/'package.json',STOPPED/'runtime.claim.json',Path(binding['path'])):
  bindings[str(p)]=sha(raw_read(p))
 return proof,bindings

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
 proof,repair_bindings=reconcile_stopped_child(read,raw_read,root,context,sources,plan)
 print('OUF_INGESTION_PUBLISHER_GUARD='+encoded(proof).decode(),flush=True)
 original_claim=read(root/('ingestion-read-authorization-'+digest({'sourceId':case['sourceId'],
  'predecessor':case['preparedPlanBinding']['sha256']})+'.claim.json'),65536)
 require(original_claim['context']==str(context)and original_claim['sourceCommit']==receipt['sourceCommit']
  and original_claim['automaticReplayAllowed']is False and original_claim['budgetReset']is False,'ORIGINAL_LOGICAL_CLAIM_REQUIRED')
 human,row=ns['existing_human'](entry,case,original['authorization']['plan']['selection'],package['closure'])
 require(row['binding']==plan['sessionBinding']and 212<=row['attempts']<=256
  and human.expires_at==1792405963,'EXACT_UNEXTENDED_EXISTING_HUMAN_REQUIRED')
 require(human.expires_at-time.time()>=650,'HUMAN_WINDOW_TOO_SHORT_FOR_ADMINISTRATIVE_ACTION')
 bindings={**repair_bindings,**{str(p):sha(raw_read(p))for p in (PREFLIGHT/'diagnostic-result.json',
  PREFLIGHT/'candidate-authorization-plan.json',PREFLIGHT/'observed-owner-baseline.json',
  root/claim_name,context/'login-review.json',context/'login-window-receipt.json',
  root/('ingestion-read-authorization-'+digest({'sourceId':case['sourceId'],
   'predecessor':case['preparedPlanBinding']['sha256']})+'.claim.json'),
  context/'runtime.claim.json')}}
 # The live HUMAN journal is deliberately not frozen: its cumulative counter can
 # advance through the native fenced refresh implementation.
 sources['tools.ingestion_read_authorization.entry']=delivery['entry']
 loader=raw_read(context/'runtime.py',expected=package['fileHashes']['runtime.py'])
 memory={'__name__':'qualified_child_loader'};exec(compile(loader,'<qualified-child-loader>','exec'),memory)
 memory['compile_sources'](sources)
 child=Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-',dir=root))
 child_claim='ingestion-read-publication-repair-'+digest({'predecessorPackageHash':STOPPED_PACKAGE,
  'planHash':PLAN,'repairProfile':'ouf.ingestion-administrative-publisher-repair.v1'})+'.claim.json'
 write_new(root,child_claim,encoded({'schema':'ouf.ingestion-existing-session-child-claim.v1',
  'originalContext':str(context),'preflightContext':str(PREFLIGHT),'planHash':PLAN,'context':str(child),
  'sourceCommit':commit,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'budgetReset':False,'automaticReplayAllowed':False}))
 new_case={**case,'humanBinding':row['binding'],'priorOAuthAttempts':row['attempts'],'publisherRepair':proof,
  'predecessorHistoryHash':digest({'originalPackageHash':receipt['packageHash'],'preflightClaim':claim,
   'originalHistoryHash':case['predecessorHistoryHash'],'planHash':PLAN,'stoppedChildPackageHash':STOPPED_PACKAGE,
   'publisherRepair':proof,'preservedPredecessorBindings':repair_bindings}),
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
 prepared={'schema':'ouf.ingestion-publication-repair-preparation.v1','contextPath':str(child),
  'packageHash':digest(new_package),'sourceCommit':commit,'sourceClosureHash':digest(closure),'planHash':PLAN,
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'newHumanLoginAllowed':False,
  'budgetReset':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4,
  'publisherGuardReproduced':True,'stoppedChildPackageHash':STOPPED_PACKAGE}
 write_new(child,'preparation-result.json',encoded(prepared))
 print('OUF_INGESTION_EXISTING_SESSION_PREPARED='+encoded(prepared).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(child/'bootstrap.py'),str(child),digest(new_package)])
