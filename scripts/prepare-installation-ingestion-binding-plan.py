"""Prepare a separate209 module read-only owner plan; no issuer/owner/runtime dispatch."""
import ast,base64,hashlib,json,os,re,signal,sys,tempfile,time
from pathlib import Path

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def sha(v):return hashlib.sha256(v).hexdigest()

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','login','plan','discovery','transform','runtime','bootstrap'}and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_INSTALLATION_PLANNING_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_READ_ONLY_PREPARATION_DEADLINE')));signal.alarm(120)
 helpers={'__name__':'qualified_read_only_installation_history'}
 exec(compile(delivery['discovery'],'<qualified-read-only-history>','exec'),helpers)
 root=helpers['CONTEXT'];read=helpers['read'];parse=helpers['parsed'];write={}
 # Execute only file-authentication helpers, never any completed action main.
 parse(root/'package.json',helpers['PACKAGE']);plan,result,package_hash=helpers['history']()
 package=parse(root/'package.json',helpers['PACKAGE']);case=parse(root/'case.json',package['fileHashes']['case.json'])
 require(package_hash==helpers['PACKAGE'],'EXACT_COMPLETED_MCP_PACKAGE_REQUIRED')
 binding=plan['humanBinding'];directory=Path(binding['sessionDirectory']);row=parse(directory/'recovery.json',maximum=65536)
 require(row.get('binding')==binding and row.get('state')=='READY'and type(row.get('attempts'))is int
  and 236<=row['attempts']<256 and row.get('budgetReset')is False and time.time()>=row['lastObservedAt']
  and not os.path.lexists(directory/'successor-window.claim.json'),'ACTUAL_COMPLETED_PLAN_HUMAN_AND_AVAILABLE_CUMULATIVE_HISTORY_REQUIRED')
 sources=parse(root/'sources.json',package['fileHashes']['sources.json']);sources={n:base64.b64decode(v,validate=True)for n,v in sources.items()}
 transformer={'__name__':'qualified_two_scope_constants_transform'};exec(compile(delivery['transform'],'<qualified-two-constants-transform>','exec'),transformer)
 h='tools.chatbot_file_cohort.human_session';old_human_sha=sha(sources[h]);sources[h]=transformer['transform'](sources[h])
 require(binding['scopes']==transformer['PREVIOUS'],'EXACT_RETAINED_SEVEN_SCOPE_HUMAN_REQUIRED')
 for n in('entry','login','plan','discovery'):sources['tools.installation_binding_plan.'+n]=delivery[n]
 memory={'__name__':'qualified_closed209_loader'};exec(compile(delivery['runtime'],'<qualified-closed209-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(sources)==209,'EXACT209_MODULE_PLAN_CLOSURE_REQUIRED')
 # Claim logical preparation once before constructing the new private capsule.
 logical=digest({'profile':'ouf.installation-ingestion-binding-plan.v1','completedMcpPackageHash':package_hash,
  'humanBindingHash':digest(binding),'scopeAdditions':transformer['ADDITIONS']})
 parent=root.parent;claim_path=parent/('installation-ingestion-binding-plan-'+logical+'.claim.json')
 require(not os.path.lexists(claim_path),'INSTALLATION_BINDING_PLAN_ALREADY_PREPARED_NO_REPLAY')
 destination=Path(tempfile.mkdtemp(prefix='installation-ingestion-binding-execution-',dir=parent))
 claim={'schema':'ouf.installation-binding-planning-preparation-claim.v1','context':str(destination),
  'completedMcpPackageHash':package_hash,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'automaticReplayAllowed':False,'budgetReset':False}
 # Reuse the strictly bounded O_EXCL/fsync preparer writer as source, not its main.
 def write_new(path,raw):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  finally:os.close(fd)
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 write_new(claim_path,encoded(claim))
 case={**case,'humanBinding':binding,'priorOAuthAttempts':row['attempts'],'completedMcpPackageHash':package_hash,
  'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)},
  'humanScopeTransformation':{'originalSha256':old_human_sha,'newSha256':sha(sources[h]),
   'onlyTwoScopeConstantsChanged':True,'allFunctionsAndGuardsUnchanged':True,'previousScopes':transformer['PREVIOUS'],'requestedScopes':transformer['REQUESTED']}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':read(root/'reader.py',package['fileHashes']['reader.py']),
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INSTALLATION_BINDING_PLAN'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution)
 closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,'executionPins':execution,
  'closure':closure,'declarationHash':digest(declaration),'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,raw in members.items():write_new(destination/name,raw)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.installation-binding-plan-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':209,'priorOAuthAttempts':row['attempts'],
  'maximumCumulativeOAuthAttempts':256,'requestedScopeAdditions':4,'newLoginRequiresSeparateNativeConsent':True,
  'runtimeAuthorityIssued':False,'ownerMutationAllowed':False,'gatewayWritesAllowed':False,
  'automaticReplayAllowed':False,'budgetReset':False,'completedInstallationReadbackReplayed':False,'completedMcpReadbackReplayed':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INSTALLATION_BINDING_PLAN_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
