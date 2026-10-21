"""One distinct native HUMAN scope consent followed by a closed owner GET plan."""
import json,signal,time
from pathlib import Path
from tools.installation_binding_plan import discovery,login,plan as planning

def main(original,sources,closure,case,context,read,emit):
 require=planning.require;planning.closure_valid(closure)
 require(closure['declaration']['entryModule']=='tools.installation_binding_plan.entry'
  and closure['declaration']['moduleCount']==209 and set(sources)==set(closure['declaration']['sourceHashes']),
  'EXACT_READ_ONLY209_SOURCE_CLOSURE_REQUIRED')
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['completedMcpPackageHash']==discovery.PACKAGE
  and claim['priorOAuthAttempts']==case['priorOAuthAttempts']and claim['maximumCumulativeOAuthAttempts']==256
  and claim['automaticReplayAllowed']is False and claim['budgetReset']is False,'EXACT_ONE_USE_INSTALLATION_PLANNING_CLAIM_REQUIRED')
 emit('OUF_MCP_INGESTION_PHASE=RETAINED_HISTORY_AND_CURRENT_BINDINGS')
 discovery.parsed(discovery.CONTEXT/'package.json',discovery.PACKAGE)
 previous,result,package_hash=discovery.history()
 require(package_hash==case['completedMcpPackageHash']==discovery.PACKAGE and previous['humanBinding']==case['humanBinding'],
  'COMPLETED_PLAN_ACTUAL_HUMAN_BINDING_REQUIRED')
 status,_=discovery.profile_binding(previous);require(status['explicitIngestionServiceBindingPresent']is False,'MISSING_BINDING_ALREADY_CHANGED')
 raw,_=discovery.root_file(discovery.PROFILE_PATH,1048576,previous['gateway']['projectionBinding']['sha256']);projection=json.loads(raw)
 # Runtime/owner API admission precedes a scope consent or issuer request.
 reader,expected,actual=planning.inspect_current(previous,result)
 alias,addresses=discovery.owner_alias(actual['gateway'],actual['ingestion'])
 transport=previous['gateway']['transport']
 with discovery.gateway_namespace(expected['gateway']['pid'],transport['networkNamespace']):
  answer=discovery.query_dns(alias,'127.0.0.11')
 require(answer['status']=='RESOLVED'and answer['addresses']and answer['addresses']<=addresses,'CURRENT_OWNER_ALIAS_DNS_NOT_EXACT')
 signal.alarm(0)
 human=login.authenticate(original['authorization']['plan']['selection'],case,context,closure,emit)
 # This phase does not start a refresh worker or replay a failed request.
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_INSTALLATION_PLAN_DEADLINE')));signal.alarm(90)
 emit('OUF_MCP_INGESTION_PHASE=THREE_READ_ONLY_INSTALLATION_OWNER_GETS')
 owner=planning.InstallationReader(human.selection,human,projection['installationId'],projection['revision'])
 active=owner.get_next();revision=owner.get_next();active_after=owner.get_next()
 for key,binding in expected.items():
  value=reader.get('/v1.44/containers/'+binding['containerId']+'/json')
  ordered=key!='gateway'or transport.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(discovery.runtime(value,ordered)==binding,'RUNTIME_DRIFT_DURING_OWNER_READ')
 discovery.profile_binding(previous)
 exact_bindings={'completedMcpPackageHash':package_hash,'retainedRouteMapHash':discovery.ROUTES,
  'projectionBinding':previous['gateway']['projectionBinding'],'currentApplications':expected,
  'humanBinding':human.current(),'ownerAliasDnsProven':True,'sourceClosureHash':planning.digest(closure)}
 plan=planning.compile_plan(active,revision,active_after,projection,alias,exact_bindings)
 planning.publish_json(context,'installation-plan.json',plan)
 report={'schema':'ouf.installation-ingestion-binding-planning-result.v1','status':'PLAN_COMPLETE_NO_OWNER_OR_GATEWAY_WRITES',
  'complete':True,'readOnlyOwner':True,'contextPath':str(context),'planHash':planning.digest(plan),
  'expectedActiveRevision':plan['expectedActive']['revision'],'sourcePayloadChecksum':plan['sourcePayloadChecksum'],
  'candidatePayloadChecksum':plan['candidatePayloadChecksum'],'bindingAdditions':1,'otherPayloadFieldsPreserved':True,
  'maximumCumulativeOAuthAttempts':256,'oauthAttemptsAfter':human._read()['attempts'],'humanWindowExpiresAt':human.expires_at,
  'ownerGetRequests':owner.calls,'engineGetRequests':reader.calls,'dnsQueries':1,'dnsRetries':0,
  'networkNamespaceRestored':True,'ownerMutationRequests':0,'projectionExports':0,'activeProjectionWrites':0,
  'gatewayWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,'grantChanges':0,'sourceActivated':False,
  'completedInstallationReadbackReplayed':False,'completedMcpReadbackReplayed':False,
  'runtimeAuthorityIssued':False,'ownerApplyAuthorized':False,'atomicOwnerActivePreconditionSupportProven':False,
  'futureNativeConsentRequired':True,'credentialValuesPrinted':False,'rawDnsNamesOrAddressesPrinted':False,
  'automaticReplayAllowed':False,'budgetReset':False,'notReleaseAcceptance':True,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 planning.publish_json(context,'planning-result.json',report);signal.alarm(0)
 emit('OUF_INSTALLATION_BINDING_PLAN_RESULT='+planning.encoded(report).decode())
