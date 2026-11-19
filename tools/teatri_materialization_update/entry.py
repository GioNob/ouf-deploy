"""Prepare all bytes and retained pins before finite HUMAN infrastructure consent."""
import copy,json,os,signal,threading,time
from pathlib import Path
from engine_creation import Engine
from image_custody import loaded,runtime_image_id
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused
from tools.teatri_materialization_update.preparation import publish_json
from tools.semantic_mcp_update import session
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.teatri_materialization_update import authority,preparation,plan as compiler,preflight
from tools.teatri_materialization_update.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.teatri_materialization_update.native import NativePorts,runtime

def predecessor(case,read):
 context=Path(case['rolloutContext']);review=read(context/'review.json',8388608,case['rolloutReviewSha256']);plan=read(context/'execution-plan.json',8388608);record=read(context/'recovery.json',131072);issued=read(context/'authority.json',131072)
 selected=review['scopes']['resolutionComparisonUpdate']
 require(review['kind']=='RESOLUTION_COMPARISON_UPDATE'and review['authorityDirectory']==str(context)
  and review['sourceClosure']['declaration']['sourceCommit']==case['rolloutSourceCommit']
  and digest(review['sourceClosure'])==review['sourceClosureHash']==issued['sourceClosureHash']
  and digest(issued)==record['authorityHash']and issued['resolutionComparisonUpdate']==selected
  and digest(plan)==selected['planHash']and record['scopeHash']==digest(selected)
  and record['version']==57 and record['incidentState']=='RECOVERED'
  and record['nextStage']==len(record['effects'])==len(selected['stages'])==21
  and [e['stage']for e in record['effects']]==selected['stages']and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':selected['planHash'],'stage':e['stage']})for e in record['effects']),
  'EXACT_COMPLETED_RESOLUTION_CONFIGURATION_REQUIRED')
 return review,plan,record


def main(prepared,sources,closure,case,context,archive,read,ns,emit):
 authority.closure_valid(closure);context=Path(context)
 previous,old_plan,record=predecessor(case,read)
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pins={'onboarding':record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'ingestion':old_plan['unchangedApplications']['ingestion']}
 for name,pin in pins.items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'RETAINED_APPLICATION_GENERATION_CHANGED')
 transport=copy.deepcopy(old_plan['gateway']['transport']);admin=NamespaceAdmin(engine,transport);routes=admin.routes()
 expected=copy.deepcopy(old_plan['gateway']['afterRoutes'])
 require(routes==expected and digest(routes)==record['effects'][-1]['evidence']['routeMapHash'],'RETAINED_RESOLUTION_ROUTES_CHANGED')
 saved=[r for r in prepared['cohortPlan']['replacements']if r['module']=='udp'];require(len(saved)==1,'ONE_RETAINED_UDP_CREATION_REQUIRED');saved=saved[0]
 audits=[old_plan['replacements']['udp']['imageAudit']]
 status,actual=engine.request('GET','/v1.44/containers/'+saved['name']+'/json')
 require(status==200 and actual['Image']==runtime_image_id(audits[0])and runtime(actual)==record['effects'][-1]['evidence']['applications']['udp']['runtimeBinding'],'EXACT_RETAINED_UDP_IMAGE_REQUIRED')
 status,image=engine.request('GET','/v1.44/images/'+actual['Image']+'/json');require(status==200,'RETAINED_UDP_IMAGE_UNAVAILABLE');loaded(audits[0],image)
 emit('OUF_UDP_RESOLUTION_PHASE=CANDIDATE_BYTE_CUSTODY technical=8/8 functional=2/6')
 candidate=preparation.candidate(archive,case,context,prepared['engine'],ns)
 row=compiler.replacement(saved,actual,candidate,case)
 private={'schema':'ouf.udp-resolution-private-review.v1','predecessorReviewHash':digest(previous),'beforeUdpPin':row['oldRuntimeBinding'],'unchangedApplications':pins,'candidateMetadata':candidate['candidateMetadata'],'imageAudit':candidate['imageAudit'],'imageArchive':candidate['imageArchive'],'gatewayRouteMapHash':digest(routes),'migrationFilesUnchanged':True,'readyForExecution':False,'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.udp-resolution-get-native-update-plan.v1','authorityDirectory':str(context),'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},'replacements':{'udp':row},'unchangedApplications':pins,'gateway':{'transport':transport,'beforeRoutes':routes,'route':copy.deepcopy(routes[case['retainedReadRouteId']]),'projectionBinding':copy.deepcopy(old_plan['gateway']['projectionBinding'])},'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,**{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
 plan['logicalUpdateRef']=digest({'retiredContainerIds':[row['oldRuntimeBinding']['containerId']],'routeId':plan['gateway']['route']['id']});scope(plan)
 publish_json(context,'prepared-plan.json',plan)
 emit('OUF_UDP_RESOLUTION_PREPARED='+encoded({'contextPath':str(context),'newImageId':row['request']['Image'],'migrationFilesUnchanged':True,'newPolicyWorkerStarted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode())
 facts=preflight.collect(prepared,ns,closure['executables']['docker'],actual,case,read)
 private['recoveryPreflight']=facts;private['preparedPlanBinding']={'path':str(context/'prepared-plan.json'),'sha256':digest(plan)}
 # The first candidate review records byte custody. Publish the final combined
 # review under a distinct immutable name to avoid adopting a partial write.
 publish_json(context,'review.json',private)
 require(admin.routes()==routes,'GATEWAY_CHANGED_DURING_PRIVATE_REVIEW')
 for name,pin in {**pins,'udp':row['oldRuntimeBinding']}.items():
  status,after=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and runtime(after)==pin,'APPLICATION_CHANGED_DURING_PRIVATE_REVIEW')
 emit('OUF_TEATRI_RECOVERY_PREFLIGHT='+encoded(facts).decode())
 emit('OUF_TEATRI_MATERIALIZATION_PRIVATE_REVIEW='+encoded({'complete':True,'contextPath':str(context),
  'reviewPath':str(context/'review.json'),'reviewSha256':digest(private),'candidateNativeImageId':row['request']['Image'],
  'completedTechnicalPhases':8,'functionalMilestonesProven':2,'newPrivateReviewOnly':True,
  'readyForExecution':False,'runtimeAuthorityIssued':False,'newPolicyWorkerStarted':False,
  'identityDecisionsPerformed':False,'databaseMutations':0,'grantRequests':0,'serviceMutations':0}).decode())
