"""Explicit postboot successor construction. Original documents stay unchanged."""
import copy,hashlib,json
def require(value,code):
 if not value:raise ValueError(code)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def completed_host(plan,journal,pointer,selection,owner):
 require(pointer=={'schema':'ouf.host-network-reconciliation-incident.v1','contextPath':selection['hostContext'],'planSha256':selection['hostPlanSha256']},'EXACT_COMPLETED_HOST_POINTER_REQUIRED')
 require(journal['schema']=='ouf.host-network-reconciliation-journal.v1'and journal['state']=='COMPLETE'and journal['planSha256']==selection['hostPlanSha256']and journal['runtimeAuthorityIssued']is False,'COMPLETED_HOST_JOURNAL_REQUIRED')
 owner.validate_profile(plan['profile']);expected=[]
 for index,move in enumerate(plan['moves']):
  expected.extend([{'name':'DISCONNECT_'+str(index),'requestSha256':owner.digest({'containerId':move['pin']['containerId'],'networkId':plan['profile']['network']['id']})},{'name':'CONNECT_'+str(index),'requestSha256':owner.digest(move['request'])}])
 expected.append({'name':'START_RETAINED_APPLICATION','requestSha256':owner.digest({'containerId':plan['restartBefore']['Id']})})
 require(journal['claims']==expected and journal['maximumEngineWrites']==len(expected)==13 and plan['runtimeAuthorityIssued']is False,'EXACT_THIRTEEN_COMPLETED_CLAIMS_REQUIRED')
 require(plan['prebootPreparedBinding']==selection['historicalPrivateInputs'],'HOST_PLAN_NOT_BOUND_TO_HISTORICAL_INPUTS')
 return {'hostContext':selection['hostContext'],'hostPlanSha256':selection['hostPlanSha256'],'completedClaims':13,'historicalAuthorityReused':False}
def project(original,historical,observed,engine,transport,raw_runtime,serving_runtime,application_proof):
 require(historical['schema']=='ouf.source-revision-private-inputs.v1'and historical['runtimeAuthorityIssued']is False and historical['readyForExecution']is False and historical['packageRootCustodyProven']is True,'HISTORICAL_INPUTS_NOT_PREPARATION_ONLY')
 require(engine['socketPath']==historical['engine']['socketPath']==original['engine']['socketPath'],'ENGINE_LOCATION_MUST_REMAIN_SELECTED')
 require(set(engine)==set(historical['engine'])and all(engine[k]==historical['engine'][k]for k in engine if k!='socketBinding'),'ONLY_ENGINE_SOCKET_GENERATION_MAY_CHANGE')
 require(len(engine['socketBinding'])==5 and engine['socketBinding'][2]==0 and engine['socketBinding'][4]in(0o600,0o660),'ROOT_CURRENT_ENGINE_SOCKET_REQUIRED')
 before=historical['beforeApplications'];require(set(before)=={'onboarding','mcp','udp'},'EXACT_APPLICATION_SCOPE_REQUIRED');actuals={};proofs={}
 for module,old in before.items():
  actual=observed[old['Id']];selected=historical['selection']['currentApplications'][module]
  require(actual['Id']==old['Id']and actual['Image']==old['Image']==selected['imageId']and actual['Config']['Labels']['org.opencontainers.image.revision']==selected['sourceCommit'],'HISTORICAL_APPLICATION_IDENTITY_CHANGED')
  require(actual['State']['Running']is True and not actual['State']['Paused']and not actual['State']['Restarting'],'CURRENT_APPLICATION_MUST_BE_RUNNING')
  proofs[module]=application_proof(old,actual);actuals[module]=copy.deepcopy(actual)
 pg=historical['databasePlan']['postgresRuntimeBinding'];actual_pg=observed[pg['containerId']]
 require(actual_pg['Id']==pg['containerId']and actual_pg['Image']==pg['imageId']and actual_pg['State']['Running']is True,'SELECTED_DATABASE_IDENTITY_CHANGED')
 new=copy.deepcopy(historical);new_original=copy.deepcopy(original);new['engine']=copy.deepcopy(engine);new_original['engine']=copy.deepcopy(engine)
 for value in(new,new_original):value['databasePlan']['postgresRuntimeBinding']=raw_runtime(actual_pg)
 new['beforeApplications']=actuals;new['gateway']['transport']=copy.deepcopy(transport)
 for pin in new['unchangedApplications'].values():
  actual=observed[pin['containerId']];require(actual['Image']==pin['imageId']and actual['State']['Running']is True,'UNCHANGED_COMPONENT_IDENTITY_CHANGED')
 new['unchangedApplications']={name:serving_runtime(observed[pin['containerId']])for name,pin in historical['unchangedApplications'].items()}
 intents={}
 for module in('onboarding','mcp'):
  host=new['retainedReplacements'][module]['request']['HostConfig'];actual=actuals[module]['HostConfig'];changed=False
  if 'Dns'in host and host['Dns']is None and type(actual.get('Dns'))is list and not actual['Dns']:
   require(proofs[module]['emptyDnsRepresentationOnly']is True,'EMPTY_DNS_APPLICATION_PROOF_REQUIRED');host['Dns']=[];changed=True
  intents[module]={'emptyDnsCreationIntentOnly':changed}
 require(new['candidates']==historical['candidates']and new['gatewayPackage']==historical['gatewayPackage']and new['selection']==historical['selection'],'CANDIDATE_OR_SELECTION_MUTATION_FORBIDDEN')
 return new_original,new,{'schema':'ouf.source-revision-postboot-successor-proof.v1','historicalOriginalSha256':digest(original),'historicalPrivateInputsSha256':digest(historical),'applicationProofs':proofs,'creationIntentProofs':intents,'engineGenerationExplicitlyRebound':True,'postgresGenerationExplicitlyRebound':True,'gatewayNamespaceExplicitlyRebound':True,'oldDocumentsModified':False,'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'readyForExecution':False}
