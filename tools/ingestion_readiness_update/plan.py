"""Compile two exact native replacements and one absent Gateway GET route."""
import copy,ipaddress,re
from tools.semantic_mcp_update.owner import require,digest,encoded
from tools.semantic_mcp_update.plan import environment
MODULES=('onboarding','ingestion')
NO_RESTART={'Name':'no','MaximumRetryCount':0}
def compile_plan(review,binding,context,actuals,transport,routes,selection):
 require(review.get('schema')=='ouf.ingestion-readiness-update-private-review.v1'and digest(review)==binding['sha256']
  and review.get('readyForExecution')is False and review.get('runtimeAuthorityIssued')is False,
  'EXACT_PRIVATE_READINESS_REVIEW_REQUIRED')
 require(review['databaseMigrationsAllowed']is False and review['grantChangesAllowed']is False
  and review['semanticDispatchAllowed']is False,'READINESS_SCOPE_WIDENING_DENIED')
 route=copy.deepcopy(review['gateway']['proposedRoute']);rid=route['id']
 require(rid not in routes and route['methods']==['GET'],
  'ABSENT_SINGLE_GATEWAY_READ_ROUTE_REQUIRED')
 require(set(selection)==set(MODULES),'EXACT_APPLICATION_EXECUTION_SELECTION_REQUIRED')
 replacements={}
 for name in MODULES:
  src=review['images'][name];old=actuals[name];config=src['oldNativeConfig'];saved=src['retainedCreationRequest']
  require(old['Config']==config and old['HostConfig']==src['oldNativeHostConfig']
   and sorted(old['Mounts'],key=lambda m:m['Destination'])==sorted(src['oldNativeMounts'],key=lambda m:m['Destination'])
   and old['NetworkSettings']['Networks']==src['oldNativeNetworks'],'RETAINED_NATIVE_INPUT_CHANGED')
  networks=src['oldNativeNetworks'];require(len(networks)==1,'ONE_REVIEWED_APPLICATION_NETWORK_REQUIRED')
  network,endpoint=next(iter(networks.items()));ip=str(ipaddress.IPv4Address(endpoint['IPAddress']));mac=endpoint['MacAddress']
  require(ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback
   and re.fullmatch('[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}',mac)and not endpoint.get('GlobalIPv6Address')
   and saved['HostConfig']['NetworkMode']==network,'RETAINED_APPLICATION_ENDPOINT_REQUIRED')
  require(old['Name'].startswith('/')and re.fullmatch('[A-Za-z0-9_.-]{1,127}',old['Name'][1:]),'EXACT_NATIVE_CONTAINER_NAME_REQUIRED')
  request=copy.deepcopy(saved)
  # Preserve all reviewed creation fields and current native process overrides.
  for key in ('User','Entrypoint','Cmd','WorkingDir','Env','Labels','Healthcheck','StopSignal','StopTimeout'):
   if key in config:request[key]=copy.deepcopy(config[key])
  request['Image']=src['nativeImageId'];request['Labels']={**(config.get('Labels')or{}),
   'org.opencontainers.image.revision':review['candidateModules'][name]['sourceCommit']}
  request['HostConfig']['RestartPolicy']=copy.deepcopy(NO_RESTART)
  previous=saved['NetworkingConfig']['EndpointsConfig'][network]
  request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':endpoint['NetworkID'],
   'Aliases':copy.deepcopy(previous.get('Aliases')or[old['Name'][1:]]),'IPAMConfig':{'IPv4Address':ip},'MacAddress':mac}}}
  env=environment(config['Env']);require(environment(request['Env'])==env,'APPLICATION_ENVIRONMENT_CHANGED')
  selected=selection[name]
  require(set(selected)=={'readinessPort','readinessPath'}and type(selected['readinessPort'])is int
   and 1<=selected['readinessPort']<=65535 and selected['readinessPath']=='/actuator/health/readiness','EXACT_NATIVE_HEALTH_SELECTION_REQUIRED')
  replacements[name]={'name':old['Name'][1:],'retiredName':old['Name'][1:]+'-readiness-retired-'+binding['sha256'][:12],
   'request':request,'oldRuntimeBinding':copy.deepcopy(src['oldRuntimeBinding']),
   'oldNativeHostConfig':copy.deepcopy(src['oldNativeHostConfig']),'oldMounts':copy.deepcopy(src['oldNativeMounts']),
   'restoreRestartPolicy':copy.deepcopy(src['oldNativeHostConfig']['RestartPolicy']),
   'imageAudit':copy.deepcopy(src['imageAudit']),'imageArchive':copy.deepcopy(src['imageArchive']),
   'network':{'name':network,'id':endpoint['NetworkID'],'ip':ip,'mac':mac},'readiness':copy.deepcopy(selected)}
 plan={'schema':'ouf.ingestion-readiness-native-update-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':copy.deepcopy(binding),'engine':copy.deepcopy(review['engine']),'replacements':replacements,
  'gateway':{'transport':copy.deepcopy(transport),'beforeRoutes':copy.deepcopy(routes),'route':route,
   'projectionBinding':copy.deepcopy(review['gateway']['targetProjectionBinding'])},
  'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'automaticReplayAllowed':False,
  'databaseMigrationsAllowed':False,'grantChangesAllowed':False,'semanticDispatchAllowed':False,'automaticRollbackAllowed':False}
 plan['logicalUpdateRef']=digest({'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId']for r in replacements.values()),'routeId':rid})
 return plan
