"""Retained-installation UDP replacement; no configuration or domain changes."""
import copy,ipaddress,re
from tools.resolution_comparison_update.owner import require,digest
from tools.resolution_comparison_update.native import runtime
from image_custody import runtime_image_id

def replacement(saved,actual,image,case,module):
 require(module in('udp','onboarding')and saved.get('module')==module and saved.get('name')==actual.get('Name','')[1:],'RETAINED_UDP_CREATION_REQUIRED')
 require(actual['State']['Running']is True and actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==case['deployedSourceCommits'][module],'EXACT_DEPLOYED_UDP_SOURCE_REQUIRED')
 request=copy.deepcopy(saved['creationRequest']);config=actual['Config'];audit=image['imageAudit']
 require(all(config.get(k)==audit['imageConfig'].get(k)for k in('User','Entrypoint','Cmd','WorkingDir')),'UDP_NATIVE_PROCESS_CONTRACT_CHANGED')
 require(len(actual['NetworkSettings']['Networks'])==1,'ONE_RETAINED_UDP_NETWORK_REQUIRED')
 network,endpoint=next(iter(actual['NetworkSettings']['Networks'].items()));ip=str(ipaddress.IPv4Address(endpoint['IPAddress']));mac=endpoint['MacAddress']
 require(ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback and re.fullmatch('[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}',mac)and not endpoint.get('GlobalIPv6Address')and request['HostConfig']['NetworkMode']==network,'RETAINED_UDP_ENDPOINT_REQUIRED')
 require(re.fullmatch('[A-Za-z0-9_.-]{1,127}',saved['name'])and set(request['NetworkingConfig']['EndpointsConfig'])=={network},'RETAINED_UDP_NETWORK_SELECTION_REQUIRED')
 for key in('User','Entrypoint','Cmd','WorkingDir','Env','Labels','Healthcheck','StopSignal','StopTimeout'):
  if key in config:request[key]=copy.deepcopy(config[key])
 request['Image']=runtime_image_id(audit);request['Labels']={**(config.get('Labels')or{}),'org.opencontainers.image.revision':case['candidateSourceCommits'][module]}
 request['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
 previous=request['NetworkingConfig']['EndpointsConfig'][network]
 request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':endpoint['NetworkID'],'Aliases':copy.deepcopy(previous.get('Aliases')or[saved['name']]),'IPAMConfig':{'IPv4Address':ip},'MacAddress':mac}}}
 require(request['Env']==config['Env'],'UDP_ENVIRONMENT_CHANGED')
 selection=case['readiness'][module];require(set(selection)=={'readinessPort','readinessPath'}and type(selection['readinessPort'])is int and 1<=selection['readinessPort']<=65535 and selection['readinessPath']=='/actuator/health/readiness','EXACT_UDP_READINESS_SELECTION_REQUIRED')
 return {'name':saved['name'],'retiredName':saved['name']+'-resolution-retired-'+digest(case)[:12],'request':request,'oldRuntimeBinding':runtime(actual),'oldNativeHostConfig':copy.deepcopy(actual['HostConfig']),'oldMounts':copy.deepcopy(actual['Mounts']),'restoreRestartPolicy':copy.deepcopy(actual['HostConfig']['RestartPolicy']),'imageAudit':audit,'imageArchive':image['imageArchive'],'network':{'name':network,'id':endpoint['NetworkID'],'ip':ip,'mac':mac},'readiness':copy.deepcopy(selection)}

from tools.resolution_ths_update.plan import CONFIRM_SCHEMA

def confirmation_route(before):
 require(before.get('uri')=='/api/udp/v1/governance/resolution/issues/package/confirm'
  and before.get('methods')==['POST']and before['plugins']['openid-connect'].get('bearer_only')is True
  and before['plugins']['openid-connect'].get('required_scopes')==['resolution.match.approve']
  and 'configuration'in before['plugins']['request-validation']['body_schema'].get('required',[]),
  'EXACT_INHERITED_PREFLIGHT_CONFIRM_SCHEMA_REQUIRED')
 following=copy.deepcopy(before)
 following['plugins']['request-validation']['body_schema']=copy.deepcopy(CONFIRM_SCHEMA)
 return following
