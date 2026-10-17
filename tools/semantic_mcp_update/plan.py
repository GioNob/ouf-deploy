"""Pure compiler for the exact one-component update; no host/network effects.

Bindings come from the sealed observer and versioned execution selection. The
caller must separately verify/issue metadata and obtain the exact signed action.
No credential, image, address or existing mount is silently substituted.
"""
import base64,copy,hashlib,ipaddress,json,re
from pathlib import Path
from urllib.parse import urlsplit
from tools.semantic_mcp_update.owner import require,digest

META_KEYS=('MCP_REPROCESSING_KEY_PROFILE_FILE','MCP_REPROCESSING_KEY_PROFILE_SHA256',
 'MCP_REPROCESSING_PERMIT_FILE','MCP_REPROCESSING_EXISTING_POLICY_FILE')

def environment(rows):
 require(type(rows)is list and len(rows)<=512,'BOUNDED_ENVIRONMENT_REQUIRED');result={}
 for row in rows:
  require(type(row)is str and '='in row,'ENVIRONMENT_ENTRY_REQUIRED');key,value=row.split('=',1)
  require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key)and key not in result,'UNIQUE_ENVIRONMENT_REQUIRED');result[key]=value
 return result

def private_path(value):
 require(type(value)is str and Path(value).is_absolute()and str(Path(value))==value
  and '..'not in Path(value).parts and not any(c in value for c in(':','\0','\n','\r')),'EXACT_PRIVATE_PATH_REQUIRED')
 return Path(value)

def metadata_binding(files,claim,history):
 require(type(files)is dict and set(files)=={'profile.json','policy.json','permit.json'}
  and all(type(v)is str and 0<len(v.encode())<=65536 for v in files.values()),'EXACT_PUBLIC_METADATA_REQUIRED')
 def unique(rows):
  result={}
  for k,v in rows:require(k not in result,'DUPLICATE_METADATA_FIELD');result[k]=v
  return result
 profile=json.loads(files['profile.json'],object_pairs_hook=unique);policy=json.loads(files['policy.json'],object_pairs_hook=unique)
 envelope=json.loads(files['permit.json'],object_pairs_hook=unique)
 raw=base64.b64decode(envelope['payload'],validate=True);permit=json.loads(raw,object_pairs_hook=unique)
 h=lambda raw:hashlib.sha256(raw).hexdigest()
 require(profile.get('schema')=='ouf.mcp-reprocessing-key-profile.v1'
  and profile.get('trustPolicyHash')==h(files['policy.json'].encode())
  and policy.get('installationRef')==profile.get('installationRef')and policy.get('entityRef')==profile.get('entityRef')
  and permit.get('schema')=='ouf.mcp-semantic-reprocessing-session.v1'
  and permit.get('keyProfileHash')==h(files['profile.json'].encode())
  and permit.get('installationRef')==profile.get('installationRef')
  and permit.get('manifestChecksum')==claim['manifestChecksum']
  and permit.get('predecessorAttemptId')==claim['attemptId']and permit.get('predecessorLockVersion')==claim['lockVersion']
  and permit.get('requestHash')==claim['requestHash']and permit.get('servicePrincipalId')==claim['servicePrincipalId']
  and permit.get('humanSubject')==history['humanSubject']and permit.get('tenantId')==history['tenant']
  and permit.get('commandKey')==history['semanticCommandKey']and permit.get('capabilityId')=='ouf.semantic.propose'
  and permit.get('owner')=='semantic'and permit.get('operationClass')=='COMMAND'
  and all(type(permit.get(k))is int for k in('priorToolCalls','maximumNewToolCalls','maximumCumulativeToolCalls'))
  and permit.get('priorToolCalls')==permit.get('maximumNewToolCalls')==1
  and permit.get('maximumCumulativeToolCalls')==2,'EXACT_REPROCESSING_METADATA_SCOPE_REQUIRED')
 for field,role in(('intent','DEPLOYMENT_INTENT'),('approval','FINAL_DEPLOYMENT_APPROVAL')):
  header=envelope[field]
  require(header.get('payloadHash')==h(raw)and header.get('keyRef')==profile.get('installerKeyRef')
   and header.get('role')==role and header.get('issuerRef')==profile.get('intentIssuerRef'if field=='intent'else'approvalIssuerRef')
   and re.fullmatch('[0-9a-f]{128}',str(header.get('signature',''))),'EXISTING_TWO_ROLE_METADATA_REQUIRED')
 return h(files['profile.json'].encode()),permit


def compile_plan(review,review_binding,directory,selection,files,admin_url):
 require(review.get('schema')=='ouf.mcp-one-component-update-private-review.v2'
  and review.get('readyForExecution')is False and review.get('runtimeAuthorityIssued')is False
  and digest(review)==review_binding.get('sha256'),'EXACT_UNEXECUTED_PRIVATE_REVIEW_REQUIRED')
 root=private_path(str(directory));private_path(review_binding['path'])
 require(root.parent==Path(review_binding['path']).parent.parent
  and re.fullmatch('semantic-mcp-update-execution-[A-Za-z0-9_-]{8,64}',root.name),'SAME_PRIVATE_SNAPSHOT_PARENT_REQUIRED')
 require(set(selection)=={'schema','oldContainerName','metadataMountTarget','readinessPort'}
  and selection['schema']=='ouf.mcp-single-update-execution-selection.v1'
  and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,126}',selection['oldContainerName'])
  and type(selection['readinessPort'])is int and 1<=selection['readinessPort']<=65535,'EXACT_VERSIONED_EXECUTION_SELECTION_REQUIRED')
 target=private_path(selection['metadataMountTarget']);require(str(target).startswith('/run/'),'PUBLIC_METADATA_RUN_MOUNT_REQUIRED')
 old=review['oldNativeConfig'];retained=review['retainedApplicationCreationRequest'];request=copy.deepcopy(retained)
 require(old['User']=='10005:10005'and old['Entrypoint']==['/usr/local/bin/ouf-mcp']
  and old['Cmd']in(['server'],['server','--http',':'+str(selection['readinessPort'])]),'RETAINED_MCP_SERVER_PROCESS_REQUIRED')
 if old['Cmd']==['server']:require(selection['readinessPort']==8080,'NATIVE_DEFAULT_SERVER_PORT_REQUIRED')
 profile_hash,permit=metadata_binding(files,review['retainedClaim'],review['history'])
 existing=environment(old['Env']);require(not set(META_KEYS)&set(existing),'REPROCESSING_MUST_BE_UNCONFIGURED_BEFORE_UPDATE')
 db=review['database']['binding'];application=urlsplit(existing['MCP_DATABASE_URL']);admin=urlsplit(admin_url)
 require(application.scheme in('postgres','postgresql')and admin.scheme==application.scheme
  and application.username==db['user']and admin.username==review['database']['backupReader']
  and application.hostname and admin.hostname==application.hostname and admin.port==application.port
  and admin.path==application.path=='/'+db['database']and admin.query==application.query
  and not admin.fragment and not application.fragment and bool(admin.password),'SAME_REVIEWED_DATABASE_ADMIN_CHANNEL_REQUIRED')
 networks=review['oldNativeNetworks'];require(len(networks)==1,'ONE_REVIEWED_MCP_NETWORK_REQUIRED')
 name,endpoint=next(iter(networks.items()));ip=str(ipaddress.IPv4Address(endpoint['IPAddress']));mac=endpoint['MacAddress']
 require(re.fullmatch('[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}',mac)
  and not endpoint.get('GlobalIPv6Address')and retained['HostConfig']['NetworkMode']==name,'RETAINED_IPV4_NETWORK_REQUIRED')
 require(all(not(str(target)==m['Destination']or str(target).startswith(m['Destination'].rstrip('/')+'/')
  or m['Destination'].startswith(str(target)+'/'))for m in review['oldNativeMounts']),'METADATA_MOUNT_OVERLAP_DENIED')
 native=review['imageImport']['nativeImageId'];audit=review['imageAudit']
 require(native in(audit.get('imageId'),(audit.get('nativeIdentity')or{}).get('nativeImageId'))
  and review['migrationContract']['command']=='migrate-semantic-reprocessing'
  and review['migrationContract']['committedMembershipAllowed']is False,'EXACT_NATIVE_ATOMIC_IMAGE_REQUIRED')
 metadata={'directory':str(root/'public'),'target':str(target),'gid':10005,'files':copy.deepcopy(files)}
 additions=dict(zip(META_KEYS,(str(target/'profile.json'),profile_hash,str(target/'permit.json'),str(target/'policy.json'))))
 request.update(Image=native,User=old['User'],Entrypoint=copy.deepcopy(old['Entrypoint']),Cmd=copy.deepcopy(old['Cmd']),
  WorkingDir=old['WorkingDir'],Env=[k+'='+v for k,v in{**existing,**additions}.items()])
 request['Labels']={**old.get('Labels',{}),'org.opencontainers.image.revision':review['imagePackage']['sourceCommit']}
 request['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
 binds=request['HostConfig'].get('Binds')or[];require(type(binds)is list,'EXACT_RETAINED_BINDS_REQUIRED')
 request['HostConfig']['Binds']=[*binds,metadata['directory']+':'+metadata['target']+':ro']
 original=(retained.get('NetworkingConfig',{}).get('EndpointsConfig')or{}).get(name,{})
 request['NetworkingConfig']={'EndpointsConfig':{name:{'NetworkID':endpoint['NetworkID'],
  'Aliases':copy.deepcopy(original.get('Aliases')or[selection['oldContainerName']]),
  'IPAMConfig':{'IPv4Address':ip},'MacAddress':mac}}}
 old_pin=copy.deepcopy(review['oldRuntimeBinding'])
 require(digest(sorted(review['oldNativeMounts'],key=lambda m:m['Destination']))==old_pin['mountsHash'],
  'PRIVATE_REVIEW_MOUNTS_BINDING_REQUIRED')
 old_pin['mountsHash']=digest(review['oldNativeMounts'])
 migrator_host={'NetworkMode':name,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'ReadonlyRootfs':True,'AutoRemove':False}
 migration_request={'Image':native,'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
  'Cmd':['migrate-semantic-reprocessing'],'WorkingDir':'/app','Env':['MCP_DATABASE_URL='+admin_url,
   'MCP_MIGRATION_APPLICATION_ROLE='+db['user'],'MCP_MIGRATION_DATABASE_OID='+str(db['databaseOid']),
   'MCP_MIGRATION_RETENTION_FUNCTION_SHA256='+review['rolePreflight']['retentionFunctionHash']],
  'HostConfig':migrator_host,'NetworkingConfig':{'EndpointsConfig':{name:{'NetworkID':endpoint['NetworkID']}}}}
 suffix=review_binding['sha256'][:16]
 plan={'schema':'ouf.mcp-single-update-execution-plan.v1','authorityDirectory':str(root),
  'predecessorReviewPath':review_binding['path'],'predecessorReviewHash':review_binding['sha256'],
  'oldRuntimeBinding':old_pin,'oldHostConfig':copy.deepcopy(review['oldNativeHostConfig']),
  'oldMounts':copy.deepcopy(review['oldNativeMounts']),'postgresRuntimeBinding':copy.deepcopy(review['database']['postgresRuntimeBinding']),
  'engine':copy.deepcopy(review['engine']),'programs':copy.deepcopy(review['programs']),
  'metadata':metadata,'imageAudit':copy.deepcopy(audit),'imageImport':{'path':review['imageImport']['archivePath']},
  'database':{'name':db['database'],'admin':review['database']['backupReader'],'oid':db['databaseOid'],
   'before':copy.deepcopy(review['database']['before']),'after':copy.deepcopy(review['database']['after']),
   'backupPath':str(root/'backup.dump'),'maximumBackupBytes':review['database']['maximumBackupBytes']},
  'retainedClaim':copy.deepcopy(review['retainedClaim']),
  'migration':{'name':'ouf-mcp-migration-'+suffix,'request':migration_request,
   'command':'migrate-semantic-reprocessing','committedMembershipAllowed':False},
  'replacement':{'name':selection['oldContainerName'],'retiredName':'ouf-mcp-retired-'+suffix,'request':request,
   'restoreRestartPolicy':copy.deepcopy(review['oldNativeHostConfig']['RestartPolicy'])},
  'network':{'name':name,'id':endpoint['NetworkID'],'ip':ip,'mac':mac},
  'readiness':{'port':selection['readinessPort'],'path':'/health/ready'},'permitExpiresAt':permit['expiresAt'],
  'maximumExecutionSeconds':900,'automaticRollbackAllowed':False,'databaseRestoreAllowed':False,'semanticDispatchAllowed':False}
 plan['logicalUpdateRef']=digest({'oldContainerId':old_pin['containerId'],'databaseOid':db['databaseOid'],
  'predecessorAttemptId':plan['retainedClaim']['attemptId']})
 return plan
