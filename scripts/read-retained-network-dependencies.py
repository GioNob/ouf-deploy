#!/usr/bin/env python3
"""Bounded current endpoint dependencies: no credentials, file reads or effects."""
import hashlib,importlib.util,ipaddress,json,re,sys,traceback
from pathlib import Path
from urllib.parse import urlsplit
spec=importlib.util.spec_from_file_location('startup',Path(__file__).with_name('read-retained-udp-startup.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FORMAT='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"env":{{json .Config.Env}},"networkMode":{{json .HostConfig.NetworkMode}},"bindings":{{json .HostConfig.PortBindings}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}'
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def dependencies(values):
 result=[];literal={ip:0 for ip in ('172.18.0.5','172.18.0.6')}
 for entry in values or []:
  key,sep,value=entry.partition('=');m.require(sep and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key),'ENVIRONMENT_SCHEMA')
  for ip in literal:literal[ip]+=len(re.findall(r'(?<![0-9.])'+re.escape(ip)+r'(?![0-9.])',value))
  for raw in re.findall(r'https?://[^\s\x22\x27<>\\]+',value):
   try:
    parsed=urlsplit(raw);host=parsed.hostname;port=parsed.port
   except ValueError:continue
   if host in ('ouf-apisix','ouf-minio','172.18.0.5','172.18.0.6'):
    result.append({'environmentKey':key,'host':host,'port':port,'scheme':parsed.scheme,'userinfoSuppressed':True})
 return {'references':result,'literalAddressCounts':literal,'environmentSha256':digest(values),'environmentValuesPrinted':False}
def collect():
 ids=[json.loads(line)for line in m.invoke(['ps','--no-trunc','--format','{{json .ID}}']).splitlines()if line]
 m.require(0<len(ids)<=24 and all(re.fullmatch('[a-f0-9]{64}',i)for i in ids),'LIVE_SCOPE_BOUND')
 rows=[json.loads(line)for line in m.invoke(['inspect','--type','container','--format',FORMAT,*ids]).splitlines()]
 m.require(len(rows)==len(ids),'LIVE_COUNT_CHANGED');output=[]
 for row in rows:
  m.require(row['id']in ids and re.fullmatch('/[A-Za-z0-9_.-]{1,128}',row['name']),'IDENTITY_SCHEMA')
  output.append({'containerId':row['id'],'name':row['name'],'imageId':row['image'],'dependencies':dependencies(row['env']),
   'endpointMetadataSha256':digest(row['networks']),'networkMode':row['networkMode'],'publishedPorts':m.ports(row.get('ports')),'declaredHostBindings':m.ports(row.get('bindings')),
   'endpointSettings':[{k:v.get(k)for k in ('NetworkID','IPAMConfig','Aliases','MacAddress','DriverOpts','GwPriority','IPAddress')}for v in row['networks'].values()]})
 return {'schema':'ouf.retained-network-dependency-read.v1','complete':True,'containers':output,'runtimeMutations':0,'credentialFilesRead':0,'credentialValuesPrinted':False,'automaticRetry':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=collect()
 except Exception as error:result={'schema':'ouf.retained-network-dependency-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
