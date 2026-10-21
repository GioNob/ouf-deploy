"""Runner-only missing routing metadata. No private files or lifecycle changes."""
import json
import re
import subprocess

TARGETS={'gateway':'ouf-semantic','southbound':'1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'}
def run(args):
 p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
 if p.returncode or len(p.stdout)>131072:raise RuntimeError('BOUNDED_METADATA_COMMAND_FAILED')
 return json.loads(p.stdout)
def main():
 stage='DOCKER_NETWORK_METADATA'
 try:
  networks={}
  for role,target in TARGETS.items():
   rows=run(['/usr/bin/docker','inspect','--type','container','--format','{{json .NetworkSettings.Networks}}',target])
   if type(rows) is not dict or len(rows)>8:raise RuntimeError('BOUNDED_NETWORK_MAPPING_REQUIRED')
   networks[role]={name:{key:data.get(key) for key in ('NetworkID','IPAddress','MacAddress','Gateway','GwPriority')}
    for name,data in rows.items()}
  stage='HOST_UPLINK_METADATA'
  routes=run(['/usr/bin/ip','-j','route','get','46.38.225.230'])
  if len(routes)!=1 or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',routes[0].get('dev','')):raise RuntimeError('EXPLICIT_UPLINK_ROUTE_REQUIRED')
  route=routes[0];link=run(['/usr/bin/ip','-j','link','show','dev',route['dev']])
  if len(link)!=1 or type(link[0].get('ifindex')) is not int:raise RuntimeError('EXPLICIT_UPLINK_INDEX_REQUIRED')
  result={'schema':'ouf.semantic-target-network-metadata.v1','status':'NETWORK_METADATA_CAPTURED','networks':networks,
   'uplink':{'interface':route['dev'],'ifindex':link[0]['ifindex'],'gateway':route.get('gateway')},
   'configurationWrites':0,'containerLifecycleOperations':0,'privateFilesRead':0,'providerCalls':0,'secretValuesPrinted':False}
  print('OUF_TARGET_NETWORK_METADATA='+json.dumps(result,sort_keys=True))
 except Exception as error:
  reason=str(error) if isinstance(error,RuntimeError) else 'NETWORK_METADATA_UNAVAILABLE'
  print('OUF_TARGET_NETWORK_METADATA='+json.dumps({'status':'BLOCKED','stage':stage,'reason':reason,'errorClass':type(error).__name__,'secretValuesPrinted':False},sort_keys=True))
  raise SystemExit(1)
if __name__=='__main__':main()
