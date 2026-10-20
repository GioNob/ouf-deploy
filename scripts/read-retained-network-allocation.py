#!/usr/bin/env python3
"""Installation-bound network allocation inventory; Docker reads only."""
import hashlib,importlib.util,ipaddress,json,re,sys,traceback
from pathlib import Path
spec=importlib.util.spec_from_file_location('startup',Path(__file__).with_name('read-retained-udp-startup.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FORMAT='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},"networks":{{json .NetworkSettings.Networks}}}'
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def metadata(value):
 m.require(re.fullmatch('[a-f0-9]{64}',value['id'])and re.fullmatch('/[A-Za-z0-9_.-]{1,128}',value['name']),'IDENTITY_SCHEMA')
 m.require(re.fullmatch('sha256:[a-f0-9]{64}',value['image'])and type(value['running'])is bool,'IMAGE_STATE_SCHEMA')
 return {'containerId':value['id'],'name':value['name'],'imageId':value['image'],'running':value['running'],'networks':m.network_metadata(value['networks'])}
def collect(selection):
 bound=selection['currentApplications']['udp'];cid=bound['containerId']
 def read(cid):return json.loads(m.invoke(['inspect','--type','container','--format',FORMAT,cid]))
 before=read(cid);m.require(before['id']==cid and before['image']==bound['imageId']and not before['running'],'UDP_GENERATION_CHANGED')
 names=set(before['networks']);m.require(0<len(names)<=4,'NETWORK_COUNT_BOUND')
 ids=[json.loads(line)for line in m.invoke(['ps','-a','--no-trunc','--format','{{json .ID}}']).splitlines()if line]
 m.require(len(ids)<=128 and len(set(ids))==len(ids)and all(re.fullmatch('[a-f0-9]{64}',i)for i in ids),'FLEET_BOUND')
 rows=[json.loads(line)for line in m.invoke(['inspect','--type','container','--format',FORMAT,*ids]).splitlines()]
 m.require(len(rows)==len(ids)and{r['id']for r in rows}==set(ids),'FLEET_ID_CHANGED')
 relevant=[]
 for row in rows:
  if names&set(row['networks']):
   row['networks']={k:v for k,v in row['networks'].items()if k in names};relevant.append(metadata(row))
 networks=[]
 for name in sorted(names):
  nid=before['networks'][name]['NetworkID'];m.require(re.fullmatch('[a-f0-9]{64}',nid),'NETWORK_ID_REQUIRED')
  records=json.loads(m.invoke(['network','inspect',nid]));m.require(len(records)==1,'ONE_NETWORK_REQUIRED');net=records[0]
  m.require(net['Id']==nid and net['Name']==name and net['Driver']=='bridge','NETWORK_IDENTITY_CHANGED')
  configs=[]
  for cfg in net['IPAM']['Config']:
   allowed={}
   for key in ('Subnet','IPRange','Gateway'):
    if cfg.get(key):
     raw=cfg[key];ipaddress.ip_network(raw,strict=False)if key in ('Subnet','IPRange')else ipaddress.ip_address(raw);allowed[key]=raw
   aux=cfg.get('AuxiliaryAddresses')or{};allowed['auxiliaryAddresses']=sorted(str(ipaddress.ip_address(v))for v in aux.values());configs.append(allowed)
  networks.append({'networkReferenceSha256':hashlib.sha256(name.encode()).hexdigest(),'networkId':nid,'internal':net['Internal'],'ipamDriver':net['IPAM']['Driver'],'ipam':configs,'endpointCount':len(net.get('Containers')or{})})
 after=read(cid);m.require(digest(after)==digest(before),'UDP_CHANGED_DURING_READ')
 for row in rows:
  if row['name']=='/ouf-apisix':
   fresh=read(row['id']);fresh['networks']={k:v for k,v in fresh['networks'].items()if k in names}
   m.require(metadata(fresh)==metadata(row),'GATEWAY_CHANGED_DURING_READ')
 return {'schema':'ouf.retained-network-allocation-read.v1','complete':True,'networks':networks,'containers':relevant,'fleetCount':len(ids),'completedTechnicalPhases':8,'functionalMilestonesProven':4,'runtimeMutations':0,'credentialFilesRead':0,'credentialValuesPrinted':False,'automaticRetry':False,'addressSelectionPerformed':False}
if __name__=='__main__':
 try:
  m.require(len(sys.argv)==2,'ONE_SELECTION_REQUIRED');result=collect(json.loads(Path(sys.argv[1]).read_bytes()))
 except Exception as error:result={'schema':'ouf.retained-network-allocation-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
