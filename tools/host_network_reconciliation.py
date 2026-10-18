"""Finite host-administrator endpoint correction; no OUF issuance or job API.

Coordinates and identities are supplied by a versioned installation profile.
Every write has a durable claim. Unknown/ambiguous results stop for readback;
there is no automatic mutation retry or rollback.
"""
import copy,hashlib,http.client,ipaddress,json,os,re,socket,stat

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def identity(row,pin):
 require(row['Id']==pin['containerId']and row['Image']==pin['imageId']and row['Name']=='/'+pin['name'],'CONTAINER_IDENTITY_CHANGED')
 s=row['State'];require(not s['Paused']and not s['Restarting']and not s.get('Dead',False),'UNSTABLE_CONTAINER')
 require(not row['HostConfig'].get('Privileged')and not row['HostConfig'].get('AutoRemove'),'INDEPENDENT_RETAINED_CONTAINER_REQUIRED')
def immutable(row):return digest({k:row[k]for k in ('Id','Image','Name','Config','HostConfig','Mounts')})
def endpoint(row,network):
 require(network in row['NetworkSettings']['Networks'],'EXPECTED_NETWORK_MISSING')
 return row['NetworkSettings']['Networks'][network]
def other_networks(row,network):return digest({k:v for k,v in row['NetworkSettings']['Networks'].items()if k!=network})
def process(row):return {k:row['State'][k]for k in ('Pid','StartedAt','Running','Paused','Restarting')}
def validate_profile(p):
 require(set(p)=={'schema','engineVersion','socketPath','network','moves','restart','reservedIPv4','maximumContainers','configurationOwnerUids'}and p['schema']=='ouf.host-network-reconciliation.v1','CLOSED_PROFILE_REQUIRED')
 require(type(p['moves'])is list and 1<=len(p['moves'])<=8 and 1<=p['maximumContainers']<=160,'FINITE_SCOPE_REQUIRED')
 require(type(p['configurationOwnerUids'])is list and p['configurationOwnerUids']and all(type(v)is int and 0<=v<65536 for v in p['configurationOwnerUids']),'CONFIGURATION_UID_SCOPE_REQUIRED')
 n=p['network'];require(set(n)=={'name','id','subnet','gateway','internal'}and re.fullmatch('[a-f0-9]{64}',n['id'])and re.fullmatch('[A-Za-z0-9_.-]{1,128}',n['name']),'NETWORK_PROFILE_SCHEMA')
 subnet=ipaddress.IPv4Network(n['subnet']);gateway=ipaddress.IPv4Address(n['gateway'])
 require(gateway in subnet and type(n['internal'])is bool,'NETWORK_COORDINATES_REQUIRED')
 seen=set()
 for move in p['moves']:
  require(set(move)=={'containerId','imageId','name','oldIPv4','newIPv4','servicePorts','configurationDestinations'},'MOVE_PROFILE_SCHEMA')
  require(re.fullmatch('[a-f0-9]{64}',move['containerId'])and re.fullmatch('sha256:[a-f0-9]{64}',move['imageId'])and re.fullmatch('[A-Za-z0-9_.-]{1,128}',move['name']),'MOVE_IDENTITY_SCHEMA')
  old=ipaddress.IPv4Address(move['oldIPv4']);new=ipaddress.IPv4Address(move['newIPv4'])
  require(old in subnet and new in subnet and new not in (gateway,subnet.network_address,subnet.broadcast_address)and new not in seen and str(new)not in p['reservedIPv4'],'REVIEWED_NONRESERVED_MOVE_REQUIRED');seen.add(new)
  require(type(move['servicePorts'])is list and move['servicePorts']and all(type(v)is int and 0<v<65536 for v in move['servicePorts']),'SERVICE_PORT_SCOPE_REQUIRED')
  require(type(move['configurationDestinations'])is list and all(type(v)is str and v.startswith('/')and'..'not in v.split('/')for v in move['configurationDestinations']),'CONFIGURATION_DESTINATION_SCOPE_REQUIRED')
 require(len({m['containerId']for m in p['moves']})==len(p['moves']),'DISTINCT_MOVES_REQUIRED')
 require(set(p['restart'])=={'containerId','imageId','name'}and p['restart']['containerId']not in{m['containerId']for m in p['moves']},'EXACT_EXISTING_RESTART_REQUIRED')
 return p

def compile_plan(p,api,scan_configuration):
 validate_profile(p);n=p['network'];net=api.get('/networks/'+n['id'])
 require(net['Id']==n['id']and net['Name']==n['name']and net['Driver']=='bridge'and net['Internal']==n['internal']and not net['EnableIPv6'],'NETWORK_IDENTITY_CHANGED')
 require(net['IPAM']['Driver']=='default'and net['IPAM']['Config']==[{'Subnet':n['subnet'],'Gateway':n['gateway']}],'IPAM_PROFILE_CHANGED')
 fleet=api.get('/containers/json?all=1');require(0<len(fleet)<=p['maximumContainers'],'FLEET_BOUND')
 ids=[v['Id']for v in fleet];require(len(ids)==len(set(ids))and all(re.fullmatch('[a-f0-9]{64}',v)for v in ids),'FLEET_ID_SCHEMA')
 rows={cid:api.get('/containers/'+cid+'/json')for cid in ids};moves=[];new={m['newIPv4']for m in p['moves']}
 for cid,row in rows.items():
  value=row['NetworkSettings']['Networks'].get(n['name'])
  if value:
   if row['State']['Running']and not value.get('IPAMConfig'):require(cid in {move['containerId']for move in p['moves']},'UNREVIEWED_DYNAMIC_ENDPOINT_REMAINS')
   own={move['newIPv4']for move in p['moves']if move['containerId']==cid and move['oldIPv4']==move['newIPv4']};others=new-own
   require(value.get('IPAddress')not in others and(value.get('IPAMConfig')or{}).get('IPv4Address')not in others,'DESTINATION_ADDRESS_ALREADY_OWNED')
  if row['State']['Running']:scan_configuration(row,p)
 for pin in p['moves']:
  require(pin['containerId']in rows,'SELECTED_CONTAINER_MISSING');row=rows[pin['containerId']];identity(row,pin)
  for destination in pin['configurationDestinations']:
   selected=[v for v in row['Mounts']if v['Destination']==destination];require(len(selected)==1 and selected[0]['Type']=='bind'and selected[0].get('RW')is False,'RETAINED_CONFIGURATION_MOUNT_REQUIRED')
  require(row['State']['Running']and row['HostConfig'].get('NetworkMode')in row['NetworkSettings']['Networks'],'LIVE_INDEPENDENT_NETWORK_MODE_REQUIRED')
  e=endpoint(row,n['name']);require(e['NetworkID']==n['id']and e['IPAddress']==pin['oldIPv4']and not e.get('IPAMConfig')and not e.get('Links')and not e.get('DriverOpts')and e.get('GwPriority',0)==0,'EXACT_LEGACY_DYNAMIC_ENDPOINT_REQUIRED')
  require(not e.get('GlobalIPv6Address')and re.fullmatch('[a-f0-9]{2}(:[a-f0-9]{2}){5}',e['MacAddress']),'SINGLE_IPV4_ENDPOINT_REQUIRED')
  aliases=e.get('Aliases');require(aliases is None or(type(aliases)is list and all(re.fullmatch('[A-Za-z0-9_.-]{1,128}',a)for a in aliases)),'RETAINED_ALIAS_SCHEMA')
  request={'Container':row['Id'],'EndpointConfig':{'IPAMConfig':{'IPv4Address':pin['newIPv4']},'Aliases':copy.deepcopy(aliases),'MacAddress':e['MacAddress']}}
  moves.append({'pin':copy.deepcopy(pin),'before':row,'immutableHash':immutable(row),'otherNetworksHash':other_networks(row,n['name']),'process':process(row),'request':request})
 restart=rows.get(p['restart']['containerId']);require(restart is not None,'RESTART_TARGET_MISSING');identity(restart,p['restart'])
 require(not restart['State']['Running']and restart['State']['Status']=='exited'and restart['State']['Pid']==0 and not restart['State']['StartedAt'].startswith('0001-')and restart['HostConfig']['RestartPolicy']['Name']=='unless-stopped','STOPPED_RETAINED_RESTART_TARGET_REQUIRED')
 scan_configuration(restart,p)
 e=endpoint(restart,n['name']);require(e['NetworkID']==n['id']and(e.get('IPAMConfig')or{}).get('IPv4Address')in p['reservedIPv4'],'RETAINED_APPLICATION_RESERVATION_REQUIRED')
 unaffected={cid:{'immutable':immutable(row),'process':process(row),'networks':digest(row['NetworkSettings'])}for cid,row in rows.items()if cid not in {v['pin']['containerId']for v in moves}and cid!=restart['Id']}
 return {'schema':'ouf.host-network-reconciliation-plan.v1','profile':copy.deepcopy(p),'moves':moves,'restartBefore':restart,'unaffected':unaffected,'fleetIds':sorted(ids),'runtimeAuthorityIssued':False}

def verify_move(api,plan,move,disconnected=False,connected=False):
 row=api.get('/containers/'+move['pin']['containerId']+'/json');identity(row,move['pin']);n=plan['profile']['network']['name']
 require(immutable(row)==move['immutableHash']and process(row)==move['process']and other_networks(row,n)==move['otherNetworksHash'],'RETAINED_PROCESS_CONFIGURATION_OR_OTHER_NETWORK_CHANGED')
 if disconnected:require(n not in row['NetworkSettings']['Networks'],'DISCONNECT_NOT_PROVEN')
 else:
  e=endpoint(row,n);old=move['before']['NetworkSettings']['Networks'][n]
  if connected:
   require(e['IPAddress']==move['pin']['newIPv4']and e.get('IPAMConfig')=={'IPv4Address':move['pin']['newIPv4']}and e['MacAddress']==old['MacAddress']and set(e.get('Aliases')or[])==set(old.get('Aliases')or[])and e['NetworkID']==old['NetworkID']and e.get('GwPriority',0)==0,'EXACT_NEW_STATIC_ENDPOINT_NOT_PROVEN')
  else:require(e==old,'ENDPOINT_CHANGED_BEFORE_WRITE')
 return row

def apply(plan,api,claim):
 p=plan['profile'];n=p['network'];effects=0
 for index,move in enumerate(plan['moves']):
  verify_move(api,plan,move)
  claim('DISCONNECT_'+str(index),{'containerId':move['pin']['containerId'],'networkId':n['id']})
  try:api.write('/networks/'+n['id']+'/disconnect',{'Container':move['pin']['containerId'],'Force':False})
  except (TimeoutError,ConnectionError,http.client.HTTPException):verify_move(api,plan,move,disconnected=True)
  effects+=1
  verify_move(api,plan,move,disconnected=True)
  claim('CONNECT_'+str(index),move['request'])
  try:api.write('/networks/'+n['id']+'/connect',move['request'])
  except (TimeoutError,ConnectionError,http.client.HTTPException):verify_move(api,plan,move,connected=True)
  effects+=1
  verify_move(api,plan,move,connected=True)
 restart=api.get('/containers/'+p['restart']['containerId']+'/json');identity(restart,p['restart']);require(immutable(restart)==immutable(plan['restartBefore'])and not restart['State']['Running'],'RESTART_TARGET_CHANGED')
 claim('START_RETAINED_APPLICATION',{'containerId':restart['Id']})
 try:api.write('/containers/'+restart['Id']+'/start',None)
 except (TimeoutError,ConnectionError,http.client.HTTPException):
  observed=api.get('/containers/'+restart['Id']+'/json');identity(observed,p['restart']);require(immutable(observed)==immutable(restart)and observed['State']['Running'],'AMBIGUOUS_APPLICATION_START_NOT_PROVEN')
 effects+=1
 after=api.get('/containers/'+restart['Id']+'/json');identity(after,p['restart']);require(immutable(after)==immutable(restart)and after['State']['Running'],'RETAINED_APPLICATION_START_UNPROVEN')
 expected_ip=endpoint(restart,n['name'])['IPAMConfig']['IPv4Address'];actual_endpoint=endpoint(after,n['name']);require(actual_endpoint['IPAddress']==expected_ip and actual_endpoint.get('IPAMConfig')=={'IPv4Address':expected_ip},'RETAINED_APPLICATION_ADDRESS_UNPROVEN')
 for move in plan['moves']:verify_move(api,plan,move,connected=True)
 require(sorted(v['Id']for v in api.get('/containers/json?all=1'))==plan['fleetIds'],'FLEET_CHANGED_DURING_CORRECTION')
 for cid,pin in plan['unaffected'].items():
  row=api.get('/containers/'+cid+'/json');require({'immutable':immutable(row),'process':process(row),'networks':digest(row['NetworkSettings'])}==pin,'INDEPENDENT_CONTAINER_CHANGED')
 return {'schema':'ouf.host-network-reconciliation-result.v1','complete':True,'endpointCorrections':len(plan['moves']),'engineWrites':effects,'retainedApplicationRunning':True,'applicationReadinessProven':False,'providerReconciliationRequired':True,'sourceRevisionReleasePerformed':False,'runtimeAuthorityIssued':False,'explicitJobRetries':0,'existingWorkersMayResume':True,'profilePublications':0,'credentialValuesPrinted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}

class Engine:
 def __init__(self,path,version):
  require(os.path.isabs(path),'ABSOLUTE_SOCKET_REQUIRED');self.path=path;self.pin=self.socket_pin();v=self.request('GET','/version',None,False);require(v['Version']==version,'ENGINE_VERSION_CHANGED')
 def socket_pin(self):
  info=os.lstat(self.path);require(stat.S_ISSOCK(info.st_mode)and info.st_uid==0 and not info.st_mode&0o002,'ROOT_ENGINE_SOCKET_REQUIRED');return(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
 def request(self,method,path,value,versioned=True):
  require(self.socket_pin()==self.pin,'ENGINE_SOCKET_REPLACED')
  require(method in ('GET','POST')and(path=='/version'or path=='/containers/json?all=1'or re.fullmatch(r'/(?:containers|networks)/[a-f0-9]{64}(?:/(?:json|disconnect|connect|start))?',path)),'CLOSED_ENGINE_OPERATION_REQUIRED')
  outer=self
  class Connection(http.client.HTTPConnection):
   def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect(outer.path)
  c=Connection('localhost',timeout=15)
  try:
   c.request(method,('/v1.44'if versioned else'')+path,body=None if value is None else encoded(value),headers={'Content-Type':'application/json'});r=c.getresponse();raw=r.read(8388609)
   require(len(raw)<=8388608 and r.status in (200,201,204),'ENGINE_RESPONSE_UNPROVEN');return json.loads(raw)if raw else None
  finally:c.close()
 def get(self,path):return self.request('GET',path,None)
 def write(self,path,value):return self.request('POST',path,value)
