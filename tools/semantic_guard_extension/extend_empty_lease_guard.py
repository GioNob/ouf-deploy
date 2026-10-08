"""Extend one owned, quiescent guard without replacing tables or old handles.

Callers authenticate old configuration/structure and hold the shared lock.
An installer supplies the exact intended new compiler footprint, computed in an
isolated namespace. This module never starts workloads or creates authority.
"""
import copy
import hashlib
import json

class TransitionDenied(RuntimeError):
 def __init__(self,stage,reason,**details):
  self.diagnosis={'status':'BLOCKED','stage':stage,'reason':reason,**details,'secretValuesPrinted':False}
  super().__init__(reason)
def require(ok,stage,reason):
 if not ok:raise TransitionDenied(stage,reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def stable(v):
 if isinstance(v,list):return [stable(x) for x in v if not isinstance(x,dict) or 'metainfo' not in x]
 if isinstance(v,dict):return {k:stable(x) for k,x in v.items() if k not in ('handle','packets','bytes','expires')}
 return v

def extension(old,new):
 stage='VALIDATE_EXTENSION'
 require(set(old)==set(new)=={'tableName','guardedInterfaces','existingInterfaces','staticFlows','providerFlows'},stage,'EXACT_KERNEL_FIELDS_REQUIRED')
 require(all(old[k]==new[k] for k in old if k!='providerFlows'),stage,'NON_PROVIDER_SCOPE_CHANGED')
 previous=old['providerFlows'];following=new['providerFlows']
 require(len(following)==len(previous)+1 and following[:-1]==previous
  and all(v['addresses']==[] for v in following),stage,'EMPTY_APPEND_ONLY_FLOW_REQUIRED')
 flow=following[-1]
 require(set(flow)=={'endpointRef','endpoint','source','addresses','leaseSeconds','resolutionEvidenceRef','allowedPrivateAddresses'},stage,'EXACT_PROVIDER_FLOW_REQUIRED')
 # Caller also runs the frozen compiler over the full new kernel. No endpoint
 # string enters nft syntax; its validated port and canonical IPv4 source do.
 from urllib.parse import urlsplit
 import ipaddress,re
 endpoint=urlsplit(flow['endpoint']);source=ipaddress.ip_address(flow['source'])
 require(endpoint.scheme=='https' and endpoint.hostname and not(endpoint.username or endpoint.password or endpoint.query or endpoint.fragment)
  and (endpoint.port or 443)==443 and source.version==4 and str(source)==flow['source'],stage,'EXACT_HTTPS_IPV4_FLOW_REQUIRED')
 require(re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,31}',old['tableName']) is not None,stage,'TABLE_NAME_INVALID')
 return len(previous),str(source),443

def objects(tables,family,kind):return [r[kind] for r in tables[family]['nftables'] if kind in r]
def require_empty(tables):
 for family in ('inet','bridge'):
  require(not any(v.get('elem') for v in objects(tables,family,'set')),'OWNERSHIP','ACTIVE_LEASES_REQUIRE_QUIESCENCE')
def last_drop(tables,family,chain):
 rules=[v for v in objects(tables,family,'rule') if v['chain']==chain]
 require(rules and rules[-1]['expr'][-1]=={'drop':None} and type(rules[-1]['handle']) is int,'OWNERSHIP','FINAL_DROP_HANDLE_REQUIRED')
 return rules[-1]['handle']
def forward_rules(source,index):
 return [f'ip saddr {source} ip daddr @provider_{index} tcp dport 443 ct state {{ new, established }} counter accept',
  f'ip saddr @provider_{index} ip daddr {source} tcp sport 443 ct state established counter accept']
def patch(old,new,tables):
 index,source,_=extension(old,new);require_empty(tables);table=old['tableName'];lines=[]
 for family,chain in [('inet','governed_flows'),('bridge','governed_bridge_flows')]:
  handle=last_drop(tables,family,chain)
  lines.append(f'add set {family} {table} provider_{index} {{ type ipv4_addr; flags timeout; }}')
  lines.extend(f'insert rule {family} {table} {chain} position {handle} '+r for r in forward_rules(source,index))
 return '\n'.join(lines)+'\n'

def rollback(old,new,before,after):
 index,_,_=extension(old,new);require_empty(after);table=old['tableName'];lines=[]
 # Existing objects/handles must be unchanged. Never overwrite a foreign rule.
 for family in ('inet','bridge'):
  existing={(kind,v.get('handle')):v for kind in ('table','chain','set','rule') for v in objects(before,family,kind)}
  current={(kind,v.get('handle')):v for kind in ('table','chain','set','rule') for v in objects(after,family,kind)}
  require(all(k in current and stable(v)==stable(current[k]) for k,v in existing.items()),'ROLLBACK','OLD_OBJECT_CHANGED')
  added={k:v for k,v in current.items() if k not in existing}
  sets=[v for (kind,_),v in added.items() if kind=='set'];rules=[v for (kind,_),v in added.items() if kind=='rule']
  require(len(added)==3 and len(sets)==1 and sets[0]['name']==f'provider_{index}' and len(rules)==2,'ROLLBACK','UNEXPECTED_ADDED_OBJECTS')
  wanted='governed_flows' if family=='inet' else 'governed_bridge_flows'
  require(all(v['chain']==wanted and v['table']==table for v in rules),'ROLLBACK','ADDED_RULE_SCOPE_DRIFT')
  lines.extend(f'delete rule {family} {table} {wanted} handle '+str(v['handle']) for v in rules)
  lines.append(f'delete set {family} {table} provider_{index}')
 return '\n'.join(lines)+'\n'

def transition(old,new,backend,expected_footprint,publish,restore_publication,record):
 """Caller holds the common lock throughout native patch and file publication.

 publish receives new exact tables for structure binding and returns no authority.
 If publication fails, restore old profile files first, then remove only the six
 newly inserted objects and prove every old handle survived. A drift blocks
 rollback and is reported without removing foreign objects.
 """
 stage='OWNERSHIP';before=None;after=None;mutated=False;publication_attempted=False;native_attempted=False
 try:
  backend.verify_ownership(old);before=backend.tables();require_empty(before)
  raw=patch(old,new,before);record({'state':'APPLYING','oldStructureHash':backend.expected})
  stage='NATIVE_EXTENSION';native_attempted=True;backend.run(['-f','-'],raw);mutated=True
  stage='NATIVE_READBACK';after=backend.tables();require_empty(after)
  require(digest(stable(after))==expected_footprint,stage,'NEW_COMPILER_FOOTPRINT_DIFFERS')
  # Validate the exact removable delta before publishing any active pointer.
  rollback(old,new,before,after)
  stage='PROFILE_PUBLICATION';publication_attempted=True;publish(after)
  require(digest(stable(backend.tables()))==expected_footprint,'FINAL_READBACK','NATIVE_FOOTPRINT_CHANGED')
  record({'state':'INSTALLED','startAuthorized':False,'leaseAuthorized':False})
  return {'status':'EMPTY_GUARD_EXTENDED','originalHandlesPreserved':True,'providerFlowCount':len(new['providerFlows']),
   'leaseAuthorized':False,'startAuthorized':False,'containerLifecycleOperations':0}
 except Exception as error:
  diagnosis=getattr(error,'diagnosis',{'status':'BLOCKED','stage':stage,'reason':'BOUNDED_TRANSITION_FAILED','errorClass':type(error).__name__,'secretValuesPrinted':False})
  if native_attempted and not mutated:
   # A timeout can occur after the atomic nft transaction committed. Observe
   # the native result instead of claiming that no mutation happened.
   try:
    backend.verify_ownership(old)
   except Exception:
    mutated=True
  if mutated:
   try:
    if publication_attempted:restore_publication()
    current=backend.tables()
    require(digest(stable(current))==expected_footprint,'ROLLBACK','NEW_STRUCTURE_DRIFT')
    backend.run(['-f','-'],rollback(old,new,before,current))
    backend.verify_ownership(old)
    require_empty(backend.tables())
    diagnosis={**diagnosis,'rollback':'OLD_HANDLES_AND_FILES_RESTORED'}
   except Exception as recovery:
    diagnosis={**diagnosis,'rollback':'BLOCKED_FOREIGN_OR_UNPROVEN_STATE_PRESERVED',
     'rollbackReason':getattr(recovery,'diagnosis',{}).get('reason',type(recovery).__name__)}
  else:diagnosis={**diagnosis,'rollback':'NO_NATIVE_CHANGE'}
  record({'state':'BLOCKED','diagnosis':diagnosis,'startAuthorized':False})
  raise TransitionDenied(diagnosis['stage'],diagnosis['reason'],**{k:v for k,v in diagnosis.items() if k not in ('status','stage','reason','secretValuesPrinted')}) from None
