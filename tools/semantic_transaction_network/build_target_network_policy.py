"""Pure target network assembly; no installation, signing, DNS or startup."""
import copy
import hashlib
import json

class NetworkDenied(ValueError):
 def __init__(self,reason):
  self.diagnosis={'status':'BLOCKED','stage':'BUILD_TARGET_NETWORK_POLICY','reason':reason,'secretValuesPrinted':False}
  super().__init__(reason)
def require(value,reason):
 if not value:raise NetworkDenied(reason)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def endpoint(value):
 require(set(value)=={'hostname','path','port'} and value['port']==443,'EXACT_HTTPS_ENDPOINT_REQUIRED')
 require(value['hostname'] in ('schema.gov.it','auth.ouf-lab.it'),'TARGET_ENDPOINT_DRIFT')
 return 'https://'+value['hostname']+value['path']
def dns_flows(profile,sources):
 import ipaddress
 require(set(profile)=={'resolvers','resolverPort','timeoutSeconds','maxLeaseSeconds','applyBudgetSeconds'},'EXACT_INSTALLATION_DNS_PROFILE_REQUIRED')
 resolvers=profile['resolvers']
 require(isinstance(resolvers,list) and 1<=len(resolvers)<=8 and len(set(resolvers))==len(resolvers)
  and profile['resolverPort']==53,'EXPLICIT_INSTALLATION_RESOLVERS_REQUIRED')
 for raw in resolvers:
  address=ipaddress.ip_address(raw)
  require(address.version==4 and str(address)==raw and not(address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified),'ROUTABLE_IPV4_RESOLVER_REQUIRED')
 # Private enterprise resolvers are accepted explicitly; no public-IP constant
 # is supplied by the code or silently inherited from the build runner.
 return [{'purpose':'DNS','source':source,'destination':resolver,'protocol':protocol,'port':53}
  for source in sources for resolver in resolvers for protocol in ('udp','tcp')]

def assemble(network_inputs,original_kernel,gateway_peer):
 """The caller must authenticate the actual original kernel, not the projection.

 Original addresses are omitted by the reader: the projection is never hashed
 as the original configuration. New leases are explicitly empty until fresh
 owner authorization. Existing shared bridges remain outside the global guard.
 """
 require(network_inputs['status']=='NETWORK_INPUTS_CAPTURED','CAPTURED_NETWORK_INPUTS_REQUIRED')
 projection=network_inputs['kernel']
 for key in ('tableName','guardedInterfaces','existingInterfaces','staticFlows'):
  require(original_kernel[key]==projection[key],'ORIGINAL_NETWORK_SCOPE_DRIFT')
 require(original_kernel['tableName']=='ouf_sem_provider'
  and set(original_kernel['guardedInterfaces'])=={'oufsp-int','oufsp-egress'}
  and not set(original_kernel['guardedInterfaces']) & set(original_kernel['existingInterfaces']), 'DEDICATED_GUARD_SCOPE_REQUIRED')
 require(len(original_kernel['providerFlows'])==1,'EXPECTED_ORIGINAL_PROVIDER_FLOW_REQUIRED')
 previous=original_kernel['providerFlows'][0]
 require({k:previous[k] for k in ('endpointRef','source','leaseSeconds','resolutionEvidenceRef','allowedPrivateAddresses')}
  =={k:projection['providerFlows'][0][k] for k in ('endpointRef','source','leaseSeconds','resolutionEvidenceRef','allowedPrivateAddresses')},'ORIGINAL_PROVIDER_SCOPE_DRIFT')
 require(previous['endpoint']==endpoint(network_inputs['providerEndpoint']) and previous['source']=='172.22.0.3'
  and previous['allowedPrivateAddresses']==[] and 1<=previous['leaseSeconds']<=30,'PROVIDER_DESTINATION_SCOPE_DRIFT')
 require(network_inputs['oidcIssuerEndpoint']=={'hostname':'auth.ouf-lab.it','path':'/realms/ouf','port':443},'OIDC_ISSUER_SCOPE_DRIFT')
 dns_profile=copy.deepcopy(network_inputs['dns'])
 expected_dns=dns_flows(dns_profile,['172.22.0.2','172.22.0.3'])
 require(sorted((v['source'],v['destination'],v['protocol'],v['port']) for v in original_kernel['staticFlows'] if v['purpose']=='DNS')
  ==sorted((v['source'],v['destination'],v['protocol'],v['port']) for v in expected_dns),'DNS_PROFILE_AND_NETWORK_FLOW_DRIFT')
 kernel=copy.deepcopy(original_kernel)
 kernel['providerFlows'][0]['addresses']=[]
 kernel['providerFlows'].append({'endpointRef':'ouf-oidc','endpoint':endpoint(network_inputs['oidcIssuerEndpoint']),
  'source':'172.22.0.2','addresses':[],'leaseSeconds':previous['leaseSeconds'],
  'resolutionEvidenceRef':previous['resolutionEvidenceRef'],'allowedPrivateAddresses':[]})
 require(gateway_peer['status']=='EXISTING_PEER_PORT_CAPTURED'
  and gateway_peer['container']=='ouf-semantic' and gateway_peer['address']=='172.18.0.6'
  and gateway_peer['mac']=='b2:96:a1:e2:c1:8d' and gateway_peer['bridge']=='br-113b5f0a3c53'
  and type(gateway_peer['hostIfindex']) is int and gateway_peer['hostIfindex']>1,'SEMANTIC_PEER_BINDING_REQUIRED')
 guard={'tableName':kernel['tableName'],'configurationHash':digest(kernel)}
 networks={}
 for role,suffix in (('adapter',3),('southbound',2)):
  networks[role]=[{'interface':iface,'bridge':bridge,'mac':f'02:42:ac:{octet}:00:0{suffix}',
   'ipv4':f'172.{subnet}.0.{suffix}','workloadRef':'ouf-semantic-'+role+'-v2','bindingRef':role+'-'+purpose,'leaseGuard':copy.deepcopy(guard)}
   for purpose,iface,bridge,subnet,octet in [('internal','oufint0','oufsp-int',21,'15'),('egress','oufeg0','oufsp-egress',22,'16')]]
 networks['southbound'].insert(0,{'interface':'oufback0','bridge':'br-113b5f0a3c53','mac':'02:42:ac:12:00:0e',
  'ipv4':'172.18.0.14','workloadRef':'ouf-semantic-southbound-v2','bindingRef':'southbound-backend'})
 flow={'purpose':'WORKLOAD_GATEWAY','authorityRef':'ouf-lab-infrastructure-installer',
  'source':'172.18.0.6','destination':'172.18.0.14','protocol':'tcp','port':10443,
  'peerIngress':{'kind':'BRIDGE_PORT','ifindex':gateway_peer['hostIfindex']}}
 return {'schema':'ouf.semantic-target-network-policy-draft.v1','status':'TARGET_NETWORK_POLICY_ASSEMBLED',
  'originalKernelHash':digest(original_kernel),'kernel':kernel,'dnsProfile':dns_profile,'networkBindings':networks,
  'semanticIngress':flow,'commonLockFile':network_inputs['commonLockFile'],
  'configurationWrites':0,'firewallWrites':0,'containerLifecycleOperations':0,'providerCalls':0,
  'startAuthorized':False,'acceptanceGranted':False,'bootMigrationImplemented':False}
