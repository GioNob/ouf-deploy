"""Release one reviewed stopped producer's retained bridge attachment.

Executor owns the one-use effect; sealed checkpoints prove old lease revocation,
fresh DB fencing, original peer/network custody and source/authority. No new
endpoint, container removal/start, network replacement or firewall write.
"""
import ipaddress,json,re
from engine_creation import digest,require

NETWORK_FIELDS=('Name','Id','Driver','Scope','EnableIPv6','Internal','Attachable','Ingress','IPAM','Options','Labels')

class EndpointAdapter:
    def __init__(self,engine,transition,intent,store):
        self.engine,self.transition,self.store=engine,transition,store
        self.intent=json.loads(json.dumps(intent,allow_nan=False))
        require(set(self.intent)=={'containerId','networkId','networkName','networkConfigurationHash','originalEndpointId','staticIpv4','macAddress','priorEvidencePhase'},'EXACT_ENDPOINT_RELEASE_INTENT_REQUIRED')
        for k in ('containerId','networkId','originalEndpointId','networkConfigurationHash'):
            require(type(self.intent[k]) is str and re.fullmatch('[0-9a-f]{64}',self.intent[k]) is not None,'EXACT_RETAINED_ENDPOINT_IDENTITIES_REQUIRED')
        require(type(self.intent['networkName']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',self.intent['networkName']) is not None
                and self.intent['priorEvidencePhase']=='QUIESCE_PRODUCERS','EXACT_RETAINED_NETWORK_SCOPE_REQUIRED')
        require(type(self.intent['staticIpv4']) is str and str(ipaddress.IPv4Address(self.intent['staticIpv4']))==self.intent['staticIpv4']
                and type(self.intent['macAddress']) is str and re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}',self.intent['macAddress']) is not None,'EXACT_RETAINED_IP_MAC_REQUIRED')
        self.intent_hash=digest(self.intent)
    def exact(self,intent):
        require(digest(intent)==self.intent_hash,'IMMUTABLE_ENDPOINT_RELEASE_INTENT_REQUIRED')
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']=='RELEASE_OLD_ENDPOINT'
                and row['effects'][-1]['intentHash']==self.intent_hash,'EXECUTOR_OWNED_ENDPOINT_INTENT_REQUIRED')
        require(row['effects'][2]['phase']=='FENCED_BACKUP' and row['effects'][2]['state']=='APPLIED','COMPLETED_BACKUP_BEFORE_ENDPOINT_RELEASE_REQUIRED')
        prior=row['effects'][1]
        require(prior['phase']=='QUIESCE_PRODUCERS' and prior['state']=='APPLIED','QUIESCED_PRODUCERS_BEFORE_ENDPOINT_RELEASE_REQUIRED')
        record=self.store.read('QUIESCE_PRODUCERS',prior['nativeEvidenceHash'])
        require(record.get('schema')=='ouf.semantic-inventoried-producers-quiesced.v1'
                and record.get('transitionContextHash')==self.transition.context,'CURRENT_QUIESCENCE_CONTEXT_REQUIRED')
        producers=[p for p in record['producers'] if p['containerId']==self.intent['containerId']]
        require(len(producers)==1,'EXACT_QUIESCED_ENDPOINT_OWNER_REQUIRED')
        producer=producers[0];initial=producer['initialNetworkSettings']
        require(digest(initial)==producer['initialRuntimeBinding']['networkSettingsHash'],'ORIGINAL_ENDPOINT_NETWORK_HASH_DRIFT')
        attachment=initial['Networks'].get(self.intent['networkName'])
        require(type(attachment) is dict and attachment.get('NetworkID')==self.intent['networkId']
                and attachment.get('EndpointID')==self.intent['originalEndpointId']
                and attachment.get('IPAddress')==self.intent['staticIpv4'] and attachment.get('MacAddress')==self.intent['macAddress']
                and type(attachment.get('IPAMConfig')) is dict and attachment['IPAMConfig'].get('IPv4Address')==self.intent['staticIpv4'],'SIGNED_INITIAL_ENDPOINT_BINDING_DRIFT')
        return producer
    def stopped(self,pin):
        status,actual=self.engine.request('GET','/v1.44/containers/'+self.intent['containerId']+'/json')
        require(status==200 and type(actual) is dict and actual['Id']==pin['containerId'] and actual['Image']==pin['imageId']
                and actual['State']['StartedAt']==pin['startedAt'] and actual['State']['FinishedAt']==pin['finishedAt']
                and actual['State']['Status']=='exited' and actual['State']['Running'] is False
                and actual['State']['Paused'] is False and actual['State']['Pid']==0 and actual['RestartCount']==pin['restartCount']
                and digest(actual['Config'])==pin['configHash'] and digest(actual['HostConfig'])==pin['hostConfigHash']
                and digest(actual['Mounts'])==pin['mountsHash'],'EXACT_STOPPED_ENDPOINT_OWNER_GENERATION_REQUIRED')
        return actual
    def network(self):
        status,network=self.engine.request('GET','/v1.44/networks/'+self.intent['networkId'])
        require(status==200 and type(network) is dict and network['Id']==self.intent['networkId']
                and network['Name']==self.intent['networkName'] and network['Driver']=='bridge'
                and digest({k:network.get(k) for k in NETWORK_FIELDS})==self.intent['networkConfigurationHash'], 'RETAINED_BRIDGE_NETWORK_CONFIGURATION_DRIFT')
        require(type(network.get('Containers')) is dict,'CURRENT_NETWORK_MEMBERSHIP_REQUIRED')
        for cid,endpoint in network['Containers'].items():
            require(type(endpoint) is dict,'CURRENT_NETWORK_ENDPOINT_SHAPE_REQUIRED')
            address=endpoint.get('IPv4Address','')
            matches_ip=bool(address) and str(ipaddress.ip_interface(address).ip)==self.intent['staticIpv4']
            matches_mac=endpoint.get('MacAddress','').lower()==self.intent['macAddress']
            if cid==self.intent['containerId']:
                require(endpoint.get('EndpointID')==self.intent['originalEndpointId'] and matches_ip and matches_mac,'RETAINED_ENDPOINT_GENERATION_DRIFT')
            else:require(not matches_ip and not matches_mac,'RETAINED_IP_OR_MAC_OWNED_BY_ANOTHER_ENDPOINT')
        return network
    def apply(self,intent):
        pin=self.exact(intent);actual=self.stopped(pin);network=self.network()
        attachment=actual['NetworkSettings']['Networks'].get(self.intent['networkName'])
        require(type(attachment) is dict and attachment.get('NetworkID')==self.intent['networkId']
                and type(attachment.get('IPAMConfig')) is dict
                and attachment['IPAMConfig'].get('IPv4Address')==self.intent['staticIpv4'], 'EXACT_RETAINED_STATIC_ATTACHMENT_REQUIRED')
        require(attachment.get('EndpointID','') in {'',self.intent['originalEndpointId']},'RETAINED_ATTACHMENT_ENDPOINT_IDENTITY_DRIFT')
        status,_=self.engine.request('POST','/v1.44/networks/'+self.intent['networkId']+'/disconnect',{'Container':self.intent['containerId'],'Force':False})
        require(status==200,'ENDPOINT_DISCONNECT_OUTCOME_REQUIRES_RECONCILIATION')
    def snapshot(self,pin):
        actual=self.stopped(pin);network=self.network()
        if self.intent['networkName'] in actual['NetworkSettings']['Networks'] or self.intent['containerId'] in network['Containers']:return None
        return {'schema':'ouf.semantic-old-endpoint-released.v1','transitionContextHash':self.transition.context,
                'intentHash':self.intent_hash,'containerId':self.intent['containerId'],'networkId':self.intent['networkId'],
                'networkConfigurationHash':self.intent['networkConfigurationHash'],'staticIpAndMacUnassigned':True,
                'retainedContainerStopped':True,'networkRemoved':False,'replacementCreated':False}
    def observe(self,intent):
        pin=self.exact(intent);before=self.snapshot(pin)
        if before is None:return 'UNKNOWN',{'retainedAttachmentStillPresent':True,'disconnectReplayAllowed':False}
        require(before==self.snapshot(pin),'RELEASED_ENDPOINT_STATE_CHANGED_DURING_READ')
        self.store.publish('RELEASE_OLD_ENDPOINT',before)
        return 'APPLIED',before
