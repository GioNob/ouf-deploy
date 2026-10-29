"""Full read-only node observation for an Engine-paused, runc-paused workload.

No modification of the existing runc-created node contract. Shares its bounded
rootfs, peer, generation and configured-frame primitives. Signing/acceptance
requires a distinct paused-workload owner contract and independently approved
full OCI policy/rootfs; a digest or this unsigned report cannot grant it.
"""
import copy,hashlib,json,os
from pathlib import Path
import socket
from tools.m2_discovery_installation_profile.paused_binding import DiscoveryPausedWorkloadBinding as PausedWorkloadBinding
from tools.m2_discovery_installation_profile.observation import DiscoveryFrameObservation
from transition_journal import require,digest
from tools.semantic_provider_node_observation import NodeObservation,rootfs_seal
from tools.semantic_provider_deployment_authentication import ancestors,decode,CreatedFrameObserver
from tools.semantic_provider_deployment_admission import application_hash,live_profile,transport_hash
from tools.semantic_provider_deployment_producer import program
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_peer_bindings import declarations,collect
from projected_frame_observation import ProjectedFrameObservation

class DiscoveryNodeObservation(NodeObservation):
    def __init__(self,cfg,budget,paused_binding,frame_observer):
        require(os.geteuid()==0 and type(paused_binding) is PausedWorkloadBinding
            and type(frame_observer) is DiscoveryFrameObservation,'TYPED_ROOT_DISCOVERY_NODE_OBSERVATION_REQUIRED')
        require(set(cfg)=={'runtimeBinding','runtimeRootParents','bundleParents','commands','candidate','rootfsLimits'}
                and set(cfg['commands'])=={'ip','nsenter'} and set(cfg['candidate'])=={'networkBindings','transport','tableName'},'EXACT_PAUSED_NODE_OBSERVATION_CONFIGURATION_REQUIRED')
        for key in ('runtimeRootParents','bundleParents'):
            require(type(cfg[key]) is list and 1<=len(cfg[key])<=8
                    and all(type(p) is str and Path(p).is_absolute() and '..' not in Path(p).parts for p in cfg[key]),'EXPLICIT_PAUSED_NODE_PATH_PARENTS_REQUIRED')
        super().__init__(copy.deepcopy(cfg),budget);self.configuration_hash=digest(cfg);self.paused,self.frame=paused_binding,frame_observer;self.inputs={}
    def observe(self,request,context,bundle_reader):
        self.budget.check();require(digest(self.cfg)==self.configuration_hash,'PAUSED_NODE_CONFIGURATION_DRIFT');before=self.paused.observe();pin=before['runtimeBinding']
        require(set(context)=={'schema','transitionContextHash','creationRequestHash','stageEvidenceHash','runtimeRoot','bundleHash'}
                and context['schema']=='ouf.semantic-paused-node-context.v1'
                and all(context[k]==before[k] for k in ('transitionContextHash','creationRequestHash','stageEvidenceHash'))
                and request['containerId']==pin['containerId'] and request['generation']['pid']==pin['pid'],'EXACT_PAUSED_NODE_CONTEXT_AND_GENERATION_REQUIRED')
        root=Path(context['runtimeRoot']);ancestors(root/'state')
        require(root.is_absolute() and any(root!=Path(p) and root.is_relative_to(Path(p)) for p in self.cfg['runtimeRootParents']),'PAUSED_NODE_RUNTIME_ROOT_OUTSIDE_APPROVAL')
        state=decode(self.run(self.cfg['runtimeBinding'],['--root',str(root),'state',request['containerId']],16384),16384)
        native_contract=self.paused.verify_runc_state(state,before)
        bundle=Path(state['bundle']);ancestors(bundle/'config.json')
        require(bundle.is_absolute() and any(Path(p) in bundle.parents for p in self.cfg['bundleParents']),'PAUSED_NODE_BUNDLE_OUTSIDE_APPROVAL')
        raw=bundle_reader(bundle/'config.json');oci=decode(raw,131072)
        require(application_hash(oci)==request['applicationHash']==context['bundleHash'],'PAUSED_NODE_FULL_OCI_DRIFT')
        generation=NativeBackend.generation(None,state['pid'])
        require(generation==request['generation'],'PAUSED_NODE_GENERATION_DRIFT')
        # Exact expected OCI/source files come from the independently compiled,
        # source-bound policy; never manufacture that policy from this OCI.
        frame_hash,frame_inputs=self.frame.observe(generation,bundle/'config.json',request['applicationHash'],request['artifactHash'])
        root_path=Path(oci['root']['path']);root_path=root_path if root_path.is_absolute() else bundle/root_path
        require('..' not in root_path.parts,'PAUSED_NODE_ROOTFS_PATH_REQUIRED')
        seal=rootfs_seal(root_path,self.cfg['rootfsLimits'],self.budget)
        networks=[v for v in oci['linux']['namespaces'] if v.get('type')=='network'];require(len(networks)==1,'PAUSED_NODE_NETWORK_NAMESPACE_REQUIRED')
        namespace=networks[0].get('path') or '/proc/'+str(state['pid'])+'/ns/net'
        require(Path(namespace).stat().st_ino==generation['namespaceInode'],'PAUSED_NODE_NAMESPACE_INODE_DRIFT')
        ip=self.cfg['commands']['ip'];ns=self.cfg['commands']['nsenter']
        children=json.loads(self.run(ns,['--net='+namespace,ip['path'],'-j','addr','show']));children=[v for v in children if v['ifname']!='lo'];hosts=[]
        require(len(children)==len(self.cfg['candidate']['networkBindings']),'PAUSED_NODE_UNAPPROVED_INTERFACE')
        program(ip,self.budget)
        for child in children:
            name=socket.if_indextoname(child['link_index']);hosts.extend(json.loads(self.run(ip,['-j','link','show','dev',name])))
        candidate={**self.cfg['candidate'],'containerId':request['containerId'],'transactionId':request['transactionId'],'applicationHash':request['applicationHash'],'bundlePath':str(bundle)}
        require(transport_hash(candidate)==request['transportHash'],'PAUSED_NODE_TRANSPORT_DRIFT')
        peer_declarations=declarations(candidate['transport'],request['containerId'])
        def peer_bundle(path):
            path=Path(path);ancestors(path)
            require(path.name=='config.json' and any(Path(p) in path.parent.parents for p in self.cfg['bundleParents']),'PAUSED_NODE_PEER_BUNDLE_OUTSIDE_APPROVAL')
            return bundle_reader(path)
        peers={peer['containerId']:collect(peer,str(root),self.cfg['runtimeBinding'],self.cfg['commands'],self.run,peer_bundle,
                lambda pid:NativeBackend.generation(None,pid),self.budget) for peer in peer_declarations}
        live_profile(candidate,oci,namespace,generation['namespaceInode'],children,hosts,peers)
        require(NativeBackend.generation(None,state['pid'])==generation and self.paused.observe()==before
                and bundle_reader(bundle/'config.json')==raw,'PAUSED_NODE_CHANGED_DURING_COMPLETE_OBSERVATION')
        self.budget.check();require(digest(self.cfg)==self.configuration_hash,'PAUSED_NODE_CONFIGURATION_DRIFT');self.inputs.update(frame_inputs)
        return {'schema':'ouf.semantic-paused-node-observation.v1','applicationHash':request['applicationHash'],'rootfsSeal':seal,
                'generation':generation,'bundle':str(bundle),'rootfs':str(root_path),'state':state,'nativeStateContract':native_contract,
                'peerObservations':peers,'creationFrameHash':frame_hash,'frameInputHashes':{str(p):hashlib.sha256(raw).hexdigest() for p,raw in frame_inputs.items()},
                'policyAuthenticationProven':False,'imagePublisherProvenanceVerified':False,'completeCreationAccepted':False,
                'acceptanceGranted':False,'signaturesIssued':0,'startAuthorized':False}

