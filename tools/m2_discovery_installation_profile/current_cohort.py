"""Current thirteen-peer runtime witness for a separately bound parent review.

Only bounded Engine GETs and native process metadata reads occur here. The
Registry, Gateway and MCP use their actual current owners; the other ten peers
retain the independently reviewed generations and complete configuration hashes.
This runtime witness does not prove DB, TLS, IAM, lease or complete admission.
"""
import copy,http.client,re,socket,stat,struct,time
from pathlib import Path
from .custody_capture import decode,digest,encoded,process_pin,require
from .private_review import hashed,absolute
from .parent_authority import review_scope
from .parent_review import REQUIRED_PROOFS
from .selected_runtime import DiscoverySelectedRuntime
from .mcp_runtime import McpReadiness
from .node_owner import ObservationBudget
from engine_creation import Engine
from gated_process_observation import RunningWorkloadBinding
from tools.semantic_provider_deployment_authentication import ancestors

REPLACED={'semantic','mcp','apisix'}
RETAINED={'onboarding','postgres','minio','keycloak','gateway-owner','udp','ingestion-evidence-read',
    'caddy','udp-evidence-read','ingestion'}
ROLES=REPLACED|RETAINED
BINDING_FIELDS={'containerId','imageId','pid','startedAt','configHash','hostConfigHash','mountsHash','networkSettingsHash'}
INPUT_SCHEMA='ouf.discovery-current-cohort-runtime-inputs.v1'
INPUT_SCHEMA_V2='ouf.discovery-current-cohort-runtime-inputs.v2'
ADDITIONAL_INPUTS={'databases','custody','tlsIam','retirementAndBackup'}
REVIEW_SCHEMA='ouf.discovery-current-cohort-runtime-review.v2'


def pin_shape(pin):
    require(type(pin) is dict and set(pin)=={'pid','startTicks','namespaces'}
        and all(type(pin[k]) is int and pin[k]>0 for k in ('pid','startTicks'))
        and type(pin['namespaces']) is dict and set(pin['namespaces'])=={'net','mnt'}
        and all(type(v) is list and len(v)==2 and all(type(i) is int and i>0 for i in v)
            for v in pin['namespaces'].values()),'EXACT_CURRENT_COHORT_PROCESS_PIN_REQUIRED')


def validate_inputs(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'bootId','engineBinding','rootProcessPins','peers'}
    require(type(inputs) is dict and inputs.get('schema') in (INPUT_SCHEMA,INPUT_SCHEMA_V2),
        'EXACT_CURRENT_COHORT_RUNTIME_INPUTS_VERSION_REQUIRED')
    if inputs['schema']==INPUT_SCHEMA_V2:
        fields.add('additionalInputsHashes');extra=inputs.get('additionalInputsHashes')
        require(type(extra) is dict and bool(extra) and set(extra)<=ADDITIONAL_INPUTS
            and all(hashed(v) for v in extra.values()),'EXACT_CURRENT_COHORT_ADDITIONAL_INPUT_BINDINGS_REQUIRED')
    require(set(inputs)==fields
        and all(hashed(inputs[k]) for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
        and type(inputs['bootId']) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',inputs['bootId'])
        and len(encoded(inputs))<=131072,'EXACT_CURRENT_COHORT_RUNTIME_INPUTS_REQUIRED')
    engine=inputs['engineBinding'];require(type(engine) is dict
        and set(engine)=={'socketPath','socketBinding','peerCredentials','startTicks'}
        and type(engine['socketBinding']) is list and len(engine['socketBinding'])==5
        and all(type(v) is int and v>=0 for v in engine['socketBinding'])
        and engine['socketBinding'][2]==0 and engine['socketBinding'][4] in (0o600,0o660)
        and type(engine['peerCredentials']) is list and len(engine['peerCredentials'])==3
        and all(type(v) is int for v in engine['peerCredentials']) and engine['peerCredentials'][0]>1
        and engine['peerCredentials'][1:]==[0,0] and type(engine['startTicks']) is int and engine['startTicks']>0,
        'EXACT_CURRENT_COHORT_ROOT_ENGINE_BINDING_REQUIRED');absolute(engine['socketPath'])
    roots=inputs['rootProcessPins'];require(type(roots) is dict and set(roots)=={'pid1','engine'},'CURRENT_COHORT_ROOT_PROCESS_PINS_REQUIRED')
    for p in roots.values():pin_shape(p)
    require(roots['pid1']['pid']==1 and roots['engine']['pid']==engine['peerCredentials'][0]
        and roots['engine']['startTicks']==engine['startTicks'],'CURRENT_COHORT_ENGINE_PROCESS_PIN_DRIFT')
    peers=inputs['peers'];require(type(peers) is dict and set(peers)==ROLES,'EXACT_THIRTEEN_CURRENT_COHORT_ROLES_REQUIRED')
    ids=set()
    for role,row in peers.items():
        require(type(row) is dict and set(row)=={'name','runtimeBinding','processPin'},'EXACT_CURRENT_COHORT_PEER_RECORD_REQUIRED')
        b=row['runtimeBinding'];pin_shape(row['processPin'])
        require(type(b) is dict and set(b)==BINDING_FIELDS
            and all(hashed(b[k]) for k in ('containerId','configHash','hostConfigHash','mountsHash','networkSettingsHash'))
            and type(b['imageId']) is str and re.fullmatch('sha256:[a-f0-9]{64}',b['imageId'])
            and type(b['pid']) is int and b['pid']>1 and b['pid']==row['processPin']['pid']
            and type(b['startedAt']) is str and 1<=len(b['startedAt'])<=128,'EXACT_CURRENT_COHORT_GENERATION_REQUIRED')
        expected='/ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role)
        require(row['name']==expected if role!='semantic' else bool(re.fullmatch('/ouf-semantic-cutover-[a-f0-9]{64}',row['name'])),
            'EXACT_CURRENT_COHORT_ROLE_NAME_REQUIRED')
        ids.add(b['containerId'])
    require(len(ids)==13,'THIRTEEN_DISTINCT_CURRENT_COHORT_CONTAINERS_REQUIRED')
    return digest(inputs)


def bind_runtime_review(review,inputs):
    """Pure new review version; original six-part compiler/child stay untouched."""
    review_scope(review);input_hash=validate_inputs(inputs);result=copy.deepcopy(review)
    component=result['components']['cohortInstallation'];requirements=component['currentAdmission']
    validate_requirements(requirements,component)
    require(requirements['schema']=='ouf.discovery-current-cohort-review-requirements.v1'
        and requirements['cohortManifestHash']==inputs['cohortManifestHash']
        and all(inputs[k]==component[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')),
        'SAME_PARENT_REVIEW_AND_CURRENT_COHORT_INPUTS_REQUIRED')
    component['currentAdmission']={'schema':REVIEW_SCHEMA,'requirements':copy.deepcopy(requirements),
        'nativeRuntimeInputsHash':input_hash,'peerCount':13,'retainedPeerCount':10,
        'mustBeCurrentAtExecution':True,'historicalEvidenceSufficient':False}
    review_scope(result);return result


def validate_requirements(value,component):
    fields={'schema','cohortManifestHash','registryCreationRequestHash','gatewayRuntimeHash','mcpComponentHash',
        'requiredProofs','mustBeCurrentAtExecution','historicalEvidenceSufficient'}
    require(type(value) is dict and set(value)==fields
        and value['schema']=='ouf.discovery-current-cohort-review-requirements.v1'
        and all(hashed(value[k]) for k in ('cohortManifestHash','registryCreationRequestHash','gatewayRuntimeHash','mcpComponentHash'))
        and value['gatewayRuntimeHash']==digest(component['gatewayRuntime']) and value['mcpComponentHash']==digest(component['mcp'])
        and value['requiredProofs']==REQUIRED_PROOFS and value['mustBeCurrentAtExecution'] is True
        and value['historicalEvidenceSufficient'] is False,'EXACT_COMPLETE_CURRENT_COHORT_REQUIREMENTS_REQUIRED')


class CurrentCohortEngine:
    """Fixed allowlist, maximum 26 GETs, no response spool or mutation API."""
    def __init__(self,engine,binding,ids,budget):
        require(type(engine) is Engine and type(budget) is ObservationBudget and len(ids)==13 and len(set(ids))==13
            and all(hashed(cid) for cid in ids),
            'ACTUAL_ENGINE_AND_THIRTEEN_COHORT_READ_TARGETS_REQUIRED')
        self.engine,self.binding,self.budget=engine,copy.deepcopy(binding),budget
        self.allowed={'/v1.44/containers/'+cid+'/json' for cid in ids};self.reads=0;self.total=0
    def guard(self):
        self.budget.check();self.engine.check_socket();e=self.binding
        require(self.engine.path==e['socketPath'] and list(self.engine.binding)==e['socketBinding']
            and process_pin(e['peerCredentials'][0])['startTicks']==e['startTicks'],
            'CURRENT_COHORT_ENGINE_BINDING_CHANGED')
        path=Path(e['socketPath']);ancestors(path);s=path.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0
            and [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==e['socketBinding'],
            'CURRENT_COHORT_ENGINE_SOCKET_CUSTODY_CHANGED')
    def get(self,cid):
        path='/v1.44/containers/'+cid+'/json';self.guard()
        require(path in self.allowed and self.reads<26,'CLOSED_CURRENT_COHORT_GET_ALLOWLIST_REQUIRED')
        reader=self
        class Local(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.sock.settimeout(reader.budget.remaining(2));connection.sock.connect(reader.binding['socketPath'])
                peer=list(struct.unpack('3i',connection.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==reader.binding['peerCredentials'],'CURRENT_COHORT_ENGINE_PEER_CREDENTIALS_CHANGED')
        client=Local('root-local-current-cohort');self.reads+=1
        try:
            client.request('GET',path,headers={'Connection':'close'});reply=client.getresponse();raw=reply.read(2097153)
            self.total+=len(raw)
            require(reply.status==200 and 0<len(raw)<=2097152 and self.total<=33554432,
                'BOUNDED_CURRENT_COHORT_ENGINE_RESPONSE_REQUIRED')
            value=decode(raw);self.guard();return value
        finally:client.close()


class CurrentCohortRuntime:
    def __init__(self,selected,inputs):
        require(type(selected) is DiscoverySelectedRuntime,'ACTUAL_SELECTED_DISCOVERY_RUNTIME_REQUIRED')
        self.selected=selected;self.inputs=copy.deepcopy(inputs);self.input_hash=validate_inputs(inputs)
        self.parent=selected.images.parent;self.ids=(id(selected),id(self.parent));self.guard()
    def guard(self):
        s=self.selected;component=s.images.component;admission=component['currentAdmission'];inputs=self.inputs
        require(self.ids==(id(s),id(self.parent)) and s.images.parent is self.parent
            and validate_inputs(inputs)==self.input_hash and admission=={
                'schema':REVIEW_SCHEMA,'requirements':admission.get('requirements'),
                'nativeRuntimeInputsHash':self.input_hash,'peerCount':13,'retainedPeerCount':10,
                'mustBeCurrentAtExecution':True,'historicalEvidenceSufficient':False}
            and admission['requirements']['schema']=='ouf.discovery-current-cohort-review-requirements.v1'
            and admission['requirements']['cohortManifestHash']==inputs['cohortManifestHash']
            and all(component[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')),
            'EXACT_PARENT_BOUND_CURRENT_COHORT_RUNTIME_REVIEW_REQUIRED')
        self.parent.guard('cohortInstallation',component);s.guard();app=s.installation.application
        validate_requirements(admission['requirements'],component)
        require(admission['requirements']['registryCreationRequestHash']==app.request_hash,
            'SAME_CURRENT_COHORT_REGISTRY_CREATION_REQUEST_REQUIRED')
        peers=inputs['peers'];require(peers['semantic']['runtimeBinding']['containerId']==app.intents['RELEASE_OLD_ENDPOINT']['containerId']
            and peers['mcp']['runtimeBinding']['containerId']==s.mcp.plan['replacement']['oldRuntimeBinding']['containerId']
            and peers['apisix']['runtimeBinding']['containerId']==s.gateway.plan['oldRuntimeBinding']['containerId'],
            'SAME_THREE_REVIEWED_OLD_COHORT_GENERATIONS_REQUIRED')
        quiesced={p['containerId'] for p in app.intents['QUIESCE_PRODUCERS']['producerBindings']}
        require(not quiesced&{peers[r]['runtimeBinding']['containerId'] for r in RETAINED},
            'RETAINED_CONTROL_PLANE_MUST_REMAIN_REACHABLE_AT_PUBLICATION_BARRIER')
    def roots(self):
        self.guard();i=self.inputs
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==i['bootId']
            and all(process_pin(p['pid'])==p for p in i['rootProcessPins'].values()),
            'CURRENT_COHORT_BOOT_OR_ROOT_PROCESS_GENERATION_CHANGED')
    def selected_now(self,budget):
        self.guard();s=self.selected;app=s.installation.application
        registry=RunningWorkloadBinding(app.node_owner.engine,app.transition,app.request,app.store).observe()
        gateway=s.gateway.generation();mcp=s.mcp.report()
        require(mcp['replacementVerified'] is True,'CURRENT_COMPLETED_MCP_REPLACEMENT_REQUIRED')
        ready=McpReadiness(s.mcp).prepare(time.monotonic()+budget.remaining(5))
        require(ready['runtimeBinding']==mcp['runtimeBinding'],'CURRENT_MCP_READINESS_GENERATION_CHANGED')
        return {'semantic':registry['runtimeBinding'],'apisix':Engine.runtime_binding(gateway),'mcp':mcp['runtimeBinding']}
    def observe(self):
        budget=ObservationBudget(90);s=self.selected;row=s.held();self.roots();selected=self.selected_now(budget)
        desired={r:(selected[r] if r in REPLACED else self.inputs['peers'][r]['runtimeBinding']) for r in ROLES}
        require(len({v['containerId'] for v in desired.values()})==13,'CURRENT_SELECTED_AND_RETAINED_GENERATIONS_MUST_BE_DISTINCT')
        reader=CurrentCohortEngine(s.images.engine,self.inputs['engineBinding'],[v['containerId'] for v in desired.values()],budget)
        def snapshot():
            result={}
            for role in sorted(ROLES):
                b=desired[role];actual=reader.get(b['containerId']);state=actual['State'];pin=process_pin(b['pid'])
                require(Engine.runtime_binding(actual)==b and state['Running'] is True and state['Paused'] is False
                    and state['Restarting'] is False and state['Status']=='running' and actual['RestartCount']==0,
                    'CURRENT_COHORT_CONFIGURATION_OR_RUNNING_GENERATION_CHANGED')
                if role in RETAINED:
                    require(actual['Name']==self.inputs['peers'][role]['name'] and pin==self.inputs['peers'][role]['processPin'],
                        'CURRENT_RETAINED_COHORT_NAME_OR_NATIVE_GENERATION_CHANGED')
                result[role]={'runtimeBindingHash':digest(b),'processPinHash':digest(pin)}
            return result
        first=snapshot();self.roots();require(self.selected_now(budget)==selected and snapshot()==first,
            'CURRENT_COHORT_CHANGED_DURING_TWO_PASS_OBSERVATION')
        self.roots();s.held(row);budget.check();require(reader.reads==26,'EXACT_TWO_PASS_THIRTEEN_PEER_OBSERVATION_REQUIRED')
        return {'schema':'ouf.discovery-current-thirteen-peer-runtime-witness.v1','nativeRuntimeInputsHash':self.input_hash,
            'heldHistoryHash':digest(row),'peerEvidenceHash':digest(first),'peerCount':13,'retainedPeerCount':10,
            'engineGets':26,'currentRuntimeRosterObserved':True,'fullCohortProven':False,
            'tlsIamDatabaseLeaseAdmissionProvenHere':False,'producerReleaseDispatched':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
