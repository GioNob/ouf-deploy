"""Compile an unsigned two-role successor proposal from independent recipes.

No Engine request, observed OCI, signing key or mutable journal is consumed.
Historical rootfs seals in the receipt are never selected as new expectations.
Creation ownership, source custody, independent Semantic expectation approval,
new rootfs expectations and authority remain the caller/installer's obligations.
This module cannot install the resulting templates or authorize their execution.
"""
import copy
import hashlib
from pathlib import Path
import re
import types

from tools.semantic_frame_compiler.compile_creation_frame_policy import canonical,compile_policy,docker_context,require

ROLES=('adapter','southbound')
COORDINATION=('kernel','dns','coordinationBinding','coordinationJournal','lockFile')
TEMPLATE_FIELDS={'schema','pythonPath','pythonHash','commands','commandHashes','candidate',
                 *COORDINATION,'budgetSeconds','hostNetworkNamespace'}
PEER_SOURCE_SHA='4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b'


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def cid(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None
def reference(value):return type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value) is not None


def peer_compiler():
    # Reuse the cohort version that understands leaseGuard NICs. The older
    # sibling module deliberately remains unchanged, as do all frozen closures.
    path=Path(__file__).parent/'cohort-draft/tools/semantic_provider_peer_bindings.py'
    raw=path.read_bytes();require(hashlib.sha256(raw).hexdigest()==PEER_SOURCE_SHA,'PINNED_COHORT_PEER_SOURCE_REQUIRED')
    ns=types.ModuleType('successor_peer_dependency');ns.__file__=str(path)
    exec(compile(raw,str(path),'exec'),ns.__dict__)
    return ns


def successor_context(context,new_cid):
    docker_context(context);old=context['containerId']
    require(cid(new_cid) and new_cid!=old and context['networkNamespaceName'] is None
        and context['cgroupDriver']=='systemd','FRESH_PRIVATE_DOCKER_CONTEXT_REQUIRED')
    require(context['rootfsPath']==context['storageParent']+'/rootfs/overlayfs/'+old,
            'EXACT_REVIEWED_OVERLAYFS_CONTEXT_REQUIRED')
    following=copy.deepcopy(context)
    following.update(containerId=new_cid,rootfsPath=context['storageParent']+'/rootfs/overlayfs/'+new_cid)
    docker_context(following);return following


def _historical(receipt,inputs,recipes,peers):
    require(type(receipt) is dict and receipt.get('schema')=='ouf.discovery-generation-source-read.v1'
        and receipt.get('status')=='DISCOVERY_GENERATION_SOURCES_READ' and receipt.get('phase')=='COMPLETE'
        and receipt.get('runtimeObserved') is False and receipt.get('sourceFilesStableDuringRead') is True
        and receipt.get('newGenerationAdmitted') is False and receipt.get('startAuthorized') is False,
        'COMPLETED_SOURCE_RECEIPT_REQUIRED')
    require(set(receipt['roles'])==set(inputs)==set(recipes)==set(ROLES),'EXACT_TWO_ROLE_INPUTS_REQUIRED')
    old={};policies={}
    for role in ROLES:
        item=inputs[role];row=receipt['roles'][role];recipe=recipes[role]
        require(item.get('schema')=='ouf.discovery-role-generation-inputs.v1' and item.get('role')==role
            and item.get('state')=='UNSIGNED_INPUTS_ONLY' and item.get('historicalIdentityReuseAllowed') is False
            and item.get('runtimeConfigurationProduced') is False and item.get('startAuthorized') is False,
            'UNSIGNED_HISTORICAL_INPUT_REQUIRED')
        template=item['historicalTemplate'];require(set(template)==TEMPLATE_FIELDS
            and template['schema']=='ouf.semantic-admission-preparer-template.v1','EXACT_HISTORICAL_TEMPLATE_REQUIRED')
        candidate=template['candidate'];require(set(candidate)=={'containerId','transactionId','networkBindings',
            'transport','tableName','runtimeBinding'} and cid(candidate['containerId']),'EXACT_HISTORICAL_CANDIDATE_REQUIRED')
        require(set(recipe)=={'template','launch','context','policy'},'EXACT_INDEPENDENT_RECIPE_REQUIRED')
        policy=compile_policy(recipe['template'],recipe['launch'],recipe['context'])
        require(policy==recipe['policy'] and digest(policy)==row['installedPolicyBinding']['sha256']
            and digest(policy['expectedOci'])==row['installedApplicationHash']
            and row['independentRecipeRecompiled'] is True and row['originalDraftMatchesInstalledPolicy'] is True
            and row['originalDraftDifferencePaths']==[],'INDEPENDENT_INSTALLED_FRAME_REQUIRED')
        require(recipe['context']['containerId']==candidate['containerId']==row['historicalContainerId']
            and candidate['networkBindings']==row['networkBindings'] and candidate['tableName']==row['tableName']
            and digest(candidate['transport'])==row['transportSha256'],'HISTORICAL_TRANSPORT_OR_IDENTITY_DRIFT')
        require(len(candidate['networkBindings'])==(2 if role=='adapter' else 3),'EXACT_ROLE_NIC_COUNT_REQUIRED')
        peers.declaration({'containerId':candidate['containerId'],'applicationHash':row['installedApplicationHash'],
                           'networkBindings':candidate['networkBindings']})
        require(peers.declarations(candidate['transport'],candidate['containerId'])==row['peers'],
                'HISTORICAL_PEER_RECEIPT_DRIFT')
        old[role]=candidate;policies[role]=policy
    require(old['adapter']['containerId']!=old['southbound']['containerId'],'DISTINCT_HISTORICAL_ROLES_REQUIRED')
    for role,other in (('adapter','southbound'),('southbound','adapter')):
        require(receipt['roles'][role]['peers']==[{'containerId':old[other]['containerId'],
            'applicationHash':digest(policies[other]['expectedOci']),'networkBindings':old[other]['networkBindings']}],
            'EXACT_RECIPROCAL_HISTORICAL_COHORT_REQUIRED')
    return old


def compile_successor_pair(receipt,inputs,recipes,*,new_container_ids,new_transactions,semantic_declaration):
    """Return proposals only. Caller-supplied identities confer no ownership.

    semantic_declaration must eventually be bound to an independently compiled,
    explicitly accepted current Semantic OCI and a fresh native peer collection.
    This function checks the declaration's shape/scope, never that acceptance.
    """
    peers=peer_compiler();old=_historical(receipt,inputs,recipes,peers)
    require(set(new_container_ids)==set(new_transactions)==set(ROLES)
        and all(cid(v) for v in new_container_ids.values()) and len(set(new_container_ids.values()))==2,
        'TWO_DISTINCT_NEW_CONTAINER_IDENTITIES_REQUIRED')
    semantic=peers.declaration(semantic_declaration)
    all_cids=[old[r]['containerId'] for r in ROLES]+list(new_container_ids.values())+[semantic['containerId']]
    require(len(set(all_cids))==5,'HISTORICAL_OR_PEER_IDENTITY_REUSE_FORBIDDEN')
    old_transactions={old[r]['transactionId'] for r in ROLES}
    old_transactions.update(inputs[r]['historicalTemplate']['coordinationBinding']['transactionId'] for r in ROLES)
    selected=inputs['adapter']['successorCoordination']
    require(type(selected) is dict and set(selected)==set(COORDINATION)
        and selected==inputs['southbound']['successorCoordination'],'ONE_SUCCESSOR_COORDINATOR_REQUIRED')
    require({k:inputs['adapter']['historicalTemplate'][k] for k in COORDINATION}
        =={k:inputs['southbound']['historicalTemplate'][k] for k in COORDINATION},
        'ONE_HISTORICAL_COORDINATOR_REQUIRED')
    old_transactions.add(selected['coordinationBinding']['transactionId'])
    require(all(reference(v) and v not in old_transactions for v in new_transactions.values())
        and len(set(new_transactions.values()))==2,'FRESH_DISTINCT_ROLE_TRANSACTIONS_REQUIRED')
    for role in ROLES:
        previous=inputs[role]['historicalTemplate']
        require(all(selected[k]==previous[k] for k in ('kernel','dns','lockFile'))
            and selected['coordinationBinding']['transactionId']!=previous['coordinationBinding']['transactionId']
            and selected['coordinationJournal']!=previous['coordinationJournal'],
            'EXACT_SUCCESSOR_COORDINATION_SELECTION_REQUIRED')
    require(len(semantic['networkBindings'])==1,'ONE_CURRENT_SEMANTIC_BACKEND_NIC_REQUIRED')
    semantic_nic=semantic['networkBindings'][0]
    require(semantic_nic['ipv4']=='172.18.0.6' and semantic_nic['bridge']=='br-113b5f0a3c53'
        and 'leaseGuard' not in semantic_nic,'EXACT_SEMANTIC_BACKEND_SCOPE_REQUIRED')
    policies={};contexts={};declarations={}
    for role in ROLES:
        contexts[role]=successor_context(recipes[role]['context'],new_container_ids[role])
        policies[role]=compile_policy(recipes[role]['template'],recipes[role]['launch'],contexts[role])
        declarations[role]=peers.declaration({'containerId':new_container_ids[role],
            'applicationHash':digest(policies[role]['expectedOci']),'networkBindings':old[role]['networkBindings']})
    result={}
    for role,other in (('adapter','southbound'),('southbound','adapter')):
        template=copy.deepcopy(inputs[role]['historicalTemplate']);template.update(copy.deepcopy(selected))
        candidate=template['candidate'];candidate.update(containerId=new_container_ids[role],transactionId=new_transactions[role])
        expected_count=1 if role=='adapter' else 2
        require(len(candidate['transport'])==expected_count,'EXACT_SOURCE_FLOW_COUNT_REQUIRED')
        sibling=0;registry=0
        for flow in candidate['transport']:
            require(set(flow)=={'purpose','authorityRef','source','destination','protocol','port','peerIngress'},
                    'EXACT_SOURCE_TRANSPORT_FLOW_REQUIRED')
            peer=flow['peerIngress']
            if peer['kind']=='CREATED_CANDIDATE':
                require(peer['declaration']==receipt['roles'][role]['peers'][0]
                    and peer['bindingRef']==other+'-internal' and flow['purpose']=='GATEWAY_ADAPTER'
                    and flow['source']=='172.21.0.2' and flow['destination']=='172.21.0.3'
                    and flow['protocol']=='tcp' and flow['port']==9443,'EXACT_SIBLING_FLOW_REQUIRED')
                peer['declaration']=copy.deepcopy(declarations[other]);sibling+=1
            else:
                require(role=='southbound' and peer=={'kind':'BRIDGE_PORT','ifindex':1377}
                    and flow['purpose']=='WORKLOAD_GATEWAY' and flow['source']=='172.18.0.6'
                    and flow['destination']=='172.18.0.14' and flow['protocol']=='tcp' and flow['port']==10443,
                    'EXACT_HISTORICAL_SEMANTIC_FLOW_REQUIRED')
                flow['peerIngress']={'kind':'CREATED_CANDIDATE','declaration':copy.deepcopy(semantic),
                                     'bindingRef':semantic_nic['bindingRef']};registry+=1
        require(sibling==1 and registry==(0 if role=='adapter' else 1),'CLOSED_SUCCESSOR_FLOW_DELTA_REQUIRED')
        found=peers.declarations(candidate['transport'],candidate['containerId'])
        require(len(found)==expected_count,'COMPLETE_SUCCESSOR_PEER_DECLARATIONS_REQUIRED')
        result[role]={'dockerContext':contexts[role],'framePolicy':policies[role],
            'applicationHash':declarations[role]['applicationHash'],'artifactHash':digest(policies[role]),
            'preparerTemplate':template,'transportHash':digest({k:candidate[k] for k in ('networkBindings','transport','tableName')})}
    return {'schema':'ouf.discovery-successor-cohort-proposal.v1','sourceReceiptHash':digest(receipt),
        'roles':result,'semanticExpectedDeclaration':semantic,
        'creationOwnershipVerified':False,'inputCustodyAuthenticated':False,'semanticExpectationAuthenticated':False,
        'currentPeersObserved':False,'rootfsExpectationsProduced':False,'historicalRootfsSealsReused':False,
        'runtimeConfigurationProduced':False,'authorityIssued':False,'signaturesProduced':0,
        'providerAdmissionProven':False,'leaseAuthorized':False,'startAuthorized':False}
