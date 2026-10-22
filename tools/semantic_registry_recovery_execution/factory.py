"""Read-only construction from an exact reviewed private recovery context.

No directory/journal creation, authority issuance, key provisioning, source
execution, OAuth acquisition or effect dispatch occurs here. A sealed installer
must separately establish source custody and initialize the finite ledgers.
"""
import json
from pathlib import Path
from .core import require,digest,Store,Runner,validate_plan
from .authorization import AuthorityScope,cutover_type
from .read_budget import ReadBudget
from .lifecycle import Lifecycle,engine_type
from .node_owner import RecoveryNodeOwner
from .database import CurrentDatabase
from .admission import CurrentAdmission
from .gateway import CurrentGateway
from .semantic_request import OriginalSemanticRequest
from .native import NativePorts
from tools.ingestion_readiness_patch_execution import private_file

FIELDS={'schema','retainedInputs','plan','engineBinding','stoppedSnapshot','nodeRecipe','database',
    'gateway','originalRequest','executionRoot'}

def canonical_root(retained_path,logical):
    # The retained input was captured under this Ente's sealed evidence parent.
    # Derive the single sibling operation path; a caller cannot choose a second
    # parent while retaining the same consumed logical operation/claims.
    p=Path(retained_path)
    require(p.is_absolute() and str(p)==retained_path and '..' not in p.parts and len(p.parents)>=3,
        'EXACT_RETAINED_INPUT_PATH_FOR_CANONICAL_RECOVERY_REQUIRED')
    return p.parent.parent/('semantic-registry-recovery-'+logical)

def factory_scope(context):
    require(type(context) is dict and set(context)==FIELDS
        and context['schema']=='ouf.semantic-registry-recovery-native-context.v1',
        'EXACT_CURRENT_PRIVATE_RECOVERY_CONTEXT_REQUIRED')
    validate_plan(context['plan']);private_file.validate(context['retainedInputs'],maximum=8388608)
    root=canonical_root(context['retainedInputs']['path'],context['plan']['logicalOperationRef'])
    require(str(root)==context['executionRoot'],'SINGLE_CANONICAL_RECOVERY_ROOT_REQUIRED')
    return {'schema':'ouf.semantic-registry-recovery-factory-scope.v1','contextHash':digest(context),
        'planHash':digest(context['plan']),'retainedInputsHash':context['retainedInputs']['sha256'],
        'executionRoot':str(root),'originalClaimsRemainConsumed':True,'automaticInitializationAllowed':False}

def require_historical_parent(prepared,execution_root):
    original=Path(prepared['directoryPlan']['root'])
    require(original.is_absolute() and original.name=='registry' and '..' not in original.parts
        and Path(execution_root).parent==original.parent.parent,
        'RECOVERY_PARENT_MUST_BE_THE_RETAINED_INSTALLATION_EVIDENCE_PARENT')

def build(context,authority,raw,token_owner,verifier,signer):
    scope=factory_scope(context)
    require(type(authority) is cutover_type() and type(raw) is bytes
        and authority.expected['intakeHash']==scope['contextHash'] and authority(raw) is True
        and json.loads(raw).get('semanticRegistryRecoveryFactory')==scope,
        'CURRENT_HUMAN_REVIEWED_FACTORY_CONTEXT_AND_SIGNATURES_REQUIRED')
    with private_file.opened(context['retainedInputs'],maximum=8388608) as fd:
        import os
        data=bytearray()
        while len(data)<=8388608:
            block=os.read(fd,65536)
            if not block:break
            data.extend(block)
    def unique(pairs):
        result={}
        for k,v in pairs:require(k not in result,'DUPLICATE_RETAINED_RECOVERY_INPUT_KEY');result[k]=v
        return result
    retained=json.loads(data,object_pairs_hook=unique);plan=context['plan']
    require(retained['schema']=='ouf.semantic-registry-recovery-private-historical-inputs.v1'
        and retained['kind']=='OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY'
        and retained['candidateContract']==plan
        and digest(retained['historicalBinding'])==plan['stages'][0]['intent']['historicalChainHash']
        and digest(retained['proposal'])==plan['stages'][0]['intent']['proposalHash'],
        'SAME_RETAINED_HISTORY_PROPOSAL_AND_RECOVERY_PLAN_REQUIRED')
    prepared=retained['registryInputs'];request=prepared['creationRequest']
    require_historical_parent(prepared,context['executionRoot'])
    recipe=context['nodeRecipe'];historical_recipe=prepared['nodeRecipe']
    require(set(recipe)==set(historical_recipe)
        and all(recipe[k]==v for k,v in historical_recipe.items() if k not in ('sourceClosureHash','renewableToken')),
        'INDEPENDENT_HISTORICAL_IMAGE_FRAME_AND_ROOTFS_RECIPE_MUST_BE_PRESERVED')
    profile=authority.execution_profile;profile.verify(request)
    require(profile.configtree==prepared['configtree'],'SAME_REVIEWED_CONFIGTREE_PROFILE_REQUIRED')
    scoped=AuthorityScope(authority,raw,plan,request)
    store=Store(context['executionRoot'],plan['logicalOperationRef'])
    budget=ReadBudget(store,scoped,plan)
    b=context['engineBinding'];require(set(b)=={'socketPath','socketBinding'},'EXACT_CURRENT_ENGINE_BINDING_REQUIRED')
    engine=engine_type()(b['socketPath'],tuple(b['socketBinding']))
    lifecycle=Lifecycle(engine,scoped,store,plan,request,context['stoppedSnapshot'],retained['proposal'])
    node=RecoveryNodeOwner(lifecycle,profile,token_owner,verifier,signer,recipe)
    db=context['database'];require(set(db)=={'readiness','postgres','program'},'EXACT_CURRENT_DATABASE_CONTEXT_REQUIRED')
    require(db['readiness']==prepared['readinessScope'],'REVIEWED_DATABASE_READINESS_SCOPE_MUST_BE_PRESERVED')
    database=CurrentDatabase(lifecycle,db['readiness'],db['postgres'],db['program'],prepared['imageAudit'],budget)
    admission=CurrentAdmission(database,node)
    gw=context['gateway'];require(set(gw)=={'pin','profile','routes','networkId'},'EXACT_CURRENT_GATEWAY_CONTEXT_REQUIRED')
    gateway=CurrentGateway(lifecycle,gw['pin'],gw['profile'],gw['routes'],gw['networkId'],budget)
    semantic=OriginalSemanticRequest(gateway,context['originalRequest'])
    ports=NativePorts(lifecycle,admission,gateway,semantic)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(factory_scope(context)==scope and authority(raw) is True,'FACTORY_SCOPE_CHANGED_DURING_BUILD')
    return Runner(plan,store,ports,boot_id=boot)
