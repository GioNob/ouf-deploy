"""Pure scope compilation for a complete reviewed postboot recovery.

These data-only views let the existing scope builders hash the same reviewed
inputs without constructing native owners before a gate or token exists. They
are never passed to runtime constructors or used as admission evidence.
"""
from types import SimpleNamespace

from .core import digest, require
from .authorization import scope as recovery_scope
from .factory import factory_scope
from .read_budget import read_scope
from .bootstrap import bootstrap_scope, installation_scope
from .node_owner import node_scope
from .database import database_scope
from .gateway import gateway_scope
from .semantic_request import request_scope
from .admission import admission_scope
from tools.semantic_policy_token_owner.producer import Binding
from tools.semantic_registry_postboot_owner.contract import compile_scope, SCOPE as OWNER_SCOPE

KEYS = frozenset({
    'semanticRegistryRecovery', 'semanticRegistryRecoveryFactory',
    'semanticRegistryRecoveryReads', 'semanticRegistryPostbootBootstrap',
    'semanticRegistryPostbootInstallation', 'semanticRegistryPostbootOwner',
    'semanticRegistryRecoveryNode', 'semanticRegistryRecoveryDatabase',
    'semanticRegistryRecoveryGateway', 'semanticRegistryRecoveryOriginalRequest',
    'semanticRegistryRecoveryAdmission',
})


def compile_scopes(native_context, owner_context, registry_inputs, profile, boot_id):
    native = native_context
    plan, request = native['plan'], registry_inputs['creationRequest']
    require(native['database']['readiness'] == registry_inputs['readinessScope']
            and profile.verify(request) == profile.sha256
            and profile.configtree == registry_inputs['configtree'],
            'SAME_RETAINED_POSTBOOT_PROFILE_AND_DATABASE_INPUTS_REQUIRED')
    recipe = native['nodeRecipe']
    retained_recipe = registry_inputs['nodeRecipe']
    require(set(recipe) == set(retained_recipe)
            and all(recipe[k] == value for k, value in retained_recipe.items()
                    if k not in ('sourceClosureHash', 'renewableToken')),
            'POSTBOOT_REVIEW_CANNOT_CHANGE_INDEPENDENT_IMAGE_RECIPE')
    owner = compile_scope(owner_context)
    require(owner['recovery'] == {
                'planHash': digest(plan), 'logicalOperationRef': plan['logicalOperationRef'],
                'registryId': plan['stages'][0]['intent']['registryId'], 'bootId': boot_id}
            and owner_context['sourceClosureHash'] == recipe['sourceClosureHash'],
            'ONE_POSTBOOT_OWNER_PLAN_BOOT_AND_SOURCE_CLOSURE_REQUIRED')
    binding = Binding(**owner_context['ownerInputs']['binding'])
    token = recipe['renewableToken']
    retained_token = retained_recipe['renewableToken']
    require(type(token) is dict and set(token) == {
                'source', 'target', 'fileName', 'gid', 'directoryDevice', 'directoryInode',
                'ownerBindingHash', 'maxBytes', 'minimumRemainingSeconds'}
            and all(token[key] == retained_token[key]
                    for key in ('target', 'maxBytes', 'minimumRemainingSeconds')),
            'SAME_RETAINED_POSTBOOT_TOKEN_MOUNT_CONTRACT_REQUIRED')
    output = owner_context['ownerInputs']['outputDirectoryIdentity']
    require(token['source'] == binding.output_directory and token['fileName'] == binding.output_member
            and token['gid'] == binding.output_gid and token['ownerBindingHash'] == binding.digest()
            and token['directoryDevice'] == output['device'] and token['directoryInode'] == output['inode'],
            'SAME_POSTBOOT_REGISTRY_TOKEN_OUTPUT_AND_OWNER_REQUIRED')
    # Data-only scope views. Runtime constructors retain their exact-type gates.
    engine_view = SimpleNamespace(path=native['engineBinding']['socketPath'],
                                  binding=tuple(native['engineBinding']['socketBinding']))
    lifecycle_view = SimpleNamespace(plan=plan, engine=engine_view)
    db = native['database']
    database = database_scope(lifecycle_view, db['readiness'], db['postgres'], db['program'],
                              registry_inputs['imageAudit'])
    gw = native['gateway']
    gateway = gateway_scope(lifecycle_view, gw['pin'], gw['profile'], gw['routes'], gw['networkId'])
    node = node_scope(plan, recipe, profile)
    gateway_view = SimpleNamespace(lifecycle=lifecycle_view, scope=gateway)
    database_view = SimpleNamespace(lifecycle=lifecycle_view, scope=database)
    node_view = SimpleNamespace(scope=node, token_owner=SimpleNamespace(binding=binding))
    result = {
        'semanticRegistryRecovery': recovery_scope(plan),
        'semanticRegistryRecoveryFactory': factory_scope(native),
        'semanticRegistryRecoveryReads': read_scope(plan, native['executionRoot']),
        'semanticRegistryPostbootBootstrap': bootstrap_scope(plan, request, profile, boot_id),
        'semanticRegistryPostbootInstallation': installation_scope(native, request, profile, boot_id),
        OWNER_SCOPE: owner,
        'semanticRegistryRecoveryNode': node,
        'semanticRegistryRecoveryDatabase': database,
        'semanticRegistryRecoveryGateway': gateway,
        'semanticRegistryRecoveryOriginalRequest': request_scope(gateway_view, native['originalRequest']),
        'semanticRegistryRecoveryAdmission': admission_scope(database_view, node_view),
    }
    if owner_context.get('schema') == 'ouf.semantic-registry-postboot-successor-owner-context.v1':
        from .resumption import KEY, scope
        result[KEY] = scope(plan, owner_context)
    require(set(result) == (KEYS | {'semanticRegistryCheckpointResumption'}
            if owner_context.get('schema') == 'ouf.semantic-registry-postboot-successor-owner-context.v1' else KEYS),
            'COMPLETE_CLOSED_POSTBOOT_REVIEW_SCOPES_REQUIRED')
    return result
