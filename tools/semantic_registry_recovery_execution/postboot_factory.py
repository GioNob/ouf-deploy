"""Resume full native admission on the exact gate-only recovery instance.

No ledger initialization, first-grant replay, authority issuance, token request
or lifecycle effect occurs here. The new owner observer must already prove a
current publication. All original OCI/rootfs/mount/database/service-read owners
remain responsible for their existing checks after the gate-only prefix.
"""
from .core import Runner, digest, require
from .bootstrap import BootstrapPorts
from .factory import current_scope
from .node_owner import RecoveryNodeOwner
from .database import CurrentDatabase
from .admission import CurrentAdmission
from .semantic_request import OriginalSemanticRequest
from .native import NativePorts
from .token_observer import guard_lease


def build_on_bootstrap(bootstrap_runner, context, owner_context, authority, raw, verifier, signer):
    require(type(bootstrap_runner) is Runner and type(bootstrap_runner.ports) is BootstrapPorts,
            'ACTUAL_EXISTING_BOOTSTRAP_RUNNER_REQUIRED')
    prefix = bootstrap_runner.ports
    lifecycle = prefix.lifecycle
    row = lifecycle.journal()
    require(4 <= row['nextStage'] <= 12 and lifecycle.store is bootstrap_runner.store
            and authority is lifecycle.authority.authority and raw == lifecycle.authority.raw,
            'SAME_PAUSED_POSTBOOT_STORE_AND_CURRENT_AUTHORITY_REQUIRED')
    _, retained, scoped = current_scope(context, authority, raw)
    require(scoped.hash == lifecycle.authority.hash and context['plan'] == lifecycle.plan
            and context['executionRoot'] == str(lifecycle.store.root)
            and context['engineBinding'] == {'socketPath': lifecycle.engine.path,
                                            'socketBinding': list(lifecycle.engine.binding)},
            'SAME_CURRENT_POSTBOOT_NATIVE_CONTEXT_REQUIRED')
    # Reuse this witness, lifecycle, gateway and read budget. Rebuilding a second
    # lifecycle for the observer would lose exact in-process owner correspondence.
    prefix.witness.observe(stage='ACTIVE')
    from tools.semantic_registry_postboot_owner.owner import build_observer
    owner = build_observer(owner_context, authority, raw, prefix.witness)
    recipe = context['nodeRecipe']
    guard_lease(owner, recipe['renewableToken']['minimumRemainingSeconds'])
    node = RecoveryNodeOwner(lifecycle, prefix.profile, owner, verifier, signer, recipe)
    prepared = retained['registryInputs']
    db = context['database']
    require(type(db) is dict and set(db) == {'readiness', 'postgres', 'program'}
            and db['readiness'] == prepared['readinessScope'],
            'SAME_REVIEWED_POSTBOOT_DATABASE_SCOPE_REQUIRED')
    database = CurrentDatabase(lifecycle, db['readiness'], db['postgres'], db['program'],
                               prepared['imageAudit'], prefix.gateway.budget)
    admission = CurrentAdmission(database, node)
    semantic = OriginalSemanticRequest(prefix.gateway, context['originalRequest'])
    ports = NativePorts(lifecycle, admission, prefix.gateway, semantic)
    require(lifecycle.journal() == row and digest(context['plan']) == bootstrap_runner.plan_hash
            and authority(raw) is True, 'POSTBOOT_NATIVE_COMPOSITION_CHANGED')
    return Runner(context['plan'], lifecycle.store, ports, boot_id=bootstrap_runner.boot_id)
