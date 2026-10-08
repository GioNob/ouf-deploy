"""Authenticate again at every locked switch checkpoint, then observe natively.

No target CLI, signing, lifecycle operation or release acceptance is provided.
The target caller must pin actual receipt/authority/command custody and source
closure before invoking this factory. Synthetic CI bindings confer no authority.
"""
from pathlib import Path

from authenticate_provider_transaction import TARGETS, build_install_plan, require
from guarded_runtime_switch import verify_installed_plan
from transaction_guard_observation import observe_locked
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, VerificationBudget, decode


def make_locked_switch_verifier(root, records, authority, sources, observer_raw,
                                python_binding, crypto, empty_adapter,
                                receipt_binding, expected_owner_hash, command_bindings):
    """Return the verifier required by switch_existing_wrapper.

    Rebuild from actual signatures rather than trusting a disk plan or receipt.
    Native empty guard must match the immutable signed NIC guard references.
    Docker candidate generation/status must remain identical across checkpoints.
    Source seal, target profile/command hashes and exact installation pins remain
    mandatory in the root caller; this factory does not choose them by discovery.
    """
    root=Path(root);baseline=[None]
    candidates={target['containerId']:{'imageManifestDigest':target['imageManifestDigest'],
                'runtimeName':'ouf-semantic-admitted-v2'} for target in TARGETS.values()}
    def verify(fd,phase):
        stage='AUTHENTICATE_LOCKED_RUNTIME_SWITCH'
        require(phase in ('BEFORE_CLAIM','BEFORE_RENAME','AFTER_RENAME','BEFORE_COHORT_CLAIM','BEFORE_COHORT_START'),
                stage,'EXACT_SWITCH_CHECKPOINT_REQUIRED')
        budget=VerificationBudget(40)
        verifier=DetachedAuthenticator(crypto['policyBinding'],crypto['signatureDirectory'],
                                        crypto['opensslBinding'],budget=budget)
        plan=build_install_plan(str(root),str(root/'source'),records,authority,sources,
            observer_raw,python_binding,crypto,verifier,empty_adapter)
        installed=verify_installed_plan(plan)
        observation=observe_locked(fd,receipt_binding,expected_owner_hash,candidates,command_bindings)
        for role in TARGETS:
            value=decode(records[role]['preparerTemplate'],131072)
            guards=[binding['leaseGuard'] for binding in value['candidate']['networkBindings'] if 'leaseGuard' in binding]
            require(len(guards)==2 and all(guard['configurationHash']==observation['kernelConfigurationHash']
                    for guard in guards),stage,'SIGNED_NIC_AND_INSTALLED_GUARD_SCOPE_DRIFT',role)
        state={'installedConfigurationHash':installed['configurationHash'],**observation}
        if baseline[0] is None:
            require(phase in ('BEFORE_CLAIM','BEFORE_COHORT_CLAIM'),stage,'INITIAL_LOCKED_SWITCH_OBSERVATION_REQUIRED');baseline[0]=state
        else:require(state==baseline[0],stage,'LOCKED_SWITCH_NATIVE_STATE_CHANGED')
        budget.check()
        # Fresh signatures and scoped mandates must still be valid after the
        # native observation; no disk plan/CI flag can extend their windows.
        from tools.semantic_provider_deployment_protocol import window
        import time
        for role in TARGETS:
            for name in ('review','intent','liveAuthorization','finalMandate'):
                window(decode(records[role][name],131072),time.time())
    return verify
