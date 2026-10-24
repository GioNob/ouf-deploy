"""Claimed, fail-closed native authority handoff; never dispatch lifecycle effects.

The two journal updates are deliberately not presented as atomic. A crash
between them consumes the durable handoff claim and requires reconciliation;
neither installation nor runtime continuation may replay the handoff.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
from .core import Store, digest, encoded, require
from .factory import current_scope
from .lifecycle import Lifecycle, engine_type
from .resumption import KEY, scope, proposed_epoch
from .read_budget import read_scope
from .postboot_authority import protected_directory, publish
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_registry_postboot_owner.owner import source_guard, retained_guard, credential_custody
from tools.semantic_policy_token_owner.installed_owner import read_private, unique


def read_counts(root):
    with protected_directory(root) as directory:
        return json.loads(read_private(directory,'native-reads.json',8192),object_pairs_hook=unique)


def replace_counts(root, before, after):
    """CAS under the native store lock, preserving every consumed counter."""
    with protected_directory(root) as directory:
        require(json.loads(read_private(directory,'native-reads.json',8192),object_pairs_hook=unique)==before,
                'PREDECESSOR_NATIVE_READS_CHANGED_BEFORE_HANDOFF')
        temporary='native-reads.successor-'+digest(after)+'.json'
        publish(directory,temporary,encoded(after))
        require(json.loads(read_private(directory,'native-reads.json',8192),object_pairs_hook=unique)==before,
                'PREDECESSOR_NATIVE_READS_CHANGED_AT_HANDOFF')
        os.replace(temporary,'native-reads.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)


def install(native_context, owner_context, authority, raw, *, clock=lambda:(time.time(),time.monotonic())):
    require(os.geteuid()==os.getegid()==0,'ROOT_CHECKPOINT_SUCCESSOR_INSTALLER_REQUIRED')
    _,retained,scoped=current_scope(native_context,authority,raw)
    expected=scope(native_context['plan'],owner_context);signed=json.loads(raw,object_pairs_hook=unique)
    require(signed.get(KEY)==expected,'CURRENT_COMPLETE_SIGNED_CHECKPOINT_SUCCESSOR_SCOPE_REQUIRED')
    source_guard(owner_context);retained_guard(owner_context);credential_custody(owner_context)
    old=owner_context['resumptionInputs']['retainedNativeJournal']
    reads=owner_context['resumptionInputs']['retainedNativeReads']
    store=Store(native_context['executionRoot'],native_context['plan']['logicalOperationRef'])
    require(reads['scopeHash']==digest(read_scope(native_context['plan'],store.root)),
            'SAME_NATIVE_READ_SCOPE_WITHOUT_COUNTER_RESET_REQUIRED')
    predecessor=Journal(owner_context['predecessorJournalPath'])
    binding=native_context['engineBinding'];engine=engine_type()(binding['socketPath'],tuple(binding['socketBinding']))
    lifecycle=Lifecycle(engine,scoped,store,native_context['plan'],retained['registryInputs']['creationRequest'],
                        native_context['stoppedSnapshot'],retained['proposal'])
    with store.lock('invocation.lock'),predecessor.invocation():
        require(store.read()==old and read_counts(store.root)==reads,'EXACT_UNCHANGED_PREDECESSOR_BEFORE_HANDOFF_REQUIRED')
        retained_guard(owner_context);source_guard(owner_context);credential_custody(owner_context)
        fence=owner_context['resumptionInputs']['retainedFence'];fence_path=Path(fence['path'])
        with protected_directory(fence_path.parent) as parent:
            require(json.loads(read_private(parent,fence_path.name,16384),object_pairs_hook=unique)==fence['value'],
                    'PREDECESSOR_POSTBOOT_FENCE_MOVED_BEFORE_NATIVE_HANDOFF')
        # Reserve these two GET attempts before either request; even a failed
        # observation consumes the single handoff scope. No read-budget reset.
        claim='checkpoint-four-successor-'+digest(old)+'.claim.json'
        with protected_directory(store.root) as directory:
            publish(directory,claim,encoded({'schema':'ouf.semantic-registry-checkpoint-successor-claim.v1',
                'authorityHash':scoped.hash,'scopeHash':digest(expected),'priorJournalHash':digest(old),
                'maximumEngineGets':2,'lifecycleEffectsAllowed':False,'budgetReset':False,'automaticReplayAllowed':False}))
        before=lifecycle.inspect();proof=lifecycle.process_evidence(before)
        require(proof['newGeneration']==old['newGeneration'] and proof['paused'] is True
                and proof['processKind']=='GATE_WAITING','SAME_DURABLY_PAUSED_UNRELEASED_GENERATION_REQUIRED')
        again=lifecycle.inspect()
        require(lifecycle.process_evidence(again)==proof and lifecycle.runtime_binding(again)==lifecycle.runtime_binding(before),
                'PAUSED_GENERATION_CHANGED_DURING_SUCCESSOR_HANDOFF')
        wall,mono=clock()
        after,following=proposed_epoch(native_context['plan'],old,reads,expected,scoped.hash,
                                       signed['issuedAt'],signed['expiresAt'],wall,mono)
        scoped.guard(after);retained_guard(owner_context);source_guard(owner_context)
        require(store.read()==old and read_counts(store.root)==reads,'PREDECESSOR_MOVED_AFTER_NATIVE_OBSERVATION')
        with protected_directory(fence_path.parent) as parent:
            require(json.loads(read_private(parent,fence_path.name,16384),object_pairs_hook=unique)==fence['value'],
                    'PREDECESSOR_POSTBOOT_FENCE_MOVED_AT_NATIVE_HANDOFF')
        with store.lock('cas.lock'):
            require(store.read()==old,'PREDECESSOR_NATIVE_CAS_CHANGED')
            # Keep a separate immutable byte-for-byte canonical copy as well as
            # the signed-hash-bound predecessor inside the new epoch record.
            with protected_directory(store.root) as directory:
                publish(directory,'checkpoint-four-predecessor-'+digest(old)+'.json',encoded({'journal':old,'nativeReads':reads}))
            replace_counts(store.root,reads,following)
        # Store.cas takes the same short CAS lock independently. The lifetime
        # invocation lock remains held throughout both writes and readback.
        store.cas(old,after)
        require(store.read()==after and read_counts(store.root)==following,'SUCCESSOR_NATIVE_EPOCH_READBACK_REQUIRED')
        scoped.guard(after)
        receipt={'schema':'ouf.semantic-registry-checkpoint-successor-installation.v1','scopeHash':digest(expected),
            'authorityHash':scoped.hash,'predecessorJournalHash':digest(old),'currentJournalHash':digest(after),
            'currentNativeReadHash':digest(following),'nativeCheckpoint':4,'retainedControlledGrantAttempts':320,
            'engineGetAllowanceConsumed':2,'lifecycleEffectsDispatched':0,'oauthRequests':0,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        with protected_directory(store.root) as directory:
            publish(directory,'checkpoint-four-successor-installed.json',encoded(receipt))
        return receipt
