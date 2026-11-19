# Postboot token-owner recovery blocker

The Registry 502 remains OPEN. Owner receipt /home/oufadmin/ouf-registry-owner-discovery.NKae4nGd/operator.log (reader e607c78606b942b9515dad59ab8c09cf3af1db2b) found18journals:all recoveryState=CANCELLED,admissionState=BLOCKED,sameCurrentBoot=false,invocationExclusiveLockObserved=false,and no positive retained token window.72metadata reads/64392bytes;1813directories/13743entries;1450subdirectories outside depth3. No credentials,Engine,SQL,OAuth or runtime effects. Evidence is owner-pasted,not independent cloud readback. No current owner is selected and other owners outside the bounded scope are not excluded. Do not rerun the discovery or ask the user again for token-manager paths.

## Existing continuation does not solve this postboot state

Source audit at b19fc2c5cf4530de5131b92ca0b1f7f22f2e3456:

- tools/semantic_policy_token_owner/installed_owner.py guard_governed_worker_session requires row.bootId==first.bootId and that same boot equals the current kernel boot. It recompiles the signed finite session from retained predecessor records. The legacy worker guard also compares the first receipt/current boot.
- tools/chatbot_file_cohort/continued_owner.py initializes both continued and governed journals with the retained first-grant receipt's bootId. Fresh HUMAN signatures alone do not migrate those clocks or that boot binding.
- installed_owner.py guard_governed_registry requires the exact signed running Registry generation. Both execute-chatbot-semantic-token-session-20261016.py and continue-chatbot-semantic-token-session-20261016.py verify current Registry runtime against the proposal before entering execution.
- The new Registry recovery NativePorts currently requires an already admitted token owner before its gated start. Combined with the preceding live-generation dependency, simply plugging a cancelled governed owner into that factory is not a coordinated bootstrap path.

These are source constraints,not a proven association of one discovered journal to the current Registry or proof that every possible owner profile is unavailable. Nevertheless none of the18observed records satisfies the factory's current-boot/ACTIVE/token-window prerequisites. Replaying the old continuation,changing bootId,admission state or expiry in place,or choosing the numerically largest observed counter is not a repair.

## Corrective work required

The existing observer/installer helpers are components,not a deployable postboot repair for this state. Complete a distinct explicitly authorized coordinated bootstrap,which admits only a fresh waiting gate while Java remains fenced;verifies its first durable native generation;establishes a genuinely current-boot owner session with verified retained lineage and cumulative grant accounting;then performs full paused OCI/rootfs/mount/current-IAM admission,attestation,separate unpause/SIGUSR1,and the original service-authenticated semantic GET200. Do not weaken the original shared owner/observer profiles or reinterpret historical signatures as current authority.

Predecessor selection must follow actual record/session/source hashes and Registry credential binding. The discovery counters include319,but this is an observation,not a selected terminal lineage,approved ceiling or HUMAN OAuth budget. Do not sum overlapping journal counters or confuse them with the separate exhausted HUMAN history304/304. Any explicit new finite grant/window requires a concrete qualified whole path and its actual native HUMAN authority first;none is ready or requested here.

No new target command is selected in this handoff. No additional broad scan,Gateway rewrite,provider restoration,activation retry,budget reset,token request or source release is implied. Preserve all18journals and every existing claim/dossier/log. Patch12/12,technical8/8,functional4/6,G3OPEN,releaseAcceptancefalse. No source-code/runtime behavior changed by this evidence update;source inspection rather than new executable tests supports this audit.
