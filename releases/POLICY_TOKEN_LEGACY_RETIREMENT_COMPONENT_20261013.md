# Governed legacy retirement — component only

The operator supplied the migration host receipt at 2026-10-13 17:46:16 Europe/Rome. Retained private input hash: `93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4`. This is operator-reported target evidence, not independently retrieved private data. Code/credential/recovery roots remain ABSENT, service inactive/static, timer active/enabled. No runtime session or grant has been created; historical grant count remains UNKNOWN/null.

The new component requires an exact retained host artifact and a fresh native `CutoverAuthority` with an explicit signed `policyTokenLegacyRetirement` scope. It binds the boot identity, systemctl bytes, logical owner and full caller source closure. It checks the exact observed unit baseline, durably reserves one command attempt, then masks and stops only the two selected legacy units. No force, unmask, restart, credential, IAM mutation, grant, budget or R12 operation is included.

A crash, timeout, nonzero exit or partial result leaves the command consumed. A later invocation can only reconcile both units as masked/inactive; it cannot repeat the command. New approval and process IDs preserve the same operation. Live revocation prevents successful completion. An exclusive process fence covers this short transaction; it is not a shared lease lock and contains no retry waits. A missing or corrupt reservation is never silently replaced.

Eight tests cover native dual-role signatures, persistent reservation, timeout, new approval, actual process crash, concurrent invocation, baseline/boot drift, partial masking, metadata ambiguity and revocation after an effect. Unit operations are simulated. Local passing tests do not prove actual systemd behavior or VPS installation.

## Remaining integration

This component is not a runnable migration installer. Before any target service change, the complete source closure, owner-controlled credential reestablishment, current IAM/TLS/generation checks, first UNKNOWN-history session and actual token admission/publication must be composed and qualified. The historical design approval is retained; it does not authorize service changes or a grant. The old worker cannot be started with fabricated zero legacy accounting. Credential rotation must preserve its own ambiguous-effect ledger and cannot replay automatically. No target command is supplied by this component review.

The previously supplied migration host read has completed. Do not repeat it merely to advance this work. Existing IAM mapper application is already reconciled and must not be replayed. The GitHub Actions survey remains read-only; no existing workflow settings or action references were changed as part of it.
