# Current installed-worker read after Registry exec — 31 October 2026

Source `1cf569c50e05aced3e9963ee81d28c99d833c92f`, PR54 draft/unmerged. `current_worker.py` is a separate read-only reader for the held Registry at phase12. It does not re-enter the paused installation phase, publish a file, issue a signature, start/restart a manager or reset a budget.

The reader binds the actual selected Registry/provider/worker owners and current parent/child. It reconstructs the original owned material, snapshot inode, capsule/source bindings and initial clocks. It checks the exact installed configuration, completed installation prefix, original start claim/dispatch and final sequence evidence against the completed phase receipt. The existing independent two-peer probe and signed provider protocol remain required. The existing fixed-budget installed observer verifies current installation signatures, manager, ACTIVE recovery and both positive owned kernel lease families. Counters may advance and must not regress. A current running Registry binding is checked before and after.

The logical lifetime fence is observed by inode without flock. No worker recovery, common invocation or kernel writer lock is acquired. The existing initial provider mandate remains finite; this reader does not extend it. Native failure propagates without repair or effect retry. It returns fullCohortProven and authority/apply/release flags false.

CI [41217385264](https://github.com/GioNob/ouf-deploy/actions/runs/41217385264), job124584664498: **40 tests, five suites, zero failures/skips**, final log read. Suites: running12/1.572s, cohort7/.383s, current-worker7/95.802s, paused-frame8/.180s, paused-node6/.203s. The seven new worker cases use real original private material, Ed25519/HUMAN fixture, signed provider protocol and journals. A real exclusive lifetime flock is held during a successful read. Systemd, kernel leases, target native generation and selected runtime leaves are modeled. This is source protocol qualification, not a current target-worker or E2E admission. The original37/108/128/136 closures/pins remain unchanged.

Local initial six PASS91.456s; updated success plus new completed-sequence drift case PASS34.785s. CI is the unified seven-case result. Previous runtime witness qualification and fresh public MCP HEALTHY read are documented in `OUF_M2_CURRENT_RUNTIME_ADMISSION_20261031.md`.

Next work remains the full sealed native checkpoint/controller and the current DB/TLS/IAM/backup/fencing/custody/supply-chain composition. Keep finite provider/THS ordering explicit. No target apply, grant, restart, reset, replay, merge or release acceptance. The operator's metadata does not demonstrate a current VPS QUIESCED incident; flags remain declared false.

Evidence: `evidence/m2-current-installed-worker-20261031.json`.
