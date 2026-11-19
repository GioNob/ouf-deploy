# OUF — Registry recovery proposal, 22 October 2026

## Target result

Owner supplied REGISTRY_RECOVERY_INPUTS_OBSERVED from /home/oufadmin/ouf-registry-recovery-inputs.xmeDnp6X/operator.log,6/6DockerGETs,2/2guardshows,132containers,no runtime writes/OAuth/credentials/DB/activation/replay/reset. Complete public receipt is retained in evidence/semantic-registry-recovery-inputs-target-20261022.json. No independent cloud requery.

The exact historical Registry is exited143,Pid0,restartCount0,notOOMKilled. Retained semantic node matches its configured IPAM address;there is no current endpoint candidate. The only same-image candidate is that stopped Registry. OCI source label absent;other Registry images remain unexcluded,current owner/service identity unproven. No current Gateway map,readiness or502rootcause claim.

Loaded guard active/exited/success,boot RUNTIME_EMPTY/startfalse,coordinated owner BLOCKED/startfalse/leasefalse,leasecounts[0,0]. These do not issue current authority or prove provider causes Registry outage.

## Source audit: file-only and generation boundaries

At d97db87360a1a501fbf49420daa8fc6ef4525538:
- tools/semantic_application_cutover/file_only_profile.py: FLAGS explicitly disables OUF_SCHEMA_GOV_ENABLED and OUF_DISCOVERY_WORKER_ENABLED; externalProviderCallsAllowedfalse,newDistinctLeaseWorkerRequiredfalse. That profile does not require reactivating the external provider. Actual stopped-container flags/launch still need validation;source design is not deployed proof.
- gated_creation_plan.py: ENTRY is a shell gate that waits for caught SIGUSR1 before exec of immutable Java command;restart policy is no. A bare Dockerstart may only run the wait gate.
- gated_stage_adapter.py: a reviewed start is followed by gate-handler/generation checks and a single pause.
- file_only_node_owner.py: complete independent OCI/rootfs/custody/current authority/token owner and scoped signing protect fresh paused-node attestation.
- gated_release_adapter.py: exact attested generation,unpause and one SIGUSR1,with current owner/source/DB checkpoints;ambiguous outcome cannot retransmit.
- gated_process_observation.py: RunningWorkloadBinding requires the original verified PID/startticks/runtime binding and RestartCount0. A new process cannot be adopted as the old verified generation.
- file_only_installation.py: current PG/image/token owner,retained effect history,DB/migration/owner checkpoints and exact action scope remain mandatory. The old full-cohort action cannot be replayed or used to redeploy already-complete modules.
- docs/OUF_RESILIENCE_POLICY.md rules6–7,14–16,31: identity/unknown errors block automatic retry;fresh runtime closure and cumulative history required,no expired-TTL/claim replay or implicit new budget.

Therefore do not start provider/replay R12/old cohort/old Registry signal or issue plain Dockerstart as a completed recovery. Candidate design is a NEW governed gated-generation recovery for the exact stopped Registry,with fresh generation proof/attestation and current independent admission. Feasibility and native executor qualification remain open;this document is not an executable plan or authority.

## Concrete preparer, no runtime authority

tools/semantic_registry_recovery_proposal/prepare.py plus case.json:
1. Reads exact completed12APPLIED patch review/journal under root custody.
2. Four bounded DockerGETs only:Gateway/historicalRegistry/historicalRegistry/Gateway. Same current Gateway generation/image/config/host/network pin and stable lifecycle/mount/metadata required.
3. Requires exact stopped historical ID,pinned image-ID shape,nonroot gated ENTRY+JavaCmd,explicit file-only flags,no JVM/Spring/feature alias override,no privileged/shared-host namespace,capdropALL/NNP and restartno. This proves only those launch properties,not complete native OCI/owner authority.
4. Saves a NEW root700directory and root400proposal.json under /etc/ouf/deploy-snapshots,using exclusive creation,fsync and byte readback. No old journal/claim/file is changed;no runtime intent/authority is reserved. It stores hashes/bindings rather than raw Config/Env/credentials. Proposal path/hash are public metadata;full proposal remains private.
5. Emits BLOCKED_RECOVERY_PROPOSAL_RETAINED,unresolvedGateCount8,nativeExecutorQualifiedfalse,targetApplyAuthorizedfalse,runtimeAuthorityIssuedfalse. Complete means proposal retained,not recovery ready.35second deadline,4secondGettimeout,2MiB/reply.

The eight unresolved gates are:
- exact historical owner/claim chain;
- complete current OCI/rootfs/mount custody;
- fresh process generation/attestation;
- current DBowner/startup admission;
- current token owner without unreviewed grants;
- current Gateway map/targetbinding;
- qualified governed recovery executor;
- fresh exact HUMAN/runtime authority.

Proposed effect classes are explicitly non-executable future review content:startwaitgate,pauseverifiednewgate,attestfreshgeneration,unpauseattestedgate,releasesamegenerationonce. No provider recovery/lease,new OAuthbudget/HUMANwindow is proposed or issued. No state-machine runner,apply/step entrypoint,signer,token refresh or runtime HTTPPOST exists in this delivery. Actual private proposal result must inform later source preparation/qualification;runtime review/approval stays separate.

## Qualification and preservation

8newlocal tests PASS,48unchanged predecessor regressions PASS,0skips. Tests cover actual original gate/FLAGS producer-contract fixtures,full4GET capture,negative stopped/launch/env/security/namespace cases,context/resource drift,closed GETpaths,budget,and real exclusive private filesystem publication/readback/mode/redaction. Original fixture functions/constants were fetched from the pinned source,not invented for the test. No native Docker/systemd/AF_UNIX/VPS/CI qualification of this new preparer or future recovery executor is claimed. Old collector target-execution proof is distinct.

Original Matrix1.7 §1 and Registry PET1.3 §160.6 reread from conversation workspace original extractions;Mini-PET1.1 §14 and resiliencev3 consulted. No PET text/archive published. No owner/capability semantics changed.

WP3/CSV-H-13,G3OPEN;patch12/12,technical8/8,functional4/6. OAuth304/304 exhausted as last observed;no new budget/window/login/authority. Source24hourwindow remains historical. Native profile publication and release acceptance unproven. Eight proposal gates are not eight new roadmap phases. No effort duration/forecast invented.

Preserve all contexts/claims/logs,especially registry-recovery-inputs.xmeDnp6X and all three endpoint/historical diagnostic chains. Do not rerun completed/stopped readers or the old boot recovery. Next only the new SHA256pinned preparer/case,once in a new operator directory via sudo python3 -I -B -S. Return public JSON/operator.log only,not raw containerConfig/env/proposal secret material. Any STOP preserves directory;no replay. No runtime start/activation is authorized by this preparation.
