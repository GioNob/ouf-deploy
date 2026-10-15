# Remaining Docker phases: audit and qualification, 2026-10-15

This audit was requested before another VPS launch. It covers the deployment machinery after image import, not CSV/chatbot acceptance. No VPS mutation was requested or performed during this audit. The application package and its six module commits are unchanged.

## Observed target baseline

The complete 103-record readback is retained in `evidence/chatbot-registry-creation-readback-20261015.json`; uploaded input SHA256 `f4e71357305f6827eac16a931b1ea23dbc85e3a5f135af4fc0b42cf09eed600b`. Its END record reports completeness and no unavailable checks.

The latest target attempt is context `chatbot-file-cohort-signed-b05102a00d9f20ec6a935e1de201d4a9bb800f2aac8876fe79b0ed187e5f9623`, source `bc2d111200de75b90f8072a83c1739fbfb945313`. Its worker is no longer running. STOP_REVOKE_OLD_LEASE, QUIESCE_PRODUCERS, FENCED_BACKUP and RELEASE_OLD_ENDPOINT are APPLIED with retained native evidence. All five old application containers are stopped. The replacement Registry container `790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d` exists in CREATED state with PID zero; its JVM has not started. PostgreSQL remains running in its pinned generation. The transition is IN_FLIGHT at CREATE_REPLACEMENT.

The first controlled grant succeeded and consumed one slot. The finite worker recovery is CANCELLED. These are post-grant, post-quiescence facts; earlier pre-grant recovery scripts are not applicable. The new container must be reconciled, not created again. No old service, timer, grant claim or budget may be reset or replayed.

## Root cause and deliberately narrow correction

The actual request puts four readonly mounts in HostConfig.Binds and separately sets HostConfig.Mounts to an empty list. Docker 29.8.1 omits the empty Mounts field in inspect. The stopped-container comparator rejected this empty/omitted representation before acknowledging the successful create. It did not find a missing bind.

The correction accepts only requested `Mounts=[]` against native omitted/null/empty Mounts. Nonempty Mounts specs and all Binds still compare exactly. Actual top-level mount source, destination, type and RW projections remain checked independently. Native inspection dictionaries, hashes and generation bindings are never rewritten. The existing narrowly bounded OomKillDisable false/null equivalence remains limited to the started profile.

## Requests expected in the remaining phases

| Phase / owner | Docker request or local operation | Independent proof before advancing | Qualification / boundary |
|---|---|---|---|
| Existing Registry create reconciliation | GET container by retained name/ID; no second create POST | Same image, ID, request config, host settings, CREATED/PID0; two stable reads and retained intent | Pure mismatch/negative cases and real 29.8.1 create/inspect/reobserve; target adoption still needs governed continuation |
| Stage Registry | POST start, then POST pause (204) | Same first PID/generation, gate waiting, paused, restart count zero | Actual shell gate and native process inspection on 29.8.1; no Java/CSV claim |
| Attest paused workload | Engine inspect, retained runc state, OCI/bundle/rootfs, namespace/NIC and key custody reads | Independent reviewed OCI recipe, current generation, four readonly mounts, nonroot/capability restrictions and signed source custody | Native Docker profile and existing node-owner code audited; synthetic attestation in Docker contract test is explicitly not target OCI acceptance |
| Admit application release | Docker-backed PostgreSQL exec and current admission checks | Exact database/OID/history, current worker/lease and signature, migration authority | Real PostgreSQL/migration/backup tests plus existing signed owner tests; no application migration acceptance inferred |
| Release Registry | POST unpause and POST kill?signal=SIGUSR1 (204 each) | Same attested PID/generation, observed exec to application; consumed durable phase prevents another signal | Actual pause/unpause/one signal and process transition on 29.8.1 |
| Registry readiness | GET inspect and bounded direct private health GET; Docker exec read-only database observations | Same running generation, HTTP UP and exact expected Flyway history | Real HTTP/native process fixture; new finite read-only wait tests; actual application health still unproved |
| Four other application replacements | POST rename old (204), create (201), start (204), update restart policy (200) | Retained old quiescent container; image/config/mount/network checks; same created/started generation and module-specific health | Actual Engine operations and CohortContainers comparator on 29.8.1; existing native owner suite tests effect ACK loss, claims, readiness and revocation |
| Gateway container installation | POST update/stop/rename/create/connect/start/update, then admin GET | Exact retained image/config, both network identities, readonly config, native generation and reachable private admin | Already APPLIED on target and must not replay; network/connect/update/rename contracts tested on 29.8.1, existing dedicated native Gateway suite retained |
| Gateway routes and authorization | Private namespace admin HTTP and existing owner authorization APIs | Exact reviewed route/config hashes and live authority | Not Docker installation success; existing concrete owner suites remain required |
| Release independent producers | POST update/start only for IDs explicitly selected by owner | Verified healthy replacement and exact preserved producer configs, mount and network identities | No old replaced application may be restarted; native Engine primitives plus existing owner phase tests |

Production does not delete the retained old containers. Forced container/image/network cleanup in the added native test applies only to disposable CI resources.

## Readiness gap found before target retry

Historical gated release qualification reconciled asynchronously from the test caller. The aggregate delivery called Registry verification only once. A normal exec-read race or early HTTP connection refusal could therefore stop the delivery after the next successful HUMAN interaction.

The candidate adds a reviewed Registry readiness policy and durable private budget. Only the exact retained UNKNOWN outcomes for exec transition / application health admit a wait. Each retry authenticates the current action and worker and rereads the consumed IN_FLIGHT phase; it does not repeat start, unpause or SIGUSR1. Unknown errors, paused/changed generations, integrity drift and explicit revocation still stop immediately. Defaults are 5/15/60/300/900 seconds with up to 20% jitter, at most 128 attempts, and at most 3600 seconds clipped to the same current action deadline. Retry-After is respected; if it exceeds the remaining authority, the budget remains exhausted and the server delay is not shortened. Counts, wall/monotonic deadlines and boot identity persist. Crashes in ATTEMPTING require reconciliation and do not refund an attempt.

Seven tests execute the actual delivery wait/classifier functions with private Journal files and explicitly synthetic remote observations/clocks: delayed exec plus HTTP recovery; revocation during wait; unknown/paused/integrity denial; crash and boot-change retention; hours-long outage and immutable exhaustion; CAS/clock/expired-success denial; Retry-After delta/date handling and refusal to shorten a server-requested delay to fit the remaining authority. These tests do not claim genuine IAM or application evidence.

## Qualification results

Production source: `2353c511dd422b692510cf31a8652f7e12fdf2be`. Current branch head: `ff3f2ba81baba4eb348c8aa07e834e404c82bbd7`; this last commit only adds the existing nine signed application/producer regression tests to the Docker CI workflow and leaves production bytes unchanged. PR31 remains draft/unmerged.

Capsule: `f5751921337637d99988d649268a356d8f8b8cfca17b068fbf5e099c7642026f` (112 files, all hashes checked). Launcher: `49637db86009c1ecb40be20a244f13a09498afb0e309216326762fef94d0ea4d`.

| Qualification | Source | Run | Observed result |
|---|---|---|---|
| Docker 29.8.1 lifecycle, readiness, signed application/producer regressions and real PostgreSQL | ff3f2ba81baba4eb348c8aa07e834e404c82bbd7 | [38736234551](https://github.com/GioNob/ouf-deploy/actions/runs/38736234551), job116426121918; PR38736241658 also passed | PASS:25 tests/4 suites, zero skips |
| Complete native cohort owners | 2353c511dd422b692510cf31a8652f7e12fdf2be | [38735728121](https://github.com/GioNob/ouf-deploy/actions/runs/38735728121), job116424416178 | PASS:288 tests/37 suites, zero skips |
| Online IAM / installed owner, disposable Keycloak | 2353c511dd422b692510cf31a8652f7e12fdf2be | [38735734188](https://github.com/GioNob/ouf-deploy/actions/runs/38735734188), job116424434234 | PASS:237 tests/31 suites, zero skips |
| Full finite owner installation | 2353c511dd422b692510cf31a8652f7e12fdf2be | [38735734096](https://github.com/GioNob/ouf-deploy/actions/runs/38735734096) | PASS |
| HUMAN scope / Ed25519 verifier | 2353c511dd422b692510cf31a8652f7e12fdf2be | [38735734025](https://github.com/GioNob/ouf-deploy/actions/runs/38735734025) | PASS |
| Governed legacy retirement | 2353c511dd422b692510cf31a8652f7e12fdf2be | [38735734000](https://github.com/GioNob/ouf-deploy/actions/runs/38735734000) | PASS |

At this recording, duplicate complete-cohort and online-IAM PR reruns on the CI-only ff3f2ba head are still running. The table attributes results to the actual tested revisions rather than claiming they have finished.

The native Docker job pins actual server and CLI 29.8.1, overlayfs and cgroup systemd on an isolated disposable daemon using external containerd and /run/docker runtime state. It verifies API1.56/min1.40 while production requests use /v1.44. The official HTTPS binary archive observed SHA256 is `d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70`.

The 25-test job comprises five comparator tests, one actual Engine/process/HTTP lifecycle, seven finite Registry readiness/Retry-After tests, nine signed application/producer reconciliation regressions and three real PostgreSQL tests. The latter exercise custom bootstrap admin, non-owned incident table privilege preservation, the exact pinned MCP audit migration, four archives/retained rows and real runc/containerd/namespace selection.

The shell fixture uses Alpine and a compiled nonroot HTTP responder named java to exercise the exact gate command. Its non-Docker attestation/admission boundaries are synthetic; it does not boot the qualified Spring services or prove independent target OCI/peer admission. The signed owner regression tests retain real private Journal/signature/HTTP channels while Docker/PostgreSQL state in those nine cases is explicitly simulated. This is not a CSV/chatbot acceptance result.

CI iterations are preserved rather than reported as target attempts: the C fixture initially failed Werror, its original PostgreSQL base introduced an unwanted image volume, a shared comparator import broke standalone plan tests, and the disposable Docker setup used tar ownership/custom exec-root that correctly failed custody/runtime checks. These were corrected before any new VPS attempt. A separate local run of the nine signed owner tests encountered four errors inside signing/verification, including an explicit 5-second OpenSSL timeout; the unchanged nine tests subsequently all passed in native-root CI. No signature timeout or production security check was weakened to obtain that result. Existing PostgreSQL subprocess ResourceWarnings in the test log are non-fatal and were not silently described as warning-free.

## Explicit outstanding work

No new target command is qualified by this document. A governed post-grant/quiesced continuation must first be implemented and tested. It must retain the four APPLIED predecessor phases and their original evidence, adopt only the exact already-created container, preserve the spent first grant and cancelled worker histories, and obtain a fresh exact HUMAN decision for any new finite worker authority. It must not relaunch the old complete preparation path or reset a budget.

After successful runtime continuation, actual application migrations, health, OCI/peer admission and the CSV/chatbot acceptance cycle remain to be demonstrated. Neither native Docker tests nor a completed service installation prove `chatbotEndToEndProven`.
