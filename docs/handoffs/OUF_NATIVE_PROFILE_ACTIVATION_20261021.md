# Native profile activation checkpoint — 2026-10-21

The completed28-stage infrastructure rollout is retained. Live native reads on the existing ouf-admin connection confirm source `teatri-csv-6609b245`, revision `c9fec43c-19b3-4ffb-9111-781bc347c5b0`, configuration hash `sha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d`, state APPROVED and lockVersion3. The original HUMAN decision is CONFIRMED. Do not recreate the revision, prepare another review, repeat confirmation, or renew the consumed challenge.

The existing owner-issued THS card is:
https://api.ouf-lab.it/trusted-human/onboarding/?challenge=9bca610c-aa24-4be3-ac29-0e5454e9d877

The recorded challenge expiry applies to confirmation. In the pinned Onboarding implementation, ManagedOnboardingReviewService.humanCard and claimActivation retain the confirmed review; activation requires APPROVED/CONFIRMED, current hash/lock, tenant/source authorization and remaining activation guards. It does not require an unexpired already-consumed confirmation challenge. This source inspection establishes the intended path, not a successful browser or activation observation.

The next action is distinct HUMAN activation in that card, only after reviewing the exact version/hash and retained20-property reconciliation policy (SINGLE, EXACT_TYPED v1, SOURCE_INTERVAL). Activation publishes a new configuration of the same source and can start a new acquisition under retained scheduler configuration, including a file already acquired. It does not authorize replay of historical jobs. The agent has not approved, activated or published anything.

Compatibility remains unobserved and activation readiness is NOT_STARTED (attempts0, generation0). The HUMAN activation coordinator performs bounded Ingestion readiness and identity checks before publication. Preserve the same review and progress if it blocks; do not generate another approval to bypass a denial.

A separate native Ingestion status read for this source on ouf-admin returned authorization denied, retryable:false (connector error_code INVALID_ARGUMENT). No retry, equivalent history read, account switch, or permission mutation followed. The precise cause is unestablished; source-read success does not prove Ingestion operational-read authorization. This result does not establish that THS activation will fail, nor does infrastructure rollout prove application authorization.

After HUMAN activation, read back the exact source/version/hash and publication result through native source capabilities. F5/F6 remain pending and require their own accepted evidence; do not count an authorization denial or infrastructure completion as functional proof.

Technical8/8, functional4/6, G0–G2 PASS, G3 OPEN. OAuth ledger remains292/292 at its last receipt; no new technical login, refresh, budget or runtime authority was requested or inferred. Preserve all rollout contexts, launchers, claims, caches and logs. No further VPS rollout command is warranted.

Evidence: evidence/native-profile-activation-checkpoint-20261021.json.
Primary sources: GioNob/ouf-source-onboarding@b0f5e3dacbe59ebf87e22dd6af2575e41249f51d, ManagedOnboardingReviewService.java, ManagedActivationCoordinator.java and OnboardingService.java; GioNob/ouf-mcp-server@1f2c28d7abadae78680b040ba7b58be62ef85ee9, docs/INGESTION_SOURCE_READ_AUTHORIZATION.md.
