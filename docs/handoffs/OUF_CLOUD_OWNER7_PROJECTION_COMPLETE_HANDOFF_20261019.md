# OUF CLOUD — owner7 and active projection complete — 19 October 2026

Current handoff for a new **ChatGPT Work CLOUD / GPT-6.1 Sol / medium reasoning** chat. The user chooses that model in the new chat; this document does not change model settings.

## Start here

Continue the existing project. **Technical phases8/8 and functional milestones4/6.** No subagents, no automations. Keep working through diagnosis and resolution; provide clear progress updates, concrete evidence and limitations. Do not stop at a plan or treat a recoverable incident as abandonment. Runtime approvals remain native HUMAN/THS gates; development authority does not substitute for them.

The user supplied the completed target receipt `OWNER7_ACTIVE_PROJECTION_PUBLISHED`. Owner ACTIVE revision7/generation7 and installation active projection7 are now aligned. The publication and the preceding owner action are COMPLETE, once-only, and must not be repeated. The only work in this handoff turn is documentation/evidence; no new target execution.

Read [AGENTS](../../AGENTS.md), the current numbered [roadmap](../CHATBOT_CSV_ROADMAP.md), [resilience policy](../OUF_RESILIENCE_POLICY.md), then this current handoff. [Cumulative handoff](OUF_CLOUD_POSTINSTALL_HANDOFF_20261019.md) preserves detailed history; its earlier pending/not-run blocks are superseded by this result. Preserve phase numbering; internal launcher stages do not replace it.

Verify the currently exposed OUF connector tools using **ouf-admin**, not giovanni-chatgpt. Last connection link: `link_6aafef96b4148191b767e9af7b756a07`, tenant ouf-lab. Tool availability and current live authorization must be discovered afresh; historical status is not a current tool response.

## Proven current checkpoint

| Item | Last proven target evidence |
|---|---|
| Owner ACTIVE | installation ouf-lab-netcup-01; revision7; generation7 |
| Owner full payload checksum | `66ab1adb9cbaf699100809568f06a7c0f4b97e63505fc8ea7fa6f9727342e5f9` |
| Strong owner ETag | `"7:66ab1adb9cbaf699100809568f06a7c0f4b97e63505fc8ea7fa6f9727342e5f9:7"` |
| Active installation projection | `/opt/ouf/installation/active-projection.json` |
| Projection SHA256 | `dd31d2b7de5ae66582275e5ac841584ff784065aa6e362ed0279d45fb6cdbc66` |
| Publication context | `/etc/ouf/deploy-snapshots/ingestion-profile-publication-execution-0gd3mwft` |
| Last HUMAN counter | **278/288**,10 remaining; no reset, no new login |
| HUMAN window |1792450664 = **2026-10-20 00:57:44 Europe/Rome**,2026-10-19 22:57:44UTC |
| Gateway |82 retained routes; no writes in publication scope |
| Source |inactive; no jobs retried; no release acceptance |
| Open gates |DB admission false; runtime rollout executor qualified false; native chatbot profile published false |

The HUMAN state is the last reported state, not a live check. At resumption, expiry may already have passed. Do not assume a valid bearer, sufficient remaining requests or continuing authority. No automatic login, budget increase, window extension, old credential replay or refresh loop.

Published metadata is exact retained evidence, not a portable installation default. Keep integers intact; nanoseconds exceed JavaScript's safe integer range:

```json
[65028,33776,0,0,33152,1,1495,1792445329071520839,1792445329123521063]
```

[Exact operator-supplied publication receipt](../../evidence/ingestion-owner7-projection-published-target-20261019.json). This is supplied target execution/readback evidence; the handoff author did not independently re-query the VPS. A repository commit or CI result alone does not prove target execution or end-to-end acceptance.

Exactly1 active projection write,0 owner POST,0 projection exports,0 Gateway writes,0 lifecycle operations,0 DB calls/migrations,0 grant changes,0 secret values generated,0 jobs retried. `completedOwnerActionReplayed:false`, `newLoginPerformed:false`, `automaticReplayAllowed:false`, `budgetReset:false`, `notReleaseAcceptance:true`.

**Installation projection publication is distinct from governed native ChatGPT/client profile publication.** `installationProfilePublished:true` does not imply `nativeProfilePublished:true`, fresh native client readback or functional milestone5.

## Owner7 and publication provenance — consumed, not instructions to execute

Preceding owner context:
`/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd`.
Canonical owner result SHA256:
`7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618`.
Owner plan:
`e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938`.
Exactly3 POSTs created/validated/activated immutable revision7 with If-Match, then1 private authoritative export:
`...d6o9cpwd/owner-active-projection.json`, SHA256 dd31 above.
[Owner target receipt](../../evidence/ingestion-owner-reference-activated-owner7-target-20261019.json).

Owner7 added only the approved reference
`secrets.references.ingestionReadOwnerKey` →
`/etc/ouf/deploy-snapshots/ingestion-read-owner-draft-71atrj6k/ingestion-read-owner.key`
under FILES provider. **No key was generated**. The path is a future secret reference, not proof the file exists. Standard exported projection includes only its defined MCP secret references; the Ingestion bootstrap must use the full validated owner payload. Do not invent an export field or silently use a local fallback.

Owner recovery source `948242095f031673df01338a3c1eb313fd3c64e6`; native CI [39322572015](https://github.com/GioNob/ouf-deploy/actions/runs/39322572015),83PASS; delivery `fbe3bb66a118221bb61bee0c7ff0e07d7e632c4f`, CI39322809597,3PASS. Its launcher `scripts/launch-ingestion-owner-recovery-20261019.sh` is CONSUMED.

Publication source `ccbba4ebd986e98b465df733bce0149f8e730fb2`; [native CI39326331436](https://github.com/GioNob/ouf-deploy/actions/runs/39326331436), job118313041336, **115PASS**. Actual Ed25519 two-role signatures, journal/claims, FD/flock/CAS/rename/fsync, approved nonroot parent custody and interrupted-rename fencing were qualified. Per-request REFRESH→USERINFO cap prevents a second rotating refresh. Earlier114-test source is superseded.

Immutable publication delivery `5471e60dd8df1e3801f44b9999a66e95abf1c50a`; [delivery CI39326530756](https://github.com/GioNob/ouf-deploy/actions/runs/39326530756), job118313721205,3PASS.
Launcher `scripts/launch-ingestion-profile-publication-20261019.sh` SHA256
`f52b5068398c475fe7540b9942cf4c489ba52524d4a4bc4a5c67fd75c758a563` is now **CONSUMED — DO NOT LAUNCH**.
Bundle `releases/ingestion-profile-publication-bundle-20261019.json`:93621bytes; Git blob `d758b5613c71ac009b2544bb9e47a35a9fa42dec`; SHA256 `a72cc64cfc212d2acca817aa2b93726bd87b69d83742377a49a8d6e684e660d1`.
244-source capsule preserved all238 previous source bytes. These qualification results are distinct from the new completed target receipt.

Publication retained approved custody: /opt/ouf UID/GID1000 mode0750; /opt/ouf/installation root0700; active projection root0600. Never chown /opt/ouf to satisfy a legacy root-only reader. Private backup `previous-active-projection.json` remains in publication context, old projection6 SHA256 `10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d`.

## What remains — advance with new, bounded scopes

1. Read current source/revision/tool contracts, original PET and current retained evidence. Prepare read-only reconciliation/admission as needed; do not execute old preparer/runtime mains to inspect their history.
2. **Prove live DB admission and qualify the rollout executor before any new Ingestion container starts.** Candidate equality of18 SQL resources proves resource equality only, not installed schema/history, role privileges, pressure/admission or zero Flyway work at startup. Use a qualified finite read-only native adapter/owner contract. No manual SQL/DDL, hidden migration, backup/restore or DB privilege change is authorized by completed owner/projection scopes.
3. Revalidate current owner ACTIVE7/full payload/ETag, live Gateway map, current app generations, input custody and HUMAN state. Key provisioning and the2-runtime/2-route rollout require their own precise native approval and fresh two-role authority. No effect is preauthorized by this handoff.
4. Implement/qualify the exact new finite runtime executor, including restart/crash/ambiguous-result fences, admission, availability, health and preservation of unchanged bindings. Only then deliver a single reviewed target action under HUMAN/THS.
5. After transport/auth works, publish the governed native client profile with its own consent and fresh client scope/readback. Test typed `ouf.ingestion.status` and `ouf.ingestion.history` through the actual ouf-admin/MCP path.
6. Continue the established functional roadmap under source owner/HUMAN/THS gates. **Milestone5:** import the same CSV again and prove object reuse without duplicates. **Milestone6:** verify both acquisitions and preservation of the8 existing Cinema objects. Native profile/readback and backend repair are prerequisites, not substitutes for these milestones. Preserve original lineage,13 Teatri objects and prior materialization references. Source activation/run is a separate protected action.

Do useful development and qualification autonomously. Present only concrete, qualified runtime plans for native approval. If stopped, diagnose and construct a distinct safe recovery; preserve all history and do not give up or request arbitrary repeated approvals.

## Auth fix candidates — code qualified, not deployed

The earlier Ingestion status/history401 path required inspection of deployed security bytecode and gateway boundary; those diagnostics did not prove the exact loaded JVM chain or final specific401 cause. Old IAM-disabled backend behavior and missing purpose-bound trusted read receipt motivated a paired code fix. Do not label it a target repair until deployed/read back.

| Component | Exact candidate |
|---|---|
| Gateway repo/PR |GioNob/ouf-api-gateway, draft [PR81](https://github.com/GioNob/ouf-api-gateway/pull/81), branch fix/ingestion-read-auth-20261019 |
| Gateway source | `6bcb28906eee08e0ebe3507b8b58dd987012c8e6` |
| Ingestion repo/PR |GioNob/ouf-ingestion-runtime, draft [PR43](https://github.com/GioNob/ouf-ingestion-runtime/pull/43), same branch name |
| Ingestion source | `663faa03288f9ad7775382b9757e44eaba4f51ca` |
| Chosen PUSH artifact run |39304976681; artifact12214420297 |
| Image | `sha256:51a514d8e07ad7448f98a3886e0c9c6d5b50829f85d320785038a2c76eae46f3` |
| Staged tar.gz SHA256 | `54eab6e127b0c2adf14e5a2b705270eba3e49dae2f4d5b456323a764c9e96059` (136664339bytes) |
| Artifact ZIP SHA256 | `1a26522ab9507bb85fbd6924c0c48c67720493516ec4471a4b3577a8f853ec3f` |
| Candidate JAR SHA256 | `56d770d221a87fdee4fe5c954a458736522aef4a1489b0e94497bb64057416a4` |

Candidate is **staged privately, not imported, rebuilt or started**. Do not select the different PR-merge artifact39304985543.

Actual Lua142testsPASS; Ingestion18 paired actual Lua→Java HTTP testsPASS, zero skips;20 candidate workflowsPASS. Java21, Boot4.0.8, Security7.0.7; nonroot10002:10002;18 SQL resources unchanged; TrivyHIGH/CRITICAL gatePASS. These are CI evidence, not DB admission.

Receipt header `X-OUF-Ingestion-Read-Receipt`, HMAC domain `ouf-ingestion-read-owner-v1.`, TTL30s; binds method/path/body hash/capability/HUMAN/identity/audit. No forwarded human bearer or client-asserted trusted identity. Gateway new ENV `OUF_INGESTION_READ_OWNER_KEY`, distinct from generic delegation key. Ingestion closed read chain and `GatewayReadReceiptVerifier` derive SDK trusted principal only after receipt verification; fine policy remains owner-enforced, default disabled.

Ingestion ENV names: `OUF_ING_GATEWAY_READ_ENABLED`, `OUF_ING_GATEWAY_READ_ISSUER`, `OUF_ING_GATEWAY_READ_AUDIENCE`, `OUF_ING_GATEWAY_READ_WORKLOAD`, `OUF_ING_GATEWAY_READ_KEY_FILE`. Values derive from validated installation/bootstrap, not copied hardcoded municipality defaults.

Input context `/etc/ouf/deploy-snapshots/ingestion-read-owner-inputs-z048j_zr`;
inputsHash `7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314`;
logicalRef `e9de2899283ddec4c8bd2612b6e5d4f8e7d4fef4831d8ec99584c3b9a818220a`.

Draft context `/etc/ouf/deploy-snapshots/ingestion-read-owner-draft-71atrj6k`;
draftPlanHash `2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec`;
candidate route map hash `d45d0adc26f63bc61902813c1b76fc5decf7bf3ce5ce3a023c2e51d013ef7c12`.
Original draft is preparation evidence, not a qualified executor or present authority.

Proposed runtime delta: replace Ingestion with chosen image+5 ENV+one read-only key mount; recreate Gateway with same retained image+one key ENV, unchanged mounts; exactly2 route Lua/postfunction and mediation-label PUTs for status/history,80 other routes unchanged. Gateway recreation affects all routes during readiness: qualify availability impact and finite readiness rather than calling this isolated traffic impact. Preserve host config, networks, runtime identity, restart policy and all unrelated bindings. Key generation/file UID10002/mode0400/mounts require exact approved custody; no key value or key-derived hash printed.

## Retained runtime/history — no replay

| Completed scope | Retained checkpoint |
|---|---|
| Installation/readback uow4n8lp |technical8/8 complete; never rerun |
| Admin1lxoo2ws/policy47 |published `ouf-lab-authorization:47`; existing grants/roles retained; fresh client scopes not proven |
| Gatewayazxw328z |82routes after original2 additions |
| MCPsrz6__wf |update/readback COMPLETE; source1f2c28d7abadae78680b040ba7b58be62ef85ee9; image sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182; health204 |
| Onboardinghnfn0zwg |atomic If-Match API deployed, health200; sourceb0f5e3dacbe59ebf87e22dd6af2575e41249f51d; image sha256:c124a832a1f9f07967a8f3ef9ba9692610ab5c97aa4719e614867f44e6aa63ae |
| Routesw8nfc1ko |old7x21g1fg journal reconciled, no repeated rename;2 host replacements;80 other routes preserved |
| Ownerd6o9cpwd |owner7 activation/export COMPLETE |
| Publication0gd3mwft |active projection7 published/read back COMPLETE |

Expected retained Gateway hash from completed route action:
`ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7`.
Publication retained82 routes; current live map must still be re-read in a new action.

Historical current containers, not a fresh inspection: MCP `8b199a6767bd39dadf82f6d70f964ab6da9c914a3b327229214d88991893647b`; Onboarding `0165a7d260a9c146101ac1471c843b1300587c579a18e99ea0c3a78cadcb0aae`; old Ingestion `477ea664c97ebae2bf50a9fdb4d2ae92c20275cf28e5941f09c1133354908338`. Installed old Ingestion JAR SHA256 `58199f4be91c4e99ac4b5fd2ac863303f4154257b88750d095c62409ab8f7630`.

CSV source `teatri-csv-6609b245`, version `c9fec43c-19b3-4ffb-9111-781bc347c5b0`, config SHA256 `b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d`.
Old approval challenge `9bca610c-aa24-4be3-ac29-0e5454e9d877` expired; no implicit reapproval or replay. Last retained source activation attempt0/generation0. Keep prior semantic, UDP, lineage and governed grant evidence in cumulative handoff; do not restart retired R9/R10 scopes.

## Login incident, guardrails and user interaction

Old context `.../ingestion-owner-reference-execution-tr33g8bg` stopped VERIFYING272/272. User reasonably missed URL/code and typed confirmation early. The previous flow multiplied polling and did not reserve final provider verification. Do not blame the user or propose the same flow again. Second launch was fenced before another preparation.

Read-only diagnostic log `/home/oufadmin/ouf-owner-stop-read.HnXJRo05/read.log`:232-source package verified, retained unverified token response unpublished, no login receipt/authority/owner plan/result, all claims retained, zero diagnostic OAuth/owner mutations. Old package SHA256 `afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5`, source closure `0493b8737f3421cd2c3d03eb11e1fb12b34c165c258a064e0905faf666ce7244`. Never reuse its token/refresh/device or delete/reset its claims.

Generic login repair source `5886cf722835cf2cd20505bcf626959fb4b2b11e`, CI39320511768,64PASS: explicit visible URL/code, callback before first token poll and every pending-token retry, reserve finalverification request, pause outside locks. Typing LOGIN COMPLETATO is never provider proof. Corrected v7 recovery then succeeded272→276 with explicit288 budget/window; publication used successful current v7 session276→278 without new login/window/budget. Old sealed HUMAN validators and histories remain intact.

Any future login is a **distinct native consent**, only when necessary, after preparing a concrete scope. Never silently expand288, reset consumed278, prolong the recorded window, automatically replay failed refresh or reuse old device codes. New finite budget cannot override revocation, integrity/custody, admission or consumed effect claims. Protect identity/scopes and reserve verification budget.

All STOP/interruption paths preserve private contexts, source seals, preparation/runtime/logical claims and journal. No automatic replay/rollback or launch after STOP. Diagnose read-only and issue a new narrowly scoped recovery only when qualified and authorized. No raw credentials, credential hashes, private key material or raw protected log lines in chat/GitHub.

Target is the user's oufadmin VPS; no direct SSH executor exists in this Work environment. GitHub development/CI are available. Native runtime decisions use terminal /dev/tty or THS, never chat text as substitute. Signed/immutable source and exact SHA checks precede sudo; use an outer subshell so set-e does not close the SSH session. Portable gh first:
`$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`, then command-v fallback, fail before sudo if absent. Preserve existing auth; never request/print token or assume private repo raw curl access.

## Normative baseline and handoff maintenance

AGENTS was reread for this handoff. Original current Matrix1.7 §1 and Onboarding/THS1.6 §2 P03/P07/P08/P09/P12/P14/P15/P23–P26 were consulted directly from the attached baseline text for owner/projection/HUMAN boundaries. This is a status handoff, not a new coherence/acceptance decision. Archive323 checksum PASS from prior baseline integrity work is integrity evidence only, never full compliance.

At the next sprint/coherence decision consult the actual current original PET/Matrix, Blueprint0.3 and relevant module PET (Authorization1.5, Gateway1.5, Ingestion1.3, MCP1.4) and record exact sections consulted. If original attachments are unavailable in the new chat, use the retained approved baseline source or obtain the originals rather than claiming to have consulted a summary.

Onboarding owns immutable configuration; Gateway mediates network/identity/coarse routing; Authorization evaluates; backend owners enforce fine-grained policy; HUMAN authority remains THS. Installation-specific domains, endpoints, issuer/audience, trust, secretRefs, host/network/storage/runtime identity come from validated versioned profile. No localhost/shared-host/shared-Docker-network assumptions or hardcoded municipal defaults; no contract-path changes or weaker IAM as a workaround.

Resiliencev3: finite durable cumulative budgets, idempotency/fencing, waits outside shared locks/transactions; only proven transient safe/idempotent requests retry with approved backoff/jitter, unknown/permanent/revoked/ambiguous mutations stop for reconciliation. Do not inherit default128/24h over a narrower operation profile.

Branch `feat/chat-only-recovery-package-20261018`, draft [ouf-deploy PR41](https://github.com/GioNob/ouf-deploy/pull/41). Before this handoff, head79610785daebacb9fd3df0c38ca89e4aeec8a5c0 had qualified publication but said not run. This handoff and receipt supersede that status. Do not merge/publish/deploy just because docs are current. Preserve qualification, execution, readback and acceptance as separate evidence classes.
