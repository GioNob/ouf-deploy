# OUF cloud handoff after independent source-revision installation readback

## Current checkpoint: technical8/8; functional4/6

This checkpoint supersedes pre-installation STOPs and pending-readback wording. On2026-10-19 at09:28:42 Europe/Rome the operator supplied the qualified protected readback: complete, allStagesApplied, journalVersion57, Onboarding34, UDP36, MCP migrations unchanged, revision table owned by the application with append-only trigger,80 Gateway routes with all78 original routes preserved and exactly2 added. New Onboarding readiness200/UP and MCP204; unchanged UDP/Ingestion; old Onboarding/MCP containers retained, stopped and restart disabled; existing0440 MCP metadata exact custody/hashes preserved.81 frozen files and original private inputs verified. No token/HUMAN journal/dump opened;3 explicit READ ONLY SQL sessions, no journal write/authority/publication/job retry. Backup current custody/size/receipt proven; new full dump checksum explicitly NOT proven. Current authority expired and not accepted for execution.

Exact target receipt plus a NEW direct ouf-admin MCP owner read: [evidence](../../evidence/source-revision-postinstallation-target-20261019.json). The direct read confirms Teatri source ACTIVE, lockVersion4, unchanged config/publication. The expired historical challenge is not revived or reused.

## Next actionable boundary: ChatGPT tool discovery, not another rollout

The installed MCP manifest at sourcea79b139c7a26d64a584b0a432ebb8df8c32a52ed includes two ACTIVE/toolEligible native tools:

- `source.onboarding.revision.read`, capability `ouf.onboarding.revision.read`.
- `source.onboarding.revision.prepare`, capability `ouf.onboarding.revision.prepare`.

Exact inspected manifest blob4db11dc575fdae8a1e98a6ea3b4495f4d3a85ac7 and kernel blob315901bf5f1a8b23673328a0f9d28d32456b31d9. The kernel registers ToolEligible entries through the official SDK. The current chat tool inventory lacks BOTH tools. Existing `source.onboarding.read` works through ouf-admin, but proves neither new tool discovery nor fresh token scopes. No403/unknown-call was generated for missing tools, and no alternate-account bypass or generic raw RPC was attempted. A stale client metadata snapshot is a hypothesis, not a measured diagnosis. Plugin discovery returned no public OUF directory result; this does not negate the two working existing private account connections.

Official refresh instructions consulted: https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata . For a directly connected custom MCP server, open its connection in ChatGPT Plugins and Refresh, confirm metadata changed, then start a new conversation and rerun affected tests. For published plugins the documented update mechanism differs (continuous review). The assistant has no tool for refreshing this connection; user action is required. Do not uninstall/recreate the connection, broaden permissions, restart services, rerun installation or open a new runtime HUMAN window merely to refresh discovery. If login is actually requested by the native connection, complete it there; never paste credentials or tokens into chat. Fresh scope proof remains pending.

After refreshed discovery, FIRST call the read tool with ouf-admin:

```json
{"sourceId":"teatri-csv-6609b245","onboardingVersionId":"9860853e-e8f3-4b93-b9d2-03521a039962"}
```

The connector injects `link_id`; choose ouf-admin below. Do not pass a manufactured token or skip owner/Gateway authorization. A denial must be classified using the owner response, without guessing scopes or changing accounts to evade it. Read the20 current property rules before preparing any changes. Keep parent source/version, file asset, semantic pins, extraction/acquisition settings and identity choices unchanged. Native prepare schema requires parentVersionId, expectedVersion, configurationHash, stable commandKey, explicit changes and publicationEffect=`NEW_PUBLICATION_MAY_START_ACQUISITION`. No prepare call has been made in this continuation; no command key has been consumed. After ambiguous prepare use the same source/parent/key with revision.read, never invent a new key. Preparation is not publication or acceptance.

The native publication review MUST disclose that activation may start an acquisition using retained scheduler settings. Do not promise that publication cannot acquire. Inspect and bind current state before preparing the single controlled second acquisition; never restart historical jobs implicitly. Functional5 requires a controlled second acquisition of the SAME CSV with no identity duplicates; functional6 requires both acquisitions/provenance/ACK and preserved8Cinema. Preserve13Teatri identities/13ACK/lineage,20properties and all prior identity decisions. Teatri is only the test case; the property-reconciliation profile remains generic. Publication/identity choices remain native HUMAN/THS decisions.

## Completed immutable execution chain — preserve, never replay

Latest successful execution: `/etc/ouf/deploy-snapshots/source-revision-execution-uow4n8lp`.
Prepared capsule: `/etc/ouf/deploy-snapshots/source-revision-human-recovery-inmfuoj2`.
Independently read preparation receipt SHA256`3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587`.
Source closure SHA256`aa7b67154ef76626e48ccca3fbe9b9df0995bc095baeedb6b2dcacd3ac5b0a62`.
Qualified execution sourceb829415351f7b0576f72a20b7e36e913294b447a, stage39212047375,144 passing tests including immutable delivery39212428373. The original frozen executor/loader and77 modules (81files total) are retained, with explicit qualified entry/login successors. No source-revision release reimplementation is needed.

Native runtime finished complete/applicationReady/migration34; authorization statusOWNER_POLICY_ROLES_SCOPES_RECONCILED, policy`ouf-lab-authorization:45`, old grants/role assignments preserved. THS proposal`f25d9028-b81f-4eec-a567-43fa160f869b` independently read PUBLISHED. No generic property profile published, no source activation/semantic dispatch/new client scope proof, no job retry. This is separate from installing and reconciling infrastructure.

Protected read qualification: sourcea8f091898ac73dd0e89ec17a80adb5d8e71240e5; run39215600588/job117938599307,12testsPASS. [Scope, limits and immutable read delivery](../../releases/SOURCE_REVISION_COMPLETED_READ_20261019.md). This read already succeeded; no further sudo read is required merely to repeat its evidence. Historical launch commands elsewhere must not be replayed.

Original reconciled inputs remain at `/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh`: current-original-preparation.json SHA256b3988d964a3c60b06b17952863f4fc62fc9a8f1626ced82bfb864721eb7b740a; postboot-private-inputs.json SHA2561ab309f747d2e0c70b3a284258ea0f2100d51bc149ef9c2ae2b55b73f3871c62. Preserve candidate image archives and originals. Host network recovery completed run39158332027/ce132bbcb3bd8239689415797371afe636db7762; never rerun. Host readiness is not Semantic/provider/graph acceptance.

Prior blocked/expired contexts and consumed claims/journals are evidence only:55e7sduq, f6w3lo6z, q7bq1ex3, k6rk22xj, tvc2ilnv, daxl0o6h, dvf517sr, kcw73ask, inmfuoj2. The expired zero-effect dvf authority received one explicit child claim for the new successful scope; the old global claim and journal were not reset. The failed HUMAN refresh189/256 was not replayed; the successful continuation required explicit new native login consent and fresh release APPROVO. Exact current HUMAN counter/session is not inferred from later no-token readback. No OAuth budget reset, claim deletion or authority reuse is authorized.

## Standing user instructions and normative inputs

CLOUD execution only. No subagents or automations. Repositories: GioNob/ouf-deploy, branch`feat/chat-only-recovery-package-20261018`, reuse open DRAFTPR41. Keep docs current. User already authorized read/write/documentation on all GioNob repos and every OUF MCP tool with both accounts. Do not ask generic repository/MCP consent again. Runtime HUMAN/THS remains native and cannot be supplied by development authorization. Account ouf-admin`link_6aafef96b4148191b767e9af7b756a07`; giovanni-chatgpt`link_6aaff0a687788191b28f92f6fff16c71`. Verify actual availability in each new chat.

Read AGENTS.md, docs/CHATBOT_CSV_ROADMAP.md, docs/CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md, releases/PET_ROADMAP_RECONCILIATION_20261010.md and docs/LINKED_OBJECT_PROPERTY_RECONCILIATION_V1.md. Distinguish recent target evidence from historical gaps. The generic profile implementation exists; don't send prose specification as a native profile or redo release code. Older untouched specification evaluation is historical, not fresh installed-state proof.

Consult original PET at every pertinent sprint/decision. Attached OUF_Reality_Baseline_Package_v1_7.zip checksum e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce,323checksumsPASS. Matrix1.7 prevails in cross-module conflicts; Onboarding1.6/Auth1.5/Gateway1.5/Ingestion1.3/UDP1.3/Semantic1.3/MCP1.4; unchanged Blueprint0.3. Current cloud workspace contains original DOCX and XML-extracted texts under `/workspace/scratch/39b4c484a52e/pet`; attachment under upload. These transient paths are not guaranteed to survive another chat; seek exact project/repo originals first and do not pretend inaccessible sections were read. Current decision consulted Matrix1.7 §1 and Auth1.5 §109.6; protected reader sprint also consulted Onboarding1.6 §§109.14–16. The Windows original path is not a cloud-access mechanism.

No SSH/root direct access in this session; self-hosted runner can read Docker but not all root references. Never use privileged containers to bypass that boundary. The operator's qualified protected receipt supplies the latest root readback. Preserve durable attempts/idempotency, classify unknown failures fail closed, reconcile ambiguous effects before any permitted continuation. Never recycle expired authority or repeat a successful preparer/executor. Keep progress updates concise in Italian,8/8technical and4/6functional until new end-to-end proof.

Earlier full preboot/historical context: [original immutable handoff50a1966](https://github.com/GioNob/ouf-deploy/blob/50a1966162299ded3a7d1bacffe785c70809b976/docs/handoffs/OUF_CLOUD_HANDOFF_20261018.md). Its unqualified textual policy/prepare drafts were superseded and must never be executed.
