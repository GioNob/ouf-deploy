# CURRENT — live input reader namespace correction; old reader STOP retained

The first live input invocation returned REPLACEMENT_GATEWAY_MUST_USE_NEW_NAMESPACE
at READ_RETAINED_PREFIX_AND_LIVE_METADATA. Retain
`/home/oufadmin/ouf-rollout-continuation-inputs.WLdvgBh9/reader.log` and its launcher.
No new login/authority/effect. The previously delivered bridge1776f946… incorrectly
required gateway netns inode inequality against the historical reference. The
frozen native GatewayNamespacePin already documents and supports inode reuse after
namespace destruction: it binds the durable replacement CID,first PID/start,the
stopped/detached/renamed predecessor and current `/proc/NEW_PID/ns/net`,plus a held
FD for subsequent traffic. The input reader must use the same identity semantics.

Correction is limited to the read-only bridge: validate current namespace shape,
retain both current replacement and predecessor frame/process predicates,select
the current namespace only through the recorded NEW PID,and require both live
observations to match. Report matchesPreviousGatewayNamespaceInode explicitly,
namespaceSelectedFromDurableReplacementPid=true,oldNamespaceReferenceReused=false.
Never supply a historical namespace FD or substitute a previous PID. This is not
permission to accept a changed process,CID,MAC/IP,mount,restart policy or namespace
change between passes. No frozen native module/loader change is needed.

Regression now includes a valid same-inode new-process case and composed public
output,as well as changed current namespace between passes,owner namespace drift
and invalid namespace shapes. The old negative test accidentally failed at the
owner-namespace check and did not exercise the intended gateway condition.
Its prior CI success did not cover the real target case. The failure is a bridge
predicate defect,not a proven target Gateway failure. Target runtime health is
still not established by an incomplete read. Qualify the corrected artifact on
both Python versions before a distinct pinned read-only invocation; do not reuse
the old launcher or advance rollout/login/budget.

Normative delta reread: Matrix1.7§1,Authorization1.5§12.1,currentAGENTS; actual
qualified namespace.py predicates remain the code authority for local identity.

---

# Previous checkpoint — stage18 stopped snapshot reconciled; live input read next

Technical8/8,functional4/6,G3OPEN. No acceptance or current authority.
The owner supplied the qualified stopped reader result at
21October2026 11:12:19.914845Europe/Rome. The finite rollout authority expired at
08:54:36Europe/Rome. Same boot, wall/monotonic remaining0, readStateIDLE,
18APPLIED effects, no pending stage claim. Do not call old step/reconcile/approve/
initialize, repeat key creation/image import/lifecycle, or reopen old HUMAN.

Exact receipt is in evidence/ingestion-rollout-stopped-snapshot-target-20261021.json.
Journalc9907ea94b0c5908109e45e5e10be4641f610bc0374bb053de2851781461f2c0;
reviewb0276204afeb592487428863f7c3f6392d0bb66c6dc0ca99620867b1d23f8521;
logical2d41675c88b42cf7b07964fe757b71dff1dfe04902c5a06c3efa63d38cb8a966.
Context remains `/etc/ouf/deploy-snapshots/ingestion-rollout-native-7fs9r6md`.
Log `/home/oufadmin/ouf-rollout-stopped-read.DwNpU43F/reader.log`.

## Concrete next input collection

The stopped snapshot deliberately made no Engine calls. Before preparing new
HUMAN/runtime authority, verify current durable replacement process identities,
old retained container disposition and unrelated applications. The new bounded
reader uses the EXACT frozen114native modules+loader and their pure frame,
runtime-binding and stage-aware predecessor predicates, without instantiating
NativePorts, HumanSession, key/SQL/lifecycle/owner/Gateway ports or the issuer.
Source closure/old scripts are not modified. A separately hash-bound stdlib bridge
issues only EngineGETs, with exactly8durable container IDs and the retained Gateway
image ID: two passes, maximum18GETs,5second request timeout,180second invocation
deadline. No list/discovery,POST,exec,service HTTP,login,refresh,signature or key read.

The8containers are3unchanged apps(Onboarding,MCP,UDP),unchangedPostgres,2retained
stopped/detached predecessors and2replacements. Check exact recorded first PID/start,
image,host policy,mounts,addresses/MAC and new Gateway namespace; unchanged profiles
retain their explicit native/sorted mount encoding. No host/interface defaults are
introduced: Ente-specific values come from the pinned original packet and review.
Stat the original dedicated key inode against its recorded final metadata without
opening bytes. The Gateway environment slot must be a single resolved hex value,
but equality of that value to key-file bytes is NOT reverified; current authorized
NativeKey/generation gates must still verify it before any future dependent effect.

The reader rechecks the18APPLIED prefix and exact pinned journal/review before and
after live reads. Safe output contains IDs/processes and namespace metadata; no
raw inspect,environment,key values/hashes,tokens or private payloads. It observes
runtime metadata, NOT application readiness, current owner policy, SQL admission,
route content or provider authorization. No restart policy is changed; both new
restart policies are expected still disabled because restore stages are pending.

Next manual command after CI: pinned launch-ingestion-rollout-continuation-inputs-
20261021.sh without arguments. May request sudo oufadmin password; never IAM.
Expected RETAINED_STAGE18_LIVE_INPUTS_MATCHED_NO_AUTHORITY,engineRequests18,
oauthRequests0,runtimeEffectsDispatched0. Return public JSON and reader.log.
OnSTOP retain all; diagnose same context, no replay or new authentication.

## Continuation feasibility and unimplemented work

Source review confirms a separate bridge can compile a new native review from the
same28intent records, retain logicalOperationRef and import all18APPLIED records
and durable nativeResource/nativeFinalMetadata fields. Old read/native counters,
old journal/version/claim hashes must be carried cumulatively, never set to zero.
The new journal needs explicit one-use fencing linked to the old logical claim;
new scope/HUMAN/authority hashes and a separately consented finite deadline may
describe only a NEW successor session, never rewrite the expired one. The entry
and114modules can remain frozen. The ordinary initialize path cannot be replayed:
its logical-operation claim is already consumed. This is an implementation plan,
not a qualified importer, runtime authority or permission to skip predecessor proof.

Provider budget is288/288. A possible separate proposal is4additional requests,
new ceiling292,for one DISCOVERY/DEVICE_START/post-browserTOKEN/USERINFO sequence,
zero retry reserve. This reader DOES NOT grant that budget or open a window.
Before asking for consent, implement/qualify the cumulative grant, immutable old
session linkage, concurrent/crash fencing, strict288→292 accounting, private reader
and the remaining runtime continuation with fresh current gates. Stage all commands
before fresh token acquisition; retain >930second guard and900second runtime limit.
Do not spend a fresh token while writing the applicator or assume4requests succeed.
No callbacks,background coordinators,automatic polling/login/replay,or stage loops.

The ten residual stages remain exactly:
REBIND_GATEWAY_TRANSPORT;VERIFY_REBOUND_ROUTE_MAP;
PUT/READ mcp-ingestion-history;PUT/READ mcp-ingestion-status;
VERIFY_FINAL;ingestion.RESTORE_RESTART;gateway.RESTORE_RESTART;VERIFY_RESTORED_FINAL.
F5/F6,native profile publication,M1/M2 and full PET acceptance remain open.

Normative delta actually read: Matrix1.7§1;Authorization1.5§§2.1/12.1;
Ingestion1.3§§94–95;resilience policyv3§§4–7/14–16(current blob0a7068e9… unchanged);
rootAGENTS atcf2cf882… . Full PET compliance is not inferred from this consultation.
Original baseline and measured effort are not rewritten. Operator wait since the
previous handoff is not technical effort; current unsegmented work remains explicit.
