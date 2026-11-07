# M2 infrastructure review fragment — 31 October 2026

The offline preparation path now connects the existing four-owner private review
to the exact `registryGatePeerWindow`, `providerInstallation` and
`operationalLeaseInstallation` parent components. It reuses the existing scope
compilers; native owners continue to authenticate, admit and execute separately.
The result is a **fragment**, rejected by the complete parent-review parser.

Inputs select the static provider and worker templates, finite gate and v2
full-handoff profile, existing common-lock identity, wrapper/manager bindings,
separate journals, attestor binding and parent identity context. All inputs are
hash-bound and closed to extra fields. The compiler cross-checks the independent
Registry image/frame/recipe/source closure, installation/desired-profile hashes,
provider/worker kernel, DNS, coordination and kernel lock, public verification
policy/OpenSSL, isolated provider signing keys, and matching worker attestor.
The worker's generation and newly owned logical lock remain unmaterialized.

The original v1 initial maximum remains 90 seconds. This new fragment requires
the separate v2 full-handoff profile, at most the selected gate window and the
original 300-second protocol ceiling. It never changes a live window. Each
existing provider stage permits one mutation dispatch with its original bounded
read reconciliation. All owner roots are distinct and cannot shadow protected
sources, inputs, keys, executables, retained journals or the shared kernel lock.

Existing provider binding validation reads protected ancestor metadata; assembly
does not read private file contents, sign, initialize an operational clock,
call Engine, run commands or perform native owner effects. Declared hashes are
not authenticated custody or native admission. The Registry child/HUMAN,
current full cohort/TLS/IAM/DB/trust/fencing/custody, capability publication and
complete parent review remain separate requirements.

`scripts/export-m2-discovery-infrastructure-review.py` packages an independent
127-module source closure with the fixed independent frame baseline and exact
existing loader template. The source-map file has its own fixed hash anchor.
Changing source plus a matching source map, or changing the loader, is denied
before packaging. The original 108-module review capsule and 37-module worker
pins are unchanged. Revision claims are provenance, not publisher trust;
interpreter/stdlib and complete capsule custody still require exact review.

The root `-I -B -S` capsule offers `prepare` and read-only `inspect` only. A
0600 input and 0700 empty protected output are required. An exclusive fsynced
claim precedes the private assembly; the public hash/count receipt comes last.
Partial output is preserved and cannot be completed on retry. A different
loader/source/payload/revision binding cannot adopt an earlier assembly. Private
paths, identities, exception messages and malformed arguments are not echoed.

Local verification: 15 tests, 0 failures/skips, 8.145 seconds. Tests use real
Ed25519/files/archive fixtures and the real parent guards; other parent parts,
images, native facts and current admission remain modeled. Tests also deny
content reads, commands, signatures, Engine requests and publication during
assembly; cover cross-owner drift, shadowing, hash/mode/symlink checks, partial
output, input drift, artifact tampering, isolated CLI operation and compiler
rebinding. The dedicated CI workflow exports only the compiler and its public
metadata, never private input or output. CI qualification is recorded separately
after final logs and the downloaded artifact are verified.

This advances preparation only. Teatri M1/G4 technical8/8 functional6/6 remains
acquired; Farmacie is the same SUCCEEDED61rows/10columns, ministerial STRING/all
10 OPEN, with no upload/profile/acquisition replay. M2/G5–G7, 24 AT, 8 UX,
8 stability checks, real Farmacie→Ingestion→UDP/all61 outcomes, reimport/fault/chat,
boot/rotation and two real clients remain OPEN. Registry Java stays paused.
Historical UNKNOWN/MCP/worker causes remain OPEN; a fresh passing scope does not
resolve an old incident. No target apply, runtime authority/grant, budget reset,
consumed replay, merge or release acceptance is authorized by this fragment.

Next: integrate the separately authenticated Registry child and governed
capability-publication component with the exact full parent review, then obtain
current native/cohort custody and admission before any target operation.

CI qualification: source `41f935ecdec2716926d4b6947a6dd763e8124ec4`, PR run
[41183119468](https://github.com/GioNob/ouf-deploy/actions/runs/41183119468),
job124484438883, 15 tests/0 failures/0 skips in7.214s, final log read. Earlier
four-owner compiler regression also PASS15/2.610s, run41183119343/job124484438713.

Downloaded artifact13035554097: exact two ZIP members, all127source bodies,
fixed baseline, loader, public metadata and byte-exact local rebuild verified.
Capsule2,027,433bytes SHA
`577ec0d4394b35acb9fba4482ba72064f67fdded1877c881ba9aa428d58d8ac7`;
ZIP607,139bytes SHA
`9b4c842d990453045c08540681cdec931207d1d58ca8d396298a4a01a1fd07ea`.
The claim `d47035b38474b06e8326e588c5435238933379b3` is the CI PR-merge checkout,
not authenticated publisher trust. Source-map anchor
`215781561ee46ac2682079941b63c190bf7124596671957c484d3402e598d14e`.
Full evidence: [qualification](../../evidence/m2-infrastructure-review-20261031.json).
The general protocol/native/IAM runs are separate scopes and were still running
at this qualification snapshot; their success is not inferred here.

## General native regression retained separately

The later final report for source41f935 is not all green. In native
[run41183119362](https://github.com/GioNob/ouf-deploy/actions/runs/41183119362),
finite124484438519 and sealed124484438360 passed; final logs/reports were read.
Registry-worker124484438539 failed during START observation with
`CURRENT_OWNED_DISCOVERY_LEASE_PUBLICATION_REQUIRED`. The existing tap recorded
QUIESCED/leaseAuthorized=false and two exact expected keys with nonpositive lease
families; the separate final worker read was ACTIVE/RENEWED,1attempt,16publications,
1reentry. These reads are not atomic. The positive-publication requirement was
not satisfied: treating QUIESCED as retryable UPDATING would relax revocation.
The reason for coordinator/worker divergence remains OPEN. Failure log SHA
`660c963675bee1a91d70fc55e067548c509278c4b5a5cdfb82c16e93eb573ee5`.

A CI-only follow-up now reads up to64recent service-log lines, with2s timeout,
strictly after an observation failure. It accepts at most65536raw bytes and
emits up to32strictly validated state/reason/counter records; raw messages,
identities, paths and malformed/authorized rows are omitted. This is separate
post-failure evidence, not an atomic account of the earlier publication.
Snapshot taps add no reads; successful observations trigger no new command.
Original errors survive unavailable logs or emitters. It changes no worker,
production observer, budget, signature, start or observation-retry policy.
7diagnostic/early-review tests PASS0.246s locally. The native follow-up requires
its own final report; a passing fresh run would not close the recorded cause.

Current IAM run41183119340/job124484438551 PASS251tests/33suites/0skip, final
disposable Keycloak report read,0production calls/targetInstallerReady false.
Protocol41183119606/job124484439255 was still running; Chatbot41183119318 was
cancelled (its workflow cancels previous runs on the same PR). Neither is
claimed qualified here. No all-green general qualification follows from the
independent15-test compiler pass.

## Completed follow-up reports

Source41f935 protocol run41183119606/job124484439255 subsequently PASS463tests/
54suites/0failures/0skips in746.315s, final log read. The earlier pending status
above is historical; native Registry failure and Chatbot cancellation remain.

CI-only follow-up source `11f80398c256b9c77da97ebc101164cfa6ae124a`, native
[run41183954779](https://github.com/GioNob/ouf-deploy/actions/runs/41183954779),
PASS finite124486929621/sealed124486929432/registry124486929518. All final logs
and reports were read. Each mode ran7diagnostic/early-review tests successfully
(.260/.215/.317s). The actual Registry/token/transport/sealed-worker report
passed with Registry Java paused, modeled HUMAN/IAM realm/images/packages/earlier
transition prefix, no target cohort/E2E/authority/release claim.

This fresh scope did not reproduce the failed QUIESCED snapshot and never
invoked post-failure service-log capture. The failure branch is proven by
controlled tests only. The source41f935 divergence and historical causes remain
OPEN; this pass is not a causal fix or permission to replay the failed scope.

The compiler also PASS15tests/0failures/0skips in10.170s at source11f803,
run41183954966/job124486930033, final log read. The previously downloaded and
verified127module capsule remains byte-exact against the local source after
these CI-only changes. Its original artifact/revision binding remains the one
qualified above; a later generated artifact is not independently endorsed here.
Later general CI runs remain separate scopes.
