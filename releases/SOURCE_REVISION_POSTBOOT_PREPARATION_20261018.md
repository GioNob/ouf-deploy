# Postboot preparation successor — qualified code; target preparation pending

Technical8/8; functional4/6. This is preparation only, not installation or functional acceptance. The completed host correction and run39158332027 are not repeated. Historical handoff drafts remain unchanged and must not be executed.

## Normative consultation in cloud

The newly available original v1.7 ZIP has SHA256 e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce. All323 SHA256SUMS entries PASS; manifest CURRENT_NORMATIVE_BASELINE. This supersedes only the earlier cloud file-access limitation, not the normative baseline. [Integrity receipt](../evidence/pet-baseline-cloud-integrity-20261018.json).

Read original Matrix1.7 (ownership, representative acceptance, operational awareness, channel neutrality); Onboarding1.6 §§109.3–109.8 and109.14–109.17 (immutable history, migration ownership, finite retry, binding, THS recovery, evidence and local versus activation gates); MCP1.4 §122 (proposal-only versus THS HUMAN decisions); Semantic1.3 §160.15 (exact historical references and independent local/provider readiness); Gateway1.5 §T33.14 (reference-integrity activation). This is a scoped consultation, not certification of all PET requirements. Matrix1.7 governs cross-module conflicts; unchanged Blueprint0.3 requirements remain applicable.

## Concrete defects found in the unqualified drafts

- The retained document writer accepts only prepared-plan.json/review.json. The drafts pass new names and would fail. A separate closed-name immutable writer now handles the successor documents without weakening the historical writer.
- The staged c750 declaration was still bound to the old case, and the executor reloaded the old prepared bundle. A distinct v2 case and postboot executor now bind the reconciled original, private successor, completed host plan, exact source hashes and loader. No fallback to v1/preboot is admitted.
- Final observations checked only configuration. They now recheck process and network generation, Engine socket, APISIX namespace, completed host journal, provider empty/revoked proof, original lock and mounted configuration bytes/custody.
- The seven-file stopped compiler is now inspected before new preparation output, with exact directory/file closure, private directory custody, no links, no unknown empty directories or authority artifacts, and a second stable read.
- Incomplete preparation must not become executable: executor requires the exact successful preparation receipt hash and matching case/package/source closure before entry.main can be reached. Preparation itself never invokes entry.main or a login/authority/apply port.

All77 overlay source files plus the loader are byte-identical to c750 (the staged package contains81 files including executor/case/manifest). Candidate image archives are reused, never restaged or imported. The new executor and case are explicit successors; they do not retroactively modify c750 qualification.

## Qualification and remaining gates

Eleven cloud-workspace tests pass: complete synthetic preparation with real private files, changed-PID refusal, exact13 host claims using the native owner fixture, original/authorization/history preservation, v1 rejection, no missing-input fallback, hash/parent/archive drift, seven-source partial custody and exact81-file successor assembly. External Engine/SQL/compiler boundaries in the orchestration fixture are explicit doubles; this is not a target read or native database proof.

Native CI [39160533382](https://github.com/GioNob/ouf-deploy/actions/runs/39160533382) completed successfully at source31092e92171c031facb9e65c5fc27db82e0f9844: **74 native regressions +11 postboot tests PASS**. Job117772707233 includes signed authority, real root custody, PostgreSQL and the Spring override verifier. Job117772912210 staged code only, without target preparation or deployment.

Staged path: `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-postboot-code-39160533382`. Manifest SHA256 `a1a82e66441f10ac8a564ab25c18e5bfcdac20993b73f62308253bfa4556e336`;11 files. Cloud reconstruction gives the same manifest hash.

The immutable delivery is source783925566360b96d3ea4869b986df6d79156024d, launcher SHA256 `04bf87e0a5374df9e3262ed6b855861aebdb9f061a8af1840c8412f2b3a84f19`. Delivery CI [39160838538](https://github.com/GioNob/ouf-deploy/actions/runs/39160838538), job117773616467, completed successfully: **4 tests PASS**. Four delivery tests cover the exact pinned closure and refusal of changed manifest, changed module and linked dispatcher. Target protected access is intercepted by the fixture before any file is opened; no target result is claimed.

## Required target step

The cloud runner cannot read all protected root inputs. An operator with physical sudo access must run the following **once on the VPS as oufadmin**. This only prepares new private documents and frozen code under the original lock, after checking the completed host recovery and original custody. It allows four read-only database sessions, has a300-second bound, and does not issue runtime authority or execute a release. Keep the printed log and return its redacted result; do not upload private documents. A STOP requires reconciliation before retry, with no budget reset.

```bash
(
  set -euo pipefail
  umask 077
  ouf_delivery_dir="$(mktemp -d)"
  curl --fail --silent --show-error --location \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/783925566360b96d3ea4869b986df6d79156024d/scripts/launch-source-revision-postboot-20261018.sh' \
    -o "$ouf_delivery_dir/prepare.sh"
  printf '%s  %s\n' \
    '04bf87e0a5374df9e3262ed6b855861aebdb9f061a8af1840c8412f2b3a84f19' \
    "$ouf_delivery_dir/prepare.sh" | sha256sum --check --status
  bash "$ouf_delivery_dir/prepare.sh"
)
```

Target c23 reconciliation,55e seven-file custody, current socket/PID/namespace/PG checks and native compilation remain unproven until this target step succeeds. `readyForExecution=false` is deliberate: no executor delivery or new HUMAN session is opened yet. After the result is reconciled, installation authority, Onboarding33→34/MCP release, governed generic profile publication and functional milestones5/6 remain separate native gates. Preserve13 Teatri objects/ACKs/lineage,20 properties/identity choices and8 Cinema objects.
