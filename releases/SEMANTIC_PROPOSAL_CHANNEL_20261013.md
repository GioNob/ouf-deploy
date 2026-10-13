# Semantic proposal channel implementation and runtime handoff

The source path needed to register Teatri DRAFTs, validate exact revisions and request real THS review challenges is implemented and merged. It has not been installed on the VPS, and the Teatri proposal remains unregistered. This checkpoint replaces the earlier statement that the missing proposal channel still needs implementation; it does not replace retained runtime evidence or installation gates.

| Module | Exact merged source | Change | Qualification |
| --- | --- | --- | --- |
| Semantic Registry | `0b0fc53826bd9be566092bcc621854adaba08358` | Transactional CREATE/VALIDATE/REVIEW receipts, caller-scoped read, current green validation/version fencing, signed Gateway receipt/filter | [PR36](https://github.com/GioNob/ouf-semantic-registry/pull/36), [CI38464780047](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38464780047): 65 Java/PostgreSQL tests, zero failures/errors/skips, production image smoke |
| MCP | `a02b13ecb7cf9b73c070b59f26b60aaed6060944` | Four closed tools, owner permission/resource preflight, stable mutation key, explicit receipt reconciliation, equivalence budgets ignore only the mutation command key | [PR65](https://github.com/GioNob/ouf-mcp-server/pull/65), [CI38464761855](https://github.com/GioNob/ouf-mcp-server/actions/runs/38464761855): ordinary/race tests, staticcheck, govulncheck, migration/maintenance; all twelve same-head workflows pass |
| Gateway | `8cac6c8877b16eed6f93db9eb08985035b510da5` | Fixed routes and purpose-bound body/path/actor receipts; no upstream replay; existing authorization proposal and THS route composition required | [PR71](https://github.com/GioNob/ouf-api-gateway/pull/71), [PR72](https://github.com/GioNob/ouf-api-gateway/pull/72), [CI38465302839](https://github.com/GioNob/ouf-api-gateway/actions/runs/38465302839), [general CI38465303112](https://github.com/GioNob/ouf-api-gateway/actions/runs/38465303112) |

The targeted Gateway gate passes 65 tests, including actual materialized Lua for four operations and three proposal actor types. Four receipts emitted by that Lua in CI38464424182 are committed as synthetic vectors and pass the Java owner verifier. The signed-envelope HTTP test then traverses the production filter, current owner policy, PostgreSQL, validation and challenge creation. This is composed development qualification, not deployed IAM/THS/CSV evidence. Gateway general tests retain any pre-existing explicit environmental skips; do not describe the entire platform as zero-skip from the targeted result.

Post-merge verification also passed: all twelve MCP workflows (including CI38465619673), Gateway targeted/general CI38465719561/38465719759, and all four Registry workflows including Java/PostgreSQL/image CI38465711427. These source checks do not establish installation or runtime acceptance.

## Exact tool and owner boundary

| Tool | Transport capability | Owner permission | Operation |
| --- | --- | --- | --- |
| semantic.propose | ouf.semantic.propose | ouf.semantic.propose | COMMAND |
| semantic.review.prepare | ouf.semantic.review.prepare | ouf.semantic.review.prepare | COMMAND |
| semantic.approval.request | ouf.semantic.approval.request | ouf.semantic.approval.request, plus owner review.prepare | COMMAND |
| semantic.proposal.read | ouf.semantic.proposal.read | ouf.semantic.read, plus the original command permission at owner read | READ |

The three mutation inputs require a stable `commandKey`. Validate requires the exact `revisionId` and `expectedRowVersion`; review also requires the genuine `validationRunId`. The owner computes the content hash and accepts only its current PASS validation. The key is scoped by authenticated tenant/principal, and different payload/operation reuse conflicts. Effects and the receipt commit together. Duplicate/concurrent requests converge, failed transactions leave neither receipt nor effects, and completed effects survive a missing response. Changing only the key cannot create a new semantic equivalence budget.

No automatic transport replay is enabled. An ambiguous call needs the owner receipt and the existing MCP accounting recovery protocol. A receipt read is a historical domain result, not current challenge state or permission to clear accounting debt, reset budget, activate, approve or publish. Expired/decided challenges must be examined in the authenticated THS. No decision or publication capability is exposed as a tool.

## Runtime changes that require governed target work

1. Package these exact new sources as distinct artifacts with reviewed provenance. Do not relabel them as the original signed V11 image, reuse its acceptance, replace its static key identity, or silently absorb unreviewed migration/runtime differences.
2. Establish a distinct owner receipt key through the installation owner. Gateway signs, Registry verifies, MCP never receives it. Synthetic `ab` test keys and test issuer/audience settings are not target authority.
3. Configure Registry `ouf.semantic.proposal-receipt.key-file`, `issuer`, `audience` and `workload` from the current installation. The configured key route must have protected root ancestry, root ownership, one regular non-symlink file and protected read permissions (0400/0440/0600/0640). A non-root workload may receive read access through a governed group. No target key has been read, copied, created or accepted.
4. Review the actual current database and migration delta. V10 adds the command receipt ledger; the source contains other pre-existing migrations. A source test does not authorize applying them to the retained V11 database. Use the existing backup, admission, signed authority and ambiguous-effect reconciliation contracts.
5. Materialize Gateway through `tools/materialize_semantic_proposals.py`, supplying both the existing authorization owner-key environment reference and the distinct semantic owner-key reference. The composer rejects omission of the existing reference and preserves the authorization/THS route groups. It retains three-second upstream timeouts and zero retries.
6. Deploy the separately qualified MCP/Registry/Gateway artifacts via current owner authority and verify actual grants, delegation, owner policy freshness, route closure and connector tool discovery. This session has GitHub source/CI access and read-only semantic OUF tools, but no SSH/root channel or callable runtime proposal tools. No apply-ready target installer or target acceptance is established by this handoff.

These are target prerequisites, not new chat approval requests or invented domain authority. Source development delegation is not a finite HUMAN installation mandate. The token-owner installation and original six-mount/current runtime acceptance gaps remain separate and are not waived by this native proposal path.

## Teatri continuation after installation

Preserve [the exact proposal](teatri-native-semantic-proposal-20261013.json), hash `97cc035cf957652d17b86da86bf19724845c259e901c7d34c1be1a248d121fed`, asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profile `7984c39c-7396-4248-ab0a-f2efc390b49c` version 1, historical 13 rows and 20 columns. It contains one CLASS and twenty PROPERTY proposals. Existing ownership references are review inputs and do not transfer grants.

First examine adequate internal reuse as already required by the proposal/PET. If the native extension remains appropriate, register the class then the properties with stable keys; retain real revision receipts; validate and request hash/version-bound review challenges. Give HUMAN the actual authenticated THS cards. Publication and source configuration approval/activation are separate HUMAN actions. Only afterwards perform the one real run and verify durable ACKs, canonical identity/lineage and complete authorized search/accounting for all thirteen rows. Do not retry the previously permanent ingestion denial before a fresh deployed/authorized path exists, and do not reuse the old source intake or request as a new authority.

No VPS mutation, R12 operation, budget reset, credential read, signing-key issuance, HUMAN decision, semantic publication, ingestion run or new CSV result occurred in this implementation turn. Retain all previous private snapshots, consumed claims, incident history and Cinema lineage. Follow [working rules](OUF_WORKING_RULES.md), [AGENTS](../AGENTS.md) and resilience policy v3. Keep operator updates at least once per minute; no background-work claim after the final response.
