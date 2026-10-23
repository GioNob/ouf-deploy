# Registry credential lineage reader — specification

`scripts/read-registry-bound-owner-lineage-20261023.py` is a standalone, standard-library-only, read-only reconciler. It fills the specific missing association between the reviewed Registry token mount and retained owner histories. It does not repair or start the Registry, run a token worker, or qualify a recovery executor.

## Fixed input chain

The production entry point accepts no arguments and requires root, `-I -B -S`. It uses the exact retained history-capture path/hash `8facd750…902c9`, historical review path/hash `07ee9e8a…413bc`, and source commit `d7bbb768970aad1a001ca4d085bcc87c58a29cec` already identified in `tools/semantic_registry_history_capture/case.json`. These are retained observations, not renewed authority.

The pinned review identifies the hash-pinned `child-bundle.json`. The reader checks its source declaration and prepared-input hash against the review, and its Registry inputs against the retained capture. It then requires the exact relation implemented by `tools/chatbot_file_cohort/assemble.py`: Registry `renewableToken.source/fileName/gid/ownerBindingHash` equals the owner's `Binding.output_directory/output_member/output_gid/digest`. The historical owner installation scope identifies an exact journal, session hash, owner profile hash, first-grant hash, context and generation. That journal must be one of the 18 already observed candidates.

Only those 18 literal candidate paths embedded in the script are read. Each contributes `recovery.json`, `owner-session.json`, `owner-admission.json` and `owner-first-grant.json`. No path discovery, globbing, directory enumeration, newest/max-counter selection, fallback or automatic rerun exists.

## Lineage and accounting semantics

The historical anchor must match its retained reviewed session/profile/first grant. Candidate records are linked by the exact predecessor recovery and session hashes emitted by the installed owner schemas. Equal logical-owner and first-grant references establish the metadata lineage under examination; disagreement is an ambiguous linkage and stops. The anchor's complete connected component must include every matching candidate, with one earliest record whose predecessor count is exactly the single retained first controlled grant. Duplicate predecessor matches, disconnected matching records, missing earlier accounted ancestors, branches, cycles and missing unique terminal records stop closed.

The terminal record is the unique end of this bounded hash graph. Its ordinal is an observation, **not selection of a current owner**, proof of exclusive ownership or authority to continue its budget. Other owners and records outside these 18 are explicitly unexcluded. No live fence, worker lock, installed code, signature, credential, IAM state or token is observed. A successor's recorded lineage is not independently authenticated installation authority.

Counters are validated separately in each record: `controlledCumulativeGrantAttempts = controlledPredecessorGrantAttempts + attempts`, within that retained session's policy; linked successor predecessor counts must equal the exact predecessor record's cumulative count. Overlapping cumulative counts are never added, maximized or used to choose a candidate. Unknown legacy accounting remains `UNKNOWN`, with no invented total or approved new ceiling.

`sameCurrentBoot` compares each retained worker boot to the kernel boot read at both ends. The first-grant boot must remain equal to its recorded worker boot; neither is rewritten. Even a same-boot observation grants no admission. The exact currently observed records must still be `CANCELLED` / `CANCELLED_BY_OWNER` and `BLOCKED`; changed states stop for reconciliation rather than being adopted.

## Custody, bounds and secrecy

At most 75 metadata files, 150 physical metadata reads including complete final rechecks, and 32 MiB of metadata bytes are allowed. Per-file limits are 8 MiB for the retained inputs and bundle, 256 KiB for the review, and 64/128/8/16 KiB for recovery/session/admission/first-grant records. Cooperative checks expire after 12 seconds; a 15-second alarm bounds the process. No programs, Engine/DB/OAuth calls, lock access/acquisition, writes, claims, mutations or credentials are permitted. The only nonmetadata reads are two reads of the fixed kernel boot identity.

Paths are absolute and exact. Every metadata ancestor is opened by directory descriptor with `O_NOFOLLOW`; directories must be root-controlled and not group/world writable. Metadata must be private root:root regular files with one link. File and directory identities, named entries and hashes are checked before completion and on a second full read. Symlinks, hard links, unsafe modes, mutation, unavailable files, duplicate JSON keys, nonfinite numbers, unsupported schemas, noncanonical producer bytes and budget limits stop. All four owner metadata writers use compact canonical JSON; zero-attempt governed installation writes its session, admission and first-grant records before initializing the recovery journal.

The single JSON receipt exposes hashes, fixed candidate ordinals, state classifications, per-session counters and boot comparisons only. It exposes no raw metadata, endpoint addresses, journal/credential/token paths or credential values. A stop emits a closed reason code and operation/byte counts, without exception messages or partial lineage claims.

## Qualification and interpretation

Implementation/schema references were inspected at immutable repository commit `1b5a22b4f2415325b3c8ba1bed00245434d1ed4a`: `assemble.py` output-binding check; `continued_owner.py` installation and immutable session records; `owner_installation.py` legacy finite-session schema; `installed_owner.py` governed-session schema and counter invariants; `producer.py` `Binding.digest`; `recovery_journal.py` canonical encoding; `bounded_recovery.py` cancellation reason. These modules are not imported or executed by this reader.

Run the new test module with `python3 -B -m unittest discover -s tests -p test_registry_bound_owner_lineage.py -v`. Tests exercise actual protected-file reads, lineage topology, exact per-record accounting, source-output mismatch, mutation, custody, bounds and output redaction. Fixtures do not prove target metadata availability or successful target reconciliation. No target execution has occurred during implementation.

A successful receipt provides the missing historical output/owner association and bounded retained accounting references for designing a distinct current-boot recovery. It does not establish a current owner, current token admission, a valid continuation budget, complete historical accounting, runtime authority, Registry readiness, 502 resolution or release acceptance. A separately reviewed current-boot recovery must still close the gate-only startup/owner cycle and preserve all consumed histories.
