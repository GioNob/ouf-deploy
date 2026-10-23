# OUF CLOUD: original-document custody reconciliation ready

Supersedes only the target-action instruction in HUMAN_SELECTION_RECONCILE_READY.
Technical8/8, functional4/6; G3–G7/F5/F6/M1/M2open. Preserve every previous
reader, launcher, context, claim and diagnostic log. No subagents or scheduled
automation. No target authentication, journal/claim mutation or runtime effects.

## Target receipt and source evidence

User receipt2026-10-20T14:49:00Z: STOP_RECONCILE at
RETAINED_ORIGINAL_FULL_SELECTION, EXACT_PRIVATE_RETAINED_FILE_CUSTODY_REQUIRED.
The original content had not yet been read. The combined guard checked regular
file, root UID/GID,0600mode, one link, positive size and1MiB maximum. Actual
failed predicate, original size/mode and log path were NOT supplied. Do not
claim a target size, repair or root cause from this receipt alone.

Direct original historical reader contracts consulted:
read-ingestion-db-postboot-preflight-20261020.py read/parsed/originalBinding,
and installation_binding_apply/baseline.py read/file_bytes. They admitted the
original prepared-inputs document with finite8MiB, root UID/GID,0600mode, one
link and exact originalBinding byte hash. The new reader's1MiB bound diverged
from that document contract; this source mismatch is proven, not its being
the actual target failure. No chmod/chown or fallback is authorized.

## Qualified bounded correction and observability

Source174a49c870ffb57a4dfe57c82a7ae6b34bae3b92, draft deploy PR45.
CI39443302711 jobs118698531865(Python3.13.5),118698532456(Python3.12): EACH
32successor+5native reader tests PASS, zero skips. Large original above1MiB
within8MiB, mode/hardlink rejection and beyond8MiB rejection before content
read/decode are covered. Existing full selection/278floor/288maximum/closed
isolated loader and real TLS fixtures also pass. This is CI, not VPS success.

The sealed installation case explicitly selects originalDocumentReadProfile
ouf.retained-prepared-inputs-read-profile.v1, maximum8388608. ONLY that original
uses8MiB. Other artifacts and journal retain1MiB. No owner/mode/link/ancestry/
byte-hash/full-selection guard is relaxed. Safe original-only metadata is
returned on success or pre-content guard failure; credential/journal metadata,
values, hashes, file paths and raw protected logs are not printed. Separate
reason codes identify type, owner, mode, links or bound. A successful read can
prove whether the original exceeds the previous1MiB bound. Until actual output,
its size and precise failed predicate remain unknown.

## Current necessary operator action

Use scripts/launch-human-successor-custody-reconcile-20261020.sh from the
existing oufadmin terminal; this conversation has no qualified direct VPS
channel. Do not rerun either preceding diagnostic. No new login. Existing gh,
pinned source verified before sudo and again in isolated root memory. Local
private download/log retained. Return safe JSON and log path. STOP retains all
state and requires reconciliation, never replay. No OAuth, SQL, Engine/Gateway/
owner API, session/window/reset, journal/claim write, key or runtime operation.

Reader blob861414cc31f155fb5f71c17d4df702ab47a55663; SHA256
505b6e82a0c3d5b668ec92106e470974cc5526cd0bef460f6dc6178d2ba32eec.
Launcher blobd94636deb101411e16e615e639e3113962a226fb; SHA256
3137532e38ac7a079d7f0af1061a2dfd10d41b48a97d448cbe53224a37231085.

## Actual chronology versus frozen baseline

Checkpoint 2026-10-20T14:55:22.783Z, measured active effort 4.7521hours. This turn's
technical diagnosis/profile alignment/tests/documentation starts14:49:07Z;
it is not target command duration or measured human effort. Both target command
start/end times and human effort remain unknown. Unsegmented intervals remain
excluded. MiniPETv1.1 baseline unchanged: G2central14h,G3central19h,M1central24h,
M2central55h. G2passed earlier at3.16measured active hours; G3/M1/M2remain OPEN.
Two safe target diagnostics have stopped; neither is runtime acceptance or a
measured deployment success-rate statistic. No forecast reduction from CI alone.
