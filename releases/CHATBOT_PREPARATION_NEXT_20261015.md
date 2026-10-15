# Next chatbot/VPS action — 2026-10-15

Use source `0525c4186a5613000905ba4dfae6766827ad9f06` (PR31 draft/unmerged).
It corrects the complete-bundle reader that blocked the previous candidate
at POSTGRANT_RETAINED_HISTORY_PREFLIGHT / PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN.
The earlier candidate issued no new runtime authority on that attempt.

Read `releases/CHATBOT_POSTGRANT_CONTINUATION_READY_20261015.md` and
`evidence/chatbot-postgrant-continuation-qualification-20261015.json`.
Use the pinned `scripts/launch-chatbot-postgrant-20261015.sh`; do not relaunch
an older wrapper or reuse its approval hash.

The new command proves current retained target state before IAM login and
requires a fresh exact HUMAN decision before runtime effects. All prior
consumed grants, claims, journals and the created Registry are preserved.
Actual target continuation and CSV E2E remain unproven by CI qualification.
