# Next chatbot/VPS action — 2026-10-15

The post-grant continuation is implemented and natively qualified at source
`2a122f1144579fe03d57c14e35452a8fbf6e0547` (PR31 draft/unmerged).

Read `releases/CHATBOT_POSTGRANT_CONTINUATION_READY_20261015.md` and
`evidence/chatbot-postgrant-continuation-qualification-20261015.json`.
Use the pinned `scripts/launch-chatbot-postgrant-20261015.sh`; do not relaunch an
old full-preparation wrapper or reuse its approval hash.

All six required same-source CI checks passed, including311 native cohort,
25 Docker29.8.1,70 independent installer and237 online-IAM tests with no skips.
The new command must prove current retained target state and obtain the fresh
exact HUMAN action before runtime effects. No new target operation was executed
from this workspace. CSV E2E and permanent runtime acceptance remain unproven.
