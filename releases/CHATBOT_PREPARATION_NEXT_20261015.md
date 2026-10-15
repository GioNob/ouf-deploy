# Next chatbot/VPS action — 2026-10-15

STOP runtime relaunches. The previously qualified source0525c4186a5613000905ba4dfae6766827ad9f06
failed after approval in the paused Registry attestation, with ValueError.
Read releases/CHATBOT_PAUSED_NODE_FAILURE_20261015.md and
evidence/chatbot-paused-node-failed-successor-20261015.json.

The next action is only scripts/read-chatbot-paused-node-20261015.py. It needs
sudo read access, no IAM/device/APPROVO and performs no runtime mutation.
The retained current authority isfa7bdc08f0c0ea048b064774648176cf54ce51279118ce1df0ff296fc8616d3b.
Do not reuse the prior runtime launcher or approval, remove claims, reset worker
history, replay CREATE/STAGE/first grant, or infer current grant counts from CI.
Current readback and an actual reproduced diagnosis are prerequisites to a
concrete new recovery review. The prior paused Registry and new finite worker
have effects that must be preserved and accounted for.
