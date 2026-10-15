# Next chatbot/VPS action — 2026-10-15, mount-owner lifetime incident

Do NOT rerun the prior paused-recovery launcher. Its fixed incident claim was
consumed by the action below; no admission or worker is adopted on restart.

Latest owner output: sourceb7d24c57d6e45e71994ac3f99f56f249d83cde22,
review2380132af8e47de185894fde156470e162dab784942c8615778e7620e7f8fc60,
authority8c59697f46b3ce1b54d1cff1acf1f08dde6c4087062d28e379465d9a76ec570a,
context/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-d3ef7a038a6b587dde883e802080cb393732be9c4399f98e43a1a3ff6b3b2c2f,
unitouf-file-cohort-d3ef7a038a6b587dde883e802080cb39.service.
All six retained effects, native full OCI/rootfs and DB fence passed preflight.
It started a distinct worker and entered private frame observation, then failed
at OnlineIamAdmission.admit line239 (Permanent/AUTHORITY_EXPIRED). It passed
issuer identity, audience and scope checks before that lifetime refusal.
Actual latest worker attempts/cumulative count/journal/claim/node issuance are
not yet read back. Do not infer them from entering a delivery phase.

Confirmed source defect: mount observer passed its read deadline(up to30s)+
signed mount minimum30s as token expiry. That ceiling<60s cannot satisfy owner
minimum90s. The old suites separately tested real mounts and real owner but
missed their integration. Source4be0acc81fccb15d66245525de5eba45b5083541 fixes
this with an explicit fail-closed mounted-token owner witness using the
existing durable publication expiry on both clocks plus unchanged online IAM.
Minimum90s stays enforced; no fabricated TTL, lifetime extension, grant, token
publication, counter reset or source/authority bypass. Seven new actual native
readonly mount+signed owner+TLS tests pass in the hosted cohort and IAM steps.
Full six-gate regression qualification is still pending at this checkpoint.
See CHATBOT_MOUNT_OWNER_LIFETIME_FIX_20261015.md and target failure evidence.

The next target action is ONLY scripts/read-chatbot-mount-owner-failure-20261015.py
from this evidence commit, after its own dedicated CI passes. Reader SHA:
80d2903fe5093bd0fc41cd0ea3a227d7929da6fd7b68f36c4d91fab26bd644fe.
It reads the fixed latest review/private bundle, stopped unit, retained worker/
session/admission, phase journal/old failed intent marker, node issuance boundary,
later journals and one native Docker GET. It validates exact frozen source pins,
computes the mismatch from reviewed metadata and reports persisted lifetime
metadata only. No token/credential file reads, IAM/DB calls, grants, source-body
execution, journal/claim writes, signatures or runtime changes. Only sudo.
Its complete fixture plus custody/privacy checks pass6 local tests; hosted
qualification is required before giving the command. Expect END complete true.

After that readback, prepare a new governed continuation from the latest signed
scope, preserve BOTH historical failed intents and all six applied effects,
retain all old claims/receipts/DB fence/backups, account the newly observed
worker attempts cumulatively and use one new explicit finite HUMAN budget.
The corrected source alone does not authorize such a continuation. Do not reuse
old global claims, CREATE/STAGE/SIGUSR1, credentials, first grant or old worker.
Target full frame/token/peer attestation and CSV chatbot E2E remain unproven.
