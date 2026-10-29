# Readback after ambiguous first Registry-binding PUT

Operator emitted repair authoritye1b672b93ba670849690860c99426683eee06fb88ff6c111f6428fde4ab0f496,
expiry1792148012, then REPAIR_WRITE_ACK_UNPROVEN_NO_REPLAY. The first PUT may
have taken effect. Do not rerun the applicator or reset its journal/claims.
The original CSV window expiry1792148226 is separate and unchanged.

Source21cd552503f68351bd909214fdfd62a0dd1d5d76; qualification
run38890087614/job116937188614:80tests pass, zero skipped. New tests prove
claim-before/after-map classification without mutation, foreign authority denial,
unrelated drift detection and GET-only/no-live-process dependency in main.

The reader binds exact prepared review71e8c444f6164cd077e25c13429f218c27bf909131b4031529c836e28687ccfa,
original review/authority/bundle/completed journals and current exact APISIX
transport generation. It rereads the new repair journal with the issued repair
executionAuthorityHash, verifies every intent/state/prefix and takes two full
route-map GETs. Results distinguish the exact prefix before the ambiguous claim,
the exact map after that one claim, the final proposed map and other drift.
It does not mark any claim APPLIED, reconcile, retry PUT or issue new authority.
A bounded Docker log read reports only admin PUT status counts and byte counts;
it does not recover or assert the historical response body/cause. No raw logs,
route values, names, IPs or credentials are printed.

Maximum120seconds,2Gateway GETs,1log read. Zero DB/archive/grant/IAM/MCP calls,
Gateway writes or service mutations. The exact existing admin credential is used
only for GET. No signing key read/signing/authority renewal. Original/recovery
journal snapshots are checked unchanged at completion. Expired repair or original
finite authority does not prevent this read-only observation; no live-process
requirement is imposed and no process is stopped or restarted.

No target execution or repair completion is claimed by CI. Technical phases1–8
remain retained, functional CSV0/6, no permanent runtime/E2E acceptance.
