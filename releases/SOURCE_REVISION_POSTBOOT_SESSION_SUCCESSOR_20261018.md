# Postboot successor — exact retained HTTP session properties

Technical8/8; functional4/6. The second protected diagnosis reconciled q7bq1ex3 (90 files, closure e44977b8fd421cd4280ce2792e56c1819d7f7b301f70009c092a975aad57a818), and rechecked f6w3lo6z (90 files, closure e693804def0e2494404cfb7cc025bef1f5ee6c80cac1b9dfdadb51a4db7a86e1). No authority or completion receipt in either. Original consumer binding verified; no current runtime generation certification is inferred from this read.

The full property diagnostic shows20 property entries/21 scalar leaves (the scope list contributes more than one scalar). Only four entries fail the prior namespace guard: server.servlet.session.cookie.http-only (bool), .same-site (str), .secure (bool), and server.servlet.session.timeout (str). OUF and OAuth entries are accepted individually; the complete prior verifier still rejects the document. Values and dynamic identifiers remain undisclosed. [Operator evidence](../evidence/source-revision-postboot-property-target-20261018.json).

## Normative review and correction

Original Onboarding1.6 THS-09 requires Secure/HttpOnly/SameSite cookie security and session timeout/revocation; §109.11 lists THS session-timeout with mandatory expiry. §§109.14–109.15 preserve recovery history, expired challenges and protected observability. Matrix1.7 ownership and HUMAN/THS separation remain unchanged.

Official Spring documentation identifies the same four property names and timeout duration semantics: https://docs.spring.io/spring-boot/appendix/application-properties/index.html and https://docs.spring.io/spring-boot/3.5/reference/web/servlet.html . This is property-contract verification, not certification of the currently deployed application's runtime security.

The explicit verifier successor admits only those four session properties in addition to the previously qualified OUF/THS OAuth surface. It requires all four together, booleans for Secure/HttpOnly with both true, SameSite strict/lax/none, and a positive literal simple/ISO duration for timeout. Wrong types, disabled cookie protections, unknown SameSite, zero/negative/infinite/invalid timeouts, interpolation, missing members and other server/session/Spring settings remain denied. It never rewrites configuration. Actual target values must pass these guards during preparation; their safety is not inferred from the redacted diagnostic.

Only configuration.py differs among77 overlay modules;76 modules and the loader are reused from c750. Both old/new configuration hashes are checked before verified-memory loading. The new case/package/declaration and eventual completion receipt bind the changed source bytes and source commit. The frozen package remains81 files. Both prior postboot contexts are mandatory and hash-checked before creating a successor and after compilation; neither can be silently omitted or overwritten. Original c23,55e partial compiler and all candidate archives are preserved. Runtime provider/socket/PID/namespace/PG/configuration/journal/route checks remain mandatory.

## Immutable qualification

Preparation source6f8493ec372f8ca3e12c8a4e6df19552e28fd383, workflow39164421815; expected12-file staged manifest dc310b977508915af520792d48e1bf970abcdffcf2b4a6d9b33a8c72f77c4ccf. Target stage path `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-postboot-code-39164421815`.

Delivery sourced1cc03dd4816ecb0e350322189915d16dc7966b1; launcher SHA2566616beff7fc5a2daafc5ad17566bdfef91ad412c8e8256c0ad72a2d85393b320. CI39164421815:85 native tests +14 postboot tests PASS (job117784267873); stage job117784477326 confirms the12-file manifest above. Delivery CI39164478331, job117784438092:5 tests PASS. Logs independently retrieved. Target preparation using this successor has not run.

The next step is one new protected preparation on VPS, maximum300seconds, four read-only database sessions, new private artifacts only. No login, authority, image import, service start/stop, migration, publication or historical job retry. Preserve output/context; a STOP blocks replay and requires reconciliation. Successful preparation still reports readyForExecution=false. Runtime HUMAN/THS gates and the functional5/6 route remain separate; preserve13 Teatri/ACK/lineage,20 properties/identity choices and8 Cinema objects.

## Target command — one preparation as oufadmin

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$ouf_gh" ]] || ouf_gh="$(command -v gh)"
  ouf_dir="$(mktemp -d "$HOME/ouf-postboot-session-successor.XXXXXXXX")"
  "$ouf_gh" api \
    'repos/GioNob/ouf-deploy/contents/scripts/launch-source-revision-postboot-20261018.sh?ref=d1cc03dd4816ecb0e350322189915d16dc7966b1' \
    --jq '.content' | base64 --decode > "$ouf_dir/prepare.sh"
  printf '%s  %s\n' \
    '6616beff7fc5a2daafc5ad17566bdfef91ad412c8e8256c0ad72a2d85393b320' \
    "$ouf_dir/prepare.sh" | sha256sum --check
  bash "$ouf_dir/prepare.sh"
)
```
