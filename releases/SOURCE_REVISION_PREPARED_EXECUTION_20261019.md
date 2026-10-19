# Successful postboot preparation — delivery to existing native release gates

Technical8/8; functional4/6. Target END complete=true for `/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-gezxi85l`: host completion readback, native plan compilation and effective Flyway configuration proven; four readonly DB sessions; candidate archives reused, no image import or backup; no authority/publication/runtime mutation. The two90-file postboot contexts and55e seven-file compiler are reconciled and retained. Baseline78 routes, UDP36, Onboarding33→34, MCP migrations unchanged. [Operator receipt and exact bindings](../evidence/source-revision-postboot-preparation-target-success-20261019.json).

The receipt printed by the preparer is an END projection. Its private result schema is separately known from exact qualified source6f8493ec372f8ca3e12c8a4e6df19552e28fd383. Reconstructing that canonical private result gives SHA256 a9ecda1c812236605a91415d776d4a69c5487087d2e47dda1642847845d6535e. This is an expected hash, not a claimed independent file read. The root delivery verifies it against the actual private file before entering the executor. Any mismatch stops before a native gate.

## Authority and effect boundary

Original Onboarding1.6 THS-01/03/04/10 and §§109.14–109.15 were consulted: OUF-controlled human approval, human-bound identity, native ownership, expired challenges remain expired, history/evidence protected. Existing Matrix1.7 ownership applies. Development/MCP permission does not issue runtime authority.

The successful preparation deliberately retains readyForExecution=false. This means the runtime review and authority have not occurred; it does not invalidate the successful preparation. No further preparer replay is needed. The pinned frozen executor already accepts this exact successful receipt and reconciled original; no release-owner, login or THS logic is reimplemented.

Delivery verifies receipt, current-original/private inputs, native prepared plan, case/package,77 source modules, loader and executor (81 exact frozen members). It then invokes the already qualified executor. That executor recompiles current native facts, loads the exact source closure, checks existing provider-admin session metadata, checks current authorities and reaches the existing native login/release flow. A stale or revoked session/authority fails closed. No expired credential/authority is recycled.

If required, `RIAPRO LOGIN <current review hash>` opens only the finite HUMAN login window. The later `APPROVO <current review hash>` approves the exact printed release review: verified backup, native Flyway V34, replacement of Onboarding/MCP while preserving old containers, two additive routes, native capability/OAuth delta and role proposal. Possible interruption of those two services is part of the native review. The role proposal requires a separate HUMAN decision inside THS; the executor only observes it with the retained finite durable budget. Do not prefill either decision or approve a different review.

This command does not publish the generic source profile, acquire CSV data, decide identities or replay jobs. Those are the subsequent authorized functional path, after actual release proof and native gates. Preserve13 Teatri objects/ACK/lineage,20 properties and identity choices, plus8 Cinema objects.

## Delivery qualification

Python delivery source120fb243c81b9a5fc78691163194911da8093aec; SHA25647129694ccaf82bae744859eba4997e3493c5f8c15d54aa476670b63c8f96b5a. Launcher source3817461d96f0bc9b889e981685c7237b271e5f39; SHA256250262e977b56362e44716e1d74bf05d37b57313b1f638e25d955d0d70842989.

The native executor and its77-module frozen package are unchanged by this delivery. Prior qualification85 native +14 postboot tests and the actual successful target preparation remain their evidence. New delivery tests use real root private files and a clearly synthetic execution gate: valid81-file closure reaches that fixture gate; modified documents/code, extra authority artifact, symlink/mode drift, invalid receipt flags and tampered root helper stop before it. This is delivery qualification, not a claim of target runtime authority or successful installation.

CI [39190694557](https://github.com/GioNob/ouf-deploy/actions/runs/39190694557), job117862601203:7 delivery tests PASS. Logs independently retrieved; shell syntax and the exact isolated root shim are covered. No target executor invocation has occurred yet. The operator must run the pinned launcher once on the VPS because root custody and the controlling HUMAN terminal are unavailable to the cloud runner. Keep the terminal in foreground, preserve log/new execution context, and do not replay after STOP/interruption or an ambiguous effect. This preserves existing journals, idempotency and budgets; no generic repository/MCP consent is requested.

## Target command — once in the foreground

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$ouf_gh" ]] || ouf_gh="$(command -v gh)"
  ouf_dir="$(mktemp -d "$HOME/ouf-source-revision-native-release.XXXXXXXX")"
  "$ouf_gh" api \
    'repos/GioNob/ouf-deploy/contents/scripts/launch-prepared-source-revision-20261019.sh?ref=3817461d96f0bc9b889e981685c7237b271e5f39' \
    --jq '.content' | base64 --decode > "$ouf_dir/release.sh"
  printf '%s  %s\n' \
    '250262e977b56362e44716e1d74bf05d37b57313b1f638e25d955d0d70842989' \
    "$ouf_dir/release.sh" | sha256sum --check
  bash "$ouf_dir/release.sh"
)
```
