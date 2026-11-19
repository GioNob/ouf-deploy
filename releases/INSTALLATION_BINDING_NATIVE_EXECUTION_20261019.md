# OUF CLOUD — distinct native installation binding action

Target remains technical8/8, functional4/6. Completed owner update hnfn0zwg, MCP srz6__wf, Gateway azxw328z and installation uow4n8lp MUST NOT be replayed. Latest CAS planning STOP is CURRENT_HUMAN_SESSION_REFRESH_PENDING,251/256,zeroOAuth,zeroauthority.

Current source 9600d850e5d4b4b42004e68028a5aa6e49c20d35; ten-file delivery cb66752e13c5e345bc68a929a31285f6cc417f7e; launcher SHA256 d0a647bbaf538b2371b1566a05031a8efada5f2c044461db8b00486a26caf717. The command below is a one-shot manual invocation, not a background watcher or scheduled automation. It admits only completed/success CI runs for the exact current source and delivery commits, before downloads/sudo or OUF preparation. Tests cover queued CI and wrong-head green rejection, then exact green admission and ten-file pins. WAIT_CI is a pre-execution GitHub-only result and can be checked again; **any OUF preparation, STOP, interruption or consumed runtime claim MUST NOT be replayed**.

## Native decisions

1. `RIAPRO LOGIN <hash>`: explicitly open ONE new7200s window from consent, preserving251/256 cumulative budget and unchanged11scopes/HUMANvalidator. No old access/refresh/device credentials. The predecessor window expired19October2026,17:54:19 Europe/Rome. No automatic renewal or reset.
2. Complete browser device login, then enter `LOGIN COMPLETATO <samehash>`. Before that acknowledgement there is no first token poll and the invocation lock has been released. Provider still verifies identity and scopes; denial/exhaustion blocks.
3. `APPROVO <hash>` owner-only: create/validate/conditionally activate one installation revision and retain one authoritative projection export; strong ACTIVE ETag/revision/checksum/generation,210s scope, separate two-role signed authority.
4. A distinct `APPROVO <hash>` permits one atomic CAS publication of that authoritative active projection and exactly two Gateway upstream-host PUTs. Other80routes and route security preserved. Separate210s signed scope and durable per-effect claims. No automatic replay/rollback.

No container lifecycle, migrations/manualSQL, IAM/grants, source activation, ingestion replay or MCP public metadata writes. Success does not prove the final native governed MCP profile, source activation, fresh chat read or functional5–6. New source CI status may remain queued; the command checks authoritative runs rather than treating previous-source tests as sufficient.

## Command on existing oufadmin VPS

```bash
(
  set -euo pipefail
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
  [[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile.'; exit 1; }

  for ouf_gate in \
    '39280839526:9600d850e5d4b4b42004e68028a5aa6e49c20d35' \
    '39280897367:cb66752e13c5e345bc68a929a31285f6cc417f7e'
  do
    ouf_run="${ouf_gate%%:*}"
    ouf_sha="${ouf_gate#*:}"
    ouf_state="$("$ouf_gh" api "repos/GioNob/ouf-deploy/actions/runs/$ouf_run" --jq '[.head_sha,.status,.conclusion] | @tsv')"
    if [[ "$ouf_state" != "$(printf '%s\tcompleted\tsuccess' "$ouf_sha")" ]]; then
      printf 'WAIT_CI: https://github.com/GioNob/ouf-deploy/actions/runs/%s\nNessun sudo, login o claim OUF eseguito.\n' "$ouf_run"
      exit 75
    fi
  done

  ouf_launcher="$(mktemp "$HOME/ouf-binding-apply.XXXXXXXX.sh")"
  "$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/launch-installation-binding-apply-20261019.sh?ref=cb66752e13c5e345bc68a929a31285f6cc417f7e' --jq '.content' |
    base64 --decode > "$ouf_launcher"
  printf '%s  %s\n' 'd0a647bbaf538b2371b1566a05031a8efada5f2c044461db8b00486a26caf717' "$ouf_launcher" | sha256sum --check
  bash "$ouf_launcher"
)
```

Retain public lines OUF_INSTALLATION_BINDING_PREPARED, OUF_INSTALLATION_BINDING_HUMAN, OUF_INSTALLATION_BINDING_OWNER_RESULT and OUF_INSTALLATION_BINDING_APPLY_RESULT, or STOP with context and phase. Never share device/credential material or private artefacts.

Qualification details and fixture limitations: ../evidence/installation-binding-native-qualification-20261019.json. Historical qualification13tests passed on previous4224a093 source is distinct from current-source CI.
