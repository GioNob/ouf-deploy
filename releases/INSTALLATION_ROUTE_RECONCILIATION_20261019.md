# Native route reconciliation and explicit budget264 review —19October2026

> **STOP target — 19 ottobre 2026:** la consegna `92c0c78c6b5dcb4dcfd7f923df1906988c235127` si è fermata in PREPARATION con `EXACT_FROZEN256_PREDECESSOR_GUARD_REQUIRED`. Il comando operativo sotto è ritirato: **non rilanciarlo**. Nessun consenso budget264 è stato raccolto; ultimo consumo riferito255/256. Il test usava un guard esportato da una capsula precedente e non provava il guard della capsula219 attuale. Prossima azione: sola lettura autenticata della sorgente e presenza della claim, senza credenziali, OAuth o mutazioni. Owner6/gen6 e file pubblicato non vanno ripetuti; journal resta da riconciliare. Tecniche8/8, funzionali4/6.


Technical8/8,functional4/6. This package is NOT executed or authorized merely by publication. Source **8ff69df5a19cd161ac185b2b15729e821bba2383**; authenticated11-file delivery **92c0c78c6b5dcb4dcfd7f923df1906988c235127**; launcher SHA256 **80dd9d9f7e5e78805a298b15fe02c0ac35d73a2f3a8501981aa7e1d03c54839f**.20CItests PASS (17source+3delivery).

## Scope and gates

The target's authoritative projection is already published, SHA25610b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d; old journal7x21g1fg is CLAIMED/version3, zero Gateway stage claims. Owner46iexg9c revision6/generation6 is complete. Never replay owner/create/validate/activate/export or the profile rename.

1. Before OAuth, verify exact sealed history/current journals, five container generations, public metadata and role horizon, projection custody and current82routes. If drift/expiry: STOP without OAuth.
2. **APPROVO BUDGET264 hash** explicitly approves a new v5 budget profile for the same logical continuation: preserve255spent, increase cumulative maximum256→264 (+8,9remaining), preserve original wall/monotonic expiry1792436155 (**20:55:55 Europe/Rome**), same11scopes. New HUMAN code is a reviewed extension in the NEW sealed capsule; older sources and HUMAN journals remain intact. This is a deliberate versioned validator change, not silent relaxation. Legacy256sessions remain readable but cannot spend OAuth through the new capsule. No old access/refresh/device credentials are reused.
3. Browser device login, then **LOGIN COMPLETATO hash** only after success. The pause has no invocation lock or token polling. Provider identity/scope/userinfo verification still required; nominal255→259. No runtime effects authorized by this gate.
4. **APPROVO hash** separately authorizes two-role signed210s route-only reconciliation. Maximum2old-journal transitions and2GatewayPUTs. Reconcile already published profile first, create new durable claims before2PUTs and exact readback, then reconcile old completion using actual new evidence/authority references. Old expiresAt stays unchanged; no expired authority used.
5. No owner POST/export, profile publication, container/DB/IAM/grant/MCP metadata/source/job effects. Preserve80other routes, ports/methods/OIDC/delegation/security. No automatic replay or rollback.

Preparation/login requires20minutes remaining; start **before20:35:55 Europe/Rome on19October2026**. A later attempt stops and does not extend any window. If not feasible, a separate future review is necessary; do not alter the deadline manually. Every preparation and runtime claim is one-use.

## Command in existing oufadmin VPS session

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
  [[ -n "$ouf_gh" && -x "$ouf_gh" ]] || {
    echo 'STOP: client GitHub non disponibile.'
    exit 1
  }

  ouf_launcher="$(mktemp "$HOME/ouf-route-reconcile.XXXXXXXX.sh")"
  "$ouf_gh" api \
    'repos/GioNob/ouf-deploy/contents/scripts/launch-installation-route-reconcile-20261019.sh?ref=92c0c78c6b5dcb4dcfd7f923df1906988c235127' \
    --jq '.content' |
    base64 --decode > "$ouf_launcher"
  printf '%s  %s\n' \
    '80dd9d9f7e5e78805a298b15fe02c0ac35d73a2f3a8501981aa7e1d03c54839f' \
    "$ouf_launcher" | sha256sum --check
  bash "$ouf_launcher"
)
```

Keep the process open. Return only public OUF_INSTALLATION_ROUTE_PREPARED/HUMAN/RESULT or STOP lines; do not share device codes, credential values or private files. Do not rerun after preparation, STOP, ambiguity or disconnection.

## Qualification and limits

Source CI39296553970/job118210477015:7real signed-authority/journal route-only tests,8fresh-login/budget checks,2isolated226-module preparation checks. Delivery CI39296750272/job118211142285:3exact11file/tamper/missing-client/root-recheck tests. Provider/terminal and Gateway replies are test fixtures. Local missing boot-ID is fixture-only; CI uses actual boot. Preparation fixture substitutes retained paths/hashes and traps old main/reader/bootstrap so they cannot be replayed. These do not prove live target effects. See ../evidence/installation-route-reconciliation-qualification-20261019.json.

A successful result completes only this administrative continuation. It does not prove fresh ChatGPT read, complete503resolution, final governed native MCP profile, source activation, functional5–6 or release acceptance. Maintain separate HUMAN/THS domain approvals.
