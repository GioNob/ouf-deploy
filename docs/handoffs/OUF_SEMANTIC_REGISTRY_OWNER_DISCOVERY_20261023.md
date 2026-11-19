# Token-owner discovery for the open Registry 502

The user does not know the installed token manager. Do not repeat the request for its path: derive journal candidates from current metadata using the command below. The 502 is still OPEN; this is a necessary read-only selection input, not repair or runtime authority.

Reader source e607c78606b942b9515dad59ab8c09cf3af1db2b; SHA256 a8b2aff8ea8e3c0be3fc928e925a756aafeb4e7ce4104530b244ec107071fb30. [CI39904837125](https://github.com/GioNob/ouf-deploy/actions/runs/39904837125):9PASS,0skips, including actual kernel flock observation without acquiring a lock. Local8PASS/1native test unavailable because this sandbox lacks the native proc files. All3source/test/workflow files read back exactly.

The standalone root/isolated/no-site reader searches only /etc/ouf/deploy-snapshots through depth3. It lists directory metadata and opens only owner-admission.json and recovery.json with the exact installed-owner schemas. It never opens token.jwt,client-secret,authority,HUMAN or owner-status files. It reads current boot and /proc/locks; it never calls flock or executes another program. Candidate journal paths and closed states/counters/boot/expiry/lock observations are exported. No raw JSON, credential value, address, token hash or authority data is exported. Paths are journal references, not authority.

Bounds:15second alarm/12second checked deadline,2048directories/32768entries/64candidates/256metadata reads/16MiB. Symlinks and non-root or writable directories are not followed. Subdirectories deeper than3 or outside the path grammar are counted outside scope. A cap, schema/custody/lock drift or unreadable metadata stops without fallback. Stable repeated marker/journal reads and lock-file identity checks protect against mixed generations. No newest/by-name/historical owner is selected; other owners remain explicitly not excluded even on zero matches. Current signatures,source,association and online admission must be verified in the existing actual observer after candidate selection.

## Operator command

No new login, OAuth budget, activation, Engine request, database call, restart, signal or runtime authority is involved. Existing dossiers and claims stay intact. Run once; retain the directory/log on both success and STOP. Do not rerun on STOP automatically.

```bash
(
  set -euo pipefail
  umask 077
  OUF_DIAG_DIR="$(mktemp -d "$HOME/ouf-registry-owner-discovery.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_DIAG_DIR" "$OUF_DIAG_DIR"' EXIT
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/e607c78606b942b9515dad59ab8c09cf3af1db2b/scripts/read-registry-token-owner-candidates-20261023.py' \
    -o "$OUF_DIAG_DIR/reader.py"
  printf '%s  %s\n' \
    'a8b2aff8ea8e3c0be3fc928e925a756aafeb4e7ce4104530b244ec107071fb30' \
    "$OUF_DIAG_DIR/reader.py" | sha256sum --check
  sudo python3 -I -B -S "$OUF_DIAG_DIR/reader.py" | tee "$OUF_DIAG_DIR/operator.log"
)
```

Use the returned candidate paths and states for the next precise current-owner binding/admission step. A live lock is not source authentication. A positive local expiry window is not online IAM acceptance. A blocked/expired/exhausted/previous-boot candidate cannot be substituted into the recovery factory. A zero result does not prove no owner exists outside this bounded scope. No fresh HUMAN/token/window consent should be requested until the full executable recovery path is concrete and qualified.

Preserve patch12/12,technical8/8,functional4/6,G3OPEN,OAuth304/304exhausted,releaseAcceptancefalse. Runtime recovery source remains qualified at its stated component boundaries only; immutable current context,sealed loader/capsule/issuer/delivery/launcher and whole JVM qualification are not completed by this reader.
