# Stopped patch after eight stages — read-only snapshot qualified

Last owner receipts confirm START_REPLACEMENT at journal1058; subsequent STOP_RECONCILE with FINITE_CURRENT_DIRECT_ENGINE_WINDOW_REQUIRED; metadata RECONCILE_REQUIRED,nextStage8,effects8,readAttempts8,IDLE,recordedExpiresAt1792664043(12:14:03 Europe/Rome). At observation that expiry is past. Runtime authority WAS issued earlier. Latest per-invocation runtimeAuthorityIssued:false does not erase issuance history. OAuth300/300 exhausted. No expired step/reconcile/approve/initialize/auth replay or automatic renewal/budget reset is allowed. Preserve all contexts/claims/logs and both old stopped reviews. Status evidence:evidence/ingestion-readiness-stage8-stop-target-20261022.json.

A separate bounded stdlib-only metadata snapshot reader binds exact newcase21a26b94...,prefix8,readAttempts8 and expiry. It holds both invocation locks,validates no-follow root-private FD custody and review/control/native/initialization-claim consistency,checks all eight APPLIED intents and rechecks stable snapshots. It does not open a credential journal,key or token,call a service,verify current role signatures/provider identity or observe live containers. Success is a metadata prefix reconciliation,not live application readiness or new authority. Packet contents and current boot are not revalidated. No old file/journal/claim is updated or deleted.

CI39762976840 ate1db6dbd8b285483c9023872374576620dab03af:Python3.12 job119771429271 and3.13.5 job119771429693 each PASS4tests,zero skips. Actual root-private synthetic prefix/crypto fixture,wrong counters/expiry,claimed prefix,concurrency/mode denial,isolated CLI and exact production artifact reproduction. No target runtime evidence is claimed. Published pins:evidence/ingestion-readiness-stopped-reader-pins-20261022.json.

Residual stages:ingestion.READINESS,VERIFY_FINAL,ingestion.RESTORE_RESTART,VERIFY_RESTORED_FINAL. Target stage8 receipt says replacement started,but current health is unobserved and restart restoration remains pending. A future recovery path must preserve the prefix,counters/resources/claim lineage and have its entire concrete path qualified before any separately explicit fresh budget/window/runtime consent. No new recovery runtime or budget is prepared or requested by this snapshot.

## Sole next target command — run once

Expected STOPPED_PATCH_PREFIX_RECONCILED_NO_AUTHORITY. Return public JSON and reader.log. After STOP preserve all and do not rerun. Patch8/12,technical8/8,functional4/6,G3OPEN,not release acceptance.

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh)"; fi
ouf_dir="$(mktemp -d "$HOME/ouf-patch-stopped-read.XXXXXXXX")"
trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/reader.log\n" "$ouf_dir" "$ouf_dir"' EXIT
"$ouf_gh" api repos/GioNob/ouf-deploy/git/blobs/dbd88b3e53e5146f94e78fc52ddb42275fd57c8f --jq .content |
  tr -d '\n' | base64 --decode > "$ouf_dir/reader.py"
printf '%s  %s\n' 27b28c604b7cf7de5422f067df375d0f226bf1dff0b336dda03124f7f762720c "$ouf_dir/reader.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_dir/reader.py" <<'PY' 2>&1 | tee "$ouf_dir/reader.log"
import hashlib, os, stat, sys
path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
def pin(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
try:
    before = os.fstat(fd)
    if not (stat.S_ISREG(before.st_mode) and
            stat.S_IMODE(before.st_mode) == 0o600 and
            before.st_nlink == 1 and 0 < before.st_size <= 65536):
        raise SystemExit("STOP_RECONCILE: READER_METADATA")
    chunks = []
    while True:
        chunk = os.read(fd, 65537 - sum(map(len, chunks)))
        if not chunk:
            break
        chunks.append(chunk)
        if sum(map(len, chunks)) > 65536:
            raise SystemExit("STOP_RECONCILE: READER_SIZE")
    raw = b"".join(chunks)
    if not (len(raw) == before.st_size and
            pin(before) == pin(os.fstat(fd)) == pin(os.stat(path, follow_symlinks=False)) and
            hashlib.sha256(raw).hexdigest() == "27b28c604b7cf7de5422f067df375d0f226bf1dff0b336dda03124f7f762720c"):
        raise SystemExit("STOP_RECONCILE: READER_CUSTODY")
finally:
    os.close(fd)
sys.argv = ["<verified-stopped-patch-reader>"]
exec(compile(raw, sys.argv[0], "exec"),
     {"__name__": "__main__", "__file__": sys.argv[0]})
PY
)
```
