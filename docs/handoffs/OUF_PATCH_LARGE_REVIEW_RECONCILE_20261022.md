# Exact large-review defect and unissued reconciliation — reader CI PASS

Owner evidence: evidence/ingestion-readiness-size-stop-target-20261022.json. Root cause is exact: historical read_member rejects review545058bytes at524288limit despite correct root0600/one-link custody. Packet1320265bytes already fits the separate existing4MiBJSON reader. The controller persisted ISSUING before attempting issuance; the first review read failed before issuance claim/publication. Preserve the exact old review/packet/material/control/global claim and every log. Do not infer runtime authority from terminal acceptance or reset the row toREVIEW_READY.

The distinct authority_v2/entry_v2/member_io_v2 add3new modules around the unchanged139source graph. runtime_v2 closes142exact imports. The historical generic reader and all139original modules are byte unchanged. V2 changes only this patch's named document readers: review2MiB,packet4MiB,decision/human64KiB,authority128KiB; unknown names and caller-defined limits are denied. Full review/packet bounds are checked during compilation/validation before issuance. Local8tests pass including exact545058/1320265size reads,legacy rejection,mode/link/path/content race protections,real existing-key two-role signing and loading a valid >512KiBreview,and isolated sealed142module imports. HUMAN/qualification/unit executable observations are explicit fixtures. V2 full production controller/fresh-HUMAN governance is still pending and not a target executable.

A separate standalone read-only reconciliation reader is concrete and hash-pinned(evidence/ingestion-readiness-unissued-reader-pins-20261022.json). It binds old runtime case9f3d63...,review0421b9...,inputsf56; checks exact reported sizes and complete canonical hashes; validates material/source/global-review fence; requires rowISSUING with no issued/native artifacts; blocks competing invocations via a shared lock; and rechecks FD/path identities. It reads no credential journal,token or key and contacts no service. A foreign/partial artifact or even an unexpected directory member blocks the snapshot. No old file/claim/state is edited or deleted.

Local8reconciliation tests pass,including real isolated CLI,concurrent invocation rejection,partial authority/signature/native claim refusal,retained bytes unchanged and exact production artifact reproduction. CI39742778066 Python3.12/3.13.5 each PASS78tests,zero skips; the single pinned read-only reader is qualified. This does not qualify the V2 production controller. Expected status STOPPED_UNISSUED_PATCH_REVIEW_RECONCILED_NO_AUTHORITY,retainedStateISSUING,readOnlytrue,noauthority/effects/OAuth. Return JSON/reader.log; preserve on STOP without replay.

Current OAuth296/296,technical8/8,functional4/6,G3OPEN,target0/12. The 296profile belongs to the old case/source and its1108second margin was at receipt only. No automatic refresh,new budget,window or source/semantic/THS action. The new code and exact continuation path must be fully qualified before requesting another fresh token. Existing full old CI success did not cover the real review size; these receipts do not install the correction or prove live admission.

## Sole next target command — run once

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh)"; fi
ouf_dir="$(mktemp -d "$HOME/ouf-unissued-reconcile.XXXXXXXX")"
trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/reader.log\n" "$ouf_dir" "$ouf_dir"' EXIT
"$ouf_gh" api repos/GioNob/ouf-deploy/git/blobs/d91593205f8f521cad54a26486cb7199a773508e --jq .content |
  tr -d '\n' | base64 --decode > "$ouf_dir/reader.py"
printf '%s  %s\n' b79b62abfc0fd4b48a1f1b7047b443fe7d672b887f40f9cf1967b933574ada07 "$ouf_dir/reader.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_dir/reader.py" <<'PY' 2>&1 | tee "$ouf_dir/reader.log"
import hashlib, os, stat, sys
path = sys.argv[1]
expected = "b79b62abfc0fd4b48a1f1b7047b443fe7d672b887f40f9cf1967b933574ada07"
def pin(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before = os.fstat(fd)
    if not (stat.S_ISREG(before.st_mode) and
            stat.S_IMODE(before.st_mode) == 0o600 and
            before.st_nlink == 1 and 0 < before.st_size <= 65536):
        raise SystemExit("STOP_RECONCILE: READER_FILE_METADATA")
    chunks = []
    while True:
        chunk = os.read(fd, 65537 - sum(map(len, chunks)))
        if not chunk:
            break
        chunks.append(chunk)
        if sum(map(len, chunks)) > 65536:
            raise SystemExit("STOP_RECONCILE: READER_SIZE")
    raw = b"".join(chunks)
    if not (pin(before) == pin(os.fstat(fd)) ==
            pin(os.stat(path, follow_symlinks=False)) and
            len(raw) == before.st_size and
            hashlib.sha256(raw).hexdigest() == expected):
        raise SystemExit("STOP_RECONCILE: READER_CUSTODY")
finally:
    os.close(fd)
sys.argv = ["<verified-unissued-reader>"]
exec(compile(raw, "<verified-unissued-reader>", "exec"),
     {"__name__": "__main__", "__file__": "<verified-unissued-reader>"})
PY
)
```
