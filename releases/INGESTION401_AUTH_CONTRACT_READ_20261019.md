# Ingestion401 read-only authentication contract diagnosis —19October2026

The route reconciliation completed in w8nfc1ko; do not replay it. Its full target receipt and fresh ouf-admin client reads are retained in evidence/installation-route-reconciliation-target-20261019.json and evidence/installation-route-post-client-read-20261019.json. Owner6/gen6, prior projection and80other routes preserved; exactly2Gateway PUTs. HUMAN259/264, original expiry1792436155 unchanged. Technical8/8,functional4/6.

Current source is APPROVED, activationNOT_STARTED; MCP HEALTHY. Ingestion.status/history report401. This diagnostic reads authenticated completed history as files and six exact current container inspections. It projects only the owner IAM enabled/issuer-present/audience-present flags and whether the retained approved Lua contains an Authorization-removal loop or explicit Authorization set_header. It does not execute source, inspect deployed IAM filter bytecode, or prove the specific401cause. No credentials, bearer, authority, HUMAN journal, raw logs, OAuth/backend probes, writes or process dispatches. No runtime authority issued.

Qualified source7a3006782c1b273aead7e7648f8f1c3a5b597f77; reader SHA256b539b6643817eba01736e8676be91ed3dc337a93bdca8a9a00106c608d8f2c4e. Seven tests PASS: https://github.com/GioNob/ouf-deploy/actions/runs/39301331242/job/118226986975 . Fixtures verify completed-history bindings/tamper denial and metadata redaction/closed read surface; no live target cause is claimed.

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || {
  echo "STOP: client GitHub non disponibile"; exit 1
}
ouf_diag="$(mktemp -d "$HOME/ouf-ingestion401-read.XXXXXXXX")"
"$ouf_gh" api \
  'repos/GioNob/ouf-deploy/contents/scripts/read-ingestion401-auth-contract.py?ref=7a3006782c1b273aead7e7648f8f1c3a5b597f77' \
  --jq '.content' | base64 --decode > "$ouf_diag/read.py"
sudo python3 -I -B -S - "$ouf_diag/read.py" <<'PY'
import hashlib, os, stat, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    st = os.fstat(fd)
    assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
    assert 0 < st.st_size <= 65536
    with os.fdopen(os.dup(fd), "rb") as stream:
        raw = stream.read(65537)
finally:
    os.close(fd)
assert hashlib.sha256(raw).hexdigest() == \
    "b539b6643817eba01736e8676be91ed3dc337a93bdca8a9a00106c608d8f2c4e"
exec(compile(raw, "<authenticated-ingestion401-read>", "exec"),
     {"__name__": "__main__"})
PY
)
```
