# Ingestion READ owner candidate/input capsule —19October2026

The code fix is prepared in GatewayPR81/source6bcb2890 and IngestionPR43/source663faa03.142Gateway tests and18actual Lua→Java→Spring Security/SDK policy tests PASS, with zero Java skips in the paired gate. The exact candidate image51a514d8 was exported by push run39304976681/artifact12214420297, including a HIGH/CRITICAL vulnerability gate and unchanged migrations compared to repository baselinec48ee4b1. Do not substitute the pull-request merge build597c921e or a different artifact: its bytes/image IDs differ.

The target remains technical8/8,functional4/6; current reads are blocked401. Native route reconciliation w8nfc1ko and prior owner6/gen6/profile publication are complete and must not be replayed. Last reported HUMAN259/264, original expiry1792436155. No budget reset or automatic window renewal is authorized. This preparation does not call OUF OAuth or use the HUMAN session and may run after the old window expires.

This exact manual command authenticates the public candidate ZIP bytes and metadata/scanner/image hashes, verifies completed226 and205 history as files, current retained container generations and approved active-profile custody, and creates one root-private input capsule. Four new preparation files maximum: the one-use claim, copied candidate gzip, inputs and result. No image import/start, owner POST/export, active projection publication, Gateway write, database, IAM/grant, source or job effects. No credential files, bearer, HUMAN journal or authority are opened. It persists references and configuration hashes; raw environment values are neither printed nor persisted. Provider FILES is installation-specific; other placement/providers fail for explicit adapter review. No shared-filesystem default is promoted for other installations.

The resulting inputs are planning evidence, not a signed runtime plan. Before any later apply: requery current owner ACTIVE/ETag and valid HUMAN/roles; qualify exact OCI/rootfs/application bytes and actual deployed migration/database state; compile the owner secret reference, Gateway signing environment and Ingestion verifier environment/mount placement from approved installation configuration; obtain new native decisions for changed intent/effects. No previous authority covers these changes. The pending two application/configuration/Gateway-function changes and any installation revision/export require finite explicit scopes. Protected HUMAN and mutation paths remain untouched by the read adapter.

Preparation CI: https://github.com/GioNob/ouf-deploy/actions/runs/39306302184 (14tests). Synthetic artifact and engine responses are fixtures; production pins the exact push ZIP1a26522a, image51a514d8, compressed archive54eab6e1 and source663faa03. No target preparation or rollout is claimed until its receipt arrives. Run once; after STOP/interruption preserve all files and do not rerun.

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || {
  echo "STOP: client GitHub non disponibile"; exit 1
}
ouf_work="$(mktemp -d "$HOME/ouf-ingestion-owner-inputs.XXXXXXXX")"
"$ouf_gh" api \
  'repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-read-owner-inputs.py?ref=a1d7272f41730bc20870291d068bd6243a944733' \
  --jq '.content' | base64 --decode > "$ouf_work/prepare.py"
"$ouf_gh" api \
  'repos/GioNob/ouf-ingestion-runtime/actions/artifacts/12214420297/zip' \
  > "$ouf_work/candidate.zip"
printf '%s  %s\n' \
  'b98be85bec46db9e929bfc0a46d773d1e3805154f99a3b2eca0b062536a6ac08' "$ouf_work/prepare.py" \
  '1a26522ab9507bb85fbd6924c0c48c67720493516ec4471a4b3577a8f853ec3f' "$ouf_work/candidate.zip" |
  sha256sum --check
printf 'Log privato: %s\n' "$ouf_work/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_work/prepare.py" "$ouf_work/candidate.zip" <<'PY' | tee "$ouf_work/run.log"
import ast, hashlib, os, re, stat, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert 0 < info.st_size <= 65536
    with os.fdopen(os.dup(fd), "rb") as stream:
        raw = stream.read(65537)
finally:
    os.close(fd)
assert hashlib.sha256(raw).hexdigest() == \
    "b98be85bec46db9e929bfc0a46d773d1e3805154f99a3b2eca0b062536a6ac08"
codes = {n.value for n in ast.walk(ast.parse(raw))
         if isinstance(n, ast.Constant) and type(n.value) is str
         and re.fullmatch("[A-Z][A-Z0-9_]{2,159}", n.value)}
sys.argv = [sys.argv[1], sys.argv[2]]
exec(compile(raw, "<authenticated-owner-input-preparation>", "exec"),
     {"__name__": "__main__", "__file__": sys.argv[0], "_OUF_SAFE_CODES": codes})
PY
)
```
