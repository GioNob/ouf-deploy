# Ingestion401 exact deployed JAR read —19October2026

The bounded environment diagnostic completed with current container generations and completed226 history verified. Its receipt is evidence/ingestion401-auth-contract-target-20261019.json. The inspected IAM environment flags are false/unconfigured, so the candidate bearer-boundary conflict is NOT proven. No OAuth, credentials or effects occurred. Source activation remains NOT_STARTED; technical8/8,functional4/6,last reported HUMAN259/264 and unchanged expiry1792436155.

This separate read qualifies /app/app.jar against the exact current Java entrypoint, excludes mount overlays, verifies the retained Ingestion477ea664 generation before and after reading, and permits only one exact Docker archive GET and two inspect GETs. Maximum120seconds, archive JAR256MiB; closed selected application class/configuration/security library projection. No filesystem extraction, Java/process execution, log reads, credentials, HUMAN journal, bearer, authority, OAuth/backend probes or writes. The archive may be large but is bounded; the payload is retained in process memory only. No runtime authority issued. Metadata from disk does not prove classes loaded by the running JVM or the specific401cause.

Authenticated source84e320717f150d5ea72891cbf7f223a3841863ac; reader SHA256c16a7d3e69527c42fa1c5ae0d950eac2804537fe28dd26469539b51ce54e89b4.13testsPASS, https://github.com/GioNob/ouf-deploy/actions/runs/39302559584 . Archive exchanges and JAR/class data use fixtures; no live target JAR read has been proven before the user executes this command.

Normative boundary consulted: GatewayPET1.5 T29.7 (trusted identity propagation and backend reevaluation), AuthorizationPET1.5 section4.3 (Identity Context Adapter). Do not fix401 by trusting arbitrary headers, bypassing authentication or forwarding HUMAN tokens through MCP.

```bash
(
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || {
  echo "STOP: client GitHub non disponibile"; exit 1
}
ouf_diag="$(mktemp -d "$HOME/ouf-ingestion401-jar-read.XXXXXXXX")"
"$ouf_gh" api \
  'repos/GioNob/ouf-deploy/contents/scripts/read-ingestion401-deployed-jar.py?ref=84e320717f150d5ea72891cbf7f223a3841863ac' \
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
    "c16a7d3e69527c42fa1c5ae0d950eac2804537fe28dd26469539b51ce54e89b4"
exec(compile(raw, "<authenticated-ingestion401-jar-read>", "exec"),
     {"__name__": "__main__"})
PY
)
```
