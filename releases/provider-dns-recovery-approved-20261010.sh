#!/usr/bin/env bash
# One explicitly approved R9 activation; never replay a consumed claim.
(
  set -euo pipefail
  umask 077
  OUF_PHASE=DOWNLOAD_EXACT_APPROVED_DNS_RECOVERY_PROGRAMS
  OUF_PLAN_DIR=not_created
  trap 'OUF_CODE=$?; printf "OUF_DNS_RECOVERY_APPLY_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_PLAN_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
    printf 'OUF_DNS_RECOVERY_PLAN_DELIVERY=EXISTING_GH_NOT_FOUND\n'
    exit 1
  fi
  OUF_PLAN_DIR="$(mktemp -d "$HOME/ouf-dns-recovery-apply.XXXXXXXX")"
  while read -r OUF_REMOTE OUF_LOCAL OUF_SHA; do
    "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
      "repos/GioNob/ouf-deploy/contents/$OUF_REMOTE?ref=fafb67e8e02d78c01a7f5aa961118aa9f6b093d4" > "$OUF_PLAN_DIR/$OUF_LOCAL"
    printf '%s  %s\n' "$OUF_SHA" "$OUF_PLAN_DIR/$OUF_LOCAL" | sha256sum -c -
  done <<'OUF_COMPONENTS'
tools/semantic_lease_activation/activate_dns_recovery.py activate_dns_recovery.py 6183733f02d3a5e633deac8c07924276df8b6a5cbaa57494be289808c3aaf244
tools/semantic_lease_activation/dns_recovery_core.py dns_recovery_core.py 3ea3c575da5a61b153294a10abf810811d846f04b64bd12d9a2b8dd5380879aa
tools/semantic_lease_activation/dns_recovery_dns.py dns_recovery_dns.py f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f
tools/semantic_lease_activation/materialize_southbound_lease_refresh.py materialize_southbound_lease_refresh.py c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079
tools/semantic_target_review/read_cutover_inputs.py reader.py b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf
OUF_COMPONENTS
  OUF_PHASE=APPLY_NEW_EXPLICIT_R9_DECISION_ONCE
  sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1])
with p.open("rb") as stream:
    raw=stream.read(131073)
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!="6183733f02d3a5e633deac8c07924276df8b6a5cbaa57494be289808c3aaf244":
    raise SystemExit("OUF_DNS_RECOVERY_ENTRYPOINT_HASH_MISMATCH")
sys.argv=[str(p),"--apply","OUF_DNS_WINDOW_RECOVERY_R9_APPROVED_20261010T075611_CEST"]
exec(compile(raw,str(p),"exec"),{"__name__":"__main__","__file__":str(p),"__verified_source_bytes__":raw})
' "$OUF_PLAN_DIR/activate_dns_recovery.py" | tee "$OUF_PLAN_DIR/result.txt"
)
