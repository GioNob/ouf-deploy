#!/usr/bin/env bash
# Installazione umana D-046(a). Nessun grant sudo per questo runbook.
set -euo pipefail
umask 077
C=4025163cb5fa2970d0d83124276b37510fbbcda5 # Claude: fissato dopo review/commit D-001.
mode=${1:-}
case "$mode:$#" in
  plan:1) ;;
  apply:2) [[ "$2" =~ ^[0-9a-f]{64}$ ]] || exit 2 ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] || {
  echo 'runbook non ancora fissato a un commit' >&2; exit 2;
}
[[ $EUID == 0 ]] || { echo 'eseguire come root' >&2; exit 2; }
DEST=/usr/local/libexec/ouf-readers/r3
SUDOERS=/etc/sudoers.d/91-ouf-r3-readers
D=$(mktemp -d /tmp/ouf-r3-readers.XXXXXXXX)
T=
trap 'rm -rf -- "$D"; if [[ -n "$T" ]]; then rm -f -- "$T"; fi' EXIT
fetch() {
  local name=$1 expected=$2
  curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/ops/vps/readers/$name" -o "$D/$name"
  printf '%s  %s\n' "$expected" "$D/$name" | sha256sum --check --status
  local target=$DEST/$name mode=0755
  if [[ "$name" == 91-ouf-r3-readers ]]; then target=$SUDOERS; mode=0440; fi
  printf '%s %s root:root %s\n' "$expected" "$target" "$mode" >> "$D/manifest"
}
# BEGIN DELIVERY
fetch 91-ouf-r3-readers 6735348f06cfccc324a0767c03eeea90c50a155e9a037ececfd61a12b3303cfe
fetch r3_common.py 9f1797fa278bd7864fe37bbb4e66a8a03fbbd9151f2f342eafa53b13a29b2dd3
fetch r3-epoch-diag.py 1e5e78730cb05eb8649c792f4da5da6c43c2c83369dbf51b49766bfe3d508a31
fetch r3-epoch-timeline.py 436a94f1b424e9db5033a5001910335a3564ec0d40f56fedc61d228eef672a57
fetch r3-frame-diag.py 5632b7655aa79c11e1afafd7eacfc32bc4b5ef67d6b8791a852c39d4339d78d3
fetch r3-guard-diag.py 6fa11b789164e81f760161da1d332c08375f5cc75586f1eb83d7e14c2f29fd1d
fetch r3-status.py 00e563b48295cbd48a7cb7e4dbad3813ca6ef9192b7198b98e32434305cd0c3c
fetch r3-supervisor-journal.py 7301994a4b7938c3245d25fc7ef98ea76c20c109df53447189c82f3922921389
fetch r3-upper-delta.py 83414677f2a1884744137b937d4ea2a4afb8f6808d2e5e395fc6061f290b9181
fetch r3-watch.py df55ef764f096694a795838759f3ae3f17312dae267c0172c230e8884d372f47
# END DELIVERY
/usr/sbin/visudo -cf "$D/91-ouf-r3-readers"
printf '%s\n' "commit=$C" "runbook=$(sha256sum "$0" | cut -d' ' -f1)" >> "$D/manifest"
cat "$D/manifest"
planSha256=$(sha256sum "$D/manifest" | cut -d' ' -f1)
printf 'planSha256=%s\n' "$planSha256"
[[ "$mode" == apply ]] || exit 0
[[ "$2" == "$planSha256" ]] || { echo 'PLAN_HASH_MISMATCH' >&2; exit 2; }
# Reject symlinks and non-root/writable existing ancestors before any install.
for p in /usr /usr/local /usr/local/libexec /usr/local/libexec/ouf-readers "$DEST" /etc /etc/sudoers.d; do
  if [[ -e "$p" || -L "$p" ]]; then
    [[ -d "$p" && ! -L "$p" && $(stat -c %u "$p") == 0 ]] || exit 2
    m=$(stat -c %a "$p")
    (( (8#$m & 0022) == 0 )) || exit 2
  fi
done
[[ ! -L "$SUDOERS" ]] || exit 2
install -d -o root -g root -m 0755 /usr/local/libexec/ouf-readers "$DEST"
for f in "$D"/*.py; do
  [[ ! -L "$DEST/${f##*/}" ]] || exit 2
  install -o root -g root -m 0755 "$f" "$DEST/${f##*/}"
done
T=$(mktemp /etc/sudoers.d/.91-ouf-r3-readers.XXXXXXXX)
install -o root -g root -m 0440 "$D/91-ouf-r3-readers" "$T"
/usr/sbin/visudo -cf "$T"
mv -fT -- "$T" "$SUDOERS"
T=
sha256sum "$DEST"/*.py "$SUDOERS"
