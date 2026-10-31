(
  set -euo pipefail
  umask 077
  ouf_ths_iam_launch=$(mktemp -d "$HOME/ouf-ths-iam-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/b3038858a0c779d3ce3eb98fcb63f916f2bb350a/releases/read-managed-profile-ths-iam-bindings-20261028.sh' \
    -o "$ouf_ths_iam_launch/run.sh"
  printf '%s  %s\n' '770712e37a90336b5433610e0adebd005399ef42536176170f61b778c50455a8' "$ouf_ths_iam_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_iam_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_iam_launch/run.sh"
)
