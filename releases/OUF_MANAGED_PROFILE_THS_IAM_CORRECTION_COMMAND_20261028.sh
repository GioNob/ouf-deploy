(
  set -euo pipefail
  umask 077
  ouf_ths_iam_fix_launch=$(mktemp -d "$HOME/ouf-ths-iam-fix-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/dc848eba194a4e43abffcd97ba9791f37fc44884/releases/correct-managed-profile-ths-iam-bindings-20261028.sh' \
    -o "$ouf_ths_iam_fix_launch/run.sh"
  printf '%s  %s\n' 'ca018484e6196366cd0c83f4ec17e09a6bc4b94a66bb871a2c4232a0a0db40d5' "$ouf_ths_iam_fix_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_iam_fix_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_iam_fix_launch/run.sh"
)

