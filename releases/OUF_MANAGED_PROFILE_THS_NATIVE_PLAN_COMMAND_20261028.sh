(
  set -euo pipefail
  umask 077
  ouf_ths_plan_launch=$(mktemp -d "$HOME/ouf-ths-plan-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/6f25824ffea6318caed384cfa7b7e81378bc1e4f/releases/prepare-managed-profile-ths-native-plan-20261028.sh' \
    -o "$ouf_ths_plan_launch/run.sh"
  printf '%s  %s\n' 'ed0c03f4761604d255dd8f5f1c9768a3cc597e3fe86408c2e545da90c90d3930' "$ouf_ths_plan_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_plan_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_plan_launch/run.sh"
)
