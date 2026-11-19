# Nuova prima esecuzione; solo descriptor, fresh HUMAN review. No grant/budget/resume. STOP: non rilanciare.
(
  set -euo pipefail
  umask 077
  ouf_descriptor_launch=$(mktemp -d "$HOME/ouf-profile-descriptor-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/06bed5dc9fde4c4a570aa629e0f4f5657a02efee/releases/publish-managed-profile-descriptor-20261028.sh' \
    -o "$ouf_descriptor_launch/run.sh"
  printf '%s  %s\n' 'df9d3c507c4359c39d2c312def146427bbf6587b6062563b8bd24d00f32353b9' "$ouf_descriptor_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_descriptor_launch/run.sh"
  bash --noprofile --norc "$ouf_descriptor_launch/run.sh"
)
