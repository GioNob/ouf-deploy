if (
  set -u
  set -o pipefail
  umask 077
  OUF_R8_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$OUF_R8_GH" ]] || { echo 'OUF_R8_BOOTSTRAP=EXISTING_GH_NOT_EXECUTABLE'; exit 1; }
  OUF_R8_LAUNCH="$(mktemp -d "$HOME/ouf-r8-launch.XXXXXXXX")" || exit 1
  "$OUF_R8_GH" api 'repos/GioNob/ouf-deploy/contents/releases/provider-prepared-mountpoint-recovery-20261009.sh?ref=82216a569763e1c604c88b892c635bc0cf6a0850' --jq .content > "$OUF_R8_LAUNCH/run.base64" || exit 1
  base64 --decode "$OUF_R8_LAUNCH/run.base64" > "$OUF_R8_LAUNCH/run.sh" || exit 1
  printf '%s  %s\n' 'cadf60374c540e0195a1fedabff7f3b3648c28b181ff2e6ae28fef07158123b4' "$OUF_R8_LAUNCH/run.sh" | sha256sum -c - || exit 1
  bash "$OUF_R8_LAUNCH/run.sh"
); then
  OUF_R8_BOOTSTRAP_EXIT=0
else
  OUF_R8_BOOTSTRAP_EXIT=$?
fi
echo "OUF_R8_BOOTSTRAP_EXIT=$OUF_R8_BOOTSTRAP_EXIT"
