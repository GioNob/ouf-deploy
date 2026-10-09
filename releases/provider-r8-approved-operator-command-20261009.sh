if (
  set -u
  set -o pipefail
  umask 077
  OUF_R8_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$OUF_R8_GH" ]] || { echo 'OUF_R8_BOOTSTRAP=EXISTING_GH_NOT_EXECUTABLE'; exit 1; }
  OUF_R8_LAUNCH="$(mktemp -d "$HOME/ouf-r8-launch.XXXXXXXX")" || exit 1
  "$OUF_R8_GH" api 'repos/GioNob/ouf-deploy/contents/releases/provider-prepared-mountpoint-recovery-20261009.sh?ref=5a7249c1b65e209e468de3baa10e73800f69d53e' --jq .content > "$OUF_R8_LAUNCH/run.base64" || exit 1
  base64 --decode "$OUF_R8_LAUNCH/run.base64" > "$OUF_R8_LAUNCH/run.sh" || exit 1
  printf '%s  %s\n' '1d5a745cbfc17e8e8877d2184a001a3d107df2cb3604a4589105250712c17c74' "$OUF_R8_LAUNCH/run.sh" | sha256sum -c - || exit 1
  bash "$OUF_R8_LAUNCH/run.sh"
); then
  OUF_R8_BOOTSTRAP_EXIT=0
else
  OUF_R8_BOOTSTRAP_EXIT=$?
fi
echo "OUF_R8_BOOTSTRAP_EXIT=$OUF_R8_BOOTSTRAP_EXIT"
