#!/usr/bin/env bash
set -euo pipefail
umask 077
if (( $# != 0 )); then
  printf '%s\n' 'ONE_EXACT_REVIEWED_DEPLOYMENT_ONLY' >&2
  exit 2
fi
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh=$(command -v gh || true); fi
if [[ -z "$ouf_gh" || ! -x "$ouf_gh" ]]; then
  printf '%s\n' 'EXISTING_AUTHENTICATED_GITHUB_CLIENT_REQUIRED' >&2
  exit 2
fi
ouf_source_dir=$(mktemp -d "$HOME/ouf-registry-normal-launch.XXXXXXXX")
ouf_log="$ouf_source_dir/operator.log"
: > "$ouf_log"
trap 'ouf_exit=$?; printf "\nDirectory conservata: %s\nLog conservato: %s\n" "$ouf_source_dir" "$ouf_log"; exit "$ouf_exit"' EXIT
ouf_root='/etc/ouf/deploy-snapshots/semantic-registry-operational-launch-c33b6467d424489aeec7406c65fafc37'
"$ouf_gh" api --method GET -H 'Accept: application/vnd.github.raw+json' \
  'repos/GioNob/ouf-deploy/contents/releases/semantic-registry-operational-owner-20261024.py?ref=ca9815fc3505085360c5601fc1f3c6672c21b660' \
  > "$ouf_source_dir/capsule.py"
printf '%s  %s\n' 'c33b6467d424489aeec7406c65fafc37534badc08e909bf7c2d78bb1f122d378' "$ouf_source_dir/capsule.py" | /usr/bin/sha256sum --check --status -
/usr/bin/sudo -v
# Exclusive creation: a second launch cannot repeat an uncertain operator call.
/usr/bin/sudo /usr/bin/mkdir -m 0700 "$ouf_root"
/usr/bin/sudo /usr/bin/install -o root -g root -m 0400 "$ouf_source_dir/capsule.py" "$ouf_root/capsule.py"
# Verify the protected copy again, never execute directly from a user directory.
printf '%s  %s\n' 'c33b6467d424489aeec7406c65fafc37534badc08e909bf7c2d78bb1f122d378' "$ouf_root/capsule.py" | /usr/bin/sudo /usr/bin/sha256sum --check --status -
printf '%s\n' 'Preparo la revisione concreta. Il protocollo richiedera APPROVO seguito dal suo hash esatto sul terminale.'
set +e
/usr/bin/sudo /usr/bin/python3 -I -B -S "$ouf_root/capsule.py" deploy 2>&1 | /usr/bin/tee "$ouf_log"
ouf_pipeline=( "${PIPESTATUS[@]}" )
set -e
if (( ouf_pipeline[0] != 0 )); then
  printf '%s\n' 'STOP: conservare gli output; non rilanciare questa procedura.' >&2
  exit "${ouf_pipeline[0]}"
fi
if (( ouf_pipeline[1] != 0 )); then
  printf '%s\n' 'OPERATOR_LOG_INCOMPLETE_DO_NOT_REPLAY' >&2
  exit 74
fi
