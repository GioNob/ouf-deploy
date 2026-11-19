#!/usr/bin/env python3
"""Render one immutable download/install invocation; no target operations."""
import argparse
from pathlib import Path
import re

DEFAULT_COMMANDS={key:'/usr/bin/'+value for key,value in dict(checksum='sha256sum',
    sudo='sudo',mkdir='mkdir',install='install',python='python3',tee='tee').items()}


def render(commit, capsule_sha, *, parent='/etc/ouf/deploy-snapshots', commands=None):
    assert re.fullmatch('[a-f0-9]{40}',commit) and re.fullmatch('[a-f0-9]{64}',capsule_sha)
    commands=DEFAULT_COMMANDS if commands is None else commands
    assert set(commands)==set(DEFAULT_COMMANDS)
    for value in(parent,*commands.values()):
        assert re.fullmatch(r'/[A-Za-z0-9_./-]+',value) and '..' not in Path(value).parts
    template='''#!/usr/bin/env bash
set -euo pipefail
umask 077
if (( $# != 0 )); then
  printf '%s\\n' 'ONE_EXACT_REVIEWED_DEPLOYMENT_ONLY' >&2
  exit 2
fi
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh=$(command -v gh || true); fi
if [[ -z "$ouf_gh" || ! -x "$ouf_gh" ]]; then
  printf '%s\\n' 'EXISTING_AUTHENTICATED_GITHUB_CLIENT_REQUIRED' >&2
  exit 2
fi
ouf_source_dir=$(mktemp -d "$HOME/ouf-registry-normal-launch.XXXXXXXX")
ouf_log="$ouf_source_dir/operator.log"
: > "$ouf_log"
trap 'ouf_exit=$?; printf "\\nDirectory conservata: %s\\nLog conservato: %s\\n" "$ouf_source_dir" "$ouf_log"; exit "$ouf_exit"' EXIT
ouf_root='@@PARENT@@/semantic-registry-operational-launch-@@SHORT_SHA@@'
"$ouf_gh" api --method GET -H 'Accept: application/vnd.github.raw+json' \\
  'repos/GioNob/ouf-deploy/contents/releases/semantic-registry-operational-owner-20261024.py?ref=@@COMMIT@@' \\
  > "$ouf_source_dir/capsule.py"
printf '%s  %s\\n' '@@SHA@@' "$ouf_source_dir/capsule.py" | @@CHECKSUM@@ --check --status -
@@SUDO@@ -v
# Exclusive creation: a second launch cannot repeat an uncertain operator call.
@@SUDO@@ @@MKDIR@@ -m 0700 "$ouf_root"
@@SUDO@@ @@INSTALL@@ -o root -g root -m 0400 "$ouf_source_dir/capsule.py" "$ouf_root/capsule.py"
# Verify the protected copy again, never execute directly from a user directory.
printf '%s  %s\\n' '@@SHA@@' "$ouf_root/capsule.py" | @@SUDO@@ @@CHECKSUM@@ --check --status -
printf '%s\\n' 'Preparo la revisione concreta. Il protocollo richiedera APPROVO seguito dal suo hash esatto sul terminale.'
set +e
@@SUDO@@ @@PYTHON@@ -I -B -S "$ouf_root/capsule.py" deploy 2>&1 | @@TEE@@ "$ouf_log"
ouf_pipeline=( "${PIPESTATUS[@]}" )
set -e
if (( ouf_pipeline[0] != 0 )); then
  printf '%s\\n' 'STOP: conservare gli output; non rilanciare questa procedura.' >&2
  exit "${ouf_pipeline[0]}"
fi
if (( ouf_pipeline[1] != 0 )); then
  printf '%s\\n' 'OPERATOR_LOG_INCOMPLETE_DO_NOT_REPLAY' >&2
  exit 74
fi
'''
    values={'PARENT':parent,'SHORT_SHA':capsule_sha[:32],'SHA':capsule_sha,'COMMIT':commit}
    values.update({key.upper():value for key,value in commands.items()})
    for key,value in values.items():template=template.replace('@@'+key+'@@',value)
    assert '@@' not in template
    return template


def main():
    p=argparse.ArgumentParser();p.add_argument('--artifact-commit',required=True)
    p.add_argument('--capsule-sha256',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    with Path(a.output).open('x') as stream:stream.write(render(a.artifact_commit,a.capsule_sha256))


if __name__=='__main__':main()
