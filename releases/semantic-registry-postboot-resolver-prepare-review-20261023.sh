#!/usr/bin/env bash
# Pinned source and separately published capsule, verified by exact readback.
# Scope: one preparation followed by its review, or an explicit review only.
# This wrapper cannot issue authority or dispatch recovery effects.
# Native composition fixtures do not qualify the entire operator CLI on target.
(
  set -euo pipefail
  umask 077
  OUF_POSTBOOT_SOURCE_COMMIT='9f3b33c485d13eae7616408b99141ad09765bd88'
  OUF_POSTBOOT_CAPSULE_COMMIT='bad98335414b1d95cb57b132e498715dbec9530f'
  OUF_POSTBOOT_CAPSULE_SHA256='d841407bf3d010aa9e3f7a789ed6ecf4acfd16acaba5797ef29cdc8cbeb3d2d5'
  OUF_POSTBOOT_ACTION="${1:-prepare-review}"
  if (( $# > 1 )) || [[ "$OUF_POSTBOOT_ACTION" != 'prepare-review' && "$OUF_POSTBOOT_ACTION" != 'review' ]]; then
    printf '%s\n' 'STOP: modalità ammessa prepare-review oppure review; nessuna altra azione.'
    exit 2
  fi
  if [[ ! "$OUF_POSTBOOT_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
        ! "$OUF_POSTBOOT_CAPSULE_COMMIT" =~ ^[0-9a-f]{40}$ ||
        ! "$OUF_POSTBOOT_CAPSULE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'STOP: consegna ancora non qualificata e non fissata a sorgenti pubblicate.'
    exit 2
  fi
  OUF_POSTBOOT_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [[ ! -x "$OUF_POSTBOOT_GH" ]]; then
    OUF_POSTBOOT_GH="$(command -v gh || true)"
  fi
  if [[ -z "$OUF_POSTBOOT_GH" || ! -x "$OUF_POSTBOOT_GH" || ! -x /usr/bin/python3 || ! -x /usr/bin/timeout ]]; then
    printf '%s\n' 'STOP: client GitHub esistente o programmi richiesti non disponibili.'
    exit 2
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    printf '%s\n' 'STOP: sudo non disponibile.'
    exit 2
  fi
  OUF_POSTBOOT_DIR="$(mktemp -d "$HOME/ouf-registry-postboot-review.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_POSTBOOT_DIR" "$OUF_POSTBOOT_DIR"' EXIT
  printf '{"schema":"ouf.semantic-registry-postboot-review-delivery.v1","sourceCommit":"%s","capsuleCommit":"%s","capsuleSha256":"%s","runtimeAuthorityIssued":false,"runtimeEffectsDispatched":0}\n' \
    "$OUF_POSTBOOT_SOURCE_COMMIT" "$OUF_POSTBOOT_CAPSULE_COMMIT" "$OUF_POSTBOOT_CAPSULE_SHA256" > "$OUF_POSTBOOT_DIR/operator.log"
  # Existing GitHub authentication only. No login, credential arguments,
  # anonymous private-repository fallback or automatic second download.
  if ! (
    ulimit -f 3072
    GH_PROMPT_DISABLED=1 GH_PAGER=cat /usr/bin/timeout --signal=TERM --kill-after=5 45 \
      "$OUF_POSTBOOT_GH" api --method GET --hostname github.com \
      -H 'Accept: application/vnd.github.raw+json' \
      "repos/GioNob/ouf-deploy/contents/releases/semantic-registry-postboot-resolver-20261023.py?ref=$OUF_POSTBOOT_CAPSULE_COMMIT"
  ) > "$OUF_POSTBOOT_DIR/capsule.py" 2> "$OUF_POSTBOOT_DIR/download.stderr"; then
    printf '%s\n' '{"schema":"ouf.semantic-registry-postboot-review-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"PINNED_CAPSULE_DOWNLOAD_UNCONFIRMED","automaticReplayAllowed":false}' | tee -a "$OUF_POSTBOOT_DIR/operator.log"
    exit 2
  fi

  ouf_postboot_run_mode() {
    local OUF_POSTBOOT_MODE="$1"
    # Two separate interpreters are intentional: every capsule starts with a
    # clean application namespace. The reviewed bytes are read once into memory.
    sudo -- /usr/bin/python3 -I -B -S - "$OUF_POSTBOOT_DIR/capsule.py" \
      "$OUF_POSTBOOT_CAPSULE_SHA256" "$OUF_POSTBOOT_SOURCE_COMMIT" "$OUF_POSTBOOT_MODE" <<'PY'
import ast, hashlib, json, os, re, stat, sys
def require(ok, reason):
    if not ok:
        raise ValueError(reason)
try:
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode, 'ISOLATED_ROOT_REVIEW_LAUNCH_REQUIRED')
    require(len(sys.argv) == 5 and sys.argv[4] in ('prepare', 'review'), 'PREPARATION_OR_REVIEW_ONLY')
    path, expected, source_commit, mode = sys.argv[1:]
    require(re.fullmatch('[0-9a-f]{64}', expected) and re.fullmatch('[0-9a-f]{40}', source_commit),
            'EXACT_PUBLISHED_CAPSULE_PINS_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= 3145728, 'BOUNDED_CAPSULE_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            code = stream.read(3145729)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(code) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False)), 'CAPSULE_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    require(hashlib.sha256(code).hexdigest() == expected, 'PUBLISHED_CAPSULE_HASH_MISMATCH')
    matches = [node.value for node in ast.parse(code).body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == 'DELIVERY']
    require(len(matches) == 1, 'ONE_PINNED_CAPSULE_DECLARATION_REQUIRED')
    declaration = ast.literal_eval(matches[0])
    require(declaration['nativeDeclaration']['sourceCommit'] == source_commit
            == declaration['nativeDeclaration']['sourcePins']['ouf-deploy'], 'CAPSULE_SOURCE_COMMIT_MISMATCH')
except Exception as error:
    reason = str(error)
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'CAPSULE_REVIEW_LAUNCH_UNPROVEN_PRIVATE_DETAILS_REDACTED'
    print(json.dumps({'schema': 'ouf.semantic-registry-postboot-review-launch-result.v1',
        'status': 'STOP_RECONCILE', 'reasonCode': reason, 'runtimeAuthorityIssued': False,
        'runtimeEffectsDispatched': 0, 'automaticReplayAllowed': False}), flush=True)
    raise SystemExit(2)
sys.argv = [path, mode]
exec(compile(code, '<verified-postboot-capsule>', 'exec'), {'__name__': '__main__'})
PY
  }

  ouf_postboot_confirm_receipt() {
    /usr/bin/python3 -I -B -S - "$OUF_POSTBOOT_DIR/$1.log" "$1" <<'PY'
import json, pathlib, sys
try:
    with pathlib.Path(sys.argv[1]).open('rb') as stream:
        raw = stream.read(65537)
    if not 0 < len(raw) <= 65536:
        raise ValueError()
    value = json.loads(raw)
    expected = {'prepare': ('ouf.semantic-registry-postboot-preparation-result.v1', 'CURRENT_POSTBOOT_INPUTS_PREPARED'),
                'review': ('ouf.semantic-registry-postboot-review-result.v1', 'COMPLETE_PRIVATE_POSTBOOT_REVIEW_PREPARED')}
    schema, status = expected[sys.argv[2]]
    if value.get('schema') != schema or value.get('status') != status:
        raise ValueError()
    if any(value.get(key) is not False for key in ('runtimeAuthorityIssued', 'targetApplyAuthorized', 'automaticReplayAllowed', 'budgetReset', 'releaseAcceptance')):
        raise ValueError()
    if type(value.get('runtimeEffectsDispatched')) is not int or value['runtimeEffectsDispatched'] != 0:
        raise ValueError()
    if sys.argv[2] == 'prepare' and (value.get('complete') is not True or value.get('oauthRequests') != 0):
        raise ValueError()
    if sys.argv[2] == 'review' and value.get('signedScopeCount') != 11:
        raise ValueError()
except Exception:
    raise SystemExit(2)
PY
  }

  OUF_POSTBOOT_MODES=(review)
  if [[ "$OUF_POSTBOOT_ACTION" == 'prepare-review' ]]; then
    OUF_POSTBOOT_MODES=(prepare review)
  fi
  for OUF_POSTBOOT_MODE in "${OUF_POSTBOOT_MODES[@]}"; do
    if ! ouf_postboot_run_mode "$OUF_POSTBOOT_MODE" 2> "$OUF_POSTBOOT_DIR/$OUF_POSTBOOT_MODE.stderr" \
      | tee -a "$OUF_POSTBOOT_DIR/$OUF_POSTBOOT_MODE.log" "$OUF_POSTBOOT_DIR/operator.log"; then
      printf '%s\n' '{"schema":"ouf.semantic-registry-postboot-review-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"PREPARATION_OR_REVIEW_NOT_COMPLETED","automaticReplayAllowed":false}' | tee -a "$OUF_POSTBOOT_DIR/operator.log"
      exit 2
    fi
    if ! ouf_postboot_confirm_receipt "$OUF_POSTBOOT_MODE"; then
      printf '%s\n' '{"schema":"ouf.semantic-registry-postboot-review-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"EXPECTED_PRIVATE_REVIEW_RECEIPT_UNCONFIRMED","automaticReplayAllowed":false}' | tee -a "$OUF_POSTBOOT_DIR/operator.log"
      exit 2
    fi
  done
)
