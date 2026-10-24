#!/usr/bin/env bash
# Pinned source and separately published capsule, verified by exact readback.
# Scope: execute exactly one already completed, hash-bound private review.
# The actual terminal decision precedes authority and all native effects.
# Native composition fixtures do not qualify the entire operator CLI on target.
(
  set -euo pipefail
  umask 077
  OUF_POSTBOOT_SOURCE_COMMIT='7793835ddd05af28577b4ff299222194b6397b94'
  OUF_POSTBOOT_CAPSULE_COMMIT='bccabde9a16d370d76e6cd2b941d6a09ea0b5d70'
  OUF_POSTBOOT_CAPSULE_SHA256='f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c'
  OUF_POSTBOOT_REVIEW_HASH='cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9'
  OUF_POSTBOOT_PREPARATION_HASH='90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d'
  OUF_POSTBOOT_PREPARATION_ROOT='/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2'
  OUF_POSTBOOT_RETAINED_CAPSULE='/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py'
  if (( $# != 0 )); then
    printf '%s\n' 'STOP: nessun argomento; solo esecuzione della revisione fissata.'
    exit 2
  fi
  if [[ ! "$OUF_POSTBOOT_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
        ! "$OUF_POSTBOOT_CAPSULE_COMMIT" =~ ^[0-9a-f]{40}$ ||
        ! "$OUF_POSTBOOT_CAPSULE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'STOP: consegna ancora non qualificata e non fissata a sorgenti pubblicate.'
    exit 2
  fi
  if [[ ! -x /usr/bin/python3 ]]; then
    printf '%s\n' 'STOP: interprete richiesto non disponibile.'
    exit 2
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    printf '%s\n' 'STOP: sudo non disponibile.'
    exit 2
  fi
  OUF_POSTBOOT_DIR="$(mktemp -d "$HOME/ouf-registry-postboot-apply.XXXXXXXX")"
  trap 'printf "\nDirectory conservata: %s\nLog conservato: %s/operator.log\n" "$OUF_POSTBOOT_DIR" "$OUF_POSTBOOT_DIR"' EXIT
  printf '{"schema":"ouf.semantic-registry-postboot-apply-delivery.v1","sourceCommit":"%s","capsuleCommit":"%s","capsuleSha256":"%s","observation":"LAUNCH_NOT_RUNTIME_OBSERVATION","automaticReplayAllowed":false}\n' \
    "$OUF_POSTBOOT_SOURCE_COMMIT" "$OUF_POSTBOOT_CAPSULE_COMMIT" "$OUF_POSTBOOT_CAPSULE_SHA256" > "$OUF_POSTBOOT_DIR/operator.log"
  # Reuse only the exact capsule retained by the completed preparation.
  # No prepare/review replay, capsule download, login or automatic retry.
  ouf_postboot_run_mode() {
    local OUF_POSTBOOT_MODE="$1"
    # Separate interpreters are intentional: every capsule starts with a
    # clean application namespace. The reviewed bytes are read once into memory.
    sudo -- /usr/bin/python3 -I -B -S - "$OUF_POSTBOOT_RETAINED_CAPSULE" \
      "$OUF_POSTBOOT_CAPSULE_SHA256" "$OUF_POSTBOOT_SOURCE_COMMIT" "$OUF_POSTBOOT_MODE" \
      "$OUF_POSTBOOT_REVIEW_HASH" "$OUF_POSTBOOT_PREPARATION_ROOT" "$OUF_POSTBOOT_PREPARATION_HASH" <<'PY'
import ast, hashlib, json, os, re, stat, sys
def require(ok, reason):
    if not ok:
        raise ValueError(reason)
try:
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode, 'ISOLATED_ROOT_REVIEW_LAUNCH_REQUIRED')
    require(len(sys.argv) == 8 and sys.argv[4] in ('issue', 'install', 'bootstrap', 'owner', 'continue'), 'REVIEWED_FINITE_EXECUTION_ONLY')
    path, expected, source_commit, mode, review_hash, preparation_root, preparation_hash = sys.argv[1:]
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
    require(re.fullmatch('[0-9a-f]{64}', review_hash) and re.fullmatch('[0-9a-f]{64}', preparation_hash),
            'EXACT_COMPLETED_REVIEW_AND_PREPARATION_PINS_REQUIRED')
    # The capsule additionally checks protected ancestry, canonical JSON and
    # the complete semantic/signed source bindings before any actual action.
    for name, digest in [('prepared.json', preparation_hash), ('review.json', review_hash)]:
        reference = preparation_root + '/' + name
        fd = os.open(reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and before.st_nlink == 1 and not before.st_mode & 0o077
                    and 0 < before.st_size <= 16777216, 'PRIVATE_COMPLETED_REVIEW_FILE_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(16777217)
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                    == identity(os.stat(reference, follow_symlinks=False))
                    and hashlib.sha256(raw).hexdigest() == digest, 'COMPLETED_REVIEW_OR_PREPARATION_CHANGED')
        finally:
            os.close(fd)
except Exception as error:
    reason = str(error)
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'CAPSULE_REVIEW_LAUNCH_UNPROVEN_PRIVATE_DETAILS_REDACTED'
    print(json.dumps({'schema': 'ouf.semantic-registry-postboot-apply-launch-result.v1',
        'status': 'STOP_RECONCILE', 'reasonCode': reason, 'runtimeEffectsMayBePartial': True, 'automaticReplayAllowed': False}), flush=True)
    raise SystemExit(2)
sys.argv = [path, mode, review_hash]
exec(compile(code, '<verified-postboot-capsule>', 'exec'), {'__name__': '__main__'})
PY
  }

  ouf_postboot_confirm_receipt() {
    /usr/bin/python3 -I -B -S - "$OUF_POSTBOOT_DIR/$1.log" "$1" "$OUF_POSTBOOT_REVIEW_HASH" <<'PYCODE'
import json, pathlib, sys
try:
    raw = pathlib.Path(sys.argv[1]).read_bytes()
    if not 0 < len(raw) <= 1048576:
        raise ValueError()
    rows = [json.loads(line) for line in raw.splitlines()]
    if not rows or len(rows) > 512 or any(type(row) is not dict for row in rows):
        raise ValueError()
    if any(row.get('status') == 'STOP_RECONCILE' for row in rows):
        raise ValueError()
    row, mode = rows[-1], sys.argv[2]
    common = {'automaticReplayAllowed': False, 'budgetReset': False}
    if mode == 'issue':
        expected = dict(schema='ouf.semantic-registry-postboot-issued-authority.v1',
            reviewHash=sys.argv[3], runtimeAuthorityIssued=True, runtimeEffectsDispatched=0, releaseAcceptance=False)
    elif mode == 'install':
        expected = dict(schema='ouf.semantic-registry-postboot-installation-result.v1',
            status='CURRENT_BOOT_RECOVERY_LEDGERS_INSTALLED', runtimeEffectsDispatched=0, oauthRequests=0, releaseAcceptance=False)
    elif mode == 'bootstrap':
        expected = dict(schema='ouf.semantic-registry-postboot-paused-result.v1', checkpoint=4,
            freshPausedGateObserved=True, javaReleased=False, tokenGrantAttempts=0, originalSemanticGetSucceeded=False)
    elif mode == 'owner':
        expected = dict(schema='ouf.semantic-registry-postboot-owner-installed-result.v1',
            currentSessionBootEstablished=True, retainedFirstGrantReplayed=False,
            priorControlledGrantAttempts=319, oauthRequests=0, runtimeAuthorityIssued=False)
    else:
        expected = dict(schema='ouf.semantic-registry-postboot-finite-session-result.v1',
            originalSemanticGetSucceededDuringWindow=True, ownerSessionEnded=True,
            currentOwnerAdmissionProven=False, continuousServiceRenewalEstablished=False, releaseAcceptance=False)
        if row.get('status') not in ('FINITE_PUBLISHED_TOKEN_WINDOW_ENDED', 'FINITE_OWNER_OPERATION_WINDOW_ENDED', 'FINITE_OWNER_AUTHORITY_WINDOW_ENDED'):
            raise ValueError()
        if not any(v.get('status') == 'ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER'
                and v.get('httpStatus') == 200 and v.get('originalSemanticGetSucceeded') is True for v in rows):
            raise ValueError()
    for key, value in {**common, **expected}.items():
        if type(row.get(key)) is not type(value) or row[key] != value:
            raise ValueError()
except Exception:
    raise SystemExit(2)
PYCODE
  }

  # issue owns the real controlling-terminal prompt. This wrapper never
  # supplies, fabricates or pipes its APPROVO response.
  OUF_POSTBOOT_MODES=(issue install bootstrap owner continue)
  for OUF_POSTBOOT_MODE in "${OUF_POSTBOOT_MODES[@]}"; do
    if ! ouf_postboot_run_mode "$OUF_POSTBOOT_MODE" 2> "$OUF_POSTBOOT_DIR/$OUF_POSTBOOT_MODE.stderr" \
      | tee -a "$OUF_POSTBOOT_DIR/$OUF_POSTBOOT_MODE.log" "$OUF_POSTBOOT_DIR/operator.log"; then
      printf '%s\n' '{"schema":"ouf.semantic-registry-postboot-apply-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"REVIEWED_EXECUTION_NOT_COMPLETED","runtimeEffectsMayBePartial":true,"automaticReplayAllowed":false}' | tee -a "$OUF_POSTBOOT_DIR/operator.log"
      exit 2
    fi
    if ! ouf_postboot_confirm_receipt "$OUF_POSTBOOT_MODE"; then
      printf '%s\n' '{"schema":"ouf.semantic-registry-postboot-apply-delivery-result.v1","status":"STOP_RECONCILE","reasonCode":"EXPECTED_REVIEWED_EXECUTION_RECEIPT_UNCONFIRMED","runtimeEffectsMayBePartial":true,"automaticReplayAllowed":false}' | tee -a "$OUF_POSTBOOT_DIR/operator.log"
      exit 2
    fi
  done
)
