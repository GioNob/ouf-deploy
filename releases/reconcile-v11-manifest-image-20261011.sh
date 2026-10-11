#!/usr/bin/env bash
# Reconcile existing consumed V11 import. No image load or application effect.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_MANIFEST_RECONCILIATION_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_V11_MANIFEST_RECONCILIATION_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-v11-manifest-reconcile.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/reconcile-v11-manifest-image.py?ref=7e81b2db2c83f0297f3199a7bd1e1127a44d9df4' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '628dd79524e45f9d2ed19a38fcc119303be31ff8b0bafc373100cd9bf90c1859' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/import-verified-v11-image.py?ref=cbee055c1d6c8cf115a21246f88eb104c0b74629' > "$OUF_DIR/original_program.py"
  printf '%s  %s\n' '34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed' "$OUF_DIR/original_program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/audit.py"
  printf '%s  %s\n' 'd118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23' "$OUF_DIR/audit.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_import.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/importer.py"
  printf '%s  %s\n' 'f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272' "$OUF_DIR/importer.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/recovery_journal.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/journal.py"
  printf '%s  %s\n' '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d' "$OUF_DIR/journal.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/engine_creation.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/engine.py"
  printf '%s  %s\n' 'b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392' "$OUF_DIR/engine.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_manifest_identity.py?ref=7e81b2db2c83f0297f3199a7bd1e1127a44d9df4' > "$OUF_DIR/manifest.py"
  printf '%s  %s\n' 'b8fad73953aaf44209b3a1b50209fde6198d39926d2aa46cb3995313f9c05f7a' "$OUF_DIR/manifest.py" | sha256sum -c -
  OUF_PHASE=VERIFY_EXISTING_ORIGINAL_PUBLISHER_SUBJECTS
  OUF_PACKAGE="$HOME/ouf-durable-v11-stage.drTnFl4m/package"
  for OUF_FILE in image.docker.tar source.tar source-inventory.json application.jar package-record.json migration-continuity.json trivy-image.json Dockerfile.resolved; do
    if ! "$OUF_GH" attestation verify "$OUF_PACKAGE/$OUF_FILE" --repo GioNob/ouf-semantic-registry \
      --signer-workflow GioNob/ouf-semantic-registry/.github/workflows/discovery-durable-candidate.yml \
      --source-digest 3ec99277b8383e496913b9fd3bb05c877825abf5 \
      --source-ref refs/heads/codex/discovery-durable-resilience-20261011 --deny-self-hosted-runners \
      --bundle "$OUF_PACKAGE/provenance.json" --format json \
      > "$OUF_DIR/$OUF_FILE.signature.json" 2> "$OUF_DIR/$OUF_FILE.signature.stderr"; then
      echo OUF_ORIGINAL_PUBLISHER_VERIFICATION_FAILED >&2; exit 1
    fi
  done
  echo OUF_ORIGINAL_PUBLISHER_SUBJECTS_VERIFIED=8
  OUF_PHASE=RECONCILE_EXISTING_CONSUMED_IMPORT_WITHOUT_LOAD
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["628dd79524e45f9d2ed19a38fcc119303be31ff8b0bafc373100cd9bf90c1859", "34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed", "cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf", "d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23", "f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272", "43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d", "b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392", "b8fad73953aaf44209b3a1b50209fde6198d39926d2aa46cb3995313f9c05f7a"]
if len(sys.argv)!=9:raise SystemExit("OUF_MANIFEST_RECONCILIATION_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_MANIFEST_RECONCILIATION_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_MANIFEST_RECONCILIATION_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__manifest_reconciliation_sources__":dict(zip(("original_program","custody","audit","importer","journal","engine","manifest"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/original_program.py" "$OUF_DIR/custody.py" "$OUF_DIR/audit.py" "$OUF_DIR/importer.py" "$OUF_DIR/journal.py" "$OUF_DIR/engine.py" "$OUF_DIR/manifest.py" | tee "$OUF_DIR/result.txt"
)
