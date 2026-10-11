#!/usr/bin/env bash
# Operator offline exact-image import/custody; no application/container cutover.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_IMAGE_IMPORT_SOURCE_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_V11_IMAGE_IMPORT_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-v11-image-import.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/import-verified-v11-image.py?ref=cbee055c1d6c8cf115a21246f88eb104c0b74629' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed' "$OUF_DIR/program.py" | sha256sum -c -
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
  OUF_PHASE=IMPORT_OR_RECONCILE_EXACT_TAGLESS_IMAGE_NO_APPLICATION_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf","d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23","f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272","43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d","b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392"]
if len(sys.argv)!=7:raise SystemExit("OUF_IMAGE_IMPORT_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_IMAGE_IMPORT_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_IMAGE_IMPORT_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__image_import_sources__":dict(zip(("custody","audit","importer","journal","engine"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/custody.py" "$OUF_DIR/audit.py" "$OUF_DIR/importer.py" "$OUF_DIR/journal.py" "$OUF_DIR/engine.py" | tee "$OUF_DIR/result.txt"
)
