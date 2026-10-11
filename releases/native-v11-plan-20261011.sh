#!/usr/bin/env bash
# Prepare new private native V11 plan only; no apply or import.
(
  set -euo pipefail
  umask 077
  OUF_DIR=not_created
  OUF_PHASE=DOWNLOAD_EXACT_NATIVE_V11_PLAN_CLOSURE
  trap 'OUF_CODE=$?; printf "OUF_NATIVE_V11_PLAN_LAUNCHER_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo OUF_EXISTING_GITHUB_CLIENT_REQUIRED >&2; exit 1; fi
  OUF_DIR="$(mktemp -d "$HOME/ouf-native-v11-plan.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-native-v11-plan.py?ref=13529d23b1ada57120c0491c7b3650e5eaf9954b' > "$OUF_DIR/program.py"
  printf '%s  %s\n' '1a73d3101ab085fee55137e08d04216f98f6052dde4ab36026d683af5fb26aa2' "$OUF_DIR/program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/read-current-r12-cutover-custody.py?ref=3ed7815b8164ffab212b44318fb8fbd213256fcc' > "$OUF_DIR/reader.py"
  printf '%s  %s\n' '4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f' "$OUF_DIR/reader.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/compile-semantic-creation-plan-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/planner.py"
  printf '%s  %s\n' '38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28' "$OUF_DIR/planner.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/prepare-semantic-inputs-after-r12.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/prepare.py"
  printf '%s  %s\n' '693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b' "$OUF_DIR/prepare.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/prepare_application_runtime_inputs.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/custody.py"
  printf '%s  %s\n' 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf' "$OUF_DIR/custody.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/creation_plan.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/creation.py"
  printf '%s  %s\n' 'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665' "$OUF_DIR/creation.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/scripts/import-verified-v11-image.py?ref=cbee055c1d6c8cf115a21246f88eb104c0b74629' > "$OUF_DIR/original_program.py"
  printf '%s  %s\n' '34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed' "$OUF_DIR/original_program.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/audit.py"
  printf '%s  %s\n' 'd118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23' "$OUF_DIR/audit.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_import.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/importer.py"
  printf '%s  %s\n' 'f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272' "$OUF_DIR/importer.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/recovery_journal.py?ref=9fdf4bed6ded1a01640bcaed2ffadb58204e42d5' > "$OUF_DIR/journal.py"
  printf '%s  %s\n' '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d' "$OUF_DIR/journal.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/engine_creation.py?ref=cac51b9e36b03119ab0b8621cefff1d9ca5e97d3' > "$OUF_DIR/engine.py"
  printf '%s  %s\n' 'b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392' "$OUF_DIR/engine.py" | sha256sum -c -
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/rebase_native_manifest.py?ref=ef5d1045f68f123f84e9c2c299b236aa9e8c3199' > "$OUF_DIR/rebase.py"
  printf '%s  %s\n' '0f1e559b14a481d6b24ee454ff5f6209c08e959579e5fe4a53697395755b6cdf' "$OUF_DIR/rebase.py" | sha256sum -c -
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
  OUF_PHASE=PREPARE_NEW_NATIVE_V11_PRIVATE_PLAN_NO_APPLY
  sudo /usr/bin/python3 -I -B -c '
import hashlib,os,stat,sys
expected=["1a73d3101ab085fee55137e08d04216f98f6052dde4ab36026d683af5fb26aa2", "4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f", "38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28", "693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b", "cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf", "e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665", "34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed", "d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23", "f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272", "43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d", "b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392", "0f1e559b14a481d6b24ee454ff5f6209c08e959579e5fe4a53697395755b6cdf"]
if len(sys.argv)!=13:raise SystemExit("OUF_NATIVE_PLAN_EXACT_SOURCE_SET_REQUIRED")
sources=[]
for path,digest in zip(sys.argv[1:],expected):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise SystemExit("OUF_NATIVE_PLAN_REGULAR_SOURCE_REQUIRED")
        raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("OUF_NATIVE_PLAN_SOURCE_HASH_MISMATCH")
    sources.append(raw)
path=sys.argv[1];sys.argv=[path]
exec(compile(sources[0],path,"exec"),{"__name__":"__main__","__file__":path,"__native_plan_sources__":dict(zip(("reader","planner","prepare","custody","creation","original_program","audit","importer","journal","engine","rebase"),sources[1:]))})
' "$OUF_DIR/program.py" "$OUF_DIR/reader.py" "$OUF_DIR/planner.py" "$OUF_DIR/prepare.py" "$OUF_DIR/custody.py" "$OUF_DIR/creation.py" "$OUF_DIR/original_program.py" "$OUF_DIR/audit.py" "$OUF_DIR/importer.py" "$OUF_DIR/journal.py" "$OUF_DIR/engine.py" "$OUF_DIR/rebase.py" | tee "$OUF_DIR/result.txt"
)
