#!/usr/bin/env bash
# Verify existing package ZIP signatures and public trust; diagnose R9 without replay.
(
set -euo pipefail
umask 077
OUF_PHASE=DOWNLOAD_SMALL_PROVENANCE_BUNDLES
OUF_DIR=not_created
trap 'OUF_CODE=$?; printf "OUF_FILE_LOOP_PROVENANCE_READ_EXIT=%s PHASE=%s OUTPUT=%s/result.txt\n" "$OUF_CODE" "$OUF_PHASE" "$OUF_DIR"' EXIT
OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
OUF_DIR="$(mktemp -d "$HOME/ouf-file-loop-provenance-read.XXXXXXXX")"
"$OUF_GH" api repos/GioNob/ouf-deploy/actions/artifacts/11676991790/zip > "$OUF_DIR/ingestion-proof.zip"
"$OUF_GH" api repos/GioNob/ouf-deploy/actions/artifacts/11676389122/zip > "$OUF_DIR/udp-proof.zip"
"$OUF_GH" api repos/GioNob/ouf-deploy/actions/artifacts/11676214297/zip > "$OUF_DIR/semantic-proof.zip"
"$OUF_GH" api repos/GioNob/ouf-deploy/actions/artifacts/11677280041/zip > "$OUF_DIR/roots-proof.zip"
printf '%s  %s\n' \
 '4b1fbb503887d84c70d8d3d0f43af8966de5b06ddf86e9fe0128de67d680bd81' "$OUF_DIR/ingestion-proof.zip" \
 '3cf01450fdcf0cc9e387872a44139e403f7b04b9d632fddddf10e659a098e047' "$OUF_DIR/udp-proof.zip" \
 '28794642891694e7ac513dc4ccebcc51d681ad28d13a1784d3309f10d398047f' "$OUF_DIR/semantic-proof.zip" \
 'f77eae7c8a9d042431635008e3da683be15488011380507a64819a0d6ba837f6' "$OUF_DIR/roots-proof.zip" | sha256sum -c -
python3 - "$OUF_DIR" <<'PY'
import pathlib,stat,sys,zipfile
root=pathlib.Path(sys.argv[1])
for folder,file in (("semantic","semantic-proof.zip"),("ingestion","ingestion-proof.zip"),("udp","udp-proof.zip"),("public-roots","roots-proof.zip")):
    destination=root/folder;destination.mkdir(mode=0o700)
    with zipfile.ZipFile(root/file) as z:
        infos=z.infolist();seen=set()
        if len(infos)>64 or sum(i.file_size for i in infos)>4194304:raise SystemExit("BOUNDED_PROVENANCE_BUNDLE_REQUIRED")
        for info in infos:
            p=pathlib.PurePosixPath(info.filename)
            if p.is_absolute() or ".." in p.parts or str(p) in seen or stat.S_ISLNK(info.external_attr>>16):raise SystemExit("PROVENANCE_PATH_DENIED")
            seen.add(str(p))
        z.extractall(destination)
PY
OUF_PHASE=VERIFY_PINNED_PUBLISHER_CLIENT
"$OUF_GH" release download v3.1.3 --repo sigstore/cosign --pattern cosign-linux-amd64 --dir "$OUF_DIR"
printf '%s  %s\n' '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71' "$OUF_DIR/cosign-linux-amd64" | sha256sum -c -
chmod 700 "$OUF_DIR/cosign-linux-amd64"
for OUF_FILE in verify_target_publisher.py read_candidate_trust_bytes.py; do
 "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
  "repos/GioNob/ouf-deploy/contents/tools/file_loop_package/$OUF_FILE?ref=bc985d44aa0d0a618fce9ff676d0105093b9e6ab" > "$OUF_DIR/$OUF_FILE"
done
printf '%s  %s\n' \
 '6bd1e3a54728d3339e5218314e28e5d6a80e7029c3dbd63b8589534c9f1d7c05' "$OUF_DIR/verify_target_publisher.py" \
 '6483cd6f98f092a5e5fd7cb36fab9d964438a54fa2b6f5d96762c058b6ef761e' "$OUF_DIR/read_candidate_trust_bytes.py" | sha256sum -c -
OUF_PHASE=VERIFY_EXISTING_ZIP_SIGNATURES_NO_IMAGE_DOWNLOAD
python3 -I -B "$OUF_DIR/verify_target_publisher.py" "$OUF_DIR" | tee "$OUF_DIR/publisher-result.txt"
for OUF_FILE in read_current_r9_transition.py read_cutover_inputs.py; do
 "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
  "repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/$OUF_FILE?ref=b70b1638e1e50776ad68d95198c95adcee75a5ed" > "$OUF_DIR/$OUF_FILE"
done
printf '%s  %s\n' \
 '7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc' "$OUF_DIR/read_current_r9_transition.py" \
 'b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf' "$OUF_DIR/read_cutover_inputs.py" | sha256sum -c -
OUF_PHASE=READ_EXISTING_PUBLIC_TRUST_AND_FAILED_R9_WITHOUT_LOCK_OR_APPLY
sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
paths=sys.argv[1:];expected=("6483cd6f98f092a5e5fd7cb36fab9d964438a54fa2b6f5d96762c058b6ef761e","7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc","b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf")
if len(paths)!=3:raise SystemExit("EXACT_READ_ONLY_SOURCE_TRIPLE_REQUIRED")
sources=[]
for path,digest in zip(paths,expected):
    with pathlib.Path(path).open("rb") as f:raw=f.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=digest:raise SystemExit("READ_ONLY_DELIVERY_HASH_MISMATCH")
    sources.append(raw)
trust={"__name__":"sealed_public_trust_read","__file__":paths[0]}
exec(compile(sources[0],paths[0],"exec"),trust);sys.argv=[paths[0]]
trust_code=trust["main"]()
r9={"__name__":"sealed_r9_diagnostic_read","__file__":paths[1],"__reader_source_bytes__":sources[2]}
exec(compile(sources[1],paths[1],"exec"),r9);sys.argv=[paths[1]]
r9_code=r9["main"]()
raise SystemExit(0 if trust_code==r9_code==0 else 1)
' "$OUF_DIR/read_candidate_trust_bytes.py" "$OUF_DIR/read_current_r9_transition.py" "$OUF_DIR/read_cutover_inputs.py" | tee "$OUF_DIR/result.txt"
)
