#!/usr/bin/env bash
set -euo pipefail
umask 077
OUF_STAGE="$(mktemp -d "$HOME/ouf-file-loop-offline-stage.XXXXXXXX")"
OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
command -v python3 >/dev/null
python3 - "$OUF_STAGE" <<'PY'
import shutil,sys
if shutil.disk_usage(sys.argv[1]).free < 4*1024**3:
    raise SystemExit("FOUR_GIB_FREE_REQUIRED_NO_IMPORT_PERFORMED")
PY
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
 'repos/GioNob/ouf-deploy/contents/scripts/read-file-loop-package-host-metadata.py?ref=c1f6170ccaeb36b90d2d267c76a1abac7d78b09a' > "$OUF_STAGE/read-host.py"
printf '%s  %s\n' '8d2d0d3f3808d7a0d3e6d0c62a6e29126fb2aa0ec061ed7efaa8ab70e3b8084d' "$OUF_STAGE/read-host.py" | sha256sum -c -
"$OUF_GH" api 'repos/GioNob/ouf-deploy/actions/artifacts/11676720102/zip' > "$OUF_STAGE/ingestion.zip"
printf '%s  %s\n' '29a981ddfaed56265ed1061bdf9a59088e87cd0cac46d5844a7fe9255a7d9c32' "$OUF_STAGE/ingestion.zip" | sha256sum -c -
"$OUF_GH" api 'repos/GioNob/ouf-deploy/actions/artifacts/11676625220/zip' > "$OUF_STAGE/udp.zip"
printf '%s  %s\n' '36de53a045bbe94c3cdda80cf6599adfd014c595da1720c817f2aeb586ef14cd' "$OUF_STAGE/udp.zip" | sha256sum -c -
"$OUF_GH" api 'repos/GioNob/ouf-deploy/actions/artifacts/11676412613/zip' > "$OUF_STAGE/semantic.zip"
printf '%s  %s\n' 'a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3' "$OUF_STAGE/semantic.zip" | sha256sum -c -
python3 - "$OUF_STAGE" <<'PY'
import json,pathlib,stat,subprocess,sys,zipfile
root=pathlib.Path(sys.argv[1])
records=[]
for module in ("semantic","ingestion","udp"):
    destination=root/module
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(root/(module+".zip")) as z:
        seen=set()
        for info in z.infolist():
            name=pathlib.PurePosixPath(info.filename)
            mode=info.external_attr>>16
            if name.is_absolute() or ".." in name.parts or str(name) in seen or stat.S_ISLNK(mode):
                raise SystemExit("ARCHIVE_PATH_DENIED")
            seen.add(str(name))
        if sum(i.file_size for i in z.infolist()) > 3*1024**3:
            raise SystemExit("ARCHIVE_BOUND_EXCEEDED")
        z.extractall(destination)
    candidates=list(destination.rglob("package-record.json"))
    if len(candidates)!=1:
        raise SystemExit("EXACT_PACKAGE_RECORD_REQUIRED")
    package=candidates[0].parent
    subprocess.run(["sha256sum","-c","SHA256SUMS"],cwd=package,check=True)
    record=json.loads(candidates[0].read_text())
    if record.get("module")!=module or record.get("targetApplyAuthorized") is not False or record.get("signatureIssued") is not False:
        raise SystemExit("UNSIGNED_STAGING_ONLY_RECORD_REQUIRED")
    records.append({"module":module,"sourceCommit":record["sourceCommit"],"imageId":record["imageId"],
                    "imageScanGate":record["imageScanGate"],"checksumsVerified":True})
print("OUF_FILE_LOOP_OFFLINE_STAGE="+json.dumps({
  "schema":"ouf.file-loop.offline-candidate-stage.v1","status":"UNSIGNED_PACKAGES_STAGED_NOT_IMPORTED",
  "stageDirectory":str(root),"packages":records,"imageImports":0,"containerLifecycleOperations":0,
  "applicationCutoverAuthorized":False,"existingConfigurationWrites":0,"r9Touched":False,
  "privateKeysRead":0,"signaturesIssued":0,"notReleaseAcceptance":True},sort_keys=True))
PY
sudo python3 -B "$OUF_STAGE/read-host.py" | tee "$OUF_STAGE/host-read-result.txt"
printf 'OUF_FILE_LOOP_STAGE_EXIT=0 OUTPUT=%s\n' "$OUF_STAGE"
