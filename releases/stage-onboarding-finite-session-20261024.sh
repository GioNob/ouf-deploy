#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$#" -ne 0 ]; then exit 2; fi
work=$(mktemp -d "$HOME/ouf-onboarding-finite-package.XXXXXXXX")
log="$work/operator.log"
: > "$log"
trap 'rc=$?; trap - EXIT; set +e; printf "\nExit=%s\nDirectory=%s\nLog=%s\n" "$rc" "$work" "$log" | tee -a "$log"; exit "$rc"' EXIT
{
  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$gh_bin" ]; then gh_bin=$(command -v gh || true); fi
  if [ -z "$gh_bin" ] || [ ! -x "$gh_bin" ]; then
    printf '%s\n' 'STOP: client gh esistente assente; nessun sudo eseguito.'
    exit 2
  fi
  /usr/bin/python3 -I -B -S - "$HOME" /etc/ouf/deploy-snapshots <<'PYSPACE'
import shutil,sys
required=3*(210846158+210844914)
if any(shutil.disk_usage(p).free<required for p in sys.argv[1:]):
    raise SystemExit('STOP: spazio libero insufficiente per pacchetto e margine di staging.')
PYSPACE
  "$gh_bin" api --hostname github.com --method GET \
    repos/GioNob/ouf-source-onboarding/actions/artifacts/12553563263/zip > "$work/package.zip"
  printf '%s  %s\n' '9f23ae706ff9f26efa8c72af332c309bd873edca0cb1f3553ab65e33216eca09' "$work/package.zip" | sha256sum -c -
  /usr/bin/python3 -I -B -S - "$work" <<'PYVERIFY'
import hashlib,json,os,sys,zipfile
from pathlib import Path
root=Path(sys.argv[1])
with zipfile.ZipFile(root/'package.zip') as archive:
    if set(archive.namelist())!={'image.tar.gz','manifest.json','SHA256SUMS'}:
        raise SystemExit('STOP: struttura artifact diversa dalla qualifica.')
    raw=archive.read('manifest.json')
    if hashlib.sha256(raw).hexdigest()!='879b3f05c43483f8a2dfeeb5d84c0453d7dbd39ec075e0c0f9ef0a043d65394a':
        raise SystemExit('STOP: manifest diverso dalla qualifica.')
    manifest=json.loads(raw)
    if manifest['reviewedSourceCommit']!='431c601de9b7faa9769b0a210300cd466bf82cfc' or manifest['testedCommit']!='2959efa53f44d0eec353753a4c8bcc5e11f1a89b':
        raise SystemExit('STOP: commit artifact diverso dalla qualifica.')
    if archive.getinfo('image.tar.gz').file_size!=210844914:
        raise SystemExit('STOP: dimensione immagine diversa dalla qualifica.')
    checksum=hashlib.sha256()
    with archive.open('image.tar.gz') as source,(root/'image.tar.gz').open('xb') as target:
        for block in iter(lambda:source.read(1048576),b''):
            checksum.update(block);target.write(block)
        target.flush();os.fsync(target.fileno())
    if checksum.hexdigest()!='ee8b7756f72f82a6b699bafa43cd9cbc4714a828c620df1146668f5bce8583a9':
        raise SystemExit('STOP: immagine diversa dalla qualifica.')
    with (root/'manifest.json').open('xb') as target:
        target.write(raw);target.flush();os.fsync(target.fileno())
    print(json.dumps({'status':'TESTED_PACKAGE_BYTES_VERIFIED','reviewedSourceCommit':manifest['reviewedSourceCommit'],
        'testedCommit':manifest['testedCommit'],'imageId':manifest['imageId'],
        'imageLoaded':False,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0}),flush=True)
PYVERIFY
  sudo -- /bin/bash -c '
    set -euo pipefail
    umask 077
    root=/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6
    mkdir -m 0700 -- "$root"
    chown 0:0 -- "$root"
    install -o 0 -g 0 -m 0400 -- "$1/image.tar.gz" "$root/image.tar.gz"
    install -o 0 -g 0 -m 0400 -- "$1/manifest.json" "$root/manifest.json"
    printf "%s  %s\n" ee8b7756f72f82a6b699bafa43cd9cbc4714a828c620df1146668f5bce8583a9 "$root/image.tar.gz" | sha256sum -c -
    printf "%s  %s\n" 879b3f05c43483f8a2dfeeb5d84c0453d7dbd39ec075e0c0f9ef0a043d65394a "$root/manifest.json" | sha256sum -c -
    printf "{\"status\":\"ONBOARDING_FINITE_SESSION_PACKAGE_STAGED\",\"packagePath\":\"%s\",\"rootProtected\":true,\"imageLoaded\":false,\"databaseMigrations\":0,\"sourceActivations\":0,\"humanBudgetsGranted\":0,\"targetApplyAuthorized\":false,\"releaseAcceptance\":false}\n" "$root"
  ' ouf-onboarding-package "$work"
} 2>&1 | tee "$log"
