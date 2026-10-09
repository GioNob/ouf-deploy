#!/usr/bin/env bash
# Reviewed operator launch in its own shell; fail immediately before root on any failed verification.
trap 'rc=$?; printf "REVIEWED_RECOVERY_EXIT=%s\n" "$rc"' EXIT
  set -euo pipefail
  gh_bin="$(command -v gh || true)"
  if [[ -z "$gh_bin" ]]; then
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  fi
  [[ -x "$gh_bin" ]]
  work="$(mktemp -d "$HOME/ouf-reviewed-recovery.XXXXXXXX")"
  printf 'OUF_RECOVERY_DOWNLOAD=%s\n' "$work"
  "$gh_bin" api repos/GioNob/ouf-deploy/actions/artifacts/11599489979/zip > "$work/evidence.zip"
  printf '%s  %s\n' 'acd592af6d96bcb716ca2f49573fd91d33114b96579b9d2f9ae33ad8af605c72' "$work/evidence.zip" | sha256sum -c -
  /usr/bin/python3.13 -I -B - "$work" <<'OUF_PUBLIC_EVIDENCE'
import hashlib, json, pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
out = root / "evidence"
out.mkdir(mode=0o700)
with zipfile.ZipFile(root / "evidence.zip") as archive:
    items = archive.infolist()
    assert len(items) <= 64 and sum(i.file_size for i in items) <= 134217728
    for item in items:
        assert pathlib.Path(item.filename).name == item.filename and item.file_size <= 67108864
        (out / item.filename).write_bytes(archive.read(item))
receipt = json.loads((out / "readback-receipt.json").read_bytes())
for name, expected in receipt["actualSubjectsVerified"].items():
    assert hashlib.sha256((out / name).read_bytes()).hexdigest() == expected
assert hashlib.sha256((out / "provenance.json").read_bytes()).hexdigest() == "68407fa1d1b3cceaa5f6ec0445b6847e93e3ab728704775a93b1ca6b3245c333"
OUF_PUBLIC_EVIDENCE
  for file in inventory.json database-pin.json adapter.extended.syft.json southbound.extended.syft.json adapter.extended.grype.json southbound.extended.grype.json; do
    "$gh_bin" attestation verify "$work/evidence/$file" --repo GioNob/ouf-semantic-registry --signer-workflow GioNob/ouf-semantic-registry/.github/workflows/provider-unchanged-sbom-refresh.yml --source-digest ab1667d08f80737d63a9be2715036d505cb702c6 --source-ref refs/heads/codex/r4a-smoke-semantic-inventory --deny-self-hosted-runners --bundle "$work/evidence/provenance.json" --format json > "$work/$file.verification.json"
  done
  printf 'OUF_RECOVERY_SIX_SIGNATURES=PASS\n'
  "$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_approved_provider_transaction.py?ref=0a01d31d7bfa892e598df1e4c5e6a8185508b11f' --jq '.content' | base64 --decode > "$work/execute.py"
  printf '%s  %s\n' 'e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4' "$work/execute.py" | sha256sum -c -
  sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_FRESH_DEPENDENCY_ACCEPTANCE_20261009_085303' <<'OUF_VERIFIED_RECOVERY'
import hashlib, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
try:
    raw = os.read(fd, 131073)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != "e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4":
    raise SystemExit("REVIEWED_OPERATOR_HASH_DRIFT")
sys.argv = [sys.argv[1], sys.argv[2]]
exec(compile(raw, sys.argv[0], "exec"), {"__name__": "__main__", "__file__": sys.argv[0]})
OUF_VERIFIED_RECOVERY
