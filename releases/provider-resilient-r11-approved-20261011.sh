#!/usr/bin/env bash
# New one-use R11 lease recovery. Never replays the consumed R10.
set -euo pipefail
umask 077
OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then
  printf "OUF_RESILIENT_R11=EXISTING_GH_NOT_FOUND\n"; exit 1
fi
OUF_APPLY="$(mktemp -d "$HOME/ouf-resilient-r11-apply.XXXXXXXX")"
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/activate_resilient_r11.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/activate.py"
printf '%s  %s\n' '0cf3275fcd959da58a2b320de49b1059159da3da00fca611236e65c8d7136ad9' "$OUF_APPLY/activate.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/activation_core.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/activation_core.py"
printf '%s  %s\n' '06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a' "$OUF_APPLY/activation_core.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/resilient_reader.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/reader.py"
printf '%s  %s\n' 'e4bbbe56e6eb9d890d1d1bc7559e7816f485922d6a058fc6daafd948b8622243' "$OUF_APPLY/reader.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/bounded_recovery.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/bounded_recovery.py"
printf '%s  %s\n' 'ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd' "$OUF_APPLY/bounded_recovery.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/recovery_journal.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/recovery_journal.py"
printf '%s  %s\n' '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d' "$OUF_APPLY/recovery_journal.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/lease_recovery_budget.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/lease_recovery_budget.py"
printf '%s  %s\n' 'c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf' "$OUF_APPLY/lease_recovery_budget.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/resilient_lease_adapter.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/resilient_lease_adapter.py"
printf '%s  %s\n' 'beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683' "$OUF_APPLY/resilient_lease_adapter.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/adaptive_supervisor.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/adaptive_supervisor.py"
printf '%s  %s\n' '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c' "$OUF_APPLY/adaptive_supervisor.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/nft_seconds_backend.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/nft_seconds_backend.py"
printf '%s  %s\n' '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1' "$OUF_APPLY/nft_seconds_backend.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/deadline_backend.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/deadline_backend.py"
printf '%s  %s\n' '9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2' "$OUF_APPLY/deadline_backend.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/continuous_supervisor.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/continuous_supervisor.py"
printf '%s  %s\n' '8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e' "$OUF_APPLY/continuous_supervisor.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/dns.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/dns.py"
printf '%s  %s\n' 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f' "$OUF_APPLY/dns.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/readback_margin_compiler.py?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/readback_margin_compiler.py"
printf '%s  %s\n' '814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d' "$OUF_APPLY/readback_margin_compiler.py" | sha256sum -c -
"$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/tools/semantic_lease_recovery/target_bindings_r11.json?ref=d0048f428bbe5bc499c5d5d5e9c3e407b573f835' > "$OUF_APPLY/target_bindings_r11.json"
printf '%s  %s\n' 'b99440a310d23ede9125936f51a3f8fb75ffcffb9dd2d37390c0b7e28c93e7b4' "$OUF_APPLY/target_bindings_r11.json" | sha256sum -c -
set +e
sudo /usr/bin/python3 -I -B -c '
import hashlib,pathlib,sys
path=sys.argv[1]
raw=pathlib.Path(path).read_bytes()
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!="0cf3275fcd959da58a2b320de49b1059159da3da00fca611236e65c8d7136ad9":
    raise SystemExit("R11_ENTRYPOINT_SOURCE_HASH_MISMATCH")
sys.argv=[path,"--apply","OUF_R10_RESILIENT_RECOVERY_OWNER_REQUEST_20261011T144318_CEST"]
exec(compile(raw,path,"exec"),{"__name__":"__main__","__file__":path,"__verified_source_bytes__":raw})
' "$OUF_APPLY/activate.py" | tee "$OUF_APPLY/result.txt"
OUF_PIPE_STATUS=("${PIPESTATUS[@]}")
OUF_APPLY_EXIT="${OUF_PIPE_STATUS[0]}"
if [ "$OUF_APPLY_EXIT" -eq 0 ] && [ "${OUF_PIPE_STATUS[1]}" -ne 0 ]; then OUF_APPLY_EXIT="${OUF_PIPE_STATUS[1]}"; fi
set -e
printf 'OUF_RESILIENT_R11_APPLY_EXIT=%s PHASE=APPLY_NEW_SOURCE_BOUND_R11_ONCE OUTPUT=%s/result.txt\n' "$OUF_APPLY_EXIT" "$OUF_APPLY"
exit "$OUF_APPLY_EXIT"
