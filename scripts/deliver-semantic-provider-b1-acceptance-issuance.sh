#!/usr/bin/env bash
set -euo pipefail
umask 077

# D-001: fill these three pins after review and commit; never infer a moving ref.
commit='__PIN_COMMIT__'
controller_sha='__PIN_CONTROLLER_SHA256__'
signer_sha='__PIN_SIGNER_SHA256__'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ && "$signer_sha" =~ ^[0-9a-f]{64}$ ]]

# The declared closure provenance must be the very commit delivered here.
source_commit=''
seen=0
argv=("$@")
for ((i=0; i<${#argv[@]}; i++)); do
  case "${argv[i]}" in
    --closure-source-commit)
      ((i+=1))
      [[ $i -lt ${#argv[@]} ]]
      source_commit=${argv[i]}; seen=$((seen+1)) ;;
    --closure-source-commit=*)
      source_commit=${argv[i]#*=}; seen=$((seen+1)) ;;
  esac
done
[[ $seen -eq 1 && "$source_commit" == "$commit" ]]

python_sha='889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B -c 'import sys; assert sys.version_info[:2] == (3, 13)'
work=$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-b1-acceptance-source.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_B1_ACCEPTANCE_DELIVERY=%s\n" "$work"' EXIT
sudo mkdir -m 0700 "$work/scripts" "$work/tools" "$work/tools/semantic_b1_acceptance" \
  "$work/tools/semantic_b1b2_authority" "$work/tools/semantic_runtime_v5"

fetch() {
  local path=$1 expected=$2
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$commit/$path" -o "$work/$path"
  sudo chmod 0600 "$work/$path"
  printf '%s  %s\n' "$expected" "$work/$path" | sudo sha256sum --check --status
}

fetch scripts/issue-semantic-provider-b1-acceptance.py "$controller_sha"
fetch tools/semantic_b1b2_authority/signer.py "$signer_sha"
fetch tools/semantic_b1_acceptance/__init__.py b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d
fetch tools/semantic_b1_acceptance/acceptance.py 5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708
fetch tools/semantic_b1b2_authority/__init__.py 19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7
fetch tools/semantic_b1b2_authority/authority.py 04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
fetch tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py 572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255
fetch tools/semantic_runtime_v5/arming_verifier.py c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338

printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/scripts/issue-semantic-provider-b1-acceptance.py" "$@"
