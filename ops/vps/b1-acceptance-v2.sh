#!/usr/bin/env bash
# Runbook D-027: accettazione B1 generazione 2 (ricette v2).
# Uso:  bash b1-acceptance-v2.sh plan              (nessuna lettura di chiavi)
#       bash b1-acceptance-v2.sh apply <planSha256> (firma con la chiave installer)
# L'apply riusa la STESSA consegna del plan (il piano lega i path della consegna).
set -euo pipefail
umask 077

C=e111c5cb5a8a1db114fe955a4f77596d954e7c99
L=fa2aae44ec32473225495ac1a520d5cde6e3cbd9f578ca9dc4a6b6937569426d
S=/etc/ouf/deploy-snapshots
ST=/var/lib/ouf-storage-migration
SAVED=$HOME/.ouf-b1-acceptance-v2-delivery
ROOTFS=$ST/semantic-provider-b1-rootfs-20261113-a2/result.json
RECIPES=$S/semantic-provider-b1-recipes-20261114-v2/result.json
ISSUED_AT=1794672600

rootfs_sha=$(sudo sha256sum -- "$ROOTFS" | cut -c1-64)
recipes_sha=$(sudo sha256sum -- "$RECIPES" | cut -c1-64)
echo "rootfs-result=$rootfs_sha recipes-result=$recipes_sha"
[[ $rootfs_sha == 0a542c899013a657415c838ad0856a6c4ba14a54504e4eba324a6472f6f4cbda ]]

args=(
  --installation-profile /etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json
  --installation-profile-sha256 5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d
  --trust-policy "$S/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json"
  --trust-policy-sha256 6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95
  --authority-profile "$S/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json"
  --authority-profile-sha256 7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18
  --a2-root "$ST/semantic-provider-preparation-a2-20261113"
  --a2-plan-sha256 a435f29bd107fbb61d4f5d3ca594e42d2851a82beadeafb1aef13bcbe997cad2
  --a2-successors-sha256 394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
  --recreation-receipt "$S/southbound-recreate-20261113-d022-v1/result.json"
  --recreation-receipt-sha256 56528cb24df9ce1d48f18ee67ac8105d308db8ee1602dd604a9573b08b22b79c
  --rootfs-result "$ROOTFS" --rootfs-result-sha256 "$rootfs_sha"
  --recipes-result "$RECIPES" --recipes-result-sha256 "$recipes_sha"
  --adapter-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --southbound-transaction 864a28dbbd5ccc402f9406e500359123
  --declared-gap ADAPTER_CREATION_PLAN_DIGEST_RECONSTRUCTED
  --declared-gap ADAPTER_CREATION_RECEIPT_NOT_RETAINED
  --generation 2 --issued-at "$ISSUED_AT"
  --closure-source-commit 1cd6ea7c9c1da35a745cfd2c0d3755d99dfc7efd
  --closure-file tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py=572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255
  --closure-file tools/semantic_runtime_v5/arming_verifier.py=c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338
  --closure-file tools/semantic_b1b2_authority/authority.py=04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
  --openssl /usr/bin/openssl
  --openssl-sha256 acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549
  --openssl-version 3.5.7
  --output-root "$S"
  --output-name semantic-provider-b1-acceptance-20261114-v2
)

case "${1:-}" in
  plan)
    work=$(mktemp -d)
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 -o "$work/deliver.sh" \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/deliver-semantic-provider-b1-acceptance-issuance.sh"
    printf '%s  %s\n' "$L" "$work/deliver.sh" | sha256sum --check
    out=$(bash "$work/deliver.sh" --plan "${args[@]}") || { printf '%s\n' "$out"; exit 1; }
    printf '%s\n' "$out"
    printf '%s\n' "$out" | sed -n 's/^OUF_B1_ACCEPTANCE_DELIVERY=//p' > "$SAVED"
    echo "consegna salvata per l'apply: $(cat "$SAVED")"
    ;;
  apply)
    [[ "${2:-}" =~ ^[0-9a-f]{64}$ ]] || { echo 'uso: apply <planSha256>' >&2; exit 2; }
    D=$(cat "$SAVED")
    [[ $D == $S/semantic-b1-acceptance-source.* ]]
    printf '%s  %s\n' \
      f054e92e4b4ebca0f62fec7a94014b445de08bb74331c1623f0ea949537f81c6 "$D/scripts/issue-semantic-provider-b1-acceptance.py" \
      84c3fb7a1986f1608481b9906f3794214311f8db875f04211f1b863e3c17306f "$D/tools/semantic_b1b2_authority/signer.py" \
      19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7 "$D/tools/semantic_b1b2_authority/__init__.py" \
      04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728 "$D/tools/semantic_b1b2_authority/authority.py" \
      b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d "$D/tools/semantic_b1_acceptance/__init__.py" \
      5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708 "$D/tools/semantic_b1_acceptance/acceptance.py" \
      572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255 "$D/tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py" \
      c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338 "$D/tools/semantic_runtime_v5/arming_verifier.py" \
      889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9 /usr/bin/python3.13 \
      | sudo sha256sum --check
    sudo /usr/bin/python3.13 -I -B "$D/scripts/issue-semantic-provider-b1-acceptance.py" \
      --apply --plan-sha256 "$2" "${args[@]}"
    ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac
