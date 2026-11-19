#!/usr/bin/env bash
# Runbook task-29a: accettazione generazione 3 per la closure del runtime v5.1.
# Uso:  bash acceptance-v51.sh plan               (nessuna lettura di chiavi)
#       bash acceptance-v51.sh apply <planSha256> (firma con la chiave installer)
# L'apply riusa la STESSA consegna del plan (il piano lega i path della consegna).
set -euo pipefail
umask 077

mode=$(printf %s "${1:-}" | tr -d "[:space:]")
hash=$(printf %s "${2:-}" | tr -d "[:space:]")
case "$mode" in
  plan) ;;
  apply) [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "uso: apply <planSha256> (ricevuti ${#hash} caratteri)" >&2; exit 2; } ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

# Claude fills these pins after review and commit (D-001).
C=c25dca54a6a991f5e9f8812f544692952a67c0ce
ISSUED_AT=1794691492
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 && "$ISSUED_AT" -gt 0 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
I=bd65872a40edb7c53acb123ed314c9d30c97b1f568c81133d7576534f60af542
VI=d019d4558c529add5fb3a7b052df3d8b92843167d6093f966b0b9b02265a3cd4
V0=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
BA=5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708
B0=b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d
AA=04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
A0=19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7
R51=8c7a166b299cb602afcfad4ceb6fc474e08cb1125cb00f6b4eb7c16a819c6f88
V51=142bb726001d5f36224dc9b70374df3b86ddda6026b65a06d9917a634dc925c4
MD=86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
ST=/var/lib/ouf-storage-migration
SAVED=$HOME/.ouf-acceptance-v51-delivery
ROOTFS=$ST/semantic-provider-b1-rootfs-20261113-a2/result.json
RECIPES=$S/semantic-provider-b1-recipes-20261114-v2/result.json
RT=tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py
AV=tools/semantic_runtime_v51/arming_verifier_v51.py
MP=tools/semantic_authority_mandates/mandates.py

files() {
  printf '%s  %s\n' \
    "$I" "$1/scripts/issue-semantic-provider-acceptance-v51.py" \
    "$VI" "$1/tools/semantic_acceptance_v51/issuance.py" \
    "$V0" "$1/tools/semantic_acceptance_v51/__init__.py" \
    "$BA" "$1/tools/semantic_b1_acceptance/acceptance.py" \
    "$B0" "$1/tools/semantic_b1_acceptance/__init__.py" \
    "$AA" "$1/tools/semantic_b1b2_authority/authority.py" \
    "$A0" "$1/tools/semantic_b1b2_authority/__init__.py" \
    "$R51" "$1/$RT" \
    "$V51" "$1/$AV" \
    "$MD" "$1/$MP"
}

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
  --generation 3 --issued-at "$ISSUED_AT"
  --closure-source-commit "$C"
  --closure-file "$RT=$R51"
  --closure-file "$AV=$V51"
  --closure-file "$MP=$MD"
  --mandate-root /var/lib/ouf-authority-mandates/b1b2
  --openssl /usr/bin/openssl
  --openssl-sha256 acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549
  --openssl-version 3.5.7
  --output-root "$S"
  --output-name semantic-provider-acceptance-v51-g3
)

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
case "$mode" in
  plan)
    D=$(sudo mktemp -d "$S/semantic-acceptance-v51-source.XXXXXXXX")
    sudo chmod 0700 "$D"
    for f in scripts/issue-semantic-provider-acceptance-v51.py tools/semantic_acceptance_v51/issuance.py \
        tools/semantic_acceptance_v51/__init__.py tools/semantic_b1_acceptance/acceptance.py \
        tools/semantic_b1_acceptance/__init__.py tools/semantic_b1b2_authority/authority.py \
        tools/semantic_b1b2_authority/__init__.py "$RT" "$AV" "$MP"; do
      sudo mkdir -p -m 0700 "$D/$(dirname "$f")"
      sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
        "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$f" -o "$D/$f"
      sudo chmod 0600 "$D/$f"
    done
    files "$D" | sudo sha256sum --check --status
    printf '%s\n' "$D" > "$SAVED"
    echo "consegna salvata per l'apply: $D"
    sudo /usr/bin/python3.13 -I -B "$D/scripts/issue-semantic-provider-acceptance-v51.py" --plan "${args[@]}"
    ;;
  apply)
    D=$(cat "$SAVED")
    [[ $D == $S/semantic-acceptance-v51-source.* ]]
    files "$D" | sudo sha256sum --check --status
    sudo /usr/bin/python3.13 -I -B "$D/scripts/issue-semantic-provider-acceptance-v51.py" \
      --apply --plan-sha256 "$hash" "${args[@]}"
    ;;
esac
