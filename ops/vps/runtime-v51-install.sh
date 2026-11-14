#!/usr/bin/env bash
# Runbook task-29b: runtime v5.1 al posto del v5 di B1 (wrapper switch, tutto INACTIVE).
# Uso:  bash runtime-v51-install.sh plan               (sola lettura, nessuna chiave)
#       bash runtime-v51-install.sh apply <planSha256> (pubblica la root v5.1 e commuta il wrapper)
# L'apply riusa la STESSA consegna del plan, ricontrollata byte per byte.
set -euo pipefail
umask 077

mode=$(printf %s "${1:-}" | tr -d "[:space:]")
hash=$(printf %s "${2:-}" | tr -d "[:space:]")
case "$mode" in
  plan) ;;
  apply) [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo "uso: apply <planSha256> (ricevuti ${#hash} caratteri)" >&2; exit 2; } ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

# Claude fills this pin after review and commit (D-001).
C=0000000000000000000000000000000000000000
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
SAVED=$HOME/.ouf-runtime-v51-install-delivery
D=
DOWNLOAD=0

fetch() {
  local path=$1 expected=$2
  if [[ $DOWNLOAD == 1 ]]; then
    sudo mkdir -p -m 0700 "$D/$(dirname "$path")"
    sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$D/$path"
    sudo chmod 0600 "$D/$path"
  fi
  printf '%s  %s\n' "$expected" "$D/$path" | sudo sha256sum --check --status
}

delivery() {
  # BEGIN DELIVERY
  fetch scripts/install-semantic-runtime-v51.py 5340345fba1507eae2ab97ea82c2b7d0e083f5aea9e9e5931d796b687eee7227
  fetch tools/semantic_runtime_v51_install/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_runtime_v51_install/common.py f2351bec00dbb4234b28ce5de79d000600cc1adba95cce4fc1d1a11484aa22bb
  fetch tools/semantic_b1_acceptance/__init__.py b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d
  fetch tools/semantic_b1_acceptance/acceptance.py 5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708
  fetch tools/semantic_b1b2_authority/__init__.py 19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7
  fetch tools/semantic_b1b2_authority/authority.py 04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
  fetch tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py 8c7a166b299cb602afcfad4ceb6fc474e08cb1125cb00f6b4eb7c16a819c6f88
  fetch tools/semantic_runtime_v51/arming_verifier_v51.py 142bb726001d5f36224dc9b70374df3b86ddda6026b65a06d9917a634dc925c4
  fetch tools/semantic_authority_mandates/mandates.py 86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79
  fetch tools/semantic_transaction_profiles/guarded_runtime_switch.py 1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd
  fetch tools/semantic_transaction_profiles/authenticate_provider_transaction.py b47e245abab2bb55ccd172c5e3f8da2a0b167e89c588811159f87cc4d929f258
  fetch tools/semantic_transaction_profiles/assemble_provider_profiles.py 890dff15e3826175ef01467a812cdd523e8ea5d50a306ad8727f866475ab9734
  fetch tools/semantic_transaction_profiles/publish_provider_transaction.py 7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080
  fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py 29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py 53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py 53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py 66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py 98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py 4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py 7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93
  # END DELIVERY
}

args=(
  --wrapper /usr/local/sbin/ouf-semantic-admitted-v2
  --wrapper-sha256 764c26d5a28c64fa50b376ca0215d2aedede0b3ef26534fbd84f4e58e3162879
  --b1-root "$S/semantic-provider-b1-install-20261114-v1"
  --b1-plan-sha256 e8444689f5e0743acf4fb7b3f54f2acb8ae042a8e44d35ef34f3aa6bb7ef7745
  --acceptance-root "$S/semantic-provider-acceptance-v51-g3"
  --mandate-root /var/lib/ouf-authority-mandates/b1b2
  --lock /run/ouf-semantic-boot-guard/guard.lock
  --docker /usr/bin/docker
  --docker-sha256 7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
  --docker-socket unix:///var/run/docker.sock
  --output-root "$S"
  --output-name semantic-runtime-v51-install-20261114-v1
)

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status
case "$mode" in
  plan)
    D=$(sudo mktemp -d "$S/semantic-runtime-v51-source.XXXXXXXX")
    sudo chmod 0700 "$D"
    DOWNLOAD=1
    delivery
    printf '%s\n' "$D" > "$SAVED"
    echo "consegna salvata per l'apply: $D"
    sudo /usr/bin/python3.13 -I -B "$D/scripts/install-semantic-runtime-v51.py" --plan "${args[@]}"
    ;;
  apply)
    D=$(cat "$SAVED")
    [[ $D == "$S"/semantic-runtime-v51-source.* ]]
    delivery
    sudo /usr/bin/python3.13 -I -B "$D/scripts/install-semantic-runtime-v51.py" \
      --apply --plan-sha256 "$hash" "${args[@]}"
    ;;
esac
