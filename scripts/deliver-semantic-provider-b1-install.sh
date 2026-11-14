#!/usr/bin/env bash
set -euo pipefail
umask 077

# D-001: fill these two pins only after review and commit.
commit='4cf85adadb6fcb41893fd71d8c868400d355c829'
controller_sha='0e5ce618740000700b62189683dda9368f268ff509529ae281cf3d4163c1d3bf'
closure_commit='1cd6ea7c9c1da35a745cfd2c0d3755d99dfc7efd'
[[ "$commit" =~ ^[0-9a-f]{40}$ && "$controller_sha" =~ ^[0-9a-f]{64}$ ]]

python_sha='889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status

# Retain the root-private public-source delivery for review.
work=$(sudo mktemp -d /etc/ouf/deploy-snapshots/semantic-b1-install-source.XXXXXXXX)
sudo chmod 0700 "$work"
trap 'printf "OUF_B1_INSTALL_DELIVERY=%s\n" "$work"' EXIT

fetch() {
  local path=$1 expected=$2 revision=$3
  sudo mkdir -p -m 0700 "$work/$(dirname "$path")"
  sudo curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$revision/$path" -o "$work/$path"
  sudo chmod 0600 "$work/$path"
  printf '%s  %s\n' "$expected" "$work/$path" | sudo sha256sum --check --status
  printf '%s  %s\n' "$expected" "$work/$path" | \
    sudo tee -a "$work/delivery.sha256" >/dev/null
  sudo chmod 0600 "$work/delivery.sha256"
}

fetch scripts/install-semantic-provider-b1.py "$controller_sha" "$commit"
fetch scripts/prepare-semantic-provider-installation.py a19f08678c82472abafa8cb6508245c0f49b39464cdbb7b74222e3cf14967d2c "$commit"
fetch tools/semantic_b1_acceptance/__init__.py b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d "$commit"
fetch tools/semantic_b1_acceptance/acceptance.py 5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708 "$commit"
fetch tools/semantic_b1b2_authority/__init__.py 19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7 "$commit"
fetch tools/semantic_transaction_profiles/guarded_runtime_switch.py 1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd "$commit"
fetch tools/semantic_transaction_profiles/authenticate_provider_transaction.py b47e245abab2bb55ccd172c5e3f8da2a0b167e89c588811159f87cc4d929f258 "$commit"
fetch tools/semantic_transaction_profiles/assemble_provider_profiles.py 890dff15e3826175ef01467a812cdd523e8ea5d50a306ad8727f866475ab9734 "$commit"
fetch tools/semantic_transaction_profiles/publish_provider_transaction.py 7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080 "$commit"
fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py 29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py 53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py 53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py 66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py 98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py 4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587 "$commit"
fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py 7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93 "$commit"
fetch tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py 572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255 "$closure_commit"
fetch tools/semantic_runtime_v5/arming_verifier.py c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338 "$closure_commit"
fetch tools/semantic_b1b2_authority/authority.py 04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728 "$closure_commit"

sudo sha256sum --check --status "$work/delivery.sha256"
printf '%s  %s\n' "$python_sha" /usr/bin/python3.13 | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$work/scripts/install-semantic-provider-b1.py" "$@"
