#!/usr/bin/env bash
# D-049, invocazione umana. Nessuna esecuzione in questa task.
# Uso (binding ricavati come in r3-operate.sh e stampati su stderr; override via env C_*):
#   sudo bash c-probe.sh plan > "$HOME/c-probe-plan.json"
# sudo bash c-probe.sh apply <planSha256> > "$HOME/c-probe-apply.json"
# Conservare i due file e la directory di evidenza; non rigiocare apply.
set -euo pipefail
umask 077
mode=${1:-}
case "$mode" in
  plan) [[ $# == 1 ]] ;;
  apply) [[ $# == 2 && $2 =~ ^[0-9a-f]{64}$ ]] ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac
# Claude fissa il commit dopo review e commit D-001.
C=0b76e76225c5342c5ab1ca9211fb538b0d7bbce7
[[ $C =~ ^[0-9a-f]{40}$ && $C != 0000000000000000000000000000000000000000 ]] || {
  echo 'runbook non ancora fissato a un commit' >&2; exit 2;
}
[[ $EUID == 0 ]] || { echo 'eseguire come root tramite sudo' >&2; exit 2; }
S=/etc/ouf/deploy-snapshots
STATE=${C_PROBE_STATE:-$HOME/.ouf-c-probe-state}
PY=/usr/bin/python3.13
PY_SHA=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
CA=$S/semantic-provider-v2-trust-vf7B4SM5/trust-bundle.pem
CA_SHA=2e3f4bd8bdcefa651718233d2e7e0fb80cadecf69a3ad9deed00e55e85bf8401
DOWNLOAD=0

directory() {
  local p=$1 m
  [[ $p == /* && $p != *'/../'* && $p != *'/./'* ]] || exit 2
  while :; do
    [[ -d $p && ! -L $p && $(stat -c %u "$p") == 0 ]] || exit 2
    m=$(stat -c %a "$p")
    (( (8#$m & 0022) == 0 )) || exit 2
    [[ $p != / ]] || break
    p=$(dirname "$p")
  done
}
file() {
  local p=$1 m
  directory "$(dirname "$p")"
  [[ -f $p && ! -L $p && $(stat -c %u:%g:%h "$p") == 0:0:1 ]] || exit 2
  m=$(stat -c %a "$p")
  (( (8#$m & 0022) == 0 )) || exit 2
}
verify() {
  file "$1"
  printf '%s  %s\n' "$2" "$1" | sha256sum --check --status
}
fetch() {
  local path=$1 expected=$2
  if [[ $DOWNLOAD == 1 ]]; then
    mkdir -p "$D/$(dirname "$path")"  # umask 077: 0700 on every created level
    curl --fail --silent --show-error --max-time 30 --proto '=https' --tlsv1.2 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/$path" -o "$D/$path"
    chmod 0600 "$D/$path"
  fi
  verify "$D/$path" "$expected"
}
delivery() {
  # BEGIN DELIVERY
  fetch ops/vps/r3-settings.json e4040d9428f055362b500cd4d6042ccda117baba48c89d37101988999c923a37
  fetch scripts/install-semantic-provider-r3.py d8c49b543bc73f1ea3b85f41d7196fea3ee614b934f1514d8488fcc8edfa0d76
  fetch scripts/issue-semantic-provider-operation-authorization.py d3d77cf1cfc0073d8ce2072ef1ec77640765db40cc63f35c8b1a1f077e080a58
  fetch scripts/operate-semantic-provider-r3.py f1f1dca6447a2c69d4b7d08fe765cb10012da36e9dc07aff7c224a2db0d76926
  fetch scripts/prepare-semantic-provider-b1-rootfs-v3.py 29899e5ee25aa9e772f21fb62fb473706cdf2b8f921034efeccb3b284d350397
  fetch scripts/prepare-semantic-provider-b1-rootfs.py 8107d055fe0bfd8fe363506f39ffa006f157a292a54bbcbf4de11b011816178d
  fetch scripts/prepare-semantic-provider-installation.py a19f08678c82472abafa8cb6508245c0f49b39464cdbb7b74222e3cf14967d2c
  fetch scripts/probe-semantic-provider-c.py c458d63ce7b7d3507974bb91b901f654d1e5d862a1c9b0a7fba0e0e9fde63e88
  fetch scripts/restore-semantic-provider-r3.py 1be4b6cd69f0c70959627f87502de307488ebca1862928b984b653e290e3fdd8
  fetch scripts/semantic-provider-admission-preparer-v2.py 7e041ddf4e7668861cc5ae111f6069f73eeda32be065622ee51381129a4f9b57
  fetch scripts/semantic-provider-deployment-broker-v2.py 6e97807d5fa010ec7bc670a49533a031dc8f1d5e2472d8569368adfdc15b2d7c
  fetch scripts/semantic-provider-lease-supervisor-v2.py 0311cd4c3515a68530605ee201ccb7cbbc46d5ab989427efd174e6a647826ec5
  fetch scripts/semantic-provider-lease-supervisor-v3.py 3cb4c858935df6538cb1c9934def0f40cc9ea7fc393931aeb38ab63633bbaf8b
  fetch scripts/semantic-provider-preexec-hook-v2.py 834b5b6ae60d0cd37269d2592b31db7dcca2c02639f774a169e030548767df03
  fetch scripts/upgrade-semantic-provider-r3.py d36753cd23b2c993a43e2b6b04062304b575567a13267a1d3247602df5b11639
  fetch tools/semantic_acceptance_v51/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_acceptance_v51/issuance.py d019d4558c529add5fb3a7b052df3d8b92843167d6093f966b0b9b02265a3cd4
  fetch tools/semantic_authority_mandates/mandates.py 86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79
  fetch tools/semantic_b1_acceptance/__init__.py b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d
  fetch tools/semantic_b1_acceptance/acceptance.py 5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708
  fetch tools/semantic_b1b2_authority/__init__.py 19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7
  fetch tools/semantic_b1b2_authority/authority.py 04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py 66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py 98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py 1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py 29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_consumption.py 053e2e5031cd51adf957388296a808cd8ba824dbc2ab671143e756312d050aef
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_producer.py 582371358c769f7724fb76bb17fd5e11530a09ab06c19a3a66351fc77d984776
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py 53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py 7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py 92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py 5a355a9904b6fc4bf665bb79c438e1cb9f3d11f8c2505b16df9834c046fde9c2
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py 4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py 53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797
  fetch tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528
  fetch tools/semantic_frame_compiler/compile_creation_frame_policy.py 36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d
  fetch tools/semantic_frame_compiler/frame-observer-v2.py 59368071f27a27be5d2501bf1128c617102133f5e0e670dc61f7c8a8f697e08a
  fetch tools/semantic_frame_compiler/frame-observer.py 122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc
  fetch tools/semantic_image_rootfs/prepare_provider_image_rootfs.py cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32
  fetch tools/semantic_lease_recovery/activation_core.py 06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a
  fetch tools/semantic_lease_recovery/activation_core_v2.py c8c7a6841b1427f677349a889e6cb4502ce5bb5a28f6a5b65d5e72fbc2ae1aeb
  fetch tools/semantic_lease_recovery/adaptive_supervisor.py 08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c
  fetch tools/semantic_lease_recovery/adaptive_supervisor_v2.py 7a6be86794002e32b79a4c9c4ac0a0913eebe3f5585e9b24dcd62fe5613449ae
  fetch tools/semantic_lease_recovery/bounded_recovery.py ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd
  fetch tools/semantic_lease_recovery/continuous_supervisor.py 8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e
  fetch tools/semantic_lease_recovery/continuous_supervisor_v2.py c68a10ea6d340a29bf27098bd3b36afe4259fd6520898bde1182e4f5aff55c4e
  fetch tools/semantic_lease_recovery/deadline_backend.py 9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2
  fetch tools/semantic_lease_recovery/dns.py f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f
  fetch tools/semantic_lease_recovery/dns_v2.py a0cb8191b0561b76128f5b12851e249d03a1c7d480576c7dbc85f981af01be70
  fetch tools/semantic_lease_recovery/lease_owner_v2.py ad95bd8766caaa644b4475cc092739eb767b047275fffa0f1dcf0756d6c93e6d
  fetch tools/semantic_lease_recovery/lease_recovery_budget.py c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf
  fetch tools/semantic_lease_recovery/nft_seconds_backend.py 04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1
  fetch tools/semantic_lease_recovery/readback_margin_compiler.py 814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d
  fetch tools/semantic_lease_recovery/recovery_journal.py 43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d
  fetch tools/semantic_lease_recovery/resilient_lease_adapter.py beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683
  fetch tools/semantic_lease_recovery/resilient_lease_adapter_v2.py 38e070b3638bf0736d2788f36cac51d3ca922f6878abf2f57b8cdf0bfa65b7eb
  fetch tools/semantic_provider_admission_v2/__init__.py bbae3553c950479a55a26ac71f7a4d79e32f69402967b0b39064cfadd4e41b31
  fetch tools/semantic_provider_admission_v2/broker_v2.py a87d1eda988736e6a8467edd96d343f627a3662acdaed06f539135a34afb1c37
  fetch tools/semantic_provider_admission_v2/consumption_v2.py 44a6ef8de7e7bafd6881104fe148fb984a2acc595685c3095530155bd82c22e4
  fetch tools/semantic_provider_admission_v2/driver_v7.py 27a3b0ec3c4d21a1faec9b15b1e5a5b7526472eddcf35f3462c77bcba8f8af58
  fetch tools/semantic_provider_admission_v2/evidence_v2.py d6f7c659f87705d164c1abdb5589586103abcfebd12bc65f88668130d010d723
  fetch tools/semantic_provider_admission_v2/l2_binding.py 27ecff88f1abe0dc08022770c6dbb2ed030908f2c8c20ed1b78ef5d3215cbaa7
  fetch tools/semantic_provider_admission_v2/locking.py 1a92011a1948ab82498fcc2fc92ee17b7cbf11f1858cbe7edc1dac606de0b564
  fetch tools/semantic_provider_admission_v2/preparer_v2.py c417cd74f4a1712b93e19b145df959ac85d1e42a07484c729cfd18182dd579c7
  fetch tools/semantic_provider_admission_v2/reauthorization_v2.py 53fb58772280116845a47351bdbce802dfd26169175cb36e3e9c11421df6b39c
  fetch tools/semantic_provider_c/probe.py 95cc735a40bb9ee61a948144f24f5bb34845a0aa349044d98216300c00de83c5
  fetch tools/semantic_provider_operation/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_provider_operation/authorization.py 8f5dd2fd86efb7add1bdb5325b6428db41cc539b7b00a3b33efa4d692ab958fc
  fetch tools/semantic_provider_operation/epochs.py b5188406c935079b35f2a81ba670df9578d6ef97a5d7308cbb9cf502a72635bb
  fetch tools/semantic_provider_operation/lease_supervisor.py 71e477e4acaa6a3b49e9d1ff58752d045538426cd415f2edccfd3987a0b7d966
  fetch tools/semantic_provider_operation/lease_supervisor_v2.py 06f7fb2744a1ac3d4b94ef20aa04801e9625f9ca920dfe8fcd421e11456d0de4
  fetch tools/semantic_provider_r3/__init__.py 44f7a91396fbd53e601cc981747063d61ac3c8733fd69595808694d9250a61e6
  fetch tools/semantic_provider_r3/compose.py e577a99329b24d2b814f448d747f59a9ed4846baa02a9044a9d8038df5d45f1e
  fetch tools/semantic_provider_r3/install_common.py 55fd4e7745b290ad36195f07ae6b49d3360c430c8a3a77aee9d02226155e4b33
  fetch tools/semantic_provider_r3/operate.py abd9801a45ac62bc177681228d0c85717e8ea7305ae8da87dbcb9394582e2282
  fetch tools/semantic_provider_r3/upgrade.py 690c22cd19b4781754bb64259b0a3b96e8467fdc00b8694138721782a563ed54
  fetch tools/semantic_provider_r3/volatile_restore.py 8a8ccc3750f241809d35d949a71ec844d2fdc8e9d7c056bb392cfc1a58b3b0f0
  fetch tools/semantic_runtime_v51_install/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_runtime_v51_install/common.py f2351bec00dbb4234b28ce5de79d000600cc1adba95cce4fc1d1a11484aa22bb
  fetch tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py 117c9c86bb173742e4da7051d18bdef68526d3a8172cf231c41a27d2ea815911
  fetch tools/semantic_stopped_rootfs/rootfs_difference_report.py cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115
  fetch tools/semantic_stopped_rootfs/rootfs_image_equivalence.py 5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028
  fetch tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5
  fetch tools/semantic_transaction_profiles/assemble_provider_profiles.py 890dff15e3826175ef01467a812cdd523e8ea5d50a306ad8727f866475ab9734
  fetch tools/semantic_transaction_profiles/authenticate_provider_transaction.py b47e245abab2bb55ccd172c5e3f8da2a0b167e89c588811159f87cc4d929f258
  fetch tools/semantic_transaction_profiles/guarded_runtime_switch.py 1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd
  fetch tools/semantic_transaction_profiles/publish_provider_transaction.py 7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080
  # END DELIVERY
}

directory "$S"
directory "$(dirname "$STATE")"
verify "$PY" "$PY_SHA"
if [[ $mode == plan ]]; then
  [[ ! -e $STATE && ! -L $STATE ]] || { echo 'stato esistente: conservarlo; scegliere C_PROBE_STATE nuovo' >&2; exit 2; }
  # Bindings derived like r3-operate.sh; the probe cross-checks them against the
  # installed R3 acceptance/runtime. Env overrides stay possible for diagnosis.
  OPERATOR_HOME=$(getent passwd "${SUDO_USER:-oufadmin}" | cut -d: -f6)
  if [[ -z ${C_R3_INPUTS:-} ]]; then
    read -r R3D _ < "$OPERATOR_HOME/.ouf-r3-v11-state"
    [[ $R3D =~ ^/etc/ouf/deploy-snapshots/semantic-provider-r3-source\.[A-Za-z0-9]{8}$ ]] || exit 2
    C_R3_INPUTS=$R3D/inputs.json
  fi
  C_INSTALLATION_PROFILE=${C_INSTALLATION_PROFILE:-/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json}
  file "$C_R3_INPUTS"; file "$C_INSTALLATION_PROFILE"
  C_R3_INPUTS_SHA256=${C_R3_INPUTS_SHA256:-$(sha256sum "$C_R3_INPUTS" | cut -d' ' -f1)}
  C_INSTALLATION_PROFILE_SHA256=${C_INSTALLATION_PROFILE_SHA256:-$(sha256sum "$C_INSTALLATION_PROFILE" | cut -d' ' -f1)}
  C_WRAPPER_SHA256=${C_WRAPPER_SHA256:-$(sha256sum /usr/local/sbin/ouf-semantic-admitted-v2 | cut -d' ' -f1)}
  C_SYSTEMCTL_SHA256=${C_SYSTEMCTL_SHA256:-$(sha256sum /usr/bin/systemctl | cut -d' ' -f1)}
  printf 'binding %s %s\n' inputs "$C_R3_INPUTS_SHA256" profile "$C_INSTALLATION_PROFILE_SHA256" \
    wrapper "$C_WRAPPER_SHA256" systemctl "$C_SYSTEMCTL_SHA256" >&2
  D=$(mktemp -d "$S/semantic-provider-c-source.XXXXXXXX")
  DOWNLOAD=1
  delivery
  OUT=$S/semantic-provider-c-probe-$(date -u +%Y%m%dT%H%M%SZ)
  args=(--install-root "${C_INSTALL_ROOT:-$S/semantic-provider-r3-install-v1}"
    --wrapper /usr/local/sbin/ouf-semantic-admitted-v2 --wrapper-sha256 "$C_WRAPPER_SHA256"
    --docker /usr/bin/docker --docker-sha256 7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
    --docker-socket unix:///var/run/docker.sock
    --systemctl /usr/bin/systemctl --systemctl-sha256 "$C_SYSTEMCTL_SHA256"
    --nft /usr/sbin/nft --nft-sha256 57bdb96c8a48844ddd6dd469c267cda951b9a466be93d254c928891ed8c3b7f0
    --inputs "$C_R3_INPUTS" --inputs-sha256 "$C_R3_INPUTS_SHA256"
    --installation-profile "$C_INSTALLATION_PROFILE" --installation-profile-sha256 "$C_INSTALLATION_PROFILE_SHA256"
    --southbound-ca "$CA" --southbound-ca-sha256 "$CA_SHA" --output-directory "$OUT")
  (set -o noclobber; printf '%s\0' "${args[@]}" > "$D/arguments")
  (set -o noclobber; printf '%s\n' "$D" > "$STATE")
else
  file "$STATE"
  read -r D < "$STATE"
  [[ $D =~ ^/etc/ouf/deploy-snapshots/semantic-provider-c-source\.[A-Za-z0-9]{8}$ ]] || exit 2
  directory "$D"
  delivery
  file "$D/arguments"
  mapfile -d '' -t args < "$D/arguments"
fi
if [[ $mode == plan ]]; then
  exec "$PY" -I -B "$D/scripts/probe-semantic-provider-c.py" --plan "${args[@]}"
else
  exec "$PY" -I -B "$D/scripts/probe-semantic-provider-c.py" --apply --plan-sha256 "$2" "${args[@]}"
fi
