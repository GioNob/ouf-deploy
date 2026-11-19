#!/usr/bin/env bash
# shellcheck disable=SC2034  # the R3 runbooks share one constant block; each uses a subset
# Runbook R3 (task-43): aggiornamento governato alla versione 18 (provider fermo, nessun container avviato).
# Prerequisito: r3-issue-v18.sh apply eseguito (autorizzazione 18 OPERATE).
# Uso:  bash r3-upgrade-v18.sh plan | apply <planSha256>
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
C=4b9e9e34a570f79b171f37f7a7fc3765544d94f1
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
P=889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9
S=/etc/ouf/deploy-snapshots
INSTALL=$S/semantic-provider-r3-install-v1
STATE=$HOME/.ouf-r3-v18-state
NFT_SHA=57bdb96c8a48844ddd6dd469c267cda951b9a466be93d254c928891ed8c3b7f0
TABLES=(adapter=ouf_r3_adapter southbound=ouf_r3_southbound)
PROFILE=$S/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json
PROFILE_SHA=7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18
DOCKER_SHA=7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40
V51_WRAPPER_SHA=e5080250d55dbf59e37c53c8137e8b9fea05bf0625a93e2e61c906ee9641af5d
V51=$S/semantic-runtime-v51-install-20261114-v1
WRAPPER=/usr/local/sbin/ouf-semantic-admitted-v2
LOCK=/run/ouf-semantic-boot-guard/guard.lock
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
  fetch ops/vps/r3-driver-budget.json 2fc0921fd26cdb69adf6ab7dc683b3fea321bb59c5db24db95428d7ac59a1e16
  fetch ops/vps/r3-lease-renewal.json c35a9a6a22da6027ce3c07eccf1a4b8e21d4f697399de5e83ecab1f8340f403f
  fetch ops/vps/r3-settings.json 4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150
  fetch scripts/install-semantic-provider-r3.py d8c49b543bc73f1ea3b85f41d7196fea3ee614b934f1514d8488fcc8edfa0d76
  fetch scripts/issue-semantic-provider-operation-authorization.py e5f14e218efdc73fa9a592ef6dd9a2f7fafeb997ed22c785bc72951c82080197
  fetch scripts/migrate-semantic-lease-kernel.py 7143499813c70c936e0c2792b2e19d44a3cd32cac072fd5b82312ae4dd923901
  fetch scripts/operate-semantic-provider-r3.py f1f1dca6447a2c69d4b7d08fe765cb10012da36e9dc07aff7c224a2db0d76926
  fetch scripts/prepare-semantic-provider-b1-rootfs-v3.py 29899e5ee25aa9e772f21fb62fb473706cdf2b8f921034efeccb3b284d350397
  fetch scripts/prepare-semantic-provider-b1-rootfs.py 8107d055fe0bfd8fe363506f39ffa006f157a292a54bbcbf4de11b011816178d
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
  fetch tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel_v2.py 5144360babceb42530f252efef66a0b9d1f682d4d5a6763c07b567ed661b1da6
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
  fetch tools/semantic_lease_kernel_migration/__init__.py f28e340dc4cbae36c07010190190d5a8479e5fef730965ba1c2b33dd36ad2496
  fetch tools/semantic_lease_kernel_migration/boot_dispatcher.py 6524076bbfeb54546df2ccb2e5b1d3ac051b919c8f75200b70dde1d958a9aa9b
  fetch tools/semantic_lease_kernel_migration/boot_runner_v2.py e6f968e939842fcf71c6b1632886eeb377df9b1ce57f390293b4bb34c1afe713
  fetch tools/semantic_lease_kernel_migration/cli.py 6ef7827768ecb52fcd542a403c50f1d3b19cfc6e847bbe8af0da4ac5d86cd67d
  fetch tools/semantic_lease_kernel_migration/migration.py cbcd08ac71d0221f60530125b52861e5a23a37896116c3224576b883ced45464
  fetch tools/semantic_lease_kernel_migration/native.py 1ab1a3568227f604f4d4c87a8aae8bb88476e96edfba8e0269846762cf622a22
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
  fetch tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py b40430dc2523afca8d4781590e20724013c936f32e1e5d7ab71483e5d52b1c62
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
  fetch tools/semantic_provider_config/contract.py 056a97bd7d9f4e506c9200f232fa95a44b766ee7fa628444bb3816018b676e15
  fetch tools/semantic_provider_operation/__init__.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  fetch tools/semantic_provider_operation/authorization.py 8f5dd2fd86efb7add1bdb5325b6428db41cc539b7b00a3b33efa4d692ab958fc
  fetch tools/semantic_provider_operation/epochs.py b5188406c935079b35f2a81ba670df9578d6ef97a5d7308cbb9cf502a72635bb
  fetch tools/semantic_provider_operation/lease_supervisor.py 71e477e4acaa6a3b49e9d1ff58752d045538426cd415f2edccfd3987a0b7d966
  fetch tools/semantic_provider_operation/lease_supervisor_v2.py 06f7fb2744a1ac3d4b94ef20aa04801e9625f9ca920dfe8fcd421e11456d0de4
  fetch tools/semantic_provider_operation/supersede_gate.py d27e874ceef9e2a1f34f2543d4f79dcdd5b76bdf4db72c10156bc33665cc0ef5
  fetch tools/semantic_provider_r3/__init__.py 44f7a91396fbd53e601cc981747063d61ac3c8733fd69595808694d9250a61e6
  fetch tools/semantic_provider_r3/adapter_v16.py 1af794ea243bfa1d2caa8cfa702017bd5a378c49d27e6c753f52ab4f1890825a
  fetch tools/semantic_provider_r3/compose.py 7de0c12495184cec2e08494234fc9f0637c84cd3f6ba6747b9b4b079957e9b2f
  fetch tools/semantic_provider_r3/driver_budget_v17.py 086b695267ac94ce50053fe1c8f6c8bcec6f702d36e6d350fe74c319741a4f02
  fetch tools/semantic_provider_r3/driver_denial_overlay_v16.py cc2393eb2bea4b299cd8b0a8cdecb7b6e67b8c83f7e8d3d15bd09d915e3b2009
  fetch tools/semantic_provider_r3/egress_v15.py 03552b9750a551fb227917ac5756667995362e3f9e9acbaf91d717ded4422f82
  fetch tools/semantic_provider_r3/identity_overlay_v13.py 0334b8a3387e3a9342b3ff6f2679f9ddd179cee67c5085ef9d3e4751bd82e131
  fetch tools/semantic_provider_r3/identity_provider_v13.py 3bdcf7688ffac5c485abfc5893a3f6a3ff5777aab136138ee7488e3a2bd747bf
  fetch tools/semantic_provider_r3/install_common.py f06476342095d0e9590df66ca16b1718d58ea0dbdcb3c767242f58124720d781
  fetch tools/semantic_provider_r3/lease_observability_overlay_v18.py f75e72ff00d395aa6f7370760e58cbb6fd75089091db6cae5149b98f8a11e33c
  fetch tools/semantic_provider_r3/lease_renewal_overlay_v18.py dd2c600df369f8dc6c595d3e65ff739abeced198a3cf3f547aaaadf27f19889a
  fetch tools/semantic_provider_r3/lease_renewal_v18.py c6fefa170903a92bcb706a061c91a3bfd5af560b51447f08dd0ac3135a5a7ecd
  fetch tools/semantic_provider_r3/operate.py f0bd132c86d0bebb185a7f473c9abae4819fc47e2cf5284ccc2cfbdad255d885
  fetch tools/semantic_provider_r3/read_adapter_v16.py 66b1dd83d4543e4454036489ff64433d16a9a30bb63127b4310431271064de77
  fetch tools/semantic_provider_r3/read_identity_provider_v13.py 7aa1a9067f59d1fb15341d6567bd88af8eac4bbd0b027df6751235190297d4e7
  fetch tools/semantic_provider_r3/read_routes_v15.py e3e62ea885e0a54fb74de591e49891d1b209fae7756296ad74ae2a958506390e
  fetch tools/semantic_provider_r3/runtime_absent_overlay_v19.py 81e9da05d14906ebbf8efe4c9adec66987177f4adb357f9ad6e9b93b48c46bf9
  fetch tools/semantic_provider_r3/upgrade.py bc18eee17996d2cb0533d132ec40789c43244187d2edb2d2ca59f48ff850c754
  fetch tools/semantic_provider_r3/volatile_restore.py 8a8ccc3750f241809d35d949a71ec844d2fdc8e9d7c056bb392cfc1a58b3b0f0
  fetch tools/semantic_provider_routes/custody.py 2ab7177f21fb5b330473895798c141282cdabc85c245142f96511fa13e848db3
  fetch tools/semantic_provider_routes/routes.py 305f2535e2cc547de5f242080247d62a43b4bdb93303bf00a03bb36e87097997
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

saved_state() {
  [[ -f $STATE ]] || { echo "stato dell'emissione assente: eseguire prima r3-issue.sh plan" >&2; exit 2; }
  read -r D ISSUED_AT < "$STATE"
  [[ $D == "$S"/semantic-provider-r3-source.* && $ISSUED_AT =~ ^[0-9]+$ ]] \
    || { echo 'stato dell emissione non valido' >&2; exit 2; }
  delivery
}

# Builds $D/inputs.json (canonical, root 0600) from the delivered settings and the VPS
# inputs; known inputs are checked against their pinned hashes before use.
inputs() {
  INPUTS_SHA=$(sudo /usr/bin/python3.13 -I -B - "$D" <<'PY'
import hashlib, json, pathlib, sys
D = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(D))
from tools.semantic_provider_r3 import compose as C
S, M = "/etc/ouf/deploy-snapshots", "/var/lib/ouf-storage-migration"
CO = S + "/discovery-coordinator-successor-20261109-uz9gw5ny"
A2 = M + "/semantic-provider-preparation-a2-20261113"
REC = S + "/semantic-provider-b1-recipes-20261114-v2"
REG = S + "/semantic-provider-v2-transaction-mf9x0eqd/registry"
OLD = {"adapter": "f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67",
       "southbound": "1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916"}
files = {"settings": str(D / "ops/vps/r3-settings.json"),
         "coordinator": CO + "/coordinated-configuration.json",
         "coordinationJournal": CO + "/coordination-journal.json",
         "a2Manifest": A2 + "/manifest.json", "successors": A2 + "/successors.json",
         "semanticPeer": A2 + "/semantic-peer.json",
         "rootfs": M + "/semantic-provider-b1-rootfs-20261116-mountpoint-0711/result.json",
         "acceptance": S + "/semantic-provider-acceptance-v51-g5/manifest.json"}
for role in ("adapter", "southbound"):
    files[role + "/historicalTemplate"] = REG + "/" + OLD[role] + "/preparer-template.json"
    for part in ("template", "launch", "context", "policy"):
        files[role + "/" + part] = REC + "/" + role + "/" + part + ".json"
PINS = {"coordinator": "5deb74791d7d3e20b1f91285320a5d48a15b7d99af2d14f03c063bdd970dd8df",
        "a2Manifest": "817e178b8615766569a4278a3288a4774fc940217667eeeb79b97fa09440f777",
        "successors": "394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb",
        "rootfs": "49a82a05f7f935e63b76cfacdda742f928c112a1de2a61353436ef1cdac3f2b8",
        "acceptance": "a7c394bce12ffa6f0114401e83cee434f47532c9db4be99c49e29739b1eac320",
        "adapter/historicalTemplate": "0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53",
        "southbound/historicalTemplate": "7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894",
        "adapter/template": "b5b7c915588c29141f77cab2526cf65d601a3c2f03fe5c0813db6673eb3d3067",
        "adapter/launch": "061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943",
        "adapter/context": "d6a76226bc5626ad4e5bcf87c21005063caaca41b747a4ae074511e8d4037b99",
        "adapter/policy": "42677046162cf340080c4062321be2c5881fbe0ef299b869ce812569c8a634f3",
        "southbound/template": "02e6d4253b36c2744aec542d831d62929210d691c2848868e9a78c8309531f05",
        "southbound/launch": "f066a65cffc7766bbf77b9de15fe9d527ce8ca68a9bb0d74cadfe8370c6ad63b",
        "southbound/context": "18a1df8d45fbe0914514478910041d3a49ecf402b8c78a06c8148cf95c06a1c9",
        "southbound/policy": "e489068bc8a86f226dadfa5a3870dc05aaae65437d638a8b9ce56c4c42e218a8"}
if 18 >= 12:
    # D-050: v12 composes on the generation-2 lease kernel published by the migration.
    G2 = "/etc/ouf/lease-kernel-generations/g2-20261117T122656"
    MIG = S + "/semantic-lease-kernel-migration-20261117T122656"
    files.update(coordinator=G2 + "/coordinated-configuration.json",
                 coordinationJournal=G2 + "/coordination-journal.json",
                 migrationPlan=MIG + "/plan.json", migrationReceipt=MIG + "/receipt.json",
                 generationReceipt=G2 + "/generation-receipt.json",
                 bootPointer="/etc/ouf/coordinated-boot-installation.json")
    PINS.update(coordinator="899f39c193b88017b88931dcd9713ed80d7f63b87594c2cd00636a695e06b02f",
                migrationPlan="65a825ac859d81e4ebed4a3f791141a3154a5db1703db6edf4809194a917adaf",
                migrationReceipt="a3456dfb839001657922e5aed892180cb9347b35e9e765c2a38fb8489a6d534b",
                generationReceipt="0233576fd023ce6f6afe62f040bfaec1d5a3103035c4b7c4b5657eb81082cca8",
                bootPointer="2c532ae900128e423c33addee66f5536078d7ce2589237601d6b963bd35bbd42")
    if 18 >= 13:
        # D-051: identity provider peer read at plan time into the delivery (verified by the composer).
        files["identityProviderPeer"] = str(D / "identity-provider-peer.json")
        if 18 >= 15:
            # D-052: B1 recipes v3, acceptance g6 and the routes projection read at plan time.
            REC3 = S + "/semantic-provider-b1-recipes-20261118-v3"
            for role in ("adapter", "southbound"):
                for part in ("template", "launch", "context", "policy"):
                    files[role + "/" + part] = REC3 + "/" + role + "/" + part + ".json"
            files["acceptance"] = S + "/semantic-provider-acceptance-v51-g6/manifest.json"
            files["southbound/routesProjection"] = str(D / "routes-projection.json")
            PINS.update({"southbound/launch": "28a50731e885c58e3df1c765b686c4699a102e64564f48d7c66a07020a975945",
                         "southbound/policy": "9109fd88221b25386f68c27327eada4dc392eb0d6c3d426447849ed2c4265a51",
                         "acceptance": "78954515c36921d7321120a2e7e0bf2cb690eeb7f852b913fb3afea5ddf242c9"})
            if 18 >= 16:
                # D-053: B1 v4 recipes, acceptance g7, revised installation profile, adapter projection.
                REC4 = S + "/semantic-provider-b1-recipes-v4"
                for role in ("adapter", "southbound"):
                    for part in ("template", "launch", "context", "policy"):
                        files[role + "/" + part] = REC4 + "/" + role + "/" + part + ".json"
                files["acceptance"] = S + "/semantic-provider-acceptance-v51-g7/manifest.json"
                files["installationProfile"] = "/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json"
                files["adapter/configProjection"] = str(D / "adapter-projection.json")
                PINS.update({"adapter/launch": "307e366ec63abf5dc400b22e5d90110cd5433245d69254505de5db45cdbfb182",
                             "adapter/policy": "6ed79d6e0cfdda7079a7f5417cbcb269388f613a238856c76d4c913a14200f50",
                             "acceptance": "8dcbb865056cf86ff443772653d8daf346ce04520272add747c7cbda83626752",
                             "installationProfile": "b7ca10e139d91e564c313eb226953db6d384e95283c31c13f7091fa40ffbb160"})
                if 18 >= 17:
                    # R-030: driver verification budget as an installation input (delivered, pinned).
                    files["driverBudget"] = str(D / "ops/vps/r3-driver-budget.json")
                    PINS["driverBudget"] = "2fc0921fd26cdb69adf6ab7dc683b3fea321bb59c5db24db95428d7ac59a1e16"
                    if 18 >= 18:
                        # R-022: lease renewal/recovery parameters as an installation input (delivered, pinned).
                        files["leaseRenewal"] = str(D / "ops/vps/r3-lease-renewal.json")
                        PINS["leaseRenewal"] = "c35a9a6a22da6027ce3c07eccf1a4b8e21d4f697399de5e83ecab1f8340f403f"
                        assert set(files) == (C.DATA_INPUTS_V19 if 18 >= 19 else C.DATA_INPUTS_V18), "R3_INPUT_SET_DRIFT"
                    else:
                        assert set(files) == C.DATA_INPUTS_V17, "R3_INPUT_SET_DRIFT"
                else:
                    assert set(files) == C.DATA_INPUTS_V16, "R3_INPUT_SET_DRIFT"
            else:
                assert set(files) == C.DATA_INPUTS_V15, "R3_INPUT_SET_DRIFT"
        else:
            assert set(files) == C.DATA_INPUTS_V13, "R3_INPUT_SET_DRIFT"
    else:
        assert set(files) == C.DATA_INPUTS_V12, "R3_INPUT_SET_DRIFT"
else:
    assert set(files) == C.DATA_INPUTS, "R3_INPUT_SET_DRIFT"
def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
bound = {}
for name, path in sorted(files.items()):
    digest = sha(path)
    if name in PINS and PINS[name] != digest:
        sys.stderr.write("R3_INPUT_PIN_MISMATCH " + name + "\n"); raise SystemExit(3)
    bound[name] = {"path": path, "sha256": digest}
SOURCE_SET = (C.SOURCE_INPUTS_V19 if 18 >= 19 else C.SOURCE_INPUTS_V18 if 18 >= 18 else C.SOURCE_INPUTS_V17 if 18 >= 17 else C.SOURCE_INPUTS_V16 if 18 >= 16 else C.SOURCE_INPUTS_V15 if 18 >= 15 else C.SOURCE_INPUTS_V13 if 18 >= 13 else C.SOURCE_INPUTS_V12 if 18 >= 12 else C.SOURCE_INPUTS_V11 if 18 >= 11
              else C.SOURCE_INPUTS_V6 if 18 >= 6 else C.SOURCE_INPUTS)
sources = {p: {"path": str(D / p), "sha256": sha(D / p)} for p in sorted(SOURCE_SET)}
raw = json.dumps({"schema": "ouf.semantic-provider-r3-inputs.v1", "files": bound, "sources": sources},
                 sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
target = D / "inputs.json"
if target.exists() and target.read_bytes() != raw:
    sys.stderr.write("R3_INPUTS_CHANGED_SINCE_PLAN\n"); raise SystemExit(3)
target.write_bytes(raw); target.chmod(0o600)
print(hashlib.sha256(raw).hexdigest())
PY
)
}

printf '%s  %s\n' "$P" /usr/bin/python3.13 | sudo sha256sum --check --status

saved_state
inputs
CURRENT_SHA=$(sudo sha256sum "$WRAPPER" | cut -d' ' -f1)
SYSTEMCTL_SHA=$(sha256sum /usr/bin/systemctl | cut -d' ' -f1)
echo "wrapper attuale: $CURRENT_SHA"
echo "systemctl: $SYSTEMCTL_SHA"
args=(
  --install-root "$INSTALL"
  --wrapper "$WRAPPER" --current-wrapper-sha256 "$CURRENT_SHA"
  --lock "$LOCK"
  --docker /usr/bin/docker --docker-sha256 "$DOCKER_SHA" --docker-socket unix:///var/run/docker.sock
  --systemctl /usr/bin/systemctl --systemctl-sha256 "$SYSTEMCTL_SHA"
  --output-directory "$S/semantic-provider-r3-upgrade-v18"
  --inputs "$D/inputs.json" --inputs-sha256 "$INPUTS_SHA"
  --issued-at "$ISSUED_AT"
  --table-name "${TABLES[@]}"
)
if [[ $mode == plan ]]; then
  sudo /usr/bin/python3.13 -I -B "$D/scripts/upgrade-semantic-provider-r3.py" --plan "${args[@]}"
else
  sudo /usr/bin/python3.13 -I -B "$D/scripts/upgrade-semantic-provider-r3.py" --apply --plan-sha256 "$hash" "${args[@]}"
fi
