#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo "Client GitHub non disponibile." >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-linked-property-update.XXXXXXXX")"
echo 'Policy generiche: riutilizzo UDP e Onboarding gia preparati. Nessun download immagini o nuovo worker. Tecniche8/8; funzionali2/6.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/execute-linked-property-update-20261017.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/execute.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/runtime.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/runtime.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/linked-property-update-selection-20261017.json?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/case.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/iam_binding_candidate.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/migration_root_custody.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/migration_root_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/continued_owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/continued_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/review.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/review.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/human_session.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/human_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/gateway.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/installed_owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/installed_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/supervisor.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/supervisor.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/permit.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_permit.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/session.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/mcp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/readiness_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/readiness_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/readiness_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/readiness_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/readiness_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/audit_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/audit_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/audit_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/audit_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/preparation.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/audit_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/resolution_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/resolution_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/resolution_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/resolution_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/resolution_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/config_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/config_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/config_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/config_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/config_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/udp_resolution_update/preparation.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/udp_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_comparison_update/preparation.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/comparison_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/entry.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/authority.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/owner.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/native.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/plan.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/preparation.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/database.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_database.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/configuration.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_configuration.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/linked_property_rollout/login.py?ref=5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981' --jq .content | base64 --decode > "$ouf_stage/linked_login.py"
cat > "$ouf_stage/package.json" <<'PACKAGE'
{"caseSha256":"30c65c1d7d254f703cccc3984a1fc03707010682719b68c12e1f973437653499","executorSha256":"7ffb2b5bcd6037823066fc9631b715d64718e234dd9ba4532ad556fd40dacae5","loaderSha256":"9aef02f411bba5a8faa796cd6a7caad40e571ef3f19cb3e81c39c4757f8e8327","runtimeAuthorityIssued":false,"schema":"ouf.linked-property-update-code-package.v1","sourceCommit":"5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981","sourceHashes":{"iam_binding_candidate":"dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b","image_custody":"9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2","migration_root_custody":"1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2","tools.chatbot_file_cohort.continued_owner":"1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df","tools.chatbot_file_cohort.gateway":"5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f","tools.chatbot_file_cohort.human_session":"2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285","tools.chatbot_file_cohort.review":"fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432","tools.ingestion_readiness_update.authority":"94d4718ed9091de55cf9cd67fc7ecc2265a9db822e5c367e55c4c252773a494c","tools.ingestion_readiness_update.entry":"2be394b68e5b5e4cf004814aaa020f5139496e161609ad6d9341c5849f5d5696","tools.ingestion_readiness_update.native":"cad037ac7a936983d76fde4fb42e11de6ff41be06d6ad430c9165b5320f23523","tools.ingestion_readiness_update.owner":"4ec7b297bc5154dad2426a7cc7fcc09379c0d36404bcf97c68be825a2b7ab560","tools.ingestion_readiness_update.plan":"f6ab1ae11208cc058aff861ce918db1a246056540b1f6ebe9cbc4983e565ec6c","tools.linked_property_rollout.authority":"5a6f89909e3a4ab2aff37a8c5c8c6e137703adf03f7126160f6fd299f883f1b3","tools.linked_property_rollout.configuration":"3e4535bdd546f5cfdc658086f0a4cbbbc15458a995b7d818c41115f7cad58016","tools.linked_property_rollout.database":"11050accc82b8bbbe5e2005dcea755d7f79fef1e46c016eec618fafbeaa8354b","tools.linked_property_rollout.entry":"aa49958b7b5253f401a192cde758b101a69a3dc351a95673e0b705194e30d1c9","tools.linked_property_rollout.login":"7691b1cbdd811a4b0c67e0a8355c4f737d96f71cdc880b2dd2194e2da0cee25e","tools.linked_property_rollout.native":"9db2d99347511d76f96b7e16039db2ec51dc73b93c1febebaeeca2f64221bce5","tools.linked_property_rollout.owner":"80535c7be030fa8a72f0045aa14ca19f636aa4f18c2b55577b48c6116203c5a0","tools.linked_property_rollout.plan":"1aebda8716a997cd63b3f592bf17cad87399f5886a5553b4d6c2264b08413706","tools.linked_property_rollout.preparation":"b7f20e03d3df60023e8f382c4fef7edb2b82f1182ed49812e740f82f5bc84cbc","tools.onboarding_audit_update.authority":"49d70354934ce3eb2ccb57eeec457247da5a3c78b3787d2bf3c0bb6c7aeab641","tools.onboarding_audit_update.entry":"e54f5306be8a5d072cffe1cdc5a956d879d95c52636ef42ac243ef586c8d1485","tools.onboarding_audit_update.native":"51da1138b5f3bea28bae0fde42dfb619095924516ba0cd5e6a73f0cb75d394e3","tools.onboarding_audit_update.owner":"3e026425a90e30c782a32ea0bd202595e43fdc1b68b6145bb5797d010950c204","tools.onboarding_audit_update.preparation":"ab2d9b62473e81bb58ff4e2f4a5e999b0d092abb2bd8031a9bd7a760bef61e22","tools.resolution_comparison_update.authority":"38f6fcf5839bf41569d3eb017341a428647bcf8ee140bfecc316b4f6c1ebd975","tools.resolution_comparison_update.entry":"5f75bd1093dc411c98356bad8784f01c72e43df05b04b48bab6ec507c6bd555d","tools.resolution_comparison_update.native":"8caf9d0d2a7e884b4e1dd0942a3867c9a1f513e0e00befa4c1f97397bcb20a29","tools.resolution_comparison_update.owner":"525121cd5f4f727b8cac655694a13a3f5cd76c268334d1db3183890ed393c1fd","tools.resolution_comparison_update.plan":"4134ce4f901088715db566c1fbe824b185ad1e04659db3c28cf06534b3a244ef","tools.resolution_comparison_update.preparation":"6708ce1dfbdda8b33cd4bab40b9832f5c7b070ca6bba3e1f15cac0b41426ac55","tools.resolution_ths_configuration.authority":"6b3b59e9020271587fd087d29085e380833bf0f479744aaacdd9f037713b735a","tools.resolution_ths_configuration.entry":"e621fb8960f411427ed3dc8cdebb6163b6068181f7220211740974381016e1b2","tools.resolution_ths_configuration.native":"e39a4771b02f59ddf572d5aca47a8e952ad9cc157e65badbd37abeab2cca4df8","tools.resolution_ths_configuration.owner":"c731071f3b8eb5563258726aabd57df7c280b4607c526b8ac4d9a83f8a29b6de","tools.resolution_ths_configuration.plan":"bd2d61480e4aede630c4b4850f3253c5424f373d7991613a1a77fecfbfb82d1c","tools.resolution_ths_update.authority":"07e9f0f032cdd4b556e7dc3490e8cb2431ab9cda5bcb53ad9b819607ad343232","tools.resolution_ths_update.entry":"ac2e3588af924489712f8f9eaf45471207c6c2b60eb4b94e8464f0842a7bb0de","tools.resolution_ths_update.native":"156440a6d9f706b2e810f1807c374c32cc08fcbd26c98327957604b35c545f75","tools.resolution_ths_update.owner":"02e3bf3f1510c6df79dc87f9d9be1b51ee027f9f4c868d506e4b303b5592550d","tools.resolution_ths_update.plan":"c1513e10d22393581a9c672700bfb63333b74aad24db886f994c009782abee1e","tools.semantic_mcp_update.authority":"36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54","tools.semantic_mcp_update.entry":"0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16","tools.semantic_mcp_update.native":"7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a","tools.semantic_mcp_update.owner":"c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775","tools.semantic_mcp_update.permit":"85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103","tools.semantic_mcp_update.plan":"abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82","tools.semantic_mcp_update.session":"ec2010706969f37590d43ed864f4bbe464f56377110c7ecb2d735dc8218f5682","tools.semantic_policy_token_owner.installed_owner":"5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba","tools.semantic_policy_token_owner.supervisor":"1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf","tools.udp_resolution_update.authority":"af9c22821dd97e4ef2774e07ebb0a9ddde71ba4a2e951b2bb9c65a4114ed8c70","tools.udp_resolution_update.entry":"bcda674e69dc2c91bca622c3fcb140d3c42932305096bd44abcb9cccd5dcbb7d","tools.udp_resolution_update.native":"a2eda7cafada2f5910b513e5719f312670bd89732b8a8e08c55524f533a771dd","tools.udp_resolution_update.owner":"5de5a2131f2f0392887e169d2f8cd091e719ebdabced0550bd29b03e8bdbedbe","tools.udp_resolution_update.plan":"bc563f96a68512c0a8fff2de11697725856c66112168ce0c3c5d21933d1bbe37","tools.udp_resolution_update.preparation":"1a3d70690bc381c901f7abf6b385cf69b9c746c7ae4985e9cf3737f727ebe36e"}}
PACKAGE
printf '%s  %s\n' \
 '7ffb2b5bcd6037823066fc9631b715d64718e234dd9ba4532ad556fd40dacae5' "$ouf_stage/execute.py" \
 '9aef02f411bba5a8faa796cd6a7caad40e571ef3f19cb3e81c39c4757f8e8327' "$ouf_stage/runtime.py" \
 '30c65c1d7d254f703cccc3984a1fc03707010682719b68c12e1f973437653499' "$ouf_stage/case.json" \
 'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b' "$ouf_stage/iam_binding_candidate.py" \
 '1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2' "$ouf_stage/migration_root_custody.py" \
 '1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df' "$ouf_stage/continued_owner.py" \
 'fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432' "$ouf_stage/review.py" \
 '2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285' "$ouf_stage/human_session.py" \
 '5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f' "$ouf_stage/gateway.py" \
 '5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba' "$ouf_stage/installed_owner.py" \
 '1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf' "$ouf_stage/supervisor.py" \
 '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" \
 '0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16' "$ouf_stage/mcp_entry.py" \
 '36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54' "$ouf_stage/mcp_authority.py" \
 '85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103' "$ouf_stage/mcp_permit.py" \
 'abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82' "$ouf_stage/mcp_plan.py" \
 'ec2010706969f37590d43ed864f4bbe464f56377110c7ecb2d735dc8218f5682' "$ouf_stage/mcp_session.py" \
 'c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775' "$ouf_stage/mcp_owner.py" \
 '7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a' "$ouf_stage/mcp_native.py" \
 '2be394b68e5b5e4cf004814aaa020f5139496e161609ad6d9341c5849f5d5696' "$ouf_stage/readiness_entry.py" \
 '94d4718ed9091de55cf9cd67fc7ecc2265a9db822e5c367e55c4c252773a494c' "$ouf_stage/readiness_authority.py" \
 'f6ab1ae11208cc058aff861ce918db1a246056540b1f6ebe9cbc4983e565ec6c' "$ouf_stage/readiness_plan.py" \
 '4ec7b297bc5154dad2426a7cc7fcc09379c0d36404bcf97c68be825a2b7ab560' "$ouf_stage/readiness_owner.py" \
 'cad037ac7a936983d76fde4fb42e11de6ff41be06d6ad430c9165b5320f23523' "$ouf_stage/readiness_native.py" \
 'e54f5306be8a5d072cffe1cdc5a956d879d95c52636ef42ac243ef586c8d1485' "$ouf_stage/audit_entry.py" \
 '49d70354934ce3eb2ccb57eeec457247da5a3c78b3787d2bf3c0bb6c7aeab641' "$ouf_stage/audit_authority.py" \
 '3e026425a90e30c782a32ea0bd202595e43fdc1b68b6145bb5797d010950c204' "$ouf_stage/audit_owner.py" \
 '51da1138b5f3bea28bae0fde42dfb619095924516ba0cd5e6a73f0cb75d394e3' "$ouf_stage/audit_native.py" \
 'ab2d9b62473e81bb58ff4e2f4a5e999b0d092abb2bd8031a9bd7a760bef61e22' "$ouf_stage/audit_preparation.py" \
 'ac2e3588af924489712f8f9eaf45471207c6c2b60eb4b94e8464f0842a7bb0de' "$ouf_stage/resolution_entry.py" \
 '07e9f0f032cdd4b556e7dc3490e8cb2431ab9cda5bcb53ad9b819607ad343232' "$ouf_stage/resolution_authority.py" \
 '02e3bf3f1510c6df79dc87f9d9be1b51ee027f9f4c868d506e4b303b5592550d' "$ouf_stage/resolution_owner.py" \
 '156440a6d9f706b2e810f1807c374c32cc08fcbd26c98327957604b35c545f75' "$ouf_stage/resolution_native.py" \
 'c1513e10d22393581a9c672700bfb63333b74aad24db886f994c009782abee1e' "$ouf_stage/resolution_plan.py" \
 'e621fb8960f411427ed3dc8cdebb6163b6068181f7220211740974381016e1b2' "$ouf_stage/config_entry.py" \
 '6b3b59e9020271587fd087d29085e380833bf0f479744aaacdd9f037713b735a' "$ouf_stage/config_authority.py" \
 'c731071f3b8eb5563258726aabd57df7c280b4607c526b8ac4d9a83f8a29b6de' "$ouf_stage/config_owner.py" \
 'e39a4771b02f59ddf572d5aca47a8e952ad9cc157e65badbd37abeab2cca4df8' "$ouf_stage/config_native.py" \
 'bd2d61480e4aede630c4b4850f3253c5424f373d7991613a1a77fecfbfb82d1c' "$ouf_stage/config_plan.py" \
 'bcda674e69dc2c91bca622c3fcb140d3c42932305096bd44abcb9cccd5dcbb7d' "$ouf_stage/udp_entry.py" \
 'af9c22821dd97e4ef2774e07ebb0a9ddde71ba4a2e951b2bb9c65a4114ed8c70' "$ouf_stage/udp_authority.py" \
 '5de5a2131f2f0392887e169d2f8cd091e719ebdabced0550bd29b03e8bdbedbe' "$ouf_stage/udp_owner.py" \
 'a2eda7cafada2f5910b513e5719f312670bd89732b8a8e08c55524f533a771dd' "$ouf_stage/udp_native.py" \
 'bc563f96a68512c0a8fff2de11697725856c66112168ce0c3c5d21933d1bbe37' "$ouf_stage/udp_plan.py" \
 '1a3d70690bc381c901f7abf6b385cf69b9c746c7ae4985e9cf3737f727ebe36e' "$ouf_stage/udp_preparation.py" \
 '5f75bd1093dc411c98356bad8784f01c72e43df05b04b48bab6ec507c6bd555d' "$ouf_stage/comparison_entry.py" \
 '38f6fcf5839bf41569d3eb017341a428647bcf8ee140bfecc316b4f6c1ebd975' "$ouf_stage/comparison_authority.py" \
 '525121cd5f4f727b8cac655694a13a3f5cd76c268334d1db3183890ed393c1fd' "$ouf_stage/comparison_owner.py" \
 '8caf9d0d2a7e884b4e1dd0942a3867c9a1f513e0e00befa4c1f97397bcb20a29' "$ouf_stage/comparison_native.py" \
 '4134ce4f901088715db566c1fbe824b185ad1e04659db3c28cf06534b3a244ef' "$ouf_stage/comparison_plan.py" \
 '6708ce1dfbdda8b33cd4bab40b9832f5c7b070ca6bba3e1f15cac0b41426ac55' "$ouf_stage/comparison_preparation.py" \
 'aa49958b7b5253f401a192cde758b101a69a3dc351a95673e0b705194e30d1c9' "$ouf_stage/linked_entry.py" \
 '5a6f89909e3a4ab2aff37a8c5c8c6e137703adf03f7126160f6fd299f883f1b3' "$ouf_stage/linked_authority.py" \
 '80535c7be030fa8a72f0045aa14ca19f636aa4f18c2b55577b48c6116203c5a0' "$ouf_stage/linked_owner.py" \
 '9db2d99347511d76f96b7e16039db2ec51dc73b93c1febebaeeca2f64221bce5' "$ouf_stage/linked_native.py" \
 '1aebda8716a997cd63b3f592bf17cad87399f5886a5553b4d6c2264b08413706' "$ouf_stage/linked_plan.py" \
 'b7f20e03d3df60023e8f382c4fef7edb2b82f1182ed49812e740f82f5bc84cbc' "$ouf_stage/linked_preparation.py" \
 '11050accc82b8bbbe5e2005dcea755d7f79fef1e46c016eec618fafbeaa8354b' "$ouf_stage/linked_database.py" \
 '3e4535bdd546f5cfdc658086f0a4cbbbc15458a995b7d818c41115f7cad58016' "$ouf_stage/linked_configuration.py" \
 '7691b1cbdd811a4b0c67e0a8355c4f737d96f71cdc880b2dd2194e2da0cee25e' "$ouf_stage/linked_login.py" \
 '4b3314bcf3bfea46c079ec23afc2bad1709843d8e98c15abfc5312fd8582a422' "$ouf_stage/package.json" | sha256sum --check -
echo "Log della sessione: $ouf_stage/run.log"
echo 'Preparo tutti gli input prima del consenso. Un APPROVO per backup UDP verificato, migrazione nativa34->35 e aggiornamento UDP/Onboarding.'
echo 'Riutilizzo HUMAN se valido; altrimenti RIAPRO LOGIN e browser, budget cumulativo256 conservato. Nessun worker policy.'
echo 'I profili saranno pubblicati in un passaggio successivo. Nessuna ripresa job o nuova decisione di identita.'
echo 'Lascia aperto il terminale sul PC. Dopo APPROVO massimo15 minuti. Incolla OUF_LINKED_PROPERTY_UPDATE_RESULT oppure STOP; non rilanciare dopo STOP.'
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" <<'ROOTPY' 2>&1 | tee "$ouf_stage/run.log"
import hashlib,json,os,re,stat,sys,tempfile
from pathlib import Path
assert os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
os.umask(0o077)
source=Path(sys.argv[1])
def read(name,expected,maximum=262144):
 assert re.fullmatch('[A-Za-z0-9_.-]+',name)
 fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum
  raw=bytearray()
  while len(raw)<=maximum:
   part=os.read(fd,min(65536,maximum+1-len(raw)))
   if not part:break
   raw.extend(part)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))and hashlib.sha256(raw).hexdigest()==expected
  return bytes(raw)
 finally:os.close(fd)
manifest_raw=read('package.json','4b3314bcf3bfea46c079ec23afc2bad1709843d8e98c15abfc5312fd8582a422');package=json.loads(manifest_raw)
assert package['sourceCommit']=='5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981'
files={'package.json':manifest_raw,'execute.py':read('execute.py',package['executorSha256']),
 'runtime.py':read('runtime.py',package['loaderSha256']),'case.json':read('case.json',package['caseSha256'])}
# Only this verified bootstrap's static overlay declaration selects source names.
ns={'__name__':'readiness_stage_metadata'};exec(compile(files['execute.py'],'<verified-bootstrap-stage>','exec'),ns)
assert set(package['sourceHashes'])==set(ns['OVERLAYS'])
for module,(name,path)in ns['OVERLAYS'].items():files[name]=read(name,package['sourceHashes'][module])
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='linked-property-executor-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print('OUF_LINKED_PROPERTY_EXECUTOR_CODE='+str(code),flush=True)
sys.argv=[str(code/'execute.py'),str(code),'5a3bb8d979ce10d65b53b5b81ccf3a0c5b4a1981','4b3314bcf3bfea46c079ec23afc2bad1709843d8e98c15abfc5312fd8582a422']
exec(compile(files['execute.py'],'<verified-scoped-readiness-bootstrap>','exec'),{'__name__':'__main__'})
ROOTPY
