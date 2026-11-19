#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo "Client GitHub non disponibile." >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-csv-recovery-login.XXXXXXXX")"
echo 'Login HUMAN con lo scope generico udp.materialization.retry. Nessun worker, download immagini o modifica IAM.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/open-csv-materialization-recovery-login-20261017.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/execute.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/runtime.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/runtime.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/csv-materialization-recovery-login-selection-20261017.json?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/case.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/iam_binding_candidate.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/migration_root_custody.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/migration_root_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/continued_owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/continued_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/review.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/review.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/human_session.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/human_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/gateway.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/installed_owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/installed_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/supervisor.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/supervisor.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/permit.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_permit.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/plan.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/session.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/mcp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/readiness_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/readiness_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/plan.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/readiness_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/readiness_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/readiness_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/audit_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/audit_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/audit_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/audit_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/preparation.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/audit_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/resolution_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/resolution_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/resolution_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/resolution_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/plan.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/resolution_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/config_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/config_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/config_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/config_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/plan.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/config_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/authority.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/owner.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/native.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/plan.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/preparation.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/preflight.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_preflight.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/permissions.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_permissions.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/login.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/udp_login.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/entry.py?ref=4cd61a27c75d608aea0c99ca969506455149cac7' --jq .content | base64 --decode > "$ouf_stage/recovery_entry.py"
cat > "$ouf_stage/package.json" <<'PACKAGE'
{"caseSha256":"5f75d158725a54e6bd3fc4db8e6e1d4479df22cc1b551297d106dc12cd6e93a9","executorSha256":"310ce2550a40b40d22f44bf727082c515b6fcd9c6bc614cc0685e7f57aae6041","loaderSha256":"bf0c67baebe06397c275545f9200a02a0c7c7e2115c47c1ea043ffe26b390772","runtimeAuthorityIssued":false,"schema":"ouf.csv-recovery-scope-login-code-package.v1","sourceCommit":"4cd61a27c75d608aea0c99ca969506455149cac7","sourceHashes":{"iam_binding_candidate":"dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b","image_custody":"9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2","migration_root_custody":"1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2","tools.chatbot_file_cohort.continued_owner":"1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df","tools.chatbot_file_cohort.gateway":"5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f","tools.chatbot_file_cohort.human_session":"2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285","tools.chatbot_file_cohort.review":"fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432","tools.csv_materialization_recovery.entry":"bf7b8064084794a032a9c8c3108742be898c1531fd9edd27bfd8e60fa76e3dd3","tools.ingestion_readiness_update.authority":"94d4718ed9091de55cf9cd67fc7ecc2265a9db822e5c367e55c4c252773a494c","tools.ingestion_readiness_update.entry":"2be394b68e5b5e4cf004814aaa020f5139496e161609ad6d9341c5849f5d5696","tools.ingestion_readiness_update.native":"cad037ac7a936983d76fde4fb42e11de6ff41be06d6ad430c9165b5320f23523","tools.ingestion_readiness_update.owner":"4ec7b297bc5154dad2426a7cc7fcc09379c0d36404bcf97c68be825a2b7ab560","tools.ingestion_readiness_update.plan":"f6ab1ae11208cc058aff861ce918db1a246056540b1f6ebe9cbc4983e565ec6c","tools.onboarding_audit_update.authority":"49d70354934ce3eb2ccb57eeec457247da5a3c78b3787d2bf3c0bb6c7aeab641","tools.onboarding_audit_update.entry":"e54f5306be8a5d072cffe1cdc5a956d879d95c52636ef42ac243ef586c8d1485","tools.onboarding_audit_update.native":"51da1138b5f3bea28bae0fde42dfb619095924516ba0cd5e6a73f0cb75d394e3","tools.onboarding_audit_update.owner":"3e026425a90e30c782a32ea0bd202595e43fdc1b68b6145bb5797d010950c204","tools.onboarding_audit_update.preparation":"ab2d9b62473e81bb58ff4e2f4a5e999b0d092abb2bd8031a9bd7a760bef61e22","tools.resolution_ths_configuration.authority":"6b3b59e9020271587fd087d29085e380833bf0f479744aaacdd9f037713b735a","tools.resolution_ths_configuration.entry":"e621fb8960f411427ed3dc8cdebb6163b6068181f7220211740974381016e1b2","tools.resolution_ths_configuration.native":"e39a4771b02f59ddf572d5aca47a8e952ad9cc157e65badbd37abeab2cca4df8","tools.resolution_ths_configuration.owner":"c731071f3b8eb5563258726aabd57df7c280b4607c526b8ac4d9a83f8a29b6de","tools.resolution_ths_configuration.plan":"bd2d61480e4aede630c4b4850f3253c5424f373d7991613a1a77fecfbfb82d1c","tools.resolution_ths_update.authority":"07e9f0f032cdd4b556e7dc3490e8cb2431ab9cda5bcb53ad9b819607ad343232","tools.resolution_ths_update.entry":"ac2e3588af924489712f8f9eaf45471207c6c2b60eb4b94e8464f0842a7bb0de","tools.resolution_ths_update.native":"156440a6d9f706b2e810f1807c374c32cc08fcbd26c98327957604b35c545f75","tools.resolution_ths_update.owner":"02e3bf3f1510c6df79dc87f9d9be1b51ee027f9f4c868d506e4b303b5592550d","tools.resolution_ths_update.plan":"c1513e10d22393581a9c672700bfb63333b74aad24db886f994c009782abee1e","tools.semantic_mcp_update.authority":"36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54","tools.semantic_mcp_update.entry":"0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16","tools.semantic_mcp_update.native":"7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a","tools.semantic_mcp_update.owner":"c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775","tools.semantic_mcp_update.permit":"85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103","tools.semantic_mcp_update.plan":"abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82","tools.semantic_mcp_update.session":"ec2010706969f37590d43ed864f4bbe464f56377110c7ecb2d735dc8218f5682","tools.semantic_policy_token_owner.installed_owner":"5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba","tools.semantic_policy_token_owner.supervisor":"1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf","tools.teatri_materialization_apply.authority":"e6873d2c5dadd500ae9425699a1023e86e376c6d33c80311202b488a7e7edf92","tools.teatri_materialization_apply.entry":"d3ee05de60c72828de26aae1ead95616115d84eb37106abdabfcdd358ab1ad05","tools.teatri_materialization_apply.login":"f7f1d89130df3136edc68f4e638a9487d367b12519e7eda80c299aa0edd9703f","tools.teatri_materialization_apply.native":"deda6e05586f9df868c0e0926627fd5dfa5e61da0208a85fdf4786bfc0f35798","tools.teatri_materialization_apply.owner":"2ef216a63f7e5a39385ef292a4542c553249c0862261d2988af3c1223e050e07","tools.teatri_materialization_apply.permissions":"d5e4b1a387e4dcf0aa2c5c83a3f435a8dbec18017cb404c933c7ee8f5c85fe7d","tools.teatri_materialization_apply.plan":"60764bc2f98f6fe86c8b954847b76671bc1bce38e7a0aa7cd1bf93a7b9e808d1","tools.teatri_materialization_apply.preflight":"0f19c781e129ca47a6e8a3e56930b13492d6905b6804d3f3ea661fbe65302ebf","tools.teatri_materialization_apply.preparation":"bd6338cfe895d6c69b3655f53c1c7f305220d7e2f429993b97c9a445302d4b3f"}}
PACKAGE
printf '%s  %s\n' \
 '310ce2550a40b40d22f44bf727082c515b6fcd9c6bc614cc0685e7f57aae6041' "$ouf_stage/execute.py" \
 'bf0c67baebe06397c275545f9200a02a0c7c7e2115c47c1ea043ffe26b390772' "$ouf_stage/runtime.py" \
 '5f75d158725a54e6bd3fc4db8e6e1d4479df22cc1b551297d106dc12cd6e93a9' "$ouf_stage/case.json" \
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
 'd3ee05de60c72828de26aae1ead95616115d84eb37106abdabfcdd358ab1ad05' "$ouf_stage/udp_entry.py" \
 'e6873d2c5dadd500ae9425699a1023e86e376c6d33c80311202b488a7e7edf92' "$ouf_stage/udp_authority.py" \
 '2ef216a63f7e5a39385ef292a4542c553249c0862261d2988af3c1223e050e07' "$ouf_stage/udp_owner.py" \
 'deda6e05586f9df868c0e0926627fd5dfa5e61da0208a85fdf4786bfc0f35798' "$ouf_stage/udp_native.py" \
 '60764bc2f98f6fe86c8b954847b76671bc1bce38e7a0aa7cd1bf93a7b9e808d1' "$ouf_stage/udp_plan.py" \
 'bd6338cfe895d6c69b3655f53c1c7f305220d7e2f429993b97c9a445302d4b3f' "$ouf_stage/udp_preparation.py" \
 '0f19c781e129ca47a6e8a3e56930b13492d6905b6804d3f3ea661fbe65302ebf' "$ouf_stage/udp_preflight.py" \
 'd5e4b1a387e4dcf0aa2c5c83a3f435a8dbec18017cb404c933c7ee8f5c85fe7d' "$ouf_stage/udp_permissions.py" \
 'f7f1d89130df3136edc68f4e638a9487d367b12519e7eda80c299aa0edd9703f' "$ouf_stage/udp_login.py" \
 'bf7b8064084794a032a9c8c3108742be898c1531fd9edd27bfd8e60fa76e3dd3' "$ouf_stage/recovery_entry.py" \
 '5a0d660d7743144b4e4d48c915c6a283e97055f065fd857c1e82e7614dad766c' "$ouf_stage/package.json" | sha256sum --check -
echo "Log della sessione: $ouf_stage/run.log"
echo 'Prima RIAPRO LOGIN e browser. OAuth cumulativi conservati, massimo256. Nessun APPROVO worker o ripresa job in questo comando.'
echo 'Il nuovo token deve contenere lo scope di ripresa concesso dall issuer. Nessun permesso viene autoattribuito dal client.'
echo 'Incolla OUF_CSV_RECOVERY_HUMAN_LOGIN oppure STOP. Nessuna modifica a grant, route, servizi o decisioni di identita.'
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
manifest_raw=read('package.json','5a0d660d7743144b4e4d48c915c6a283e97055f065fd857c1e82e7614dad766c');package=json.loads(manifest_raw)
assert package['sourceCommit']=='4cd61a27c75d608aea0c99ca969506455149cac7'
files={'package.json':manifest_raw,'execute.py':read('execute.py',package['executorSha256']),
 'runtime.py':read('runtime.py',package['loaderSha256']),'case.json':read('case.json',package['caseSha256'])}
# Only this verified bootstrap's static overlay declaration selects source names.
ns={'__name__':'readiness_stage_metadata'};exec(compile(files['execute.py'],'<verified-bootstrap-stage>','exec'),ns)
assert set(package['sourceHashes'])==set(ns['OVERLAYS'])
for module,(name,path)in ns['OVERLAYS'].items():files[name]=read(name,package['sourceHashes'][module])
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='csv-recovery-login-executor-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print('OUF_CSV_RECOVERY_LOGIN_EXECUTOR_CODE='+str(code),flush=True)
sys.argv=[str(code/'execute.py'),str(code),'4cd61a27c75d608aea0c99ca969506455149cac7','5a0d660d7743144b4e4d48c915c6a283e97055f065fd857c1e82e7614dad766c']
exec(compile(files['execute.py'],'<verified-scoped-readiness-bootstrap>','exec'),{'__name__':'__main__'})
ROOTPY
