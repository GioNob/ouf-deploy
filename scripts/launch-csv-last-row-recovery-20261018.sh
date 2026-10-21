#!/usr/bin/env bash
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
[ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo 'Client GitHub non disponibile; nessuna esecuzione sudo.' >&2; exit 1; }
ouf_stage="$(mktemp -d "$HOME/ouf-csv-last-row-recovery.XXXXXXXX")"
echo 'Tecniche 8/8; funzionali 2/6. Recupero vincolato al piano privato e al solo job residuo.'
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/execute-csv-last-row-recovery-20261018.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/execute.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/runtime.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/runtime.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/releases/csv-last-row-recovery-selection-20261018.json?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/case.json"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/iam_binding_candidate.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/iam_binding_candidate.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/migration_root_custody.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/migration_root_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_application_cutover/image_custody.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/image_custody.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/continued_owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/continued_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/review.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/review.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/human_session.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/human_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/chatbot_file_cohort/gateway.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/gateway.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/installed_owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/installed_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/supervisor.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/supervisor.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/permit.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_permit.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/plan.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/session.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_session.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_mcp_update/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/mcp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/readiness_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/readiness_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/plan.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/readiness_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/readiness_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/ingestion_readiness_update/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/readiness_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/audit_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/audit_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/audit_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/audit_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/onboarding_audit_update/preparation.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/audit_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/resolution_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/resolution_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/resolution_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/resolution_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_update/plan.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/resolution_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/config_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/config_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/config_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/config_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/resolution_ths_configuration/plan.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/config_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/owner.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_owner.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/native.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_native.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/plan.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_plan.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/preparation.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_preparation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/teatri_materialization_apply/preflight.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_preflight.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/permissions.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_permissions.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/login.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/udp_login.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/authority.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_authority.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/run.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_run.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_last_row_recovery/retry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_retry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/journal.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_journal.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/continuation.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_continuation.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/tools/csv_materialization_recovery/entry.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/recovery_entry.py"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/read-teatri-post-resolution-materialization-20261017.py?ref=73bf5767e4ee2e3397ef5cf9193b91589d0522d6' --jq .content | base64 --decode > "$ouf_stage/csv_readback.py"
cat > "$ouf_stage/package.json" <<'PACKAGE'
{"schema":"ouf.csv-last-row-recovery-code-package.v1","sourceCommit":"73bf5767e4ee2e3397ef5cf9193b91589d0522d6","sourceHashes":{"iam_binding_candidate":"dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b","migration_root_custody":"1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2","image_custody":"9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2","tools.chatbot_file_cohort.continued_owner":"1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df","tools.chatbot_file_cohort.review":"fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432","tools.chatbot_file_cohort.human_session":"2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285","tools.chatbot_file_cohort.gateway":"5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f","tools.semantic_policy_token_owner.installed_owner":"5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba","tools.semantic_policy_token_owner.supervisor":"1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf","tools.semantic_mcp_update.entry":"0207289f77a735e446a49a0a40bb7d667706cef265595530bf28a3d42139da16","tools.semantic_mcp_update.authority":"36079b8394c06a96c719081c98ee244ffb827e8133582b9579cd300a780bec54","tools.semantic_mcp_update.permit":"85825789906152ba43c5c28fb0b502820f18d9a86a47bac59e47aca29e3f9103","tools.semantic_mcp_update.plan":"abfd55c5e25aa0323aec43ce3e90a34073680267a127a3ad4994013316f28c82","tools.semantic_mcp_update.session":"ec2010706969f37590d43ed864f4bbe464f56377110c7ecb2d735dc8218f5682","tools.semantic_mcp_update.owner":"c9fe376bcb1d83c1139b8216920e1c797022a6e73a8d78d6c30c89c17d1ad775","tools.semantic_mcp_update.native":"7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a","tools.ingestion_readiness_update.entry":"2be394b68e5b5e4cf004814aaa020f5139496e161609ad6d9341c5849f5d5696","tools.ingestion_readiness_update.authority":"94d4718ed9091de55cf9cd67fc7ecc2265a9db822e5c367e55c4c252773a494c","tools.ingestion_readiness_update.plan":"f6ab1ae11208cc058aff861ce918db1a246056540b1f6ebe9cbc4983e565ec6c","tools.ingestion_readiness_update.owner":"4ec7b297bc5154dad2426a7cc7fcc09379c0d36404bcf97c68be825a2b7ab560","tools.ingestion_readiness_update.native":"cad037ac7a936983d76fde4fb42e11de6ff41be06d6ad430c9165b5320f23523","tools.onboarding_audit_update.entry":"e54f5306be8a5d072cffe1cdc5a956d879d95c52636ef42ac243ef586c8d1485","tools.onboarding_audit_update.authority":"49d70354934ce3eb2ccb57eeec457247da5a3c78b3787d2bf3c0bb6c7aeab641","tools.onboarding_audit_update.owner":"3e026425a90e30c782a32ea0bd202595e43fdc1b68b6145bb5797d010950c204","tools.onboarding_audit_update.native":"51da1138b5f3bea28bae0fde42dfb619095924516ba0cd5e6a73f0cb75d394e3","tools.onboarding_audit_update.preparation":"ab2d9b62473e81bb58ff4e2f4a5e999b0d092abb2bd8031a9bd7a760bef61e22","tools.resolution_ths_update.entry":"ac2e3588af924489712f8f9eaf45471207c6c2b60eb4b94e8464f0842a7bb0de","tools.resolution_ths_update.authority":"07e9f0f032cdd4b556e7dc3490e8cb2431ab9cda5bcb53ad9b819607ad343232","tools.resolution_ths_update.owner":"02e3bf3f1510c6df79dc87f9d9be1b51ee027f9f4c868d506e4b303b5592550d","tools.resolution_ths_update.native":"156440a6d9f706b2e810f1807c374c32cc08fcbd26c98327957604b35c545f75","tools.resolution_ths_update.plan":"c1513e10d22393581a9c672700bfb63333b74aad24db886f994c009782abee1e","tools.resolution_ths_configuration.entry":"e621fb8960f411427ed3dc8cdebb6163b6068181f7220211740974381016e1b2","tools.resolution_ths_configuration.authority":"6b3b59e9020271587fd087d29085e380833bf0f479744aaacdd9f037713b735a","tools.resolution_ths_configuration.owner":"c731071f3b8eb5563258726aabd57df7c280b4607c526b8ac4d9a83f8a29b6de","tools.resolution_ths_configuration.native":"e39a4771b02f59ddf572d5aca47a8e952ad9cc157e65badbd37abeab2cca4df8","tools.resolution_ths_configuration.plan":"bd2d61480e4aede630c4b4850f3253c5424f373d7991613a1a77fecfbfb82d1c","tools.teatri_materialization_apply.entry":"d3ee05de60c72828de26aae1ead95616115d84eb37106abdabfcdd358ab1ad05","tools.teatri_materialization_apply.authority":"e6873d2c5dadd500ae9425699a1023e86e376c6d33c80311202b488a7e7edf92","tools.teatri_materialization_apply.owner":"2ef216a63f7e5a39385ef292a4542c553249c0862261d2988af3c1223e050e07","tools.teatri_materialization_apply.native":"deda6e05586f9df868c0e0926627fd5dfa5e61da0208a85fdf4786bfc0f35798","tools.teatri_materialization_apply.plan":"60764bc2f98f6fe86c8b954847b76671bc1bce38e7a0aa7cd1bf93a7b9e808d1","tools.teatri_materialization_apply.preparation":"bd6338cfe895d6c69b3655f53c1c7f305220d7e2f429993b97c9a445302d4b3f","tools.teatri_materialization_apply.preflight":"0f19c781e129ca47a6e8a3e56930b13492d6905b6804d3f3ea661fbe65302ebf","tools.teatri_materialization_apply.permissions":"656e3c5769b51a4012b92f9c6bb907ea3c227e7b9291ee69c1661a7d4bc1ebe5","tools.teatri_materialization_apply.login":"e2750b35737c84db0bf5508f9a7633c401109681a15e1068a94791592ff9799d","tools.csv_materialization_recovery.authority":"387cda12701f325500cc8061580caef52bd12c1531a9147eff4013f984cac80e","tools.csv_materialization_recovery.run":"b2d8408c1839e098eeae48b571ad3fe14462c2b467275a325fc0a3610dce1f9c","tools.csv_materialization_recovery.retry":"50320a32bf843048df1b5cc34133d76ed6d9ed1a781db408fc51c4614e81babc","tools.csv_materialization_recovery.journal":"d3fd2715c5aa0fe5a6b6e1e17b59fb4fb9117a6b4dd8c93aa79bbbbc079433b0","tools.csv_materialization_recovery.continuation":"a22ce3bf38fe37949f45e11960a7ba583a306f65700e5c827b36517c845b983a","tools.csv_materialization_recovery.entry":"bf7b8064084794a032a9c8c3108742be898c1531fd9edd27bfd8e60fa76e3dd3","tools.csv_materialization_recovery.readback":"ff9f1f593e8c831e2192bc8483431de2b226f7408da28744ad7f5b9490fdcc6e"},"executorSha256":"583dd4d016c8fdd45262fb570e82c84fd675f039832b6dd256d5851c920f7cb4","loaderSha256":"8e495a9f0527d932ca275ed10801ab347b0b596388f7e4bbe2b834217753ac5f","caseSha256":"0bc9698ddf98b855c6d924b2523c790abf60c0a6026ee3559984419e3c7d8a73","runtimeAuthorityIssued":false}
PACKAGE
printf '%s  %s\n' \
 '583dd4d016c8fdd45262fb570e82c84fd675f039832b6dd256d5851c920f7cb4' "$ouf_stage/execute.py" \
 '8e495a9f0527d932ca275ed10801ab347b0b596388f7e4bbe2b834217753ac5f' "$ouf_stage/runtime.py" \
 '0bc9698ddf98b855c6d924b2523c790abf60c0a6026ee3559984419e3c7d8a73' "$ouf_stage/case.json" \
 'dcfab9f362ddfd9be95dcd41ee8281d5cecc074918e4ed3995e19dd17da1801b' "$ouf_stage/iam_binding_candidate.py" \
 '1b8aaa23d26ad9b6e04d7b61eead1af1f80ad4c6cd131d48c21ce7e183b207c2' "$ouf_stage/migration_root_custody.py" \
 '9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2' "$ouf_stage/image_custody.py" \
 '1d64e5bf7540dd8c3bee5c40e15d0b9fc0541600317b2f7ad53639e42d0904df' "$ouf_stage/continued_owner.py" \
 'fa595c5cc12108653e1ac06a4cc04433d5e2f69345720ce70787b7b51b837432' "$ouf_stage/review.py" \
 '2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285' "$ouf_stage/human_session.py" \
 '5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f' "$ouf_stage/gateway.py" \
 '5455d56e973f6c6d9a35900193ac50dab44147a9bd7dedfa13d356bd91901cba' "$ouf_stage/installed_owner.py" \
 '1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf' "$ouf_stage/supervisor.py" \
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
 '656e3c5769b51a4012b92f9c6bb907ea3c227e7b9291ee69c1661a7d4bc1ebe5' "$ouf_stage/udp_permissions.py" \
 'e2750b35737c84db0bf5508f9a7633c401109681a15e1068a94791592ff9799d' "$ouf_stage/udp_login.py" \
 '387cda12701f325500cc8061580caef52bd12c1531a9147eff4013f984cac80e' "$ouf_stage/csv_authority.py" \
 'b2d8408c1839e098eeae48b571ad3fe14462c2b467275a325fc0a3610dce1f9c' "$ouf_stage/csv_run.py" \
 '50320a32bf843048df1b5cc34133d76ed6d9ed1a781db408fc51c4614e81babc' "$ouf_stage/csv_retry.py" \
 'd3fd2715c5aa0fe5a6b6e1e17b59fb4fb9117a6b4dd8c93aa79bbbbc079433b0' "$ouf_stage/csv_journal.py" \
 'a22ce3bf38fe37949f45e11960a7ba583a306f65700e5c827b36517c845b983a' "$ouf_stage/csv_continuation.py" \
 'bf7b8064084794a032a9c8c3108742be898c1531fd9edd27bfd8e60fa76e3dd3' "$ouf_stage/recovery_entry.py" \
 'ff9f1f593e8c831e2192bc8483431de2b226f7408da28744ad7f5b9490fdcc6e' "$ouf_stage/csv_readback.py" \
 '0b7fe852c76eabd399a764613229fd3d8c1a580feaa7c162c8961c4cb48e29d5' "$ouf_stage/package.json" | sha256sum --check -
echo "Log della sessione: $ouf_stage/run.log"
echo 'La sessione HUMAN e scaduta: un nuovo login conserva160/256 tentativi. Poi una sola revisione operativa completa.'
echo 'Rinnovo policy318+126=444, un grant esatto policy41->42 e massimo una ripresa nativa del job residuo. Nessuna decisione di identita.'
echo 'Lascia aperto il terminale fino a OUF_LAST_ROW_RECOVERY_RESULT o STOP; in caso di STOP non rilanciare senza riconciliare.'
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
manifest_raw=read('package.json','0b7fe852c76eabd399a764613229fd3d8c1a580feaa7c162c8961c4cb48e29d5');package=json.loads(manifest_raw)
assert package['sourceCommit']=='73bf5767e4ee2e3397ef5cf9193b91589d0522d6'
files={'package.json':manifest_raw,'execute.py':read('execute.py',package['executorSha256']),
 'runtime.py':read('runtime.py',package['loaderSha256']),'case.json':read('case.json',package['caseSha256'])}
# Only this verified bootstrap's static overlay declaration selects source names.
ns={'__name__':'readiness_stage_metadata'};exec(compile(files['execute.py'],'<verified-bootstrap-stage>','exec'),ns)
assert set(package['sourceHashes'])==set(ns['OVERLAYS'])
for module,(name,path)in ns['OVERLAYS'].items():files[name]=read(name,package['sourceHashes'][module])
parent=Path('/etc/ouf/deploy-snapshots')
for p in(parent,*parent.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
code=Path(tempfile.mkdtemp(prefix='csv-last-row-recovery-executor-code-',dir=parent));code.chmod(0o700)
for name,raw in files.items():
 fd=os.open(code/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
print('OUF_LAST_ROW_RECOVERY_EXECUTOR_CODE='+str(code),flush=True)
sys.argv=[str(code/'execute.py'),str(code),'73bf5767e4ee2e3397ef5cf9193b91589d0522d6','0b7fe852c76eabd399a764613229fd3d8c1a580feaa7c162c8961c4cb48e29d5']
exec(compile(files['execute.py'],'<verified-scoped-readiness-bootstrap>','exec'),{'__name__':'__main__'})
ROOTPY
