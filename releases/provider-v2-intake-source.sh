#!/usr/bin/env bash
# New passive intake source package only. No signing/runtime/start authority.
(
set -Eeuo pipefail
umask 077
phase=FIND_EXISTING_AUTHENTICATED_GH
trap 'rc=$?; printf "OUF_INTAKE_BOOTSTRAP=BLOCKED PHASE=%s EXIT_CODE=%s NO_RAW_OUTPUT=true\n" "$phase" "$rc"' ERR
if command -v gh >/dev/null 2>&1; then
    gh_bin="$(command -v gh)"
elif [[ -x "$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh" ]]; then
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
else
    printf '%s\n' 'OUF_INTAKE_BOOTSTRAP=BLOCKED REASON=EXISTING_GH_NOT_FOUND NO_INSTALL_REQUESTED=true'
    exit 1
fi
source_ref='e16d58125dfa794e14357d1dfc0cafa2d59faa96'
download="$(mktemp -d "$HOME/ouf-provider-intake.XXXXXXXX")"
printf 'OUF_INTAKE_DOWNLOAD=%s\n' "$download"
phase=DOWNLOAD_EXACT_SEALED_SOURCE
while IFS=$'\t' read -r package_path repository_path; do
    mkdir -p "$download/$(dirname "$package_path")"
    "$gh_bin" api "repos/GioNob/ouf-deploy/contents/$repository_path?ref=$source_ref" --jq '.content' 2>/dev/null |
        base64 --decode > "$download/$package_path"
done <<'OUF_EXACT_SOURCE_MAP'
frame-observer.py	tools/semantic_frame_compiler/frame-observer.py
source/scripts/semantic_provider_admission_preparer.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_admission_preparer.py
source/scripts/semantic_provider_creation_intent.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_creation_intent.py
source/scripts/semantic_provider_deployment_broker.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_deployment_broker.py
source/scripts/semantic_provider_docker_runtime.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py
source/scripts/semantic_provider_installer_approval.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_installer_approval.py
source/scripts/semantic_provider_node_attestor.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_node_attestor.py
source/scripts/semantic_provider_preexec_hook.py	tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_preexec_hook.py
source/scripts/stage_semantic_local_producers_package.py	tools/semantic_cohort_admission/cohort-draft/scripts/stage_semantic_local_producers_package.py
source/tools/materialize_semantic_shared_faces.py	tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py
source/tools/materialize_southbound_kernel.py	tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py
source/tools/materialize_southbound_lease_refresh.py	tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py
source/tools/semantic_provider_creation_intent.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_creation_intent.py
source/tools/semantic_provider_deployment_admission.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py
source/tools/semantic_provider_deployment_authentication.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py
source/tools/semantic_provider_deployment_consumption.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_consumption.py
source/tools/semantic_provider_deployment_producer.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_producer.py
source/tools/semantic_provider_deployment_protocol.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py
source/tools/semantic_provider_deployment_reauthorization.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_reauthorization.py
source/tools/semantic_provider_deployment_signing.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py
source/tools/semantic_provider_dns.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py
source/tools/semantic_provider_installer_approval.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_installer_approval.py
source/tools/semantic_provider_lease_coordination.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py
source/tools/semantic_provider_lease_nft.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py
source/tools/semantic_provider_lease_owner.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py
source/tools/semantic_provider_node_attestor.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_attestor.py
source/tools/semantic_provider_node_observation.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py
source/tools/semantic_provider_peer_bindings.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py
source/tools/semantic_provider_preexec.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py
source/tools/semantic_provider_preexec_native.py	tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py
utility/assemble_provider_profiles.py	tools/semantic_transaction_profiles/assemble_provider_profiles.py
utility/authenticate_provider_transaction.py	tools/semantic_transaction_profiles/authenticate_provider_transaction.py
utility/authenticated_runtime_switch.py	tools/semantic_transaction_profiles/authenticated_runtime_switch.py
utility/compile_creation_frame_policy.py	tools/semantic_frame_compiler/compile_creation_frame_policy.py
utility/docker_cohort_activation.py	tools/semantic_transaction_profiles/docker_cohort_activation.py
utility/guarded_runtime_switch.py	tools/semantic_transaction_profiles/guarded_runtime_switch.py
utility/issue_provider_transaction_authority.py	tools/semantic_transaction_profiles/issue_provider_transaction_authority.py
utility/publish_provider_transaction.py	tools/semantic_transaction_profiles/publish_provider_transaction.py
utility/transaction_guard_observation.py	tools/semantic_transaction_profiles/transaction_guard_observation.py
intake-source-closure.json	tools/semantic_transaction_profiles/intake-source-closure.json
provider_transaction_intake.py	tools/semantic_transaction_profiles/provider_transaction_intake.py
prepare.py	tools/semantic_target_review/prepare_private_transaction_intake.py
OUF_EXACT_SOURCE_MAP
phase=VERIFY_ROOT_PREPARATION_HELPER
printf '%s  %s\n' '135b6d903f6d65cd44a2e21cc834d65987633af3cee51b3ba4d35f33ff5ba221' "$download/prepare.py" | sha256sum -c -
phase=ROOT_NEW_SOURCE_AND_EXISTING_PAIR_PREFLIGHT
sudo /usr/bin/python3.13 -I -B - "$download/prepare.py" "$download" <<'OUF_VERIFIED_ROOT_LOADER'
import hashlib,pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_bytes()
if hashlib.sha256(raw).hexdigest()!='135b6d903f6d65cd44a2e21cc834d65987633af3cee51b3ba4d35f33ff5ba221':
    raise SystemExit('OUF_INTAKE_ROOT_LOADER=BLOCKED HELPER_HASH_DRIFT')
sys.argv=[sys.argv[1],sys.argv[2]]
exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
OUF_VERIFIED_ROOT_LOADER
printf '%s\n' 'OUF_INTAKE_BOOTSTRAP=PASS SOURCE_ONLY=true KEYS_READ=0 SIGNATURES=0 START_AUTHORIZED=false'
)

