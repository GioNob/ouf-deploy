#!/usr/bin/env bash
# Runbook B1 (sprint-01 task-25) per l'umano sul VPS: evita di incollare comandi lunghi.
# Uso:  bash b1-install.sh plan
#       bash b1-install.sh apply <planSha256>     (solo dopo D-025: annullamento pronto)
# Tutti i valori sono pubblici (path e hash); nessun segreto.
set -euo pipefail
umask 077

mode=${1:-}
case "$mode" in
  plan) extra=(--plan) ;;
  apply)
    [[ "${2:-}" =~ ^[0-9a-f]{64}$ ]] || { echo 'uso: apply <planSha256>' >&2; exit 2; }
    extra=(--apply --plan-sha256 "$2") ;;
  *) echo 'uso: plan | apply <planSha256>' >&2; exit 2 ;;
esac

C=0edc8613281dd7f7a7952ec52087d651c8b0c38f
L=5b778fac3d7e267725feb2f4709650358d9fbc13614609845889aec5f9ca65e9
S=/etc/ouf/deploy-snapshots
SD=/etc/systemd/system
ST=/var/lib/ouf-storage-migration
AC=$S/semantic-provider-b1-acceptance-20261114-v2
PL=65abb93002808a987ce2d8bbef266de68dc89ae569a28a89b0e87f16034c4803

work=$(mktemp -d)
curl --fail --silent --show-error --proto '=https' --tlsv1.2 -o "$work/deliver.sh" \
  "https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/scripts/deliver-semantic-provider-b1-install.sh"
printf '%s  %s\n' "$L" "$work/deliver.sh" | sha256sum --check

args=(
  --installation-ref ouf-lab-netcup-01
  --installation-root /etc/ouf/installations
  --a-root "$ST/semantic-provider-preparation-a2-20261113"
  --a-plan-sha256 a435f29bd107fbb61d4f5d3ca594e42d2851a82beadeafb1aef13bcbe997cad2
  --guard-pointer /etc/ouf/coordinated-boot-installation.json
  --docker-socket /run/docker.sock
  --docker-socket-activation systemd-socket
  --docker-socket-unit docker.socket
  --docker-service-unit docker.service
  --docker-socket-owner root
  --docker-socket-group docker
  --docker-socket-mode 0660
  --dockerd /usr/bin/dockerd
  --guard-service-unit ouf-semantic-boot-guard.service
  --guard-service-file "$SD/ouf-semantic-boot-guard.service"
  --docker-drop-in-file "$SD/docker.service.d/90-ouf-semantic-boot-guard.conf"
  --generation-receipt "$ST/discovery-generation-inputs-cv_hy837/result.json"
  --generation-receipt-sha256 8c6d8eb8ae5dd47b9a12d304f53d02ad1e09afad61dfa28282ccda482182af15
  --authority-profile "$S/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json"
  --authority-sha256 7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18
  --trust-policy "$S/semantic-trust-policy-preparation-20261004-172336/trust-policy.json"
  --trust-policy-sha256 21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42
  --p-profile-sha256 5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d
  --acceptance-manifest "$AC/manifest.json"
  --acceptance-manifest-sha256 "$PL"
  --acceptance-signature "$AC/$PL.ARTIFACT_ACCEPTANCE.json"
  --acceptance-signature-sha256 786d265e360a2e02fb6dc612c4e894418be02cc50fb2f3a941c67091ba0a8a87
  --b1b2-trust-policy "$S/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json"
  --b1b2-trust-policy-sha256 6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95
  --openssl /usr/bin/openssl
  --openssl-sha256 acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549
  --openssl-version 3.5.7
  --arming-issuer-ref ouf-lab-infrastructure-installer
  --bundle-parent /run/containerd/io.containerd.runtime.v2.task/moby
  --output-root "$S"
  --output-name semantic-provider-b1-install-20261114-v1
)
bash "$work/deliver.sh" "${extra[@]}" "${args[@]}"
