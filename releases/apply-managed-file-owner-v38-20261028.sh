#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
operator_uid=$(id -u)
if [[ $operator_uid == 0 ]]; then printf '%s\n' 'STOP: eseguire come oufadmin, non root.'; exit 2; fi
if [[ ! -t 0 || ! -t 1 ]]; then printf '%s\n' 'STOP: serve il terminale SSH interattivo; nessuna pipe per il controller.'; exit 2; fi
delivery=$(mktemp -d "$HOME/ouf-managed-file-owner-v38-update-delivery.XXXXXXXX")
chmod 0700 "$delivery"
delivery_log="$delivery/bootstrap.log"
trap 'delivery_exit=$?; trap - EXIT; printf "DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n" "$delivery_exit" "$delivery" "$delivery_log" | tee -a "$delivery_log"; exit "$delivery_exit"' EXIT
code_commit=a9b5904c772c6cf93e34545163e72af5e6b4941f
code_root=/usr/local/lib/ouf-managed-file-owner-v38-update-f00094e876add2eb
paths=(scripts/apply-managed-file-owner-v38-20261028.py
  tools/managed_file_owner_update/authority.py
  tools/managed_file_owner_update/context.py
  tools/managed_file_owner_update/ports.py
  tools/managed_file_owner_update/state_fence.py
  tools/onboarding_profile_recovery_update/database.py
  tools/acquisition_redaction_update/context.py
  tools/acquisition_redaction_update/ports.py
  tools/onboarding_profile_recovery_update/context.py
  tools/onboarding_profile_recovery_update/database.py
  tools/onboarding_profile_recovery_update/state_fence.py
  tools/onboarding_profile_recovery_update/backup.py
  tools/onboarding_profile_recovery_update/transport.py
  tools/mcp_diagnostic_update/transport.py
  tools/acquisition_redaction_update/quarantine.py
  tools/acquisition_read_native/recovery_journal.py
  tools/acquisition_read_native/engine_creation.py
  tools/acquisition_read_native/plan_helper.py
  tools/acquisition_read_native/image_custody.py
  tools/acquisition_read_native/retained_mac.py
  tools/human_terminal_line_review.py
  tools/source_revision_update/configuration.py
  tools/acquisition_read_native/vendor/semantic_provider_deployment_authentication.py
  tools/acquisition_read_native/vendor/semantic_provider_deployment_signing.py
  tools/acquisition_read_native/vendor/semantic_provider_deployment_protocol.py
  tools/acquisition_read_native/vendor/semantic_provider_preexec.py
  tools/acquisition_read_native/vendor/semantic_provider_deployment_producer.py
  tools/acquisition_read_native/vendor/runtime_binding_source.py
  tools/managed_csv_control_update/authority.py
  tools/managed_csv_control_update/context.py
  tools/managed_csv_control_update/ports.py)
names=(entry.py authority.py context.py ports.py state_fence.py database.py base_context.py base_ports.py onb_context.py base_database.py base_state_fence.py backup.py transport.py mcp_transport.py quarantine.py recovery_journal.py engine_creation.py plan_helper.py image_custody.py retained_mac.py terminal.py configuration.py authentication.py signing.py auth_protocol.py auth_preexec.py auth_producer.py runtime_binding.py base_authority.py control_context.py control_ports.py)
transfer_started=$SECONDS
for index in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if (( SECONDS-transfer_started >= 180 )); then printf '%s\n' 'STOP: trasferimento codice fuori finestra.'; exit 2; fi
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 10 --max-time 20 --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/$code_commit/${paths[$index]}" -o "$delivery/${names[$index]}"
done
sudo /usr/bin/python3 -I -S -B - "$delivery" "$operator_uid" <<'PY' 2>&1 | tee -a "$delivery_log"
import hashlib,json,os,pwd,stat,sys
folder,owner=sys.argv[1],int(sys.argv[2]);directory='/usr/local/lib/ouf-managed-file-owner-v38-update-f00094e876add2eb';scope='/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1'
specs=[{"name":"entry.py","path":"scripts/apply-managed-file-owner-v38-20261028.py","sha256":"f448de9b7b3709d87b733a01af72b9bb611c8dc75264c99d73f45cbe0d60ff7a"},{"name":"authority.py","path":"tools/managed_file_owner_update/authority.py","sha256":"0bacdb5fd3a97bad955bde955aa81191df3b7731ca66eb98cc2d88d62b2b2954"},{"name":"context.py","path":"tools/managed_file_owner_update/context.py","sha256":"346a0fc71265c16978b393142379aaeed9e4a9a682bb5abf476012f8575beaa4"},{"name":"ports.py","path":"tools/managed_file_owner_update/ports.py","sha256":"124a45f371f0277c47b3ceaf4307f05b7b76a039ef9fca02282259364b3b96a9"},{"name":"state_fence.py","path":"tools/managed_file_owner_update/state_fence.py","sha256":"a53f8beb1e77b31d25fbbdb83e57e14f70d17f7673221a5d870f116a9755951d"},{"name":"database.py","path":"tools/onboarding_profile_recovery_update/database.py","sha256":"973e7f786fbf81fa9856361276e1eeb4b38a9e4b46ea521b84f73f3232c9741e"},{"name":"base_context.py","path":"tools/acquisition_redaction_update/context.py","sha256":"c9cbb80177ca5ef74808e3c3fee3a7980450999232b95017179b421fef0ad3b1"},{"name":"base_ports.py","path":"tools/acquisition_redaction_update/ports.py","sha256":"03520c943f217a8fd561f3317e775c8ad43dd3e3a877ed6e6928e666eb673d57"},{"name":"onb_context.py","path":"tools/onboarding_profile_recovery_update/context.py","sha256":"2333fecb92a20ca2d6d041087045f07f604aeab50fd66240483a63350bd66b36"},{"name":"base_database.py","path":"tools/onboarding_profile_recovery_update/database.py","sha256":"973e7f786fbf81fa9856361276e1eeb4b38a9e4b46ea521b84f73f3232c9741e"},{"name":"base_state_fence.py","path":"tools/onboarding_profile_recovery_update/state_fence.py","sha256":"3acf0e82bf75333a65bd6ec613851b051d6ad20eeab52b848af60b24d9d79173"},{"name":"backup.py","path":"tools/onboarding_profile_recovery_update/backup.py","sha256":"2ba21542461887d206ee153599618357e7d061ea0c6524a635ebe57a62a5b2a9"},{"name":"transport.py","path":"tools/onboarding_profile_recovery_update/transport.py","sha256":"3fc1f9243f739f47403ee8f6e8eec0d9a731160e9530b75e4a4c44055d8596dd"},{"name":"mcp_transport.py","path":"tools/mcp_diagnostic_update/transport.py","sha256":"d0c833ffb04b687f81f88b1d9e4c92b5dffa1119e9f03332af68803a0e0c8377"},{"name":"quarantine.py","path":"tools/acquisition_redaction_update/quarantine.py","sha256":"c58b65422fece936855720b879d0946b45bda701c3e5d57359d9f089550249a9"},{"name":"recovery_journal.py","path":"tools/acquisition_read_native/recovery_journal.py","sha256":"8050144514a60ba19e71650bb8320887fe1be763a333058c21d6e2c3a789a162"},{"name":"engine_creation.py","path":"tools/acquisition_read_native/engine_creation.py","sha256":"9d6149a0b3331666496583ebbaa9f43ed05d3039e7097861f3bd147f917ab3fb"},{"name":"plan_helper.py","path":"tools/acquisition_read_native/plan_helper.py","sha256":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd"},{"name":"image_custody.py","path":"tools/acquisition_read_native/image_custody.py","sha256":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8"},{"name":"retained_mac.py","path":"tools/acquisition_read_native/retained_mac.py","sha256":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"},{"name":"terminal.py","path":"tools/human_terminal_line_review.py","sha256":"3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5"},{"name":"configuration.py","path":"tools/source_revision_update/configuration.py","sha256":"29d2df483ba5336374668633c9745072a20670d6f267aede8cab975c1dd2a429"},{"name":"authentication.py","path":"tools/acquisition_read_native/vendor/semantic_provider_deployment_authentication.py","sha256":"7cb06f7976791abfc1ffac0e9660f3cdf603347f4514cd2bab7f55c6574e251d"},{"name":"signing.py","path":"tools/acquisition_read_native/vendor/semantic_provider_deployment_signing.py","sha256":"81ad864e90b3efe17d65534ad4b1ccc187e60954f4f5d6244968d7809303a38f"},{"name":"auth_protocol.py","path":"tools/acquisition_read_native/vendor/semantic_provider_deployment_protocol.py","sha256":"cd5aa30c8c806942c53a306e76a641b876e07a12fbbc3c0d106ecf6b94e87a0d"},{"name":"auth_preexec.py","path":"tools/acquisition_read_native/vendor/semantic_provider_preexec.py","sha256":"95da7f53be88ac0e602e03acbdf6940a719e96a6fedb207693d23f59f0b31015"},{"name":"auth_producer.py","path":"tools/acquisition_read_native/vendor/semantic_provider_deployment_producer.py","sha256":"dbfb365087fb532a0df66f66b6d72be7e04e2df4f31116631beb0b20a9f6f50f"},{"name":"runtime_binding.py","path":"tools/acquisition_read_native/vendor/runtime_binding_source.py","sha256":"291daecc2b541a7c7410cd9f7c22ec7fccc82568ae67b21b78148f939035c7de"},{"name":"base_authority.py","path":"tools/managed_csv_control_update/authority.py","sha256":"322692ff64e49a60d3305d7f94abd592188634e449eca2a5853e943b3133645a"},{"name":"control_context.py","path":"tools/managed_csv_control_update/context.py","sha256":"df86aad83a0a739d407d1fc8002ae7472d2c99ea3851473462be7d1965d2d586"},{"name":"control_ports.py","path":"tools/managed_csv_control_update/ports.py","sha256":"8d79807b7e09118201a774b842bbc08d9ffbc8c489ce57da4e6647d31910568c"}]
if os.geteuid()!=os.getegid()or os.geteuid()!=0 or owner!=pwd.getpwnam('oufadmin').pw_uid or owner<=0:
    raise SystemExit('STOP: identita operatore/root non valida')
if os.path.lexists(scope)or os.path.lexists(directory):
    raise SystemExit('STOP: consegna o esecuzione consumata; conservare prove, nessun rilancio')
for path in ('/','/usr','/usr/local','/usr/local/lib'):
    row=os.lstat(path)
    if not stat.S_ISDIR(row.st_mode)or row.st_uid!=row.st_gid or row.st_uid!=0 or row.st_mode&0o022:
        raise SystemExit('STOP: custodia codice root non valida')
frame=lambda row:(row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
raws={}
for spec in specs:
    path=os.path.join(folder,spec['name']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode)or before.st_uid!=owner or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=131072:
            raise SystemExit('STOP: fonte scaricata non valida')
        raw=os.read(fd,131073)
        if frame(before)!=frame(os.fstat(fd))or frame(before)!=frame(os.lstat(path))or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=spec['sha256']:
            raise SystemExit('STOP: checksum/custodia fonte non validi')
        raws[spec['name']]=raw
    finally:os.close(fd)
manifest=json.dumps({s['name']:s['sha256']for s in specs},sort_keys=True,separators=(',',':')).encode()
if hashlib.sha256(manifest).hexdigest()!='f00094e876add2eb729ef72dc83d60e446622bf6dead33b2992ad8f6d4b6a450':raise SystemExit('STOP: chiusura codice non valida')
os.mkdir(directory,0o700)
for name,raw in [*raws.items(),('sources.json',manifest)]:
    target=os.path.join(directory,name);fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        row=os.fstat(fd)
        if row.st_uid!=row.st_gid or row.st_uid!=0 or row.st_nlink!=1 or stat.S_IMODE(row.st_mode)!=0o400 or hashlib.sha256(os.read(fd,131073)).hexdigest()!=hashlib.sha256(raw).hexdigest():
            raise SystemExit('STOP: copia root non verificata')
    finally:os.close(fd)
    print(target+': OK (root0400; checksum ROOT)')
for path in (directory,'/usr/local/lib'):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
print('ProtectedCode='+directory+'/entry.py')
print('RuntimeLog='+directory+'/operator.log')
PY
printf '%s\n' 'Nuovo controller SOLO Onboarding36-38,pianob03d681a/05e1398d,12peer invariati. Review fresca prima di firme/7SQL READ ONLY/import/lifecycle;backup quiescente e due migrazioni del solo owner. Attendere review/riga APPROVO sul TTY. Zero ownership/grant/budget/resume/job/upload/acquisizioni. SeSTOP conservare prove e non rilanciare.' | tee -a "$delivery_log"
set +e
# Stdio resta direttamente sul TTY: il Logger root conserva l output; nessuna pipe/consenso nella consegna.
sudo /usr/bin/python3 -I -S -B "$code_root/entry.py"
apply_exit=$?
set -e
printf 'Exit=%s\nDirectory=%s\nLog=%s\nRuntimeLog=%s\n' "$apply_exit" "$delivery" "$delivery_log" "$code_root/operator.log" | tee -a "$delivery_log"
exit "$apply_exit"
