"""Closed source packaging for ONBOARDING-only updater. No target entrypoint invoked."""
import hashlib,json,os
from pathlib import Path
FILES={'entry.py':'scripts/apply-onboarding-profile-recovery-update-20261027.py',
       **{n+'.py':'tools/onboarding_profile_recovery_update/'+n+'.py'for n in('authority','context','transport','ports','quarantine','state_fence','database','backup')},
       **{n+'.py':'tools/acquisition_read_native/'+n+'.py'for n in('recovery_journal','engine_creation','plan_helper','image_custody','retained_mac')},
       'migration-fence.json':'releases/onboarding-profile-recovery-migration-fence-20261027.json',
       'terminal.py':'tools/human_terminal_line_review.py',
       'configuration.py':'tools/source_revision_update/configuration.py',
       **{out+'.py':'tools/acquisition_read_native/vendor/'+src+'.py'for out,src in(('authentication','semantic_provider_deployment_authentication'),('signing','semantic_provider_deployment_signing'),('auth_protocol','semantic_provider_deployment_protocol'),('auth_preexec','semantic_provider_preexec'),('auth_producer','semantic_provider_deployment_producer'),('runtime_binding','runtime_binding_source'))}}
def stage(repository,target):
    target=Path(target);target.mkdir(mode=0o700);target.chmod(0o700);manifest={}
    def put(name,raw):
        fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(fd,'wb')as stream:
            os.fchmod(stream.fileno(),0o400);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    for name,path in FILES.items():
        raw=(Path(repository)/path).read_bytes();manifest[name]=hashlib.sha256(raw).hexdigest();put(name,raw)
    put('sources.json',json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
    fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return manifest

