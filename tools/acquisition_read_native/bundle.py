"""Build the exact source closure; packaging only, no runtime/keys/network."""
import hashlib,json,os
from pathlib import Path
FILES={'recovery.py':'scripts/recover-acquisition-detached-mcp-20261025.py','retained_mac.py':'tools/acquisition_read_native/retained_mac.py','continuation.py':'scripts/continue-acquisition-unapproved-review-20261025.py','apply.py':'scripts/apply-acquisition-read-native-20261025.py','native_prepare.py':'scripts/prepare-acquisition-read-native-execution-20261025.py','runtime_binding.py':'tools/acquisition_read_native/vendor/runtime_binding_source.py',**{n+'.py':'tools/acquisition_read_native/'+n+'.py'for n in('protocol','transport','ports','quarantine','recovery_journal','engine_creation','plan_helper','image_custody')},**{out+'.py':'tools/acquisition_read_native/vendor/'+src+'.py'for out,src in(('authentication','semantic_provider_deployment_authentication'),('signing','semantic_provider_deployment_signing'),('auth_protocol','semantic_provider_deployment_protocol'),('auth_preexec','semantic_provider_preexec'),('auth_producer','semantic_provider_deployment_producer'))}}
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def stage(repository,target):
    target=Path(target);target.mkdir(mode=0o700);manifest={}
    for name,path in FILES.items():
        raw=(Path(repository)/path).read_bytes();manifest[name]=hashlib.sha256(raw).hexdigest();fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
        finally:os.close(fd)
    raw=encoded(manifest);(target/'sources.json').write_bytes(raw);(target/'sources.json').chmod(0o400);return manifest
