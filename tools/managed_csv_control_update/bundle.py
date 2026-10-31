"""Seal new adapters with unchanged qualified Teatri/V36 building blocks."""
import hashlib
import json
import os
from pathlib import Path

FILES = {
    'entry.py': 'scripts/apply-managed-csv-control-update-20261027.py',
    **{name+'.py': 'tools/managed_csv_control_update/'+name+'.py' for name in ('authority', 'context', 'ports', 'state_fence', 'database')},
    **{'base_'+name+'.py': 'tools/acquisition_redaction_update/'+name+'.py' for name in ('context', 'ports')},
    'onb_context.py': 'tools/onboarding_profile_recovery_update/context.py',
    'base_database.py': 'tools/onboarding_profile_recovery_update/database.py',
    'base_state_fence.py': 'tools/onboarding_profile_recovery_update/state_fence.py',
    'backup.py': 'tools/onboarding_profile_recovery_update/backup.py',
    'transport.py': 'tools/onboarding_profile_recovery_update/transport.py',
    'mcp_transport.py': 'tools/mcp_diagnostic_update/transport.py',
    'quarantine.py': 'tools/acquisition_redaction_update/quarantine.py',
    **{name+'.py': 'tools/acquisition_read_native/'+name+'.py' for name in ('recovery_journal', 'engine_creation', 'plan_helper', 'image_custody', 'retained_mac')},
    'terminal.py': 'tools/human_terminal_line_review.py',
    'configuration.py': 'tools/source_revision_update/configuration.py',
    **{out+'.py': 'tools/acquisition_read_native/vendor/'+source+'.py' for out, source in (
        ('authentication', 'semantic_provider_deployment_authentication'), ('signing', 'semantic_provider_deployment_signing'),
        ('auth_protocol', 'semantic_provider_deployment_protocol'), ('auth_preexec', 'semantic_provider_preexec'),
        ('auth_producer', 'semantic_provider_deployment_producer'), ('runtime_binding', 'runtime_binding_source'))}}


def stage(repository, target):
    target = Path(target); target.mkdir(mode=0o700); target.chmod(0o700); manifest = {}
    def put(name, raw):
        fd = os.open(target/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o400); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    for name, path in FILES.items():
        raw = (Path(repository)/path).read_bytes(); manifest[name] = hashlib.sha256(raw).hexdigest(); put(name, raw)
    put('sources.json', json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest
