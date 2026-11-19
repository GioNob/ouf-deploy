"""Explicit retained binding encodings; never rewrite the selected hash."""
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import require,digest

NATIVE='ouf.runtime-binding.native-mount-order.v1'
SORTED='ouf.runtime-binding.mounts-sorted-destination.v1'
PROFILES={NATIVE,SORTED}

def observed(actual,profile):
    require(profile in PROFILES,'EXACT_RETAINED_RUNTIME_BINDING_PROFILE_REQUIRED')
    mounts=actual['Mounts']
    require(type(mounts)is list and all(type(m)is dict and type(m.get('Destination'))is str for m in mounts)
            and len({m['Destination']for m in mounts})==len(mounts),'UNIQUE_RUNTIME_MOUNT_DESTINATIONS_REQUIRED')
    value=Engine.runtime_binding(actual)
    if profile==SORTED:value['mountsHash']=digest(sorted(mounts,key=lambda m:m['Destination']))
    return value
