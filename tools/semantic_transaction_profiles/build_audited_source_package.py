"""Pure assembly of one coherent recovery package from retained pinned bytes.

Reuse the original 39 source/utility files and observer. Only three utilities,
the reviewed entry and seven explicitly repaired runtime files change. No IO,
target acceptance, keys, signatures, installation or runtime operation here.
"""
import hashlib
import json

from repair_broker_sources import repair as repair_broker
from repair_admission_transport import repair as repair_transport

ORIGINAL_MANIFEST = '2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4'
ENTRY_SHA = 'f81d8ec23d551acb2419aaefa0c2a4531de4de6219758e263496c228cfa4570d'
ENTRY_MANIFEST = '9ecd16cd04d86c68947b127e845cde7f5fc4170eaf02a9043989f3bf4409bf67'
OLD_WRAPPER = '4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd'
PRIOR_WRAPPER = 'cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b'
REPLACEMENTS = {
    'utility/publish_provider_transaction.py':'7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080',
    'utility/guarded_runtime_switch.py':'1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd',
    'utility/authenticated_runtime_switch.py':'ce5625aa645b3da470e84b8544adfa82d5bca8665bb88d8e2d49fd3701548d83'}


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(ok,reason):
    if not ok: raise ValueError(reason)


def build(manifest_raw, original, replacement_utilities, reviewed_entry):
    require(sha(manifest_raw)==ORIGINAL_MANIFEST,'ORIGINAL_INTAKE_MANIFEST_DRIFT')
    manifest=json.loads(manifest_raw)
    require(set(original)==set(manifest['sourceHashes']),'EXACT_ORIGINAL_SOURCE_FILES_REQUIRED')
    require(all(type(raw) is bytes and sha(raw)==manifest['sourceHashes'][name] for name,raw in original.items()),
            'ORIGINAL_INTAKE_SOURCE_DRIFT')
    require(set(replacement_utilities)==set(REPLACEMENTS) and all(sha(raw)==REPLACEMENTS[name]
            for name,raw in replacement_utilities.items()),'EXACT_REVIEWED_PUBLICATION_UTILITIES_REQUIRED')
    require(sha(reviewed_entry)==ENTRY_SHA,'REVIEWED_ENTRY_SOURCE_DRIFT')
    sources={name.removeprefix('source/'):raw for name,raw in original.items() if name.startswith('source/')}
    revised=repair_transport(repair_broker(sources))
    result={**original,**replacement_utilities,**{'source/'+name:raw for name,raw in revised.items()}}
    manifest={**manifest,'sourceHashes':{name:sha(raw) for name,raw in result.items()}}
    raw=encoded(manifest);manifest_hash=sha(raw)
    require(reviewed_entry.count(ENTRY_MANIFEST.encode())==1 and reviewed_entry.count(OLD_WRAPPER.encode())==2,
            'EXACT_REVIEWED_ENTRY_PATCH_SITES_REQUIRED')
    entry=reviewed_entry.replace(ENTRY_MANIFEST.encode(),manifest_hash.encode()).replace(OLD_WRAPPER.encode(),PRIOR_WRAPPER.encode())
    compile(entry,'provider_transaction_intake.py','exec')
    result.update({'intake-source-closure.json':raw,'provider_transaction_intake.py':entry})
    closure=sha(encoded({**{name:sha(raw) for name,raw in revised.items()},'frame-observer.py':sha(original['frame-observer.py'])}))
    return {'files':result,'manifestHash':manifest_hash,'entryHash':sha(entry),'sourceClosureHash':closure,
        'changedRuntimeFiles':sorted(name for name,raw in revised.items() if raw!=sources[name]),
        'changedUtilities':sorted(REPLACEMENTS),'notReleaseAcceptance':True,'startAuthorized':False}
