"""Separate closed compiler; never rewrite frozen 37/108/128/136 closures."""
import base64,hashlib,json,re
from pathlib import Path
from .parent_review_capsule import BASELINE,BASELINE_HASH,RUNTIME as PARENT_RUNTIME
from .parent_review_capsule import SOURCE_MANIFEST as PARENT_SOURCES,SOURCE_MANIFEST_HASH as PARENT_SOURCES_HASH
from .parent_review_capsule import LOADER_HASH as PARENT_LOADER_HASH
from .publication_primitives import GATEWAY,ONBOARDING

ENTRY='tools.m2_discovery_installation_profile.current_review'
SOURCE_MANIFEST='tools/m2_discovery_installation_profile/current_review_sources.json'
SOURCE_MANIFEST_HASH='400910ada6d480cf5e7c788a28f0760bc9e95e5c373ba40a7b041c04d28b3918'
RUNTIME=PARENT_RUNTIME.replace('CLOSED_COMPLETE_PARENT_REVIEW_CAPSULE','CLOSED_CURRENT_PARENT_REVIEW_CAPSULE')\
    .replace('COMPLETE_PARENT_REVIEW_PREPARED_NOT_AUTHENTICATED','CURRENT_PARENT_REVIEW_PREPARED_NOT_AUTHENTICATED')\
    .replace('COMPLETE_PARENT_REVIEW_PREPARATION_UNPROVEN','CURRENT_PARENT_REVIEW_PREPARATION_UNPROVEN')
LOADER_HASH='7b722e5c95f0365238e6e77053ab06f40d620b5e3ed74ad6ff45f85c0a68f73d'


def build(root,source_revision,gateway_root,onboarding_root):
    def require(ok):
        if not ok:raise ValueError('EXACT_CURRENT_PARENT_REVIEW_COMPILER_SOURCE_REQUIRED')
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}',source_revision))
    require(hashlib.sha256(PARENT_RUNTIME.encode()).hexdigest()==PARENT_LOADER_HASH
        and hashlib.sha256(RUNTIME.encode()).hexdigest()==LOADER_HASH)
    root=Path(root);raw_pins=(root/SOURCE_MANIFEST).read_bytes();parent_raw=(root/PARENT_SOURCES).read_bytes()
    require(hashlib.sha256(raw_pins).hexdigest()==SOURCE_MANIFEST_HASH
        and hashlib.sha256(parent_raw).hexdigest()==PARENT_SOURCES_HASH)
    pins=json.loads(raw_pins);parents=json.loads(parent_raw)
    require(ENTRY in pins and 1<=len(pins)<=256 and all(pins.get(k)==v for k,v in parents.items()))
    sources={}
    for name,binding in pins.items():
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_.]*',name) and set(binding)=={'path','sha256'}
            and not Path(binding['path']).is_absolute() and '..' not in Path(binding['path']).parts)
        raw=(root/binding['path']).read_bytes();require(hashlib.sha256(raw).hexdigest()==binding['sha256'])
        sources[name]=raw.decode('utf-8')
    baseline=(root/BASELINE).read_bytes();require(hashlib.sha256(baseline).hexdigest()==BASELINE_HASH)
    gateway={p:(Path(gateway_root)/p).read_bytes() for p in GATEWAY}
    owner={p:(root/p if p.startswith('catalogue/') else Path(onboarding_root)/p).read_bytes() for p in ONBOARDING}
    for rows,expected in ((gateway,GATEWAY),(owner,ONBOARDING)):
        require(set(rows)==set(expected) and all(0<len(v)<=131072
            and hashlib.sha256(v).hexdigest()==expected[k] for k,v in rows.items()))
    resources={'gateway':{k:v.decode() for k,v in gateway.items()},'onboarding':{k:v.decode() for k,v in owner.items()}}
    payload=json.dumps({'sources':sources,'baseline':base64.b64encode(baseline).decode(),'publicationSources':resources},
        sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();require(len(payload)<=4194304)
    manifest={'schema':'ouf.discovery-current-parent-review-capsule.v1','entryModule':ENTRY,
        'loaderTemplateSha256':LOADER_HASH,'sourceRevisionClaim':source_revision,'sourceRevisionClaimAuthenticated':False,
        'sources':pins,'frozenParentSourceManifestHash':PARENT_SOURCES_HASH,
        'publicationSourceHashes':{'gateway':GATEWAY,'onboarding':ONBOARDING},
        'payloadSha256':hashlib.sha256(payload).hexdigest(),'baselineSha256':BASELINE_HASH,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'publisherTrustAccepted':False,'releaseAcceptance':False}
    raw=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(payload).decode())).encode()
    require(len(raw)<=8388608);compile(raw,'<current-parent-review-capsule>','exec');return raw,manifest
