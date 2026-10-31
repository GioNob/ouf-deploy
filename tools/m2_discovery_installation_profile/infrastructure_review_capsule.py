"""Package the independent infrastructure fragment compiler, never authority.

Keep the earlier four-owner compiler and operational-worker closures unchanged.
The revision claim is provenance only. Exact source/loader hashes and the whole
generated capsule still require independent review before private input access.
"""
import base64,hashlib,json,re
from pathlib import Path
from .private_review_capsule import BASELINE,BASELINE_HASH,RUNTIME

ENTRY='tools.m2_discovery_installation_profile.infrastructure_review'
SOURCE_MANIFEST='tools/m2_discovery_installation_profile/infrastructure_review_sources.json'
SOURCE_MANIFEST_HASH='649322a5fa52193ca1b12efdf03901c0f30485a3051216465ebee299b40f778b'
LOADER_HASH='6c12561e3cedc6e5faacd87a8c0acbfbe7408b3da9841e5907012fc02fd67c8f'


def build(root,source_revision):
    def require(ok):
        if not ok:raise ValueError('EXACT_INFRASTRUCTURE_REVIEW_SOURCE_REQUIRED')
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}',source_revision) is not None)
    require(hashlib.sha256(RUNTIME.encode()).hexdigest()==LOADER_HASH)
    root=Path(root);raw_pins=(root/SOURCE_MANIFEST).read_bytes()
    require(hashlib.sha256(raw_pins).hexdigest()==SOURCE_MANIFEST_HASH)
    pins=json.loads(raw_pins);require(ENTRY in pins and 1<=len(pins)<=192)
    sources={}
    for name,binding in pins.items():
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_.]*',name) is not None
            and set(binding)=={'path','sha256'} and not Path(binding['path']).is_absolute()
            and '..' not in Path(binding['path']).parts)
        raw=(root/binding['path']).read_bytes();require(hashlib.sha256(raw).hexdigest()==binding['sha256'])
        sources[name]=raw.decode('utf-8')
    baseline=(root/BASELINE).read_bytes();require(hashlib.sha256(baseline).hexdigest()==BASELINE_HASH)
    payload=json.dumps({'sources':sources,'baseline':base64.b64encode(baseline).decode()},
        sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    require(len(payload)<=4194304)
    manifest={'schema':'ouf.discovery-infrastructure-review-capsule.v1','entryModule':ENTRY,
        'loaderTemplateSha256':LOADER_HASH,'sourceRevisionClaim':source_revision,
        'sourceRevisionClaimAuthenticated':False,'sources':pins,'payloadSha256':hashlib.sha256(payload).hexdigest(),
        'baselineSha256':BASELINE_HASH,'completeParentReview':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'publisherTrustAccepted':False,'releaseAcceptance':False}
    raw=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(payload).decode())).encode()
    require(len(raw)<=8388608);compile(raw,'<infrastructure-review-capsule>','exec')
    return raw,manifest
