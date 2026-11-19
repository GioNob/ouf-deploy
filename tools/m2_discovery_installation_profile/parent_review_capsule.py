"""Independent sealed six-part review compiler, including pinned public helpers."""
import base64,hashlib,json,re
from pathlib import Path
from .private_review_capsule import BASELINE,BASELINE_HASH,RUNTIME as LEGACY_RUNTIME
from .publication_primitives import GATEWAY,ONBOARDING

ENTRY='tools.m2_discovery_installation_profile.parent_review'
SOURCE_MANIFEST='tools/m2_discovery_installation_profile/parent_review_sources.json'
SOURCE_MANIFEST_HASH='eaacfca7912e094b77f11528473bdcfe493bcf31f7eb50dee26d6d73bea7e36a'
LOADER_HASH='242cce9f329499d68941732dca2e08c4f4c5fc76e751b589367b4c7e360ea8bc'
RUNTIME=LEGACY_RUNTIME.replace("set(payload)=={'sources','baseline'}", "set(payload)=={'sources','baseline','publicationSources'}")\
    .replace("return importlib.import_module(MANIFEST['entryModule']),baseline", """module=importlib.import_module(MANIFEST['entryModule'])
    from tools.m2_discovery_installation_profile.publication_primitives import PublicationPrimitives
    resources=payload['publicationSources'];require(set(resources)=={'gateway','onboarding'})
    primitives=PublicationPrimitives({k:v.encode() for k,v in resources['gateway'].items()},
        {k:v.encode() for k,v in resources['onboarding'].items()})
    return module,baseline,primitives""")\
    .replace('module,baseline=load()','module,baseline,primitives=load()')\
    .replace("'CLOSED_PRIVATE_REVIEW_CAPSULE'", "'CLOSED_COMPLETE_PARENT_REVIEW_CAPSULE'")\
    .replace('args.output_directory,baseline,','args.output_directory,baseline,primitives,')\
    .replace('PRIVATE_REVIEW_FRAGMENT_PREPARED_NOT_AUTHENTICATED','COMPLETE_PARENT_REVIEW_PREPARED_NOT_AUTHENTICATED')\
    .replace('PRIVATE_REVIEW_PREPARATION_UNPROVEN','COMPLETE_PARENT_REVIEW_PREPARATION_UNPROVEN')


def build(root,source_revision,gateway_root,onboarding_root):
    def require(ok):
        if not ok:raise ValueError('EXACT_COMPLETE_PARENT_REVIEW_COMPILER_SOURCE_REQUIRED')
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}',source_revision))
    require(hashlib.sha256(RUNTIME.encode()).hexdigest()==LOADER_HASH)
    root=Path(root);raw_pins=(root/SOURCE_MANIFEST).read_bytes()
    require(hashlib.sha256(raw_pins).hexdigest()==SOURCE_MANIFEST_HASH)
    pins=json.loads(raw_pins);require(ENTRY in pins and 1<=len(pins)<=192)
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
    manifest={'schema':'ouf.discovery-complete-parent-review-capsule.v1','entryModule':ENTRY,
        'loaderTemplateSha256':LOADER_HASH,'sourceRevisionClaim':source_revision,'sourceRevisionClaimAuthenticated':False,
        'sources':pins,'publicationSourceHashes':{'gateway':GATEWAY,'onboarding':ONBOARDING},
        'payloadSha256':hashlib.sha256(payload).hexdigest(),'baselineSha256':BASELINE_HASH,
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'publisherTrustAccepted':False,'releaseAcceptance':False}
    raw=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(payload).decode())).encode()
    require(len(raw)<=8388608);compile(raw,'<complete-parent-review-capsule>','exec');return raw,manifest
