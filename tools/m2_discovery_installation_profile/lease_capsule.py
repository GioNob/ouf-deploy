"""Pure compiler for an exact installed lease runtime; no installation authority."""
import base64,hashlib,json
from pathlib import Path

SOURCE='92803ea99658c1aeba631bf4cc9ef3f9090098fe'
PINS={'adaptive_supervisor': {'path': 'tools/semantic_lease_recovery/adaptive_supervisor.py', 'sha256': '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c'}, 'bounded_recovery': {'path': 'tools/semantic_lease_recovery/bounded_recovery.py', 'sha256': 'ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd'}, 'continuous_supervisor': {'path': 'tools/semantic_lease_recovery/continuous_supervisor.py', 'sha256': '8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e'}, 'deadline_backend': {'path': 'tools/semantic_lease_recovery/deadline_backend.py', 'sha256': '9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2'}, 'dns': {'path': 'tools/semantic_lease_recovery/dns.py', 'sha256': 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f'}, 'lease_recovery_budget': {'path': 'tools/semantic_lease_recovery/lease_recovery_budget.py', 'sha256': 'c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf'}, 'nft_seconds_backend': {'path': 'tools/semantic_lease_recovery/nft_seconds_backend.py', 'sha256': '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1'}, 'readback_margin_compiler': {'path': 'tools/semantic_lease_recovery/readback_margin_compiler.py', 'sha256': '814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d'}, 'recovery_journal': {'path': 'tools/semantic_lease_recovery/recovery_journal.py', 'sha256': '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d'}, 'resilient_lease_adapter': {'path': 'tools/semantic_lease_recovery/resilient_lease_adapter.py', 'sha256': 'beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683'}, 'tools.m2_discovery_installation_profile.custody_capture': {'path': 'tools/m2_discovery_installation_profile/custody_capture.py', 'sha256': '834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf'}, 'tools.m2_discovery_installation_profile.installed_lease_guard': {'path': 'tools/m2_discovery_installation_profile/installed_lease_guard.py', 'sha256': '71b1a3fc64d31808e48c4c8550c6bc3354d2a7a3dcda5569c348dc00fd47c4af'}, 'tools.m2_discovery_installation_profile.installed_lease_session': {'path': 'tools/m2_discovery_installation_profile/installed_lease_session.py', 'sha256': 'ea90863b14ba697e8c23a2c4a6dad7475ad1cd2c5a7ded5b6ddb813e2310e5fa'}, 'tools.m2_discovery_installation_profile.lease_service': {'path': 'tools/m2_discovery_installation_profile/lease_service.py', 'sha256': 'bd6893d46d92ebec143ab6cf562fdf379afa3162e1e96d6712d925e462781c23'}, 'tools.m2_discovery_installation_profile.lease_worker': {'path': 'tools/m2_discovery_installation_profile/lease_worker.py', 'sha256': 'c3e5a437a54a2d3123f0cf3a7d933f49004dd03ab4c768b3a2f390da2be0f524'}, 'tools.m2_discovery_installation_profile.native_generation_probe': {'path': 'tools/m2_discovery_installation_profile/native_generation_probe.py', 'sha256': 'f38f3574303917231dce80efbcd87a69704b3980e43f8f48e1ebb828075a3bdf'}, 'tools.materialize_semantic_shared_faces': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py', 'sha256': '66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62'}, 'tools.materialize_southbound_kernel': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py', 'sha256': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de'}, 'tools.materialize_southbound_lease_refresh': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py', 'sha256': '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084'}, 'tools.semantic_lease_recovery.bounded_recovery': {'path': 'tools/semantic_lease_recovery/bounded_recovery.py', 'sha256': 'ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd'}, 'tools.semantic_lease_recovery.recovery_journal': {'path': 'tools/semantic_lease_recovery/recovery_journal.py', 'sha256': '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d'}, 'tools.semantic_policy_token_owner.producer': {'path': 'tools/semantic_policy_token_owner/producer.py', 'sha256': '2b218432f719c4bb4efa47a2786238b518617ac09023e588e8e605cb18f7c4dd'}, 'tools.semantic_provider_deployment_admission': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py', 'sha256': 'fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4'}, 'tools.semantic_provider_deployment_authentication': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py', 'sha256': '29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013'}, 'tools.semantic_provider_deployment_protocol': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py', 'sha256': '53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15'}, 'tools.semantic_provider_dns': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py', 'sha256': 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930'}, 'tools.semantic_provider_lease_coordination': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py', 'sha256': 'e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587'}, 'tools.semantic_provider_lease_nft': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py', 'sha256': '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93'}, 'tools.semantic_provider_lease_owner': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py', 'sha256': '92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d'}, 'tools.semantic_provider_peer_bindings': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py', 'sha256': '4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b'}, 'tools.semantic_provider_preexec': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py', 'sha256': '53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797'}, 'tools.semantic_provider_preexec_native': {'path': 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py', 'sha256': 'ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528'}, 'tools.semantic_registry_operational_owner.contract': {'path': 'tools/semantic_registry_operational_owner/contract.py', 'sha256': '9d1d15950f24843958ed5944ebbe4474b8da6d370a19f8cc13c8c508e3ad3a45'}, 'tools.semantic_registry_operational_owner.core': {'path': 'tools/semantic_registry_operational_owner/core.py', 'sha256': '5ef38d897dce2a03e5d3583d001166cb9fc0e28e67497cdc608074ac53843a2c'}, 'tools.semantic_registry_operational_owner.guard': {'path': 'tools/semantic_registry_operational_owner/guard.py', 'sha256': 'c0a0faa63042fe2573390c6b6dd6a47a3d76dc60d25f2914a4e1da84e0b47860'}, 'tools.semantic_registry_operational_owner.store': {'path': 'tools/semantic_registry_operational_owner/store.py', 'sha256': '74ace46309720c7ffc3365e5089b66783283a8930a01a26419f9a3c0ba6f41e1'}, 'tools.m2_discovery_installation_profile.discovery_nft_backend': {'path': 'tools/m2_discovery_installation_profile/discovery_nft_backend.py', 'sha256': 'facbdd03f2351d44352e9311c9818f42189cb3959a49a939526d2fd173c353cb'}}
ENTRY='tools.m2_discovery_installation_profile.lease_service'

RUNTIME='''#!/usr/bin/env python3
"""Closed installed discovery worker. No installer, signer or container command."""
import base64,hashlib,importlib,importlib.abc,importlib.util,json,os,sys
MANIFEST=__MANIFEST__
PAYLOAD=__PAYLOAD__

def require(ok,reason):
    if not ok:raise RuntimeError(reason)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def load():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ISOLATED_NO_SITE_NO_BYTECODE_REQUIRED')
    require(os.geteuid()==os.getegid()==0,'ROOT_INSTALLED_DISCOVERY_WORKER_REQUIRED')
    pins=MANIFEST['sourcePins']
    require(not any(n in pins or n=='tools' or n.startswith('tools.') for n in sys.modules),
        'PRELOADED_DISCOVERY_APPLICATION_MODULE_DENIED')
    raw=base64.b64decode(PAYLOAD,validate=True)
    require(0<len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==MANIFEST['payloadSha256'],
        'EXACT_DISCOVERY_WORKER_PAYLOAD_REQUIRED')
    def unique(rows):
        value=dict(rows);require(len(value)==len(rows),'DUPLICATE_DISCOVERY_SOURCE_KEY');return value
    sources=json.loads(raw,object_pairs_hook=unique)
    require(set(sources)==set(pins) and 1<=len(sources)<=64,'EXACT_DISCOVERY_WORKER_SOURCE_CLOSURE_REQUIRED')
    hashes={}
    for name,source in sources.items():
        require(type(source) is str and 0<len(source.encode())<=1048576,
            'BOUNDED_DISCOVERY_WORKER_SOURCE_REQUIRED')
        hashes[name]=hashlib.sha256(source.encode()).hexdigest()
        require(hashes[name]==pins[name]['sha256'],'DISCOVERY_WORKER_SOURCE_CHANGED')
    require(digest(hashes)==MANIFEST['dependencyClosureHash'],'DISCOVERY_WORKER_CLOSURE_CHANGED')
    packages={'.'.join(n.split('.')[:i]) for n in sources for i in range(1,len(n.split('.')))}
    require(not packages.intersection(sources),'DISCOVERY_PACKAGE_MODULE_COLLISION')
    class Closed(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname in sources or fullname in packages:
                return importlib.util.spec_from_loader(fullname,self,is_package=fullname in packages)
            if fullname=='tools' or fullname.startswith('tools.'):
                raise ModuleNotFoundError('UNSEALED_DISCOVERY_APPLICATION_IMPORT_DENIED')
            return None
        def create_module(self,spec):return None
        def exec_module(self,module):
            name=module.__name__
            if name in packages:
                module.__path__=[];return
            module.__file__='<qualified:'+pins[name]['path']+'>'
            module.__qualified_source_sha256__=hashes[name]
            exec(compile(sources[name],module.__file__,'exec'),module.__dict__)
            require(module.__qualified_source_sha256__==hashes[name],
                'DISCOVERY_EXECUTING_SOURCE_IDENTITY_CHANGED')
    loader=Closed();sys.meta_path.insert(0,loader)
    for name in sorted(sources):importlib.import_module(name)
    require(all(getattr(sys.modules[n],'__qualified_source_sha256__',None)==h for n,h in hashes.items()),
        'COMPLETE_DISCOVERY_EXECUTION_CLOSURE_REQUIRED')
    return sys.modules[MANIFEST['entryModule']],dict(schema='ouf.discovery-operational-lease-sources.v1',
        sourceHashes=hashes,dependencyClosureHash=MANIFEST['dependencyClosureHash'])

def main():
    require(len(sys.argv)>1 and sys.argv[1] in ('self-check','worker'),'EXACT_DISCOVERY_WORKER_MODE_REQUIRED')
    if sys.argv[1]=='self-check':require(len(sys.argv)==2,'NO_CONFIGURATION_SELF_CHECK_REQUIRED')
    service,sources=load()
    if sys.argv[1]=='self-check':
        print(json.dumps(dict(schema='ouf.discovery-lease-runtime-self-check.v1',sourceManifest=sources,
            moduleCount=len(sources['sourceHashes']),runtimeAuthorityIssued=False,targetApplyAuthorized=False,
            releaseAcceptance=False),sort_keys=True));return 0
    return service.execute(sys.argv[2:])

if __name__=='__main__':
    try:result=main()
    except (Exception,KeyboardInterrupt):
        print(json.dumps(dict(schema='ouf.discovery-lease-runtime-exit.v1',status='STOP_RECONCILE',
            reasonCode='CLOSED_DISCOVERY_WORKER_EXECUTION_UNPROVEN',automaticReplayAllowed=False,
            runtimeAuthorityIssued=False,targetApplyAuthorized=False,releaseAcceptance=False),sort_keys=True))
        result=2
    raise SystemExit(result)
'''


def build(root):
    sources={name:(Path(root)/pin['path']).read_bytes() for name,pin in PINS.items()}
    if not all(hashlib.sha256(raw).hexdigest()==PINS[name]['sha256'] for name,raw in sources.items()):
        raise ValueError('EXACT_PUBLISHED_DISCOVERY_WORKER_SOURCE_REQUIRED')
    strings={name:raw.decode('utf-8') for name,raw in sources.items()}
    raw=json.dumps(strings,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    if not 0<len(raw)<=1048576:raise ValueError('BOUNDED_DISCOVERY_WORKER_CAPSULE_REQUIRED')
    hashes={name:pin['sha256'] for name,pin in PINS.items()}
    closure=hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    manifest={'schema':'ouf.discovery-lease-runtime-capsule.v1','sourceCommit':SOURCE,'sourcePins':PINS,
        'entryModule':ENTRY,'dependencyClosureHash':closure,'payloadSha256':hashlib.sha256(raw).hexdigest(),
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    result=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(raw).decode())).encode()
    if len(result)>2097152:raise ValueError('BOUNDED_DISCOVERY_WORKER_CAPSULE_REQUIRED')
    compile(result,'<discovery-worker-capsule>','exec')
    return result,{'schema':'ouf.discovery-operational-lease-sources.v1','sourceHashes':hashes,
        'dependencyClosureHash':closure}
