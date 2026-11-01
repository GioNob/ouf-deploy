"""Nineteen sealed sources for diagnosis of the two exact consumed image STOPs."""
import base64, hashlib, json, re
from pathlib import Path

SOURCE_MAP = 'tools/m2_discovery_installation_profile/retained_image_graph_sources.json'
SOURCE_MAP_SHA256 = '94de13bc5deb6f0c9a1bf7d36bd879a573b0eb9d4deed11afe78a03a3f4752f0'
CUSTODY_SHA256 = '834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf'
LOADER_HASH = '1150d7ec5365426950699b5935d37174011b7badbfba255291dd571c16e0c352'
ENTRY = 'tools.m2_discovery_installation_profile.retained_image_graph_diagnostic'
RUNTIME = '''#!/usr/bin/env python3
"""Diagnose missing OCI references in retained archives; no image admission or Engine."""
import base64,hashlib,importlib.abc,importlib.util,json,os,sys
MANIFEST=__MANIFEST__
PAYLOAD=__PAYLOAD__
def require(ok):
    if not ok:raise ValueError('SEALED_RETAINED_IMAGE_GRAPH_DIAGNOSTIC_UNPROVEN')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def load(inspect):
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    require(inspect or os.geteuid()==os.getegid()==0)
    names=set(MANIFEST['sources']);parents={n[:i] for n in names for i,c in enumerate(n) if c=='.'}
    require(not any(n in names or n in parents for n in sys.modules))
    raw=base64.b64decode(PAYLOAD,validate=True)
    require(0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==MANIFEST['payloadSha256'])
    def unique(rows):
        result=dict(rows);require(len(result)==len(rows));return result
    sources=json.loads(raw,object_pairs_hook=unique);require(set(sources)==names)
    for name,body in sources.items():
        require(type(body)is str and hashlib.sha256(body.encode()).hexdigest()==MANIFEST['sources'][name]['sha256'])
        compile(body,'<sealed:'+name+'>','exec')
    if inspect:return None
    class Closed(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,name,path=None,target=None):
            if name in names or name in parents:
                return importlib.util.spec_from_loader(name,self,is_package=name in parents)
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__='<sealed:'+module.__name__+'>'
            if module.__name__ in sources:exec(compile(sources[module.__name__],module.__file__,'exec'),module.__dict__)
    sys.meta_path.insert(0,Closed());return importlib.import_module(MANIFEST['entryModule'])
def main():
    try:
        require(sys.argv[1:] in ([],['--inspect-source']))
        inspect=sys.argv[1:]==['--inspect-source'];module=load(inspect)
        if inspect:
            print(json.dumps({'status':'SEALED_RETAINED_IMAGE_GRAPH_DIAGNOSTIC_SOURCE_INSPECTED_NOT_TRUSTED',
                'captureSourceManifestHash':digest(MANIFEST['sources']),'capsuleManifestHash':digest(MANIFEST),
                'sourceRevisionClaim':MANIFEST['sourceRevisionClaim'],'sourceCount':len(MANIFEST['sources']),
                'publisherTrustAccepted':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False},sort_keys=True))
            return 0
        return module.main()
    except Exception:
        print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'SEALED_RETAINED_IMAGE_GRAPH_DIAGNOSTIC_UNPROVEN',
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False},sort_keys=True))
        return 1
if __name__=='__main__':raise SystemExit(main())
'''


def build(root, source_revision):
    def require(ok):
        if not ok: raise ValueError('EXACT_RETAINED_IMAGE_ARCHIVE_SOURCES_REQUIRED')
    require(type(source_revision) is str and re.fullmatch('[a-f0-9]{40}', source_revision))
    require(hashlib.sha256(RUNTIME.encode()).hexdigest() == LOADER_HASH)
    root = Path(root); raw = (root/SOURCE_MAP).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_MAP_SHA256)
    pins = json.loads(raw)
    expected = {ENTRY, 'tools.m2_discovery_installation_profile.retained_image_graph',
        'tools.m2_discovery_installation_profile.retained_image_verification',
        'tools.m2_discovery_installation_profile.retained_image_capture',
        'tools.m2_discovery_installation_profile.retained_image_intake',
        'tools.m2_discovery_installation_profile.retained_image_identity',
        'tools.m2_discovery_installation_profile.retained_image_reader', 'tools.m2_discovery_installation_profile.retained_view_capture',
        'tools.m2_discovery_installation_profile.retained_view_intake', 'tools.m2_discovery_installation_profile.custody_capture',
        'tools.m2_discovery_installation_profile.retained_mount_capture',
        'tools.m2_discovery_installation_profile.retained_mount_role_correction',
        'tools.m2_discovery_installation_profile.retained_mount_intake',
        'tools.m2_discovery_installation_profile.retained_readonly_hashes',
        'tools.m2_discovery_installation_profile.retained_hash_reconciliation',
        'tools.m2_discovery_installation_profile.retained_mount_lifecycle',
        'tools.m2_discovery_installation_profile.retained_static_custody',
        'tools.m2_discovery_installation_profile.retained_static_intake',
        'tools.m2_discovery_installation_profile.retained_view_primitives'}
    require(pins['tools.m2_discovery_installation_profile.retained_mount_capture']['sha256'] == 'f6cb51659af47a9d7557514da34b8bf502443bc3fc77c0b1a01078a2604fcc48')
    require(set(pins) == expected and pins['tools.m2_discovery_installation_profile.custody_capture']['sha256'] == CUSTODY_SHA256)
    sources = {}
    for name, pin in pins.items():
        require(set(pin) == {'path', 'sha256'} and pin['path'] == name.replace('.', '/')+'.py')
        raw = (root/pin['path']).read_bytes(); require(hashlib.sha256(raw).hexdigest() == pin['sha256'])
        sources[name] = raw.decode('utf-8')
    payload = json.dumps(sources, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    require(len(payload) <= 262144)
    manifest = {'schema': 'ouf.retained-image-graph-diagnostic-capsule.v1', 'entryModule': ENTRY,
        'loaderTemplateSha256': hashlib.sha256(RUNTIME.encode()).hexdigest(),
        'sourceMapSha256': SOURCE_MAP_SHA256, 'sources': pins,
        'sourceRevisionClaim': source_revision, 'sourceRevisionClaimAuthenticated': False,
        'payloadSha256': hashlib.sha256(payload).hexdigest(), 'mountFileContentReadAllowed': False,
        'liveTokenAndOperationalStoreContentReadAllowed':False,
        'onlyCapturedReadonlyRegularFilesMayBeRead': False,'engineReadAllowed': False,'rawValuesExportAllowed': False,
        'privateImageArchiveOutputAllowed': False, 'privateByteEvidenceOutputAllowed': False, 'privateGraphDiagnosticOutputAllowed': True, 'maximumEngineGets': 0,
        'publisherTrustAccepted': False, 'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
        'releaseAcceptance': False}
    raw = RUNTIME.replace('__MANIFEST__', repr(manifest)).replace('__PAYLOAD__', repr(base64.b64encode(payload).decode())).encode()
    require(len(raw) <= 393216); compile(raw, '<retained-mount-capture>', 'exec'); return raw, manifest
