"""Export nine pinned modules; public trust/context preparation is not authority."""
import argparse,base64,hashlib,json
from pathlib import Path
SOURCE="1d6335c015aa9fa7a09588bdf9c05f7217a3d84f"
PINS={
    "tools/m2_discovery_installation_profile/audit.py": "e8b7813a8f6f009054593025dc2df9b79315bf2100a70f02a41973a0536658c3",
    "tools/m2_discovery_installation_profile/custody_capture.py": "834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf",
    "tools/m2_discovery_installation_profile/projections.py": "4076c25e3258bf06afc25babf5d86755e55ffb97ac5bc0c634960061bcd71352",
    "tools/m2_discovery_installation_profile/material_preparation.py": "7e342cf4d9bee25515a6b924bd5086352f8c5c660870b3ef7928046ba9285462",
    "tools/m2_discovery_installation_profile/public_truststore.py": "ade7e834d8b011da28534f416bfbb958d9cab1b1eb32dd94360c4c29dd589579",
    "tools/m2_discovery_installation_profile/trust_inputs.py": "e7c10917afa8da28027b9d880521d9df9f4d0121df69fbaa3417293511957e22",
    "tools/m2_discovery_installation_profile/trust_preparation.py": "89993271d36d63690e14ed8d2ced70fb0d12c88746f6d1a224ed5e02890797b2",
    "tools/m2_discovery_installation_profile/native_context.py": "cb3c53351e982529e4375de6ace6593d15ab09cfc597321a1d8d6b2f4e9c5845",
    "tools/m2_discovery_installation_profile/trust_context_entry.py": "8da68a6cc391e105e7fd73858aeb7bb6f438fe46223c00f62a057f7c78f95cc6"
}
RUNTIME='''#!/usr/bin/env python3
"""Exact closed public trust and native context preparation; no deployment or authentication authority."""
import base64,hashlib,json,os,stat,sys,types
MANIFEST = __MANIFEST__
PAYLOAD = __PAYLOAD__
def require(ok,reason):
    if not ok:raise RuntimeError(reason)
def load():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_NO_SITE_NO_BYTECODE_REQUIRED')
    require(os.geteuid()==0 and len(sys.argv)==1,'ROOT_NO_ARGUMENT_TRUST_CONTEXT_PREPARATION_REQUIRED')
    require(not any(k=='tools' or k.startswith('tools.') for k in sys.modules),
            'PRELOADED_APPLICATION_MODULE_DENIED')
    raw=base64.b64decode(PAYLOAD,validate=True)
    require(0<len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==MANIFEST['payloadSha256'],
            'EXACT_TRUST_CONTEXT_PREPARATION_PAYLOAD_REQUIRED')
    def unique(rows):
        result=dict(rows);require(len(result)==len(rows),'DUPLICATE_CAPSULE_SOURCE_KEY');return result
    sources=json.loads(raw,object_pairs_hook=unique)
    require(set(sources)==set(MANIFEST['sourcePins']),'EXACT_NINE_MODULE_SOURCE_CLOSURE_REQUIRED')
    for path,source in sources.items():
        require(type(source) is str and hashlib.sha256(source.encode()).hexdigest()==MANIFEST['sourcePins'][path],
                'TRUST_CONTEXT_PREPARATION_SOURCE_BYTES_CHANGED')
    for name in ('tools','tools.m2_discovery_installation_profile'):
        package=types.ModuleType(name);package.__path__=[];sys.modules[name]=package
        if '.' in name:setattr(sys.modules['tools'],name.rsplit('.',1)[1],package)
    parent=sys.modules['tools.m2_discovery_installation_profile']
    for leaf in ('audit','custody_capture','projections','material_preparation','public_truststore','trust_inputs','trust_preparation','native_context','trust_context_entry'):
        path='tools/m2_discovery_installation_profile/'+leaf+'.py'
        name='tools.m2_discovery_installation_profile.'+leaf
        module=types.ModuleType(name);module.__package__='tools.m2_discovery_installation_profile'
        module.__file__='<verified:'+path+'>';sys.modules[name]=module;setattr(parent,leaf,module)
        exec(compile(sources[path],module.__file__,'exec'),module.__dict__)
    return sys.modules['tools.m2_discovery_installation_profile.trust_context_entry']
if __name__=='__main__':
    raise SystemExit(load().main())
'''


def build(root):
    sources={p:(Path(root)/p).read_text() for p in PINS}
    assert all(hashlib.sha256(v.encode()).hexdigest()==PINS[p] for p,v in sources.items()),'EXACT_PUBLISHED_SOURCE_REQUIRED'
    raw=json.dumps(sources,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    manifest={'schema':'ouf.m2-discovery-trust-context-capsule.v1','sourceCommit':SOURCE,
        'sourcePins':PINS,'payloadSha256':hashlib.sha256(raw).hexdigest(),'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
    result=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(raw).decode())).encode()
    assert len(result)<=131072
    compile(result,'<trust-context-capsule>','exec')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',required=True);p.add_argument('--output',required=True)
    args=p.parse_args();raw=build(args.root)
    with Path(args.output).open('xb') as out:out.write(raw)
    print(json.dumps({'sourceCommit':SOURCE,'capsuleSha256':hashlib.sha256(raw).hexdigest(),
        'capsuleBytes':len(raw),'moduleCount':len(PINS),'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}))
