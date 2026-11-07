"""Export five exact published modules; packaging is not execution authority."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

SOURCE='5de8a6224aa7e5b410044a12a76136056cc62064'
PINS={
    'tools/m2_discovery_installation_profile/material_role_preparation.py':'87d4a9d941c210f5f4b5bfa2f894d84aa95855533997cd7d52ae8f469bc3cfc4',
    'tools/m2_discovery_installation_profile/audit.py':'e8b7813a8f6f009054593025dc2df9b79315bf2100a70f02a41973a0536658c3',
    'tools/m2_discovery_installation_profile/custody_capture.py':'834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf',
    'tools/m2_discovery_installation_profile/projections.py':'4076c25e3258bf06afc25babf5d86755e55ffb97ac5bc0c634960061bcd71352',
    'tools/m2_discovery_installation_profile/material_preparation.py':'7e342cf4d9bee25515a6b924bd5086352f8c5c660870b3ef7928046ba9285462',
}

RUNTIME='''#!/usr/bin/env python3
"""Exact closed material preparation; no deployment or authentication authority."""
import base64,hashlib,json,os,stat,sys,types
MANIFEST = __MANIFEST__
PAYLOAD = __PAYLOAD__
def require(ok,reason):
    if not ok:raise RuntimeError(reason)
def load():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_NO_SITE_NO_BYTECODE_REQUIRED')
    require(os.geteuid()==0 and len(sys.argv)==1,'ROOT_NO_ARGUMENT_MATERIAL_PREPARATION_REQUIRED')
    require(not any(k=='tools' or k.startswith('tools.') for k in sys.modules),
            'PRELOADED_APPLICATION_MODULE_DENIED')
    raw=base64.b64decode(PAYLOAD,validate=True)
    require(0<len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==MANIFEST['payloadSha256'],
            'EXACT_MATERIAL_PREPARATION_PAYLOAD_REQUIRED')
    def unique(rows):
        result=dict(rows);require(len(result)==len(rows),'DUPLICATE_CAPSULE_SOURCE_KEY');return result
    sources=json.loads(raw,object_pairs_hook=unique)
    require(set(sources)==set(MANIFEST['sourcePins']),'EXACT_FIVE_MODULE_SOURCE_CLOSURE_REQUIRED')
    for path,source in sources.items():
        require(type(source) is str and hashlib.sha256(source.encode()).hexdigest()==MANIFEST['sourcePins'][path],
                'MATERIAL_PREPARATION_SOURCE_BYTES_CHANGED')
    for name in ('tools','tools.m2_discovery_installation_profile'):
        package=types.ModuleType(name);package.__path__=[];sys.modules[name]=package
        if '.' in name:setattr(sys.modules['tools'],name.rsplit('.',1)[1],package)
    parent=sys.modules['tools.m2_discovery_installation_profile']
    for leaf in ('audit','custody_capture','projections','material_preparation','material_role_preparation'):
        path='tools/m2_discovery_installation_profile/'+leaf+'.py'
        name='tools.m2_discovery_installation_profile.'+leaf
        module=types.ModuleType(name);module.__package__='tools.m2_discovery_installation_profile'
        module.__file__='<verified:'+path+'>';sys.modules[name]=module;setattr(parent,leaf,module)
        exec(compile(sources[path],module.__file__,'exec'),module.__dict__)
    return sys.modules['tools.m2_discovery_installation_profile.material_role_preparation']
if __name__=='__main__':
    raise SystemExit(load().main())
'''


def build(root):
    sources={path:(Path(root)/path).read_text() for path in PINS}
    assert all(hashlib.sha256(v.encode()).hexdigest()==PINS[p] for p,v in sources.items()),'EXACT_PUBLISHED_SOURCE_REQUIRED'
    raw=json.dumps(sources,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    manifest={'schema':'ouf.m2-discovery-material-role-preparation-capsule.v1','sourceCommit':SOURCE,
        'sourcePins':PINS,'payloadSha256':hashlib.sha256(raw).hexdigest(),'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
    result=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(raw).decode())).encode()
    assert len(result)<=131072
    compile(result,'<material-preparation-capsule>','exec')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();raw=build(args.root)
    with Path(args.output).open('xb') as stream:stream.write(raw)
    print(json.dumps({'sourceCommit':SOURCE,'capsuleSha256':hashlib.sha256(raw).hexdigest(),
        'capsuleBytes':len(raw),'moduleCount':len(PINS),'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}))
