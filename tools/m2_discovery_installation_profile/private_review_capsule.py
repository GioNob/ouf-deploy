"""Package the exact offline review compiler; never an execution authority.

The explicit source revision is a provenance claim, not publisher trust. The
complete capsule SHA and closed source manifest need independent exact review.
Historical worker/material/runtime capsules are not modified.
"""
import base64,hashlib,json,re
from pathlib import Path

BASELINE='tools/semantic_frame_compiler/containerd-overlayfs-southbound.json'
BASELINE_HASH='ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63'
SOURCE_MANIFEST_HASH='4258366534214845cea3e2757382752d479001bf28b4baa4cb5fcbd57bbbc6ec'
ENTRY='tools.m2_discovery_installation_profile.private_review'
MAXIMUM=4194304

RUNTIME='''#!/usr/bin/env python3
"""Sealed offline private review assembly. No target execution mode exists."""
import argparse,base64,hashlib,importlib.abc,importlib.util,json,os,sys
MANIFEST=__MANIFEST__
PAYLOAD=__PAYLOAD__
def require(ok):
    if not ok:raise ValueError('PRIVATE_REVIEW_CAPSULE_UNPROVEN')
def load():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    require(os.geteuid()==os.getegid()==0)
    names=set(MANIFEST['sources']);parents={n[:i] for n in names for i,c in enumerate(n) if c=='.'}
    require(not any(n in names or n in parents for n in sys.modules))
    raw=base64.b64decode(PAYLOAD,validate=True)
    require(0<len(raw)<=4194304 and hashlib.sha256(raw).hexdigest()==MANIFEST['payloadSha256'])
    def unique(rows):
        result=dict(rows);require(len(result)==len(rows));return result
    payload=json.loads(raw,object_pairs_hook=unique)
    require(set(payload)=={'sources','baseline'})
    sources=payload['sources'];require(set(sources)==names)
    for name,body in sources.items():
        require(type(body) is str and hashlib.sha256(body.encode()).hexdigest()==MANIFEST['sources'][name]['sha256'])
    baseline=base64.b64decode(payload['baseline'],validate=True)
    require(hashlib.sha256(baseline).hexdigest()==MANIFEST['baselineSha256'])
    class Closed(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,name,path=None,target=None):
            if name in names or name in parents:
                return importlib.util.spec_from_loader(name,self,is_package=name in parents)
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__='<sealed:'+module.__name__+'>'
            if module.__name__ in sources:
                exec(compile(sources[module.__name__],module.__file__,'exec'),module.__dict__)
    sys.meta_path.insert(0,Closed())
    return importlib.import_module(MANIFEST['entryModule']),baseline
def main():
    try:
        class Parser(argparse.ArgumentParser):
            def error(self,message):raise ValueError('PRIVATE_REVIEW_ARGUMENTS_UNPROVEN')
        parser=Parser(prog='private-review',description=__doc__)
        parser.add_argument('mode',choices=('prepare','inspect'))
        parser.add_argument('--input',required=True);parser.add_argument('--input-sha256',required=True)
        parser.add_argument('--output-directory',required=True)
        args=parser.parse_args()
        module,baseline=load()
        def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        binding={'profile':'CLOSED_PRIVATE_REVIEW_CAPSULE','capsuleManifestHash':digest(MANIFEST),
            'sourceManifestHash':digest(MANIFEST['sources']),'payloadHash':MANIFEST['payloadSha256'],
            'sourceRevisionClaim':MANIFEST['sourceRevisionClaim'],'publisherTrustAccepted':False}
        result=module.prepare(args.input,args.input_sha256,args.output_directory,baseline,
            inspect=args.mode=='inspect',compiler_binding=binding)
        print(json.dumps({'status':'PRIVATE_REVIEW_FRAGMENT_PREPARED_NOT_AUTHENTICATED',**result},sort_keys=True))
        return 0
    except Exception:
        # Never expose parser/native exception strings or private paths/data.
        print(json.dumps({'status':'STOP_RECONCILE','reasonCode':'PRIVATE_REVIEW_PREPARATION_UNPROVEN',
            'completeParentReview':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False},sort_keys=True))
        return 1
if __name__=='__main__':raise SystemExit(main())
'''


def build(root,source_revision):
    def require(ok):
        if not ok:raise ValueError('EXACT_PRIVATE_REVIEW_SOURCE_REQUIRED')
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}',source_revision) is not None)
    root=Path(root)
    raw_pins=(root/'tools/m2_discovery_installation_profile/private_review_sources.json').read_bytes()
    require(hashlib.sha256(raw_pins).hexdigest()==SOURCE_MANIFEST_HASH)
    pins=json.loads(raw_pins)
    require(ENTRY in pins and 1<=len(pins)<=192)
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
    require(len(payload)<=MAXIMUM)
    manifest={'schema':'ouf.discovery-private-review-capsule.v1','entryModule':ENTRY,
        'sourceRevisionClaim':source_revision,'sourceRevisionClaimAuthenticated':False,'sources':pins,
        'payloadSha256':hashlib.sha256(payload).hexdigest(),'baselineSha256':BASELINE_HASH,
        'completeParentReview':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'publisherTrustAccepted':False,'releaseAcceptance':False}
    result=RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(payload).decode())).encode()
    require(len(result)<=8388608);compile(result,'<private-review-capsule>','exec')
    return result,manifest
