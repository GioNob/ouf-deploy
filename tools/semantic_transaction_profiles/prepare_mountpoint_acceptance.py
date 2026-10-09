"""Pure R8 proposal: exact empty OCI bind placeholders, never target authority.

The v1 runtime comparison stays unchanged. Independently retained image entries
plus nine explicitly reviewed empty entries explain the proposed strict seals.
Only a fresh human/root mandate can authorize their use by role issuance.
"""
import copy
import hashlib
import json

R7_MANIFEST='72594fc88836cd82c382f10e8ed42adc2e04458a00df6738b05cd258916a65a6'
R7_ENTRY='a4e9c02915cc32ab839456de57f88e57d42aa607922ba6db8a320fd27bfdc240'
R7_WRAPPER='050cb98116da36efd315d93f4e95471dfe0543c8447fd135b7b1261c7bf587e2'
R6_WRAPPER='cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b'
CLOSURE='4b9fbd3149b417a2a696302784aa54d0569b5e87ddc66ac439c153c9ab16bc02'
OFFLINE_SEALS={'adapter':'8a67afc590854316165176c39fbc0d393bb9b38ab6662430d2a36d3313858cf8',
    'southbound':'ec013e0317560153aece8e08a393442c95aaa13f64e3df274c61987953e546d8'}
IMAGE_SEALS={'adapter':'7984421ed76f37ae43681fd369b900c173e2e70a143f93517fed1c434ef578d9',
    'southbound':'e979252f1b43958071d5e497c3753058c76a4071ec92df678299b0bf5c71cfea'}
OLD_SEALS={'adapter':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73','entries':3390,'bytes':46079786},
    'southbound':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39','entries':7458,'bytes':255900260}}
PROPOSED_SEALS={'adapter':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'92c26698ef0899e909a503f5db856f55a1cc0cf44c8f6648ba4d498a6c2533c4','entries':3396,'bytes':46079786},
    'southbound':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'4236ebc8a571b5f177f2365ccfed78ba3b0bd43fce2ea75c1e34c0b90f7a844d','entries':7461,'bytes':255900260}}
BIND_FILES={'adapter':['run/ouf-semantic-provider/'+name for name in
    ('adapter.json','provider-receipt.key','server.crt','server.key','trust-bundle.pem')],
    'southbound':['run/ouf-semantic-provider/trust-bundle.pem','usr/local/apisix/conf/apisix.yaml']}


def require(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def seal_entries(records):
    """Reproduce rootfs_seal's sorted, depth-first traversal after JSON storage."""
    require('' in records and len(records)<=100000,'BOUNDED_COMPLETE_ENTRY_MAP_REQUIRED')
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\0V1\0');size=0
    for path in sorted(records,key=lambda p:tuple(p.split('/')) if p else ()):
        item=records[path];require(item['path']==path,'EXACT_ENTRY_MAP_PATH_REQUIRED')
        require(not path.startswith('/') and all(p not in ('.','..') for p in path.split('/')),'CANONICAL_IMAGE_PATH_REQUIRED')
        if path:
            parent=path.rpartition('/')[0]
            require(parent in records and records[parent]['kind']=='directory','COMPLETE_IMAGE_ANCESTRY_REQUIRED')
        raw=encoded(item);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        if item['kind']=='file':size+=item['size']
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':len(records),'bytes':size}


def image_entries(records,expected=False):
    result=copy.deepcopy(records)
    for path,item in result.items():
        if item['kind']=='directory':item.pop('links')
        if path=='' and expected:item['mode']=0o755
    return result


def image_digest(records):
    h=hashlib.sha256(b'OUF-IMAGE-EQUIVALENCE\0V1\0')
    for path in sorted(records):
        raw=encoded(records[path]);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
    return h.hexdigest()


def expanded_image(expected,oci,files):
    """Derive only fixed zero-length bind destinations and their absent parent."""
    result=copy.deepcopy(expected);added=[]
    mounts={m['destination'].lstrip('/'):m for m in oci['mounts']}
    for path in files:
        options=set(mounts.get(path,{}).get('options') or [])
        checks={'absentFromImage':path not in result,'declaredMount':path in mounts,
            'bindType':mounts.get(path,{}).get('type')=='bind',
            'readOnlyOption':bool({'ro','rro'} & options),
            'noWritableOption':not bool({'rw','rrw'} & options)}
        if not all(checks.values()):
            error=ValueError('EXACT_READ_ONLY_BIND_DESTINATION_REQUIRED')
            # Only fixed reviewed image paths and booleans, never host sources
            # or arbitrary mount option values, enter the public diagnosis.
            error.diagnosis={'mountpointReview':{'imagePath':path,'checks':checks,
                'roPresent':'ro' in options,'rroPresent':'rro' in options},
                'differentFields':[name for name,ok in checks.items() if not ok]}
            raise error
        parent=path.rpartition('/')[0]
        if parent not in result:
            require(parent=='run/ouf-semantic-provider' and result.get('run',{}).get('kind')=='directory',
                'ONLY_REVIEWED_NEW_PARENT_ALLOWED')
            result[parent]={'path':parent,'kind':'directory','mode':0o755,'uid':0,'gid':0,'xattrs':{}}
            added.append(parent)
        require(result[parent]['kind']=='directory','BIND_PARENT_DIRECTORY_REQUIRED')
        result[path]={'path':path,'kind':'file','mode':0o644,'uid':0,'gid':0,'links':1,
                      'size':0,'sha256':sha(b''),'xattrs':{}}
        added.append(path)
    return result,sorted(added)


def validate_comparison(role,value,oci):
    require(role in PROPOSED_SEALS and set(value)=={'expectedOfflineEntries','currentEntries','summary'},'EXACT_RETAINED_COMPARISON_REQUIRED')
    left,right=value['expectedOfflineEntries'],value['currentEntries']
    require(seal_entries(left)['sha256']==OFFLINE_SEALS[role],'INDEPENDENT_OFFLINE_ENTRIES_DRIFT')
    require(seal_entries(right)==PROPOSED_SEALS[role],'PROPOSED_STRICT_SEAL_ENTRIES_DRIFT')
    expected=image_entries(left,True)
    require(image_digest(expected)==IMAGE_SEALS[role],'INDEPENDENT_IMAGE_BASELINE_DRIFT')
    expanded,added=expanded_image(expected,oci,BIND_FILES[role])
    require(image_entries(right)==expanded,'UNREVIEWED_ROOTFS_CONTENT_OR_METADATA_DIFFERENCE')
    require(len(added)==(6 if role=='adapter' else 3),'EXACT_NINE_PLACEHOLDERS_REQUIRED')
    return {'role':role,'addedEntries':added,'oldSeal':OLD_SEALS[role],'proposedSeal':PROPOSED_SEALS[role],
        'existingImageEntriesUnchanged':True,'emptyBindPlaceholdersOnly':True,
        'runtimeV1ComparisonUnchanged':True,'acceptanceGranted':False,'startAuthorized':False}


def build_package(manifest_raw,files,entry_raw):
    require(sha(manifest_raw)==R7_MANIFEST and sha(entry_raw)==R7_ENTRY,'EXACT_RETAINED_R7_PACKAGE_REQUIRED')
    manifest=json.loads(manifest_raw)
    require(set(files)==set(manifest['sourceHashes']) and all(sha(raw)==manifest['sourceHashes'][name]
        for name,raw in files.items()),'RETAINED_R7_SOURCE_BYTES_DRIFT')
    result=dict(files);name='utility/authenticate_provider_transaction.py';raw=result[name]
    for role in OLD_SEALS:
        old=repr(OLD_SEALS[role]).encode();new=repr(PROPOSED_SEALS[role]).encode()
        require(raw.count(old)==1,'EXACT_R7_ROOTFS_ACCEPTANCE_PATCH_SITE_REQUIRED');raw=raw.replace(old,new)
    compile(raw,name,'exec');result[name]=raw
    revised={**manifest,'sourceHashes':{name:sha(raw) for name,raw in result.items()}}
    manifest_bytes=encoded(revised);manifest_hash=sha(manifest_bytes)
    require(entry_raw.count(R7_MANIFEST.encode())==1 and entry_raw.count(R6_WRAPPER.encode())==2,
        'EXACT_R7_ENTRY_BINDINGS_REQUIRED')
    entry=entry_raw.replace(R7_MANIFEST.encode(),manifest_hash.encode()).replace(R6_WRAPPER.encode(),R7_WRAPPER.encode())
    compile(entry,'provider_transaction_intake.py','exec')
    closure=sha(encoded({**{n.removeprefix('source/'):sha(v) for n,v in result.items() if n.startswith('source/')},
                        'frame-observer.py':sha(result['frame-observer.py'])}))
    require(closure==CLOSURE,'RUNTIME_SOURCE_CLOSURE_MUST_REMAIN_UNCHANGED')
    result.update({'provider_transaction_intake.py':entry,'intake-source-closure.json':manifest_bytes})
    return {'files':result,'manifestHash':manifest_hash,'entryHash':sha(entry),'sourceClosureHash':closure,
        'changedUtilities':[name],'changedRuntimeFiles':[],'acceptanceGranted':False,'startAuthorized':False}
