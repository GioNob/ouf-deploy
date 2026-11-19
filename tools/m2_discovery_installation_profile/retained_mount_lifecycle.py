"""Separate static custody from owner-managed live mounts.

The reviewed capture binds the declarations and old root identities. It is
not permission policy or token/database admission. Live members are deliberately
not enumerated by this witness: their native owners must admit them separately.
"""
import copy, os, stat
from pathlib import Path
from .custody_capture import attrs, digest, require

TOKEN_TARGETS={
    'gateway-owner':('/run/ouf-gateway-auth',),
    'ingestion':('/run/ouf-ingestion-auth',),
    'ingestion-evidence-read':('/run/ouf-ingestion-auth',),
    'onboarding':('/run/ouf-onboarding-auth','/run/ouf-onboarding-identity'),
    'udp':('/run/ouf-udp-auth',),
    'udp-evidence-read':('/run/ouf-udp-auth',)}
STORE_TARGET='/var/lib/ouf-gateway-operations'
CONTRACT={'schema':'ouf.retained-mount-lifecycle-contract.v1',
    'renewableTokenTargets':TOKEN_TARGETS,'gatewayOperationalStoreTarget':STORE_TARGET,
    'gatewaySourceRevision':'81fdf7a5f9f3ef02ed930a1db911d34cab1a9415',
    'renewableOwnerSourceSha256':'4e1ed5032d33ba6a249f7909cb8cbb8cbe70a8fdef0e4443c05375aeba9ec837',
    'sidecarMountInheritanceSourceSha256':'09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd',
    'liveMemberObservationOrAdmission':False,'observedMetadataIsPermissionPolicy':False}
CONTRACT_HASH=digest(CONTRACT)
LIVE={'RENEWABLE_TOKEN_OWNER_INPUT','LIVE_GATEWAY_OPERATIONAL_STORE'}


def classification(role,mount):
    target=mount['destination']
    if target in TOKEN_TARGETS.get(role,()):
        require(mount['type']=='bind' and mount['readOnly'] and mount['kind']=='READONLY_METADATA_CANDIDATE',
            'RENEWABLE_TOKEN_REQUIRES_EXACT_READONLY_BIND_DECLARATION')
        tree=mount['metadataTree']
        require(tree['kind']=='DIRECTORY' and set(tree['children'])=={'token'}
            and tree['children']['token']['kind']=='REGULAR_FILE',
            'CAPTURED_RENEWABLE_TOKEN_DIRECTORY_SHAPE_REQUIRED')
        return 'RENEWABLE_TOKEN_OWNER_INPUT'
    if role=='gateway-owner' and target==STORE_TARGET:
        require(mount['type']=='bind' and mount['readOnly'] and mount['kind']=='READONLY_METADATA_CANDIDATE'
            and mount['metadataTree']['kind']=='DIRECTORY'
            and 'gateway-operations.sqlite' in mount['metadataTree']['children'],
            'CAPTURED_READONLY_GATEWAY_OPERATIONAL_STORE_REQUIRED')
        return 'LIVE_GATEWAY_OPERATIONAL_STORE'
    if mount['kind']=='READONLY_METADATA_CANDIDATE':return 'STATIC_CAPTURE_CANDIDATE'
    return mount['kind']


def plan(peers,*,exact_static_input=False):
    require(digest(CONTRACT)==CONTRACT_HASH,'RETAINED_LIFECYCLE_SOURCE_CONTRACT_CHANGED')
    result={};totals={'readonly':0,'mutable':0,'tokens':0,'stores':0,'staticRegularMounts':0,'nodes':0}
    def nodes(tree):return 1+sum(nodes(t) for t in tree.get('children',{}).values())
    for role,peer in sorted(peers.items()):
        result[role]=[]
        for mount in peer['mounts']:
            kind=classification(role,mount);result[role].append(kind)
            if mount['kind']=='READONLY_METADATA_CANDIDATE':
                totals['readonly']+=1;totals['nodes']+=nodes(mount['metadataTree'])
                if kind=='RENEWABLE_TOKEN_OWNER_INPUT':totals['tokens']+=1
                elif kind=='LIVE_GATEWAY_OPERATIONAL_STORE':totals['stores']+=1
                elif mount['metadataTree']['kind']=='REGULAR_FILE':totals['staticRegularMounts']+=1
                else:require(not exact_static_input,'UNCLASSIFIED_READONLY_DIRECTORY_OR_SPECIAL_SOURCE')
            elif mount['kind']=='MUTABLE_CONTENT_NOT_OBSERVED':totals['mutable']+=1
            else:require(not exact_static_input,'UNCLASSIFIED_EPHEMERAL_OR_SPECIAL_MOUNT')
    if exact_static_input:
        require(totals=={'readonly':25,'mutable':4,'tokens':7,'stores':1,'staticRegularMounts':17,'nodes':33},
            'EXACT_CAPTURED_TWENTY_FIVE_READONLY_FOUR_MUTABLE_LIFECYCLE_SET_REQUIRED')
    return result,totals


def observe_mounts(c,role,mounts):
    """Static trees keep all nine fields; live/RW roots keep five custody fields.

    No live leaf, directory listing, token body or database handle is opened.
    A successful result proves only the fields that this function observes.
    """
    proofs=[]
    for mount in mounts:
        c.guarded();kind=classification(role,mount)
        row={k:copy.deepcopy(v) for k,v in mount.items() if k not in ('metadataTree','metadata')}
        row['lifecycleClass']=kind
        if kind=='STATIC_CAPTURE_CANDIDATE':
            observed=c.metadata_tree(Path(mount['source']))
            require(observed==mount['metadataTree'],'CURRENT_RETAINED_STATIC_METADATA_DIFFERS_FROM_CAPTURE')
            row['metadataTree']=observed;c.counts['readonlyMounts']+=1
        elif kind in LIVE or kind=='MUTABLE_CONTENT_NOT_OBSERVED':
            expected=(mount['metadataTree']['metadata'] if kind in LIVE else mount['metadata'])[:5]
            fd=c.node(Path(mount['source']))
            try:
                actual=attrs(os.fstat(fd))
                require(actual[:5]==expected and not stat.S_ISLNK(actual[2]),
                    'CURRENT_RETAINED_ROOT_METADATA_DIFFERS_FROM_CAPTURE')
                if kind in LIVE:require(stat.S_ISDIR(actual[2]),'CURRENT_LIVE_ROOT_DIRECTORY_REQUIRED')
                old=c.observed.get(mount['source'])
                require(old is None or (old[0][:5]==actual[:5] and not old[1]),
                    'STATIC_AND_LIVE_ROOT_CLASSIFICATION_OVERLAP')
                c.observed[mount['source']]=(actual,False);row['rootCustodyMetadata']=actual[:5]
            finally:os.close(fd)
            c.counts['readonlyMounts' if kind in LIVE else 'mutableMounts']+=1
        else:
            # Legacy ephemeral/special declarations remain explicitly unobserved.
            c.counts['ephemeralMounts']+=1
        proofs.append(row)
    return proofs


def excluded_sources(peers,classes):
    """Include captured live descendants to reject differently named bind aliases."""
    result=[]
    def tree(path,node):
        result.append((path,node['metadata']))
        for name,child in node.get('children',{}).items():tree(path/name,child)
    for role,peer in peers.items():
        for mount,kind in zip(peer['mounts'],classes[role]):
            if kind in LIVE:tree(Path(mount['source']),mount['metadataTree'])
            elif kind=='MUTABLE_CONTENT_NOT_OBSERVED':result.append((Path(mount['source']),mount['metadata']))
    return result
