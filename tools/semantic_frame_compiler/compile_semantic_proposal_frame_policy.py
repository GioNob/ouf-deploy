"""Independent seven-mount proposal-channel plan; no observed OCI or authority.

Preserve the six-mount compiler and its original static-key identity. A distinct
root-owned receipt key is the fifth immutable file, never a configtree member
or the renewable policy token. This pure compiler reads no secret/key bytes.
"""
import copy
import hashlib
from compile_six_mount_frame_policy import compile_policy as compile_six
from compile_six_mount_frame_policy import require,canonical,path,Denied

def receipt_key(binding):
    fields={'source','target','readOnly','uid','gid','mode','maxBytes','sha256','metadataHash'}
    require(type(binding)is dict and set(binding)==fields,'EXACT_PROPOSAL_RECEIPT_KEY_BINDING_REQUIRED')
    value=copy.deepcopy(binding)
    for key in ('source','target'):
        path(value[key]);require(value[key]!='/', 'PROPOSAL_RECEIPT_KEY_PATH_REQUIRED')
    require(type(value['uid'])is int and value['uid']==0 and type(value['gid'])is int and value['gid']==10001
        and type(value['mode'])is int and value['mode']==0o440 and value['readOnly']is True
        and type(value['maxBytes'])is int and 1<=value['maxBytes']<=256,
        'ROOT_OWNED_GROUP_READONLY_PROPOSAL_KEY_REQUIRED')
    for key in ('sha256','metadataHash'):
        require(type(value[key])is str and len(value[key])==64 and all(c in '0123456789abcdef'for c in value[key]),
            'INDEPENDENT_PROPOSAL_KEY_BYTES_AND_METADATA_HASH_REQUIRED')
    return value

def compile_policy(template,launch,context,*,configtree,renewable_token,delegation_key_metadata_hash,proposal_receipt_key):
    key=receipt_key(proposal_receipt_key)
    require(type(template)is dict and type(launch)is dict,'EXACT_PROPOSAL_FRAME_INPUTS_REQUIRED')
    require(len(canonical(template))<=131072 and len(canonical(launch))<=131072,'PROPOSAL_FRAME_INPUT_UNBOUNDED')
    template,launch=copy.deepcopy(template),copy.deepcopy(launch)
    sources=launch.get('sources');manifest=launch.get('manifest',{})
    require(type(sources)is list and len(sources)==5,'EXACT_FIVE_FILES_AND_TWO_DIRECTORIES_REQUIRED')
    file={k:key[k]for k in key if k!='metadataHash'}
    require(sources[4]==file,'FIFTH_IMMUTABLE_SOURCE_MUST_BE_DISTINCT_RECEIPT_KEY')
    declared=manifest.get('mounts')
    require(type(declared)is list and len(declared)==7,'EXACT_SEVEN_MOUNT_MANIFEST_REQUIRED')
    binds=[{k:s[k]for k in ('source','target','readOnly')}for s in sources]
    binds+=[{k:configtree[k]for k in ('source','target','readOnly')},
        {k:renewable_token[k]for k in ('source','target')}|{'readOnly':True}]
    require(binds==declared and len({b['source']for b in binds})==len({b['target']for b in binds})==7,
        'DISTINCT_EXACT_SEVEN_SOURCE_TARGET_BINDINGS_REQUIRED')
    require(not any(a['target'].startswith(b['target']+'/')for a in binds for b in binds if a is not b),
        'NONSHADOWING_SEVEN_MOUNT_TARGETS_REQUIRED')
    require(not any(key['source'].startswith(directory['source']+'/')for directory in (configtree,renewable_token)),
        'PROPOSAL_KEY_CANNOT_ENTER_CONFIGTREE_OR_TOKEN_DIRECTORY')
    mounts=template.get('expectedOci',{}).get('mounts')
    require(type(mounts)is list,'PROPOSAL_FRAME_MOUNT_TEMPLATE_REQUIRED')
    selected=[(i,m)for i,m in enumerate(mounts)if m.get('destination')==key['target']]
    require(len(selected)==1,'EXACT_PROPOSAL_KEY_TEMPLATE_MOUNT_REQUIRED')
    index,mount=selected[0]
    require(mount.get('type')=='bind' and mount.get('source')==key['source']
        and type(mount.get('options'))is list and bool({'ro','rro'}&set(mount['options']))
        and not {'rw','shared','rshared','slave','rslave'}&set(mount['options']),
        'PRIVATE_READONLY_PROPOSAL_KEY_TEMPLATE_REQUIRED')
    # Project only the independently supplied extra slot. All inherited source,
    # process, resource, template and original-key checks still run unchanged.
    launch['sources'].pop(4);launch['manifest']['mounts'].pop(4)
    extra=template['expectedOci']['mounts'].pop(index)
    result=compile_six(template,launch,context,configtree=configtree,renewable_token=renewable_token,
        delegation_key_metadata_hash=delegation_key_metadata_hash)
    result['schema']='ouf.semantic-configured-proposal-seven-mount-frame-policy.v1'
    result['sources'].append(file);result['manifest']['mounts'].insert(4,binds[4])
    result['expectedOci']['mounts'].insert(index,extra)
    result['proposalReceiptKey']=key
    require(b'$OUF_'not in canonical(result) and len(canonical(result))<=131072,'PROPOSAL_FRAME_POLICY_UNBOUNDED_OR_UNRESOLVED')
    return result

def compilation_receipt(template,launch,context,policy):
    return {'schema':'ouf.semantic-proposal-seven-mount-frame-compilation.v1',
        **{name+'Hash':hashlib.sha256(canonical(value)).hexdigest()for name,value in
            (('template',template),('launch',launch),('context',context),('policy',policy))},
        'immutableFileCount':5,'directoryMountCount':2,'observedOciUsed':False,
        'inputsAuthenticated':False,'templateApproved':False,'privateKeyReads':0,
        'signaturesIssued':0,'acceptanceGranted':False,'startAuthorized':False}
