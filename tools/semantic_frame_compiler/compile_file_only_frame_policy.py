"""Independent file-only frame compiler; no observed OCI or signing authority.

Reuse the generic immutable-file compiler with the two directory slots projected
out, then restore their independently verified bind declarations. The result is
accepted only by the explicit four-mount, token-owner-backed file-only observer.
"""
import copy,re
from compile_creation_frame_policy import compile_policy as compile_files,canonical,path,require,environment
from compile_semantic_proposal_frame_policy import receipt_key
from file_only_profile import FileOnlyProfile
from gated_creation_plan import ENTRY

def compile_policy(template,launch,context,*,execution_profile,renewable_token,delegation_key_metadata_hash,proposal_receipt_key):
    require(type(execution_profile) is FileOnlyProfile,'EXACT_TYPED_FILE_ONLY_FRAME_PROFILE_REQUIRED')
    profile_hash=execution_profile.verify(execution_profile.request);tree=execution_profile.configtree
    require(type(template) is dict and type(launch) is dict and len(canonical(template))<=131072 and len(canonical(launch))<=131072,
            'BOUNDED_INDEPENDENT_FILE_ONLY_FRAME_REQUIRED')
    template,launch=copy.deepcopy(template),copy.deepcopy(launch);original=copy.deepcopy(launch)
    token_fields={'source','target','fileName','gid','ownerBindingHash','maxBytes','minimumRemainingSeconds'}
    native_fields=token_fields|{'directoryDevice','directoryInode'}
    deferred_fields=token_fields|{'directoryCustodyScopeHash'}
    require(type(renewable_token) is dict and set(renewable_token) in (native_fields,deferred_fields),'EXACT_FILE_ONLY_RENEWABLE_TOKEN_REQUIRED')
    deferred=set(renewable_token)==deferred_fields
    require((deferred and type(renewable_token['directoryCustodyScopeHash']) is str
        and re.fullmatch('[a-f0-9]{64}',renewable_token['directoryCustodyScopeHash'])) or
        (not deferred and type(renewable_token['directoryDevice']) is int and renewable_token['directoryDevice']>=0
            and type(renewable_token['directoryInode']) is int and renewable_token['directoryInode']>0),
        'EXACT_COMPLETED_OR_SIGNED_FUTURE_TOKEN_CUSTODY_REQUIRED')
    for k in ('source','target'):path(renewable_token[k]);require(renewable_token[k]!='/','EXACT_TOKEN_DIRECTORY_REQUIRED')
    require(renewable_token['gid']==10001 and type(renewable_token['gid']) is int
        and type(renewable_token['fileName']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',renewable_token['fileName'])
        and renewable_token['fileName'] not in ('.','..') and type(renewable_token['maxBytes']) is int and 1<=renewable_token['maxBytes']<=16384
        and type(renewable_token['minimumRemainingSeconds']) is int and 1<=renewable_token['minimumRemainingSeconds']<=3600
        and re.fullmatch('[a-f0-9]{64}',renewable_token['ownerBindingHash']),'EXACT_FILE_ONLY_OWNER_ADMISSION_BINDING_REQUIRED')
    sources=launch.get('sources');receipt=receipt_key(proposal_receipt_key)
    require(type(sources) is list and len(sources)==2 and sources[1]=={k:v for k,v in receipt.items() if k!='metadataHash'},
        'EXACT_CONSULTATION_AND_RECEIPT_FILE_SET_REQUIRED')
    key=sources[0];require(key['uid']==key['gid']==10001 and key['mode']==0o400 and key['readOnly'] is True
        and type(delegation_key_metadata_hash) is str and re.fullmatch('[a-f0-9]{64}',delegation_key_metadata_hash),
        'EXACT_ORIGINAL_CONSULTATION_KEY_METADATA_REQUIRED')
    dirs=[{k:tree[k] for k in ('source','target','readOnly')},{k:renewable_token[k] for k in ('source','target')}|{'readOnly':True}]
    bindings=[{k:s[k] for k in ('source','target','readOnly')} for s in sources]+dirs
    require(launch.get('manifest',{}).get('mounts')==bindings and len({b['source'] for b in bindings})==len({b['target'] for b in bindings})==4
        and not any(a['target'].startswith(b['target']+'/') or a['source'].startswith(b['source']+'/') for a in bindings for b in bindings if a is not b),
        'EXACT_DISTINCT_NONSHADOWING_FOUR_MOUNT_MANIFEST_REQUIRED')
    # The actual launch, including inherited image environment, is independently
    # derived and must equal the signed creation request (plus Docker HOSTNAME).
    expected_env=environment(execution_profile.request['Env']);env=environment(launch['startup']['env'])
    require(env.pop('HOSTNAME',None)=='$OUF_HOSTNAME' and env==expected_env
        and launch['startup']['args']==execution_profile.request['Entrypoint']+(execution_profile.request.get('Cmd') or [])
        and launch['startup']['uid']==launch['startup']['gid']==10001,'FILE_ONLY_FRAME_AND_SIGNED_LAUNCH_DRIFT')
    mounts=template.get('expectedOci',{}).get('mounts');require(type(mounts) is list,'FILE_ONLY_OCI_MOUNT_TEMPLATE_REQUIRED')
    for directory in dirs:
        found=[m for m in mounts if m.get('destination')==directory['target']]
        require(len(found)==1 and found[0].get('type')=='bind' and found[0].get('source')==directory['source']
            and type(found[0].get('options')) is list and bool({'ro','rro'}&set(found[0]['options']))
            and not {'rw','shared','rshared','slave','rslave'}&set(found[0]['options']),'EXACT_READONLY_DIRECTORY_TEMPLATE_REQUIRED')
    full_mounts=copy.deepcopy(mounts);directory_targets={d['target'] for d in dirs}
    template['expectedOci']['mounts']=[m for m in mounts if m.get('destination') not in directory_targets]
    launch['manifest']['mounts']=bindings[:2]
    # ENTRY is an exact, already validated runtime shell program. Its literal
    # $OUF_APPLICATION_GATE is not a Docker template slot. Project only the two
    # authenticated argv fields while the unchanged generic compiler resolves
    # and rejects template slots everywhere else; never rewrite the shell text.
    full_args=copy.deepcopy(launch['startup']['args'])
    gated=execution_profile.request['Entrypoint']==ENTRY
    if gated:
        require(template['expectedOci']['process'].get('args')==full_args,
            'FILE_ONLY_FRAME_AND_SIGNED_LAUNCH_DRIFT')
        application_args=copy.deepcopy(execution_profile.request['Cmd'])
        template['expectedOci']['process']['args']=copy.deepcopy(application_args)
        launch['startup']['args']=copy.deepcopy(application_args)
    result=compile_files(template,launch,context)
    if gated:
        result['expectedOci']['process']['args']=copy.deepcopy(full_args)
        result['startup']['args']=copy.deepcopy(full_args)
    resolved=result['expectedOci']['mounts'];by_target={m['destination']:m for m in resolved}
    result['expectedOci']['mounts']=[copy.deepcopy(m) if m.get('destination') in directory_targets else by_target[m['destination']] for m in full_mounts]
    result.update(schema=('ouf.semantic-configured-file-only-four-mount-frame-policy.v2-proposal' if deferred
        else 'ouf.semantic-configured-file-only-four-mount-frame-policy.v1'),executionProfileHash=profile_hash,
        manifest=original['manifest'],configtree=copy.deepcopy(tree),renewableToken=copy.deepcopy(renewable_token),
        delegationKeyTarget=key['target'],delegationKeyMetadataHash=delegation_key_metadata_hash,proposalReceiptKey=receipt)
    checked=copy.deepcopy(result)
    if gated:
        # Only these two complete, exact signed argv lists are excluded from
        # slot scanning. A matching string in ENV, paths, hooks or metadata is
        # still rejected, including directory inputs restored after projection.
        for process in (checked['expectedOci']['process'],checked['startup']):
            require(process['args']==full_args,'FILE_ONLY_GATE_COMMAND_DRIFT')
            process['args']=copy.deepcopy(application_args)
    require(b'$OUF_' not in canonical(checked) and len(canonical(result))<=131072,'UNRESOLVED_OR_UNBOUNDED_FILE_ONLY_FRAME')
    return result
