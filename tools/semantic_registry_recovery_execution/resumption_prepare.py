"""Prepare a complete successor review from one exact retained checkpoint.

Only private metadata and sealed source copies are written. No credentials,
Engine socket, IAM endpoint, Gateway or database are opened here.
"""
import copy
from pathlib import Path
from .core import digest, encoded, require, hashed
from . import postboot_prepare as p
from .resumption import scope
from tools.semantic_registry_postboot_owner.contract import compile_scope

SCHEMA='ouf.semantic-registry-resumption-case.v1'


def validate_case(case):
    require(type(case) is dict and set(case)=={'schema','inputs','historicalCapsule','ownerBudget'}
            and case['schema']==SCHEMA,'EXACT_CHECKPOINT_RESUMPTION_CASE_REQUIRED')
    for key in ('inputs','historicalCapsule'):
        binding=case[key]
        require(type(binding) is dict and set(binding)=={'path','sha256'} and hashed(binding['sha256']),
                'EXACT_RESUMPTION_CASE_BINDING_REQUIRED')
        p.exact_path(binding['path'])
    require(case['ownerBudget']=={'maximumGrantAttempts':1,'maximumSeconds':900,'attemptTimeoutSeconds':30,'intervalSeconds':60},
            'EXACT_ONE_GRANT_FINITE_SUCCESSOR_PROPOSAL_REQUIRED')


def root(case,manifest):
    validate_case(case)
    return Path(p.PARENT)/('semantic-registry-postboot-inputs-'+digest({'operation':SCHEMA,
        'inputsHash':case['inputs']['sha256'],'sourceClosureHash':digest(manifest)}))


def inputs(case,files):
    value,_=files.json(case['inputs']['path'],case['inputs']['sha256'])
    require(value.get('schema')=='ouf.semantic-registry-resumption-inputs.v1'
            and value.get('newGrantAllowance')==0 and value.get('runtimeAuthorityIssued') is False,
            'CAPTURED_INPUTS_ARE_NOT_AUTHORITY_REQUIRED')
    oldpath=value['privatePreparedInputs'];binding=value['inputBindings'].get(oldpath)
    require(type(binding) is dict and set(binding)=={'sha256'},'PINNED_ORIGINAL_PREPARATION_REQUIRED')
    old,_=files.json(oldpath,binding['sha256'],maximum=16777216)
    require(old.get('schema')=='ouf.semantic-registry-postboot-prepared-inputs.v1', 'ORIGINAL_PREPARED_INPUTS_REQUIRED')
    return value,old


def retained_pins(case,value,files):
    historical=case['historicalCapsule'];pins=value['inputBindings']
    require(pins.get(historical['path'])=={'sha256':historical['sha256']}
            and 1<=len(pins)<=64,'EXACT_PRIOR_LITERAL_CAPSULE_PROVENANCE_REQUIRED')
    for path,pin in pins.items():
        if path==historical['path']:continue
        require(type(pin) is dict and set(pin)=={'sha256'} and hashed(pin['sha256']),
                'CLOSED_CAPTURED_INPUT_HASH_REQUIRED')
        files.seal(path,16777216,pin['sha256'])


def contexts(case,value,old,manifest,source_profiles):
    context=copy.deepcopy(old['nativeContext'])
    context['nodeRecipe']['sourceClosureHash']=digest(manifest)
    owner=copy.deepcopy(old['ownerContext'])
    previous=copy.deepcopy(owner)
    owner.update(schema='ouf.semantic-registry-postboot-successor-owner-context.v1',
        predecessorContext=previous,resumptionInputs=copy.deepcopy(value),resumptionBinding=copy.deepcopy(case['inputs']),
        predecessorJournalPath=value['retainedOwnerRecords']['owner-session.json']['journalPath'],
        retainedRecords={**copy.deepcopy(value['retainedOwnerRecords']),'recovery.json':copy.deepcopy(value['retainedOwnerJournal'])},
        sourceClosureHash=digest(manifest),sourceFiles=copy.deepcopy(source_profiles),budget=copy.deepcopy(case['ownerBudget']))
    compile_scope(owner);scope(context['plan'],owner)
    return context,owner


def prepare(case,manifest,sources):
    validate_case(case);files=p.Files(maximum_reads=256);value,old=inputs(case,files)
    retained_pins(case,value,files)
    destination=root(case,manifest)
    # This is a preparation claim, not an authorization or token allowance.
    # Source changes can produce a new preparation, but issuance/installation
    # remain globally fenced by the predecessor journal hash, independently.
    destination.mkdir(mode=0o700)
    p.publish(destination,'claim.json',{'schema':SCHEMA,'inputsHash':case['inputs']['sha256'],
        'sourceClosureHash':digest(manifest),'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False})
    source_profiles=p.source_files(destination,manifest,sources,files)
    context,owner=contexts(case,value,old,manifest,source_profiles)
    p.exact_path('/proc/sys/kernel/random/boot_id')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==value['retainedNativeJournal']['bootId'],
            'SAME_CAPTURED_BOOT_FOR_SUCCESSOR_PREPARATION_REQUIRED')
    private={'schema':'ouf.semantic-registry-postboot-prepared-inputs.v1','nativeContext':context,'ownerContext':owner,
        'registryInputs':copy.deepcopy(old['registryInputs']),'authorityInputs':copy.deepcopy(old['authorityInputs']),
        'sourceClosure':copy.deepcopy(manifest),'preparationProof':{'schema':SCHEMA,'case':copy.deepcopy(case),
            'caseHash':digest(case),'sourceClosureHash':digest(manifest),'resumptionInputsHash':case['inputs']['sha256'],
            'retainedNativeJournalHash':digest(value['retainedNativeJournal']),'retainedControlledGrantAttempts':320,
            'engineGets':0,'oauthRequests':0,'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'budgetReset':False}}
    files.verify()
    p.publish(destination,'prepared.json',private)
    return {'privatePreparationPath':str(destination/'prepared.json'),'privatePreparationHash':digest(private),
            'sourceClosureHash':digest(manifest),'retainedControlledGrantAttempts':320,
            'proposedMaximumNewServiceGrantAttempts':1,'proposedMaximumSeconds':900,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'engineGets':0,'oauthRequests':0,
            'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}


def read(case,manifest):
    validate_case(case);files=p.Files(maximum_reads=256)
    private,_=files.json(str(root(case,manifest)/'prepared.json'),maximum=16777216)
    require(private.get('sourceClosure')==manifest and private.get('preparationProof',{}).get('case')==case,
            'EXACT_RETAINED_SUCCESSOR_PREPARATION_REQUIRED')
    value,old=inputs(case,files)
    expected=contexts(case,value,old,manifest,private['ownerContext']['sourceFiles'])
    require((private['nativeContext'],private['ownerContext'])==expected
            and private['registryInputs']==old['registryInputs'] and private['authorityInputs']==old['authorityInputs'],
            'SUCCESSOR_CONTEXT_CANNOT_CHANGE_RETAINED_DEPLOYMENT_OR_AUTHORITY_INPUTS')
    for name,binding in private['ownerContext']['sourceFiles'].items():
        files.seal(binding['path'],262144,manifest['sourceHashes'][name])
    files.verify()
    return private
