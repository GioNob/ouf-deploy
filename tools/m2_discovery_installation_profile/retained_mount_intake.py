"""Hash-bound intake of the successful private retained-mount capture.

Produces declarations for a new review, never expected permission policy or
current admission. Inventory labels are resolved by unique accepted IDs. The
Engine runtime-binding contract preserves mount order, unlike the historical
producer's sorted stable_binding; do not substitute one digest for the other.
"""
import copy, stat
from pathlib import Path
from .custody_capture import decode, digest, encoded, require
from .retained_mount_capture import SEED_HASH, RETAINED, ROLES, LIMITS, identity
from .retained_mount_role_correction import (OUTPUT, PREDECESSOR_HASH, PUBLIC_ROSTER_HASH,
    PROFILE, ROSTER, select_roles)

CANDIDATE = OUTPUT/'retained-mounts.private.json'
CANDIDATE_HASH = '46f6e6355a1bb133c4f72537f09d7b60250fd4c47265cde24fc1ea792cb366a7'
RESULT_HASH = '59935457cad39f7ffe245c8e76a71216b73ebf49bc27c7a20e5bf4e1c7612c0f'
COMMON = ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')
FALSE = ('observedMetadataIsExpectedPolicy','mountFileContentsObserved','mutableContentsObserved',
    'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance')


def validate_capture(candidate, result, seed, *, candidate_hash=CANDIDATE_HASH,
        result_hash=RESULT_HASH, seed_hash=SEED_HASH, roster=ROSTER):
    require(digest(candidate)==candidate_hash and digest(result)==result_hash and digest(seed)==seed_hash,
        'EXACT_SUCCESSFUL_RETAINED_CAPTURE_AND_ORIGINAL_SEED_REQUIRED')
    require(set(candidate)=={'schema','seedHash','bootId','peers','limits','budgetProfile','publicRosterHash',
        'inventoryRoleMap','predecessorResultHash',*FALSE}
        and candidate['schema']=='ouf.m2-retained-mount-custody-candidates.v1'
        and candidate['seedHash']==seed_hash and candidate['bootId']==seed['bootId']
        and candidate['publicRosterHash']==PUBLIC_ROSTER_HASH and candidate['predecessorResultHash']==PREDECESSOR_HASH
        and candidate['limits']==LIMITS and candidate['budgetProfile']==PROFILE
        and all(candidate[k] is False for k in FALSE), 'EXACT_NONAUTHORITATIVE_RETAINED_CANDIDATE_REQUIRED')
    require(result['schema']=='ouf.m2-retained-mount-role-correction-result.v1'
        and result['status']=='PRIVATE_MOUNT_CANDIDATES_CAPTURED_NOT_ADMITTED'
        and result['candidateHash']==candidate_hash and result['selectedRetainedPeers']==10
        and result['cumulativeControlAttempts']==2 and result['cumulativeEngineGetAttempts']==20
        and result['predecessorEngineGetAttempts']==0 and result['predecessorPreserved'] is True
        and result['predecessorResultHash']==PREDECESSOR_HASH
        and all(result[k] is False for k in ('completePrivateCustodyProven','mountFileContentsObserved',
            'mutableContentsObserved','privateInputPathsOrValuesPrinted','runtimeAuthorityIssued',
            'targetApplyAuthorized','releaseAcceptance','automaticReplayAllowed')),
        'SUCCESSFUL_UNADMITTED_CORRECTIVE_CAPTURE_RECEIPT_REQUIRED')
    mapping=select_roles(seed,roster)
    require(candidate['inventoryRoleMap']==mapping and type(candidate['peers']) is dict
        and set(candidate['peers'])==set(result['retainedRuntimeImageIds'])==RETAINED,
        'SAME_ID_SELECTED_RETAINED_CAPTURE_AND_SEED_ROLES_REQUIRED')
    counts={'readonlyMounts':0,'mutableMounts':0,'ephemeralMounts':0,'staticEntries':0,'specialSources':0}
    def tree(row,depth=0):
        require(type(row) is dict and depth<=LIMITS['depth'] and row.get('contentsObserved') is False,
            'BOUNDED_UNOBSERVED_RETAINED_METADATA_TREE_REQUIRED')
        metadata=row['metadata']
        require(type(metadata) is list and len(metadata)==9 and all(type(v) is int and v>=0 for v in metadata)
            and not stat.S_ISLNK(metadata[2]),'EXACT_RETAINED_METADATA_FRAME_REQUIRED')
        counts['staticEntries']+=1
        require(counts['staticEntries']<=LIMITS['entries'],'BOUNDED_RETAINED_METADATA_INTAKE_REQUIRED')
        mode=metadata[2]
        if stat.S_ISDIR(mode):
            require(set(row)=={'metadata','kind','contentsObserved','children'} and row['kind']=='DIRECTORY'
                and type(row['children']) is dict,'EXACT_RETAINED_DIRECTORY_METADATA_REQUIRED')
            for name,child in row['children'].items():
                require(type(name) is str and name not in ('','.','..') and '/' not in name,
                    'EXACT_RETAINED_METADATA_CHILD_NAME_REQUIRED');tree(child,depth+1)
        elif stat.S_ISREG(mode):
            require(set(row)=={'metadata','kind','contentsObserved'} and row['kind']=='REGULAR_FILE'
                and metadata[5]==1,'EXACT_SINGLE_LINK_RETAINED_FILE_METADATA_REQUIRED')
        else:
            require(set(row)=={'metadata','kind','contentsObserved','protocolAccessIsReadOnlyProven'}
                and row['kind']=='SPECIAL_FILE' and row['protocolAccessIsReadOnlyProven'] is False,
                'RETAINED_SPECIAL_PROTOCOL_RIGHTS_UNPROVEN_REQUIRED');counts['specialSources']+=1
    for role,proof in candidate['peers'].items():
        prior=seed['observations'][mapping[role]];pin=seed['processPins'][mapping[role]]
        require(set(proof)=={'containerId','imageId','runtimeIdentityHash','processPin','mounts'}
            and proof['containerId']==prior['Id'] and proof['imageId']==prior['Image']==result['retainedRuntimeImageIds'][role]
            and proof['runtimeIdentityHash']==digest(identity(prior)) and proof['processPin']==pin,
            'FULL_RETAINED_IDENTITY_AND_PROCESS_MUST_MATCH_ORIGINAL_PRIVATE_SEED')
        require(type(proof['mounts']) is list and len(proof['mounts'])==len(prior['Mounts'])<=LIMITS['mountsPerPeer'],
            'EXACT_RETAINED_MOUNT_DECLARATION_COUNT_REQUIRED')
        for captured,mount in zip(proof['mounts'],prior['Mounts']):
            require(captured['mountHash']==digest(mount) and captured['type']==mount['Type']
                and captured['source']==mount.get('Source','') and captured['destination']==mount['Destination']
                and captured['readOnly'] is (not mount['RW']) and captured['contentsObserved'] is False,
                'FULL_RETAINED_MOUNT_BINDING_REQUIRED')
            if mount['Type']=='tmpfs':
                counts['ephemeralMounts']+=1
                require(captured['kind']=='EPHEMERAL_CONTENT_NOT_OBSERVED','RETAINED_EPHEMERAL_CONTENT_NOT_ADMITTED')
            elif mount['RW']:
                counts['mutableMounts']+=1
                require(captured['kind']=='MUTABLE_CONTENT_NOT_OBSERVED','RETAINED_MUTABLE_CONTENT_NOT_ADMITTED')
                if not (stat.S_ISDIR(captured['metadata'][2]) or stat.S_ISREG(captured['metadata'][2])):
                    counts['specialSources']+=1
            else:
                counts['readonlyMounts']+=1
                require(captured['kind']=='READONLY_METADATA_CANDIDATE','RETAINED_STATIC_METADATA_NOT_POLICY')
                # Original producer includes contentsObserved on both the mount
                # row and every readonly metadata-tree node.
                tree(captured['metadataTree'])
    require(all(result['counts'][k]==v for k,v in counts.items())
        and result['counts']['engineGets']==20 and result['counts']['metadataReads']==3
        and all(result['counts'][k]==0 for k in ('credentialFileReads','applicationMacKeyReads',
            'publicCertificateReads','mountFileContentBytesRead')),
        'RETAINED_CAPTURE_RECEIPT_AND_PRIVATE_METADATA_COUNTS_DISAGREE')
    return mapping


def runtime_proposal(candidate,result,seed,common,**bindings):
    """Explicit independent review hashes; no old authority or guessed defaults."""
    from .current_cohort import validate_inputs, INPUT_SCHEMA
    from engine_creation import Engine
    mapping=validate_capture(candidate,result,seed,**bindings)
    require(type(common) is dict and set(common)==set(COMMON), 'FOUR_EXPLICIT_CURRENT_REVIEW_HASH_BINDINGS_REQUIRED')
    runtime={'schema':INPUT_SCHEMA,**copy.deepcopy(common),'bootId':seed['bootId'],
        'engineBinding':{**copy.deepcopy(seed['engineBinding']),
            'startTicks':seed['rootProcessPins']['engine']['startTicks']},
        'rootProcessPins':copy.deepcopy(seed['rootProcessPins']),
        'peers':{r:{'name':seed['observations'][a]['Name'],
            'runtimeBinding':Engine.runtime_binding(seed['observations'][a]),
            'processPin':copy.deepcopy(seed['processPins'][a])} for r,a in mapping.items()}}
    validate_inputs(runtime)
    result={'schema':'ouf.discovery-retained-mount-runtime-review-fragment.v1',
        'candidateHash':digest(candidate),'captureResultHash':digest(result),'originalSeedHash':digest(seed),
        'runtimeInputs':runtime,'runtimeInputsHash':digest(runtime),'retainedMounts':copy.deepcopy(candidate['peers']),
        'retainedMountMetadataHash':digest(candidate['peers']),
        'reviewCommonHashesIndependentlySelected':True,'currentAtExecutionVerificationRequired':True,
        'expectedMountPolicyEstablished':False,'mountedFileContentsObserved':False,
        'completeParentReview':False,'completePrivateCustodyProven':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
    require(len(encoded(result))<=8388608,'BOUNDED_RETAINED_MOUNT_RUNTIME_REVIEW_FRAGMENT_REQUIRED')
    return result
