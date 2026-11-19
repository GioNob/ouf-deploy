"""Pure review of fixed installation inputs before new peer identities exist.

Only the generation reference, a newly owned logical-lock inode, recipe hash
and service-unit hash are materialized later. Expected node recipes, images,
rootfs seals, runtime, paths and budgets are fixed first. No observation is
converted to an expected OCI recipe or to an admission by this compiler.
"""
import copy,dataclasses,ipaddress,re
from .custody_capture import digest,require
from .installed_lease_guard import CONFIG_FIELDS
from .lease_service import RECIPE_FIELDS
from .lease_worker import SCOPE_FIELDS
from .lease_unit import compile_unit,path
from .lease_capsule import PINS,SOURCE
from .native_generation_probe import generation_reference
from bounded_recovery import Policy,fingerprint
from tools.semantic_provider_lease_owner import LeaseOwner

CAPSULE_SHA='3b88cd8f329ea5f143bed61906270070341a6cda9ebc534a2268d82eeada3262'
CAPSULE_BYTES=464208
ZERO='0'*64
PROFILE_FIELDS={'nodeRecipeHash','applicationHash','imageConfigurationHash','rootfsSealHash'}
INDEPENDENT_FIELDS=PROFILE_FIELDS-{'applicationHash'}


def hashed(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None
def identity(value):
    return (type(value) is list and len(value)==6 and all(type(v) is int and v>=0 for v in value)
        and value[1]>0 and value[2:]==[0,0,0o100600,1])


def template(configuration,recipe,python,*,source_closure_hash,expected_images,expected_node_profiles,
             installation_root,signing_key_paths,engine_unit='docker.service',sandbox_root=None):
    """Compile a static parent-review component; every return is unadmitted."""
    c,r,p=map(copy.deepcopy,(configuration,recipe,python));install=path(installation_root)
    require(hashed(source_closure_hash) and type(c) is dict and set(c)==CONFIG_FIELDS
        and c['schema']=='ouf.discovery-operational-lease-configuration.v1'
        and c['commonLockIdentity'] is None and c['serviceUnitHash']==ZERO,
        'STATIC_DISCOVERY_CONFIGURATION_WITH_EXACT_EXPLICIT_HOLES_REQUIRED')
    hashes={name:pin['sha256'] for name,pin in PINS.items()}
    manifest={'schema':'ouf.discovery-operational-lease-sources.v1','sourceHashes':hashes,
        'dependencyClosureHash':digest(hashes)}
    require(c['sourceManifest']==manifest,'CURRENT_QUALIFIED_DISCOVERY_RUNTIME_CLOSURE_REQUIRED')
    require(type(r) is dict and set(r)==RECIPE_FIELDS
        and r['schema']=='ouf.discovery-operational-lease-recipe.v1'
        and type(r['scope']) is dict and set(r['scope'])==SCOPE_FIELDS
        and r['scope']['generationRef'] is None and identity(r['leaseCommonLockIdentity']),
        'STATIC_DISCOVERY_RECIPE_WITH_ONE_GENERATION_HOLE_REQUIRED')
    policy=copy.deepcopy(r['policy']);require(type(policy) is dict and type(policy.get('delays')) is list,
        'EXACT_STATIC_DISCOVERY_RECOVERY_POLICY_REQUIRED')
    policy['delays']=tuple(policy['delays']);policy=Policy(**policy)
    require(dataclasses.asdict(policy)=={**r['policy'],'delays':tuple(r['policy']['delays'])},
        'COMPLETE_STATIC_DISCOVERY_RECOVERY_POLICY_REQUIRED')
    scope=r['scope']
    require(scope['sourceClosureHash']==manifest['dependencyClosureHash']
        and scope['installationInputsHash']==c['installationInputsHash']
        and scope['policyHash']==c['scopePolicyHash']==fingerprint(dataclasses.asdict(policy))
        and scope['coordinatorBindingHash']==fingerprint(r['binding'])
        and scope['configurationHash']==fingerprint(r['kernel'])
        and scope['dnsProfileHash']==fingerprint(r['dns'])
        and all(hashed(scope[k]) for k in SCOPE_FIELDS-{'generationRef','pollSeconds','heartbeatSeconds'})
        and type(scope['pollSeconds']) is int and 1<=scope['pollSeconds']<=300
        and type(scope['heartbeatSeconds']) is int and 1<=scope['heartbeatSeconds']<=30
        and hashed(c['desiredProfileHash']),
        'EXACT_STATIC_DISCOVERY_SCOPE_AND_PRESERVED_BUDGET_REQUIRED')
    require(type(r['binding']) is dict and set(r['binding'])=={'transactionId','configurationHash','leaseStructureHash'}
        and hashed(r['binding']['transactionId'])
        and r['binding']['configurationHash']==scope['configurationHash']
        and r['binding']['leaseStructureHash']==scope['leaseStructureHash'],
        'EXACT_STATIC_DISCOVERY_COORDINATOR_BINDING_REQUIRED')
    LeaseOwner(r['kernel'],r['dns'],None)  # Pure validation, no resolution/backend call.
    require(type(r['dns']['resolvers']) is list and 1<=len(r['dns']['resolvers'])<=4
        and all(type(v) is str and str(ipaddress.ip_address(v))==v for v in r['dns']['resolvers'])
        and type(r['dns']['resolverPort']) is int and 1<=r['dns']['resolverPort']<=65535,
        'EXACT_STATIC_DISCOVERY_NUMERIC_RESOLVERS_REQUIRED')
    verification=c['verification']
    require(type(verification) is dict and set(verification)=={'trustPolicy','openssl','context'}
        and type(verification['trustPolicy']) is dict and set(verification['trustPolicy'])=={'path','sha256'}
        and hashed(verification['trustPolicy']['sha256'])
        and type(verification['context']) is dict
        and set(verification['context'])=={'installationRef','entityRef','attestorRef'}
        and all(type(v) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}',v)
            for v in verification['context'].values())
        and type(verification['openssl']) is dict and set(verification['openssl'])=={'path','sha256','version'}
        and type(verification['openssl']['version']) is str and bool(verification['openssl']['version']),
        'EXACT_STATIC_DISCOVERY_PUBLIC_VERIFICATION_REQUIRED')
    require(type(c['sources']) is list and 5<=len(c['sources'])<=64
        and all(type(v) is dict and set(v)=={'path','sha256','maximumBytes'}
            and hashed(v['sha256']) and type(v['maximumBytes']) is int and 1<=v['maximumBytes']<=67108864
            for v in c['sources']), 'EXACT_STATIC_DISCOVERY_SOURCE_REFERENCES_REQUIRED')
    refs={path(v['path']):v for v in c['sources']}
    require(len(refs)==len(c['sources'])
        and refs.get(install+'/capsule.py')=={'path':install+'/capsule.py','sha256':CAPSULE_SHA,'maximumBytes':CAPSULE_BYTES}
        and refs.get(install+'/worker-recipe.json')=={'path':install+'/worker-recipe.json','sha256':ZERO,'maximumBytes':1048576},
        'QUALIFIED_CAPSULE_AND_EXACT_RECIPE_HASH_HOLE_REQUIRED')
    require(type(expected_images) is dict and type(expected_node_profiles) is dict
        and set(expected_images)==set(expected_node_profiles)=={'registry','provider'}
        and all(type(v) is str and re.fullmatch('sha256:[a-f0-9]{64}',v) for v in expected_images.values())
        and all(type(v) is dict and set(v)==INDEPENDENT_FIELDS and all(hashed(h) for h in v.values())
            for v in expected_node_profiles.values()),'INDEPENDENT_EXPECTED_TWO_NODE_RECIPES_AND_IMAGES_REQUIRED')
    require(type(signing_key_paths) is list and bool(signing_key_paths)
        and len(set(signing_key_paths))==len(signing_key_paths), 'EXPLICIT_PRIVATE_SIGNING_KEY_ISOLATION_SET_REQUIRED')
    keys=sorted(path(v) for v in signing_key_paths)
    # Validate all static sandbox constraints without inventing an OCI expected
    # frame. A deliberately marked synthetic probe is used only for compilation.
    sample={'schema':'ouf.discovery-lease-generation-observation.v1','desiredProfileHash':c['desiredProfileHash'],
        'profiles':{role:{**expected_node_profiles[role],'applicationHash':'1'*64} for role in expected_images},
        'bootId':'00000000-0000-0000-0000-000000000001',
        'engineBinding':{'socketPath':'/run/docker.sock','socketBinding':[1,1,0,0,0o660],
            'peerCredentials':[99,0,0],'startTicks':1},'peers':{
            role:{'containerId':str(i)*64,'imageId':expected_images[role],'dockerBindingHash':'1'*64,
                'pid':100+i,'startedAt':'SYNTHETIC_COMPILATION_ONLY','startTicks':i,
                'namespace':{'path':'/run/docker/netns/compile-'+role,'identity':[1,i]},
                'allowedPausedStates':[False,True] if role=='registry' else [False]}
            for i,role in enumerate(('registry','provider'),1)}}
    sample['nativeProfileHash']=digest(sample['profiles']);sample['generationRef']=generation_reference(sample)
    trial_c,trial_r=copy.deepcopy(c),copy.deepcopy(r)
    trial_c['commonLockIdentity']=[1,1,0,0,0o100600,1];trial_r['scope']['generationRef']=sample['generationRef']
    next(v for v in trial_c['sources'] if v['path']==install+'/worker-recipe.json')['sha256']=digest(trial_r)
    compile_unit(trial_c,trial_r,sample,p,installation_root=install,signing_key_paths=keys,
        engine_unit=engine_unit,sandbox_root=sandbox_root)
    return {'schema':'ouf.discovery-lease-installation-template.v1','sourceClosureHash':source_closure_hash,
        'runtimeSourceSnapshot':SOURCE,'capsuleSha256':CAPSULE_SHA,'capsuleBytes':CAPSULE_BYTES,
        'configurationTemplate':c,'recipeTemplate':r,'python':p,'expectedImages':copy.deepcopy(expected_images),
        'expectedNodeProfiles':copy.deepcopy(expected_node_profiles),'installationRoot':install,
        'signingKeyPaths':keys,'engineUnit':engine_unit,'sandboxRoot':path(sandbox_root or install+'-sandbox'),
        'currentNativeAdmissionStillRequired':True,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}


def recompile(value):
    require(type(value) is dict,'EXACT_DISCOVERY_INSTALLATION_TEMPLATE_REQUIRED')
    result=template(value['configurationTemplate'],value['recipeTemplate'],value['python'],
        source_closure_hash=value['sourceClosureHash'],expected_images=value['expectedImages'],
        expected_node_profiles=value['expectedNodeProfiles'],installation_root=value['installationRoot'],
        signing_key_paths=value['signingKeyPaths'],engine_unit=value['engineUnit'],sandbox_root=value['sandboxRoot'])
    require(value==result,'DISCOVERY_INSTALLATION_TEMPLATE_CHANGED');return result


def materialize(value,snapshot,logical_lock_identity):
    """Unsigned bytes only; caller must authenticate current native admission."""
    t=recompile(value);s=copy.deepcopy(snapshot)
    require(identity(logical_lock_identity),'FRESH_OWNED_PRIVATE_LOGICAL_LOCK_IDENTITY_REQUIRED')
    fields={'schema','desiredProfileHash','nativeProfileHash','profiles','bootId','generationRef','engineBinding','peers'}
    require(type(s) is dict and set(s)==fields and s['schema']=='ouf.discovery-lease-generation-observation.v1'
        and s['desiredProfileHash']==t['configurationTemplate']['desiredProfileHash']
        and set(s['profiles'])==set(s['peers'])=={'registry','provider'}
        and all(type(s['profiles'][role]) is dict and set(s['profiles'][role])==PROFILE_FIELDS
            and all(hashed(h) for h in s['profiles'][role].values())
            and {k:s['profiles'][role][k] for k in INDEPENDENT_FIELDS}==t['expectedNodeProfiles'][role]
            and s['peers'][role]['imageId']==t['expectedImages'][role] for role in s['profiles'])
        and s['nativeProfileHash']==digest(s['profiles']) and s['generationRef']==generation_reference(s),
        'CURRENT_GENERATION_MUST_RETAIN_INDEPENDENT_APPROVED_NODE_RECIPES_AND_IMAGES')
    c,r=copy.deepcopy(t['configurationTemplate']),copy.deepcopy(t['recipeTemplate'])
    c['commonLockIdentity']=copy.deepcopy(logical_lock_identity);r['scope']['generationRef']=s['generationRef']
    next(v for v in c['sources'] if v['path']==t['installationRoot']+'/worker-recipe.json')['sha256']=digest(r)
    unit=compile_unit(c,r,s,t['python'],installation_root=t['installationRoot'],
        signing_key_paths=t['signingKeyPaths'],engine_unit=t['engineUnit'],sandbox_root=t['sandboxRoot'])
    c['serviceUnitHash']=unit['unitSha256']
    return {'schema':'ouf.discovery-lease-materialized-installation-proposal.v1','templateHash':digest(t),
        'configuration':c,'recipe':r,'nativeObservation':s,'serviceUnit':unit,
        'currentNativeAdmissionStillRequired':True,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}


def parent_scope(value):
    t=recompile(value)
    return {'schema':'ouf.discovery-lease-installation-template-scope.v1','templateHash':digest(t),
        'sourceClosureHash':t['sourceClosureHash'],'installationInputsHash':t['configurationTemplate']['installationInputsHash'],
        'desiredProfileHash':t['configurationTemplate']['desiredProfileHash'],
        'newGenerationRequiresCurrentIndependentAdmission':True,'maximumManagerStartAttempts':1,
        'automaticBudgetResetAllowed':False,'runtimeSigningKeyAccessAllowed':False,
        'containerLifecycleOperationsAllowed':False,'releaseAcceptanceGranted':False}
