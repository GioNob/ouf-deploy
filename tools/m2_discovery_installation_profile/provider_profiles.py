"""Finite initial provider mandates and exact existing v4 deployment profiles.

The parent reviews static templates before identities exist. Later identities
are bound to ProviderCreation and the signed Registry recipe, never to an
observed OCI promoted to an expectation. No runtime switch/start is performed.
"""
import copy,hashlib,ipaddress,os,stat,time
from pathlib import Path
from .custody_capture import digest,encoded,decode,require
from . import provider_installation_template as templates
from .provider_creation import ProviderCreation,creation_component
from .parent_authority import DiscoveryParentAuthority
from .frame import compile_policy as registry_policy
from .lease_file_installation import inode
from tools.semantic_transaction_profiles.assemble_provider_profiles import assemble_profiles,source_closure
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json,protected_file
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes,binding
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_deployment_protocol import validate_intent,window,identity
from tools.semantic_provider_lease_owner import LeaseOwner
from compile_file_only_frame_policy import private_bridge_namespace_name

RUNTIME='scripts/semantic_provider_docker_runtime.py'
BROKER='scripts/semantic_provider_deployment_broker.py'
NODE='scripts/semantic_provider_node_attestor.py'
INSTALLER='scripts/semantic_provider_installer_approval.py'
FRAME_SOURCE_SHA='122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc'
RUNTIME_SHA='7894d0e942642d1daa5ae2e29c85cd7f0584b7cd285c539cab3ae624bab0bba9'
BROKER_SHA='3069c3dbbb959d8e8d423f5fc0c22db65aa4a50e2ba1874ad26ccd3a928af0cf'
PAYLOADS=('intent','live','approval')
ROLES={'intent':('DEPLOYMENT_INTENT','intentIssuerRef','installer'),
    'live':('CREATION_ATTESTATION','attestorRef','attestor'),
    'approval':('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef','installer')}
SCOPE_FIELDS={'schema','providerTemplateHash','creationScopeHash','registryRecipe','sourceRoot','sourceHashes',
    'priorRuntimeConfigurationBinding','priorRuntimeConfiguration','journalDirectory','registryRoot',
    'pythonBinding','crypto','frameSourceBinding','keys','keyRefs','runtimeRootParents','rootfsLimits',
    'transactionId','approvalRef','preparerTemplate','maximumSeconds','maximumSignatures','runtimeSwitchOrStartAuthorized'}

def validate_registry_recipe(recipe,window_owner):
    require(type(recipe) is dict and recipe.get('schema')=='ouf.semantic-discovery-node-recipe.v1'
        and recipe.get('executionProfileHash')==window_owner.profile.verify(window_owner.request)
        and recipe.get('sourceClosureHash')==window_owner.scope['sourceClosureHash']
        and all(templates.hashed(recipe.get(k)) for k in ('qualifiedPackageHash','imageConfigurationHash','transactionId')),
        'INDEPENDENT_SIGNED_REGISTRY_RECIPE_REQUIRED_FOR_PROVIDER')
    intent={'creationRequestHash':window_owner.request_hash,'sourceClosureHash':recipe['sourceClosureHash'],
        'qualifiedPackageHash':recipe['qualifiedPackageHash'],'imageConfigurationHash':recipe['imageConfigurationHash'],
        'nodeRecipeHash':digest(recipe)}
    require(decode(window_owner.raw)['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']==digest(intent),
        'PROVIDER_DEPENDENCY_MUST_MATCH_REGISTRY_SIGNED_NODE_INTENT')
    return copy.deepcopy(recipe)

def profile_scope(template,creation_scope,*,registry_recipe,source_root,source_hashes,
                  runtime_configuration_binding,runtime_configuration,journal_directory,
                  python_binding,crypto,frame_source_binding,keys,key_refs,runtime_root_parents,
                  rootfs_limits,transaction_id,approval_ref,preparer_template,maximum_seconds=90):
    t=templates.recompile(template);root=templates.absolute(str(journal_directory));source=templates.absolute(str(source_root))
    cfg=copy.deepcopy(runtime_configuration)
    fields={'schema','sourceHash','runtimePath','runtimeSha256','pythonPath','pythonSha256','driverPath','driverSha256',
        'admissionPath','admissionSha256','registryRoot','runtimeStateRoot','candidates'}
    require(type(cfg) is dict and set(cfg)==fields and cfg['schema']=='ouf.semantic-docker-runtime-adapter.v4'
        and cfg['sourceHash']==RUNTIME_SHA and cfg['admissionSha256']==BROKER_SHA
        and cfg['runtimePath']==t['runtimeBinding']['path'] and cfg['runtimeSha256']==t['runtimeBinding']['sha256']
        and cfg['driverPath']==source+'/scripts/semantic_provider_preexec_hook.py'
        and cfg['admissionPath']==source+'/'+BROKER
        and type(cfg['candidates']) is dict and len(cfg['candidates'])<=15,
        'EXACT_EXISTING_QUALIFIED_V4_RUNTIME_CONFIGURATION_REQUIRED')
    registry=templates.absolute(cfg['registryRoot']);templates.absolute(cfg['runtimeStateRoot'])
    require(type(source_hashes) is dict and 1<=len(source_hashes)<=96
        and all(type(k) is str and not Path(k).is_absolute() and '..' not in Path(k).parts
            and len(k)<=256 and templates.hashed(v) for k,v in source_hashes.items())
        and source_hashes.get(RUNTIME)==RUNTIME_SHA and source_hashes.get(BROKER)==BROKER_SHA
        and source_hashes.get('scripts/semantic_provider_preexec_hook.py')==cfg['driverSha256'],
        'EXACT_PINNED_PROVIDER_SOURCE_PACKAGE_REQUIRED')
    require(type(python_binding) is dict and set(python_binding)=={'path','sha256'}
        and python_binding=={'path':cfg['pythonPath'],'sha256':cfg['pythonSha256']},
        'SAME_EXISTING_PROVIDER_INTERPRETER_REQUIRED');binding(python_binding)
    prior=binding(runtime_configuration_binding);frame=binding(frame_source_binding)
    require(frame['sha256']==FRAME_SOURCE_SHA,'QUALIFIED_PROVIDER_FRAME_OBSERVER_REQUIRED')
    require(type(crypto) is dict and set(crypto)=={'policyBinding','signatureDirectory','opensslBinding'},
        'EXACT_PROVIDER_SIGNATURE_VERIFICATION_SCOPE_REQUIRED')
    binding(crypto['policyBinding']);templates.absolute(crypto['signatureDirectory'])
    require(type(crypto['opensslBinding']) is dict and set(crypto['opensslBinding'])=={'path','sha256','version'},
        'EXACT_PROVIDER_OPENSSL_BINDING_REQUIRED');binding({k:crypto['opensslBinding'][k] for k in ('path','sha256')})
    require(type(keys) is dict and type(key_refs) is dict and set(keys)==set(key_refs)=={'installer','attestor'}
        and all(identity(v) for v in key_refs.values()),'TWO_EXPLICIT_PROVIDER_SIGNING_ROLES_REQUIRED')
    for key in keys.values():
        binding(key)
        require(all(not Path(key['path']).is_relative_to(p) and not Path(p).is_relative_to(key['path'])
            for p in (root,registry,source,crypto['signatureDirectory']))
            and all(key['path']!=f['source'] for f in t['launch']['sources']),
            'ISOLATED_EXISTING_PROVIDER_SIGNING_KEYS_REQUIRED')
    roots=(root,registry,source,creation_scope['journalDirectory'])
    require(all(not Path(a).is_relative_to(b) and not Path(b).is_relative_to(a)
        for i,a in enumerate(roots) for b in roots[i+1:]),'DISTINCT_PROVIDER_PROFILE_CUSTODY_ROOTS_REQUIRED')
    require(type(runtime_root_parents) is list and len(runtime_root_parents)==1
        and all(templates.absolute(p) for p in runtime_root_parents),'EXPLICIT_PROVIDER_RUNC_PARENTS_REQUIRED')
    require(type(rootfs_limits) is dict and set(rootfs_limits)=={'maxEntries','maxBytes','maxDepth'}
        and all(type(v) is int for v in rootfs_limits.values())
        and t['expectedRootfsSeal']['entries']<=rootfs_limits['maxEntries']<=100000
        and max(1,t['expectedRootfsSeal']['bytes'])<=rootfs_limits['maxBytes']<=8589934592
        and 1<=rootfs_limits['maxDepth']<=64,'BOUNDED_PROVIDER_ROOTFS_VERIFICATION_REQUIRED')
    require(type(creation_scope) is dict and creation_scope.get('schema')=='ouf.discovery-provider-creation-scope.v1'
        and creation_scope['templateHash']==digest(t) and templates.hashed(transaction_id) and identity(approval_ref)
        and type(maximum_seconds) is int and 1<=maximum_seconds<=90,'SAME_PROVIDER_CREATION_AND_FINITE_PROFILE_SCOPE_REQUIRED')
    preparer=copy.deepcopy(preparer_template)
    preparer_fields={'schema','pythonPath','pythonHash','commands','commandHashes','candidate','kernel','dns',
        'coordinationBinding','coordinationJournal','lockFile','budgetSeconds','hostNetworkNamespace'}
    require(type(preparer) is dict and set(preparer)==preparer_fields
        and preparer['schema']=='ouf.semantic-admission-preparer-template.v1'
        and preparer['pythonPath']==python_binding['path'] and preparer['pythonHash']==python_binding['sha256']
        and preparer['candidate']=={'containerId':None,'transactionId':transaction_id,
            'networkBindings':t['networkBindings'],'transport':t['transportTemplate'],
            'tableName':t['tableName'],'runtimeBinding':t['runtimeBinding']}
        and type(preparer['budgetSeconds']) is int and 1<=preparer['budgetSeconds']<=5
        and type(preparer['hostNetworkNamespace']) is int and preparer['hostNetworkNamespace']>0,
        'EXACT_COMPLETE_STATIC_PROVIDER_PREPARER_SELECTION_REQUIRED')
    require(type(preparer['commands']) is dict and type(preparer['commandHashes']) is dict
        and set(preparer['commands'])==set(preparer['commandHashes'])=={'nft','ip','nsenter','unshare','mount','umount'}
        and all(templates.absolute(p) for p in preparer['commands'].values())
        and all(templates.hashed(v) for v in preparer['commandHashes'].values()),
        'EXACT_PROVIDER_PREPARER_NATIVE_COMMAND_BINDINGS_REQUIRED')
    templates.absolute(preparer['coordinationJournal']);templates.absolute(preparer['lockFile'])
    require(all(type(preparer[k]) is dict and bool(preparer[k]) for k in ('kernel','dns','coordinationBinding')),
        'EXPLICIT_PROVIDER_NATIVE_KERNEL_DNS_AND_COORDINATION_REQUIRED')
    LeaseOwner(preparer['kernel'],preparer['dns'],None)  # Pure validation, no backend methods.
    dns=preparer['dns']
    require(type(dns['resolvers']) is list and 1<=len(dns['resolvers'])<=8
        and len(set(dns['resolvers']))==len(dns['resolvers']) and type(dns['resolverPort']) is int
        and 1<=dns['resolverPort']<=65535
        and all(not (ipaddress.ip_address(v).is_unspecified or ipaddress.ip_address(v).is_multicast) for v in dns['resolvers']),
        'EXPLICIT_BOUNDED_PROVIDER_NUMERIC_RESOLVERS_REQUIRED')
    require(set(preparer['coordinationBinding'])=={'transactionId','configurationHash','leaseStructureHash'}
        and all(templates.hashed(v) for v in preparer['coordinationBinding'].values()),
        'EXACT_PROVIDER_NATIVE_COORDINATION_BINDING_REQUIRED')
    value={'schema':'ouf.discovery-provider-profile-installation-scope.v1','providerTemplateHash':digest(t),
        'creationScopeHash':digest(creation_scope),'registryRecipe':copy.deepcopy(registry_recipe),
        'sourceRoot':source,'sourceHashes':copy.deepcopy(source_hashes),'priorRuntimeConfigurationBinding':prior,
        'priorRuntimeConfiguration':cfg,'journalDirectory':root,'registryRoot':registry,
        'pythonBinding':copy.deepcopy(python_binding),'crypto':copy.deepcopy(crypto),'frameSourceBinding':frame,
        'keys':copy.deepcopy(keys),'keyRefs':copy.deepcopy(key_refs),'runtimeRootParents':copy.deepcopy(runtime_root_parents),
        'rootfsLimits':copy.deepcopy(rootfs_limits),'transactionId':transaction_id,'approvalRef':approval_ref,
        'preparerTemplate':preparer,
        'maximumSeconds':maximum_seconds,'maximumSignatures':3,'runtimeSwitchOrStartAuthorized':False}
    require(len(encoded(value))<=131072,'BOUNDED_PROVIDER_PROFILE_REVIEW_REQUIRED');return value

def recompile_scope(template,creation_scope,scope):
    require(type(scope) is dict and set(scope)==SCOPE_FIELDS and scope.get('schema')=='ouf.discovery-provider-profile-installation-scope.v1',
        'EXACT_PROVIDER_PROFILE_INSTALLATION_SCOPE_REQUIRED')
    rebuilt=profile_scope(template,creation_scope,registry_recipe=scope['registryRecipe'],source_root=scope['sourceRoot'],
        source_hashes=scope['sourceHashes'],runtime_configuration_binding=scope['priorRuntimeConfigurationBinding'],
        runtime_configuration=scope['priorRuntimeConfiguration'],journal_directory=scope['journalDirectory'],
        python_binding=scope['pythonBinding'],crypto=scope['crypto'],frame_source_binding=scope['frameSourceBinding'],
        keys=scope['keys'],key_refs=scope['keyRefs'],runtime_root_parents=scope['runtimeRootParents'],
        rootfs_limits=scope['rootfsLimits'],transaction_id=scope['transactionId'],approval_ref=scope['approvalRef'],
        preparer_template=scope['preparerTemplate'],maximum_seconds=scope['maximumSeconds'])
    require(rebuilt==scope,'PROVIDER_PROFILE_SCOPE_DRIFT');return rebuilt

def registry_identity(creation,scope):
    require(type(creation) is ProviderCreation,'OWNED_PROVIDER_CREATION_REQUIRED_FOR_REGISTRY_BINDING')
    creation.sealed();w=creation.window;w.sealed();creation.parent.registry_child(w.child,w.raw)
    recipe=validate_registry_recipe(scope['registryRecipe'],w);row=creation.retained();cid=row['registryRuntimeBinding']['containerId']
    c=copy.deepcopy(recipe['dockerContext']);fields={'schema','bundleParent','metadataParent','networkNamespaceParent','cgroupDriver','storageParent','rootfsLayout'}
    require(type(c) is dict and set(c)==fields and c['rootfsLayout']=='docker-containerd-overlayfs-v1',
        'EXPLICIT_CONTAINERD_REGISTRY_FRAME_CONTEXT_REQUIRED')
    c.pop('rootfsLayout');c.update(containerId=cid,rootfsPath=c['storageParent']+'/rootfs/overlayfs/'+cid,
        networkNamespaceName=private_bridge_namespace_name(w.request))
    policy=registry_policy(recipe['template'],recipe['launch'],c,execution_profile=w.profile)
    return {'containerId':cid,'applicationHash':digest(policy['expectedOci'])}

def compile_material(template,scope,sources,container_id,registry,context,issued_at,expires_at):
    """Unsigned exact proposals; source/identity/authority authentication is external."""
    t=templates.recompile(template);require(type(sources) is dict
        and {k:hashlib.sha256(v).hexdigest() for k,v in sources.items()}==scope['sourceHashes'],
        'EXACT_PROVIDER_SOURCE_BYTES_REQUIRED')
    require(type(issued_at) is int and type(expires_at) is int and 0<expires_at-issued_at<=scope['maximumSeconds'],
        'EXACT_FINITE_PROVIDER_PROFILE_WINDOW_REQUIRED')
    m=templates.materialize(t,container_id,registry);root=scope['registryRoot']+'/'+container_id
    require(container_id not in scope['priorRuntimeConfiguration']['candidates'],'NEW_PROVIDER_CANNOT_REUSE_OLD_RUNTIME_CANDIDATE')
    intent={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':context['intentIssuerRef'],
        **{k:context[k] for k in ('installationRef','entityRef')},'containerId':container_id,'transactionId':scope['transactionId'],
        'artifactHash':m['artifactHash'],'deploymentConstraintsHash':digest({'profileScopeHash':digest(scope),'providerTemplateHash':digest(t)}),
        'transportHash':m['transportHash'],'runtimeExecutableHash':t['runtimeBinding']['sha256'],
        'issuedAt':issued_at,'expiresAt':expires_at,'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
    intent_hash=digest(intent);common={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId',
        'artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')}
    live={'schema':'ouf.semantic-node-live-acceptance-authorization.v1','issuerRef':context['attestorRef'],**common,
        'intentHash':intent_hash,'applicationHash':m['applicationHash'],'rootfsSeal':copy.deepcopy(t['expectedRootfsSeal']),
        'generationBinding':'OBSERVED_CREATED','issuedAt':issued_at,'expiresAt':expires_at,'state':'ACTIVE',
        'mandateIssuanceAuthorized':True,'attestationAuthorized':True,'completeCreationAccepted':True}
    approval={'schema':'ouf.semantic-final-approval-mandate.v1','issuerRef':context['approvalIssuerRef'],**common,
        'intentHash':intent_hash,'approvalRef':scope['approvalRef'],'issuedAt':issued_at,'expiresAt':expires_at,
        'state':'ACTIVE','issuanceAuthorized':True,'applicationStartAuthorized':True}
    prepared=copy.deepcopy(scope['preparerTemplate']);prepared['candidate']={
        'containerId':container_id,'transactionId':scope['transactionId'],**m['candidate'],
        'runtimeBinding':copy.deepcopy(t['runtimeBinding'])}
    profiles=assemble_profiles(root,scope['sourceRoot'],sources,
        {'authorities':context,'keyBindings':scope['keys'],'keyRefs':scope['keyRefs']},scope['pythonBinding'],scope['crypto'],
        {'path':root+'/intent.json','sha256':intent_hash},intent,prepared,
        {'path':root+'/final-approval-mandate.json','sha256':digest(approval)},
        {'python':scope['pythonBinding'],'source':scope['frameSourceBinding'],
            'configuration':{'path':root+'/frame-policy.json','sha256':m['artifactHash']}},
        scope['runtimeRootParents'],[scope['registryRoot']],scope['rootfsLimits'])
    configuration=copy.deepcopy(scope['priorRuntimeConfiguration'])
    configuration['candidates'][container_id]={'intentRef':intent_hash,
        'bundleParents':[t['dockerContext']['bundleParent']],
        'admissionConfiguration':root+'/broker.json','admissionConfigurationHash':digest(profiles['broker.json'])}
    adapter={'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':container_id,
        'configurationHash':digest({**{k:v for k,v in configuration.items() if k!='candidates'},
            'candidate':configuration['candidates'][container_id]}),
        'state':'STAGED','runtimeRoot':None,'bundleHash':None,'driverHash':None}
    files={root+'/'+name:encoded(v) for name,v in profiles.items()}
    files.update({root+'/intent.json':encoded(intent),root+'/live-authorization.json':encoded(live),
        root+'/final-approval-mandate.json':encoded(approval),root+'/frame-policy.json':encoded(m['framePolicy']),
        root+'/adapter.json':encoded(adapter),root+'/operation.lock':b'',
        scope['journalDirectory']+'/runtime-configuration.json':encoded(configuration)})
    directories=[root,root+'/attestation-results',root+'/approval-results']
    return {'schema':'ouf.discovery-provider-unsigned-initial-material.v1','templateHash':digest(t),'scopeHash':digest(scope),
        'materialized':m,'root':root,'payloads':{'intent':intent,'live':live,'approval':approval},
        'intentHash':intent_hash,'candidateTemplate':prepared,'profiles':profiles,'runtimeConfiguration':configuration,
        'files':files,'directories':directories,
        'inputsAuthenticated':False,'signaturesIssued':0,'profilesPublished':False,'runtimeSwitchOrStartAuthorized':False}

class ProviderInitialIssuer:
    """Issue only three initial mandates; no actual admission record is forged."""
    def __init__(self,*,creation,scope,signers):
        require(type(creation) is ProviderCreation and type(creation.parent) is DiscoveryParentAuthority
            and type(creation.parent.verifier) is DetachedAuthenticator and type(signers) is dict and set(signers)==set(PAYLOADS),
            'TYPED_PROVIDER_CREATION_PARENT_AND_THREE_ROLE_SIGNERS_REQUIRED')
        self.creation,self.parent=creation,creation.parent;self.template=creation.template
        self.scope=recompile_scope(self.template,creation.scope,scope);self.scope_hash=digest(self.scope)
        self.root=Path(self.scope['journalDirectory']);self.root_pin=inode(self.root)
        self.directory_pins={p:inode(p)[:5] for p in (str(self.root),self.scope['sourceRoot'],self.scope['registryRoot'],self.scope['crypto']['signatureDirectory'])}
        self.signers=dict(signers);self.signer_ids={k:id(v) for k,v in signers.items()};self.check_scope()
    def check_scope(self):
        require(type(self.creation) is ProviderCreation and self.creation.parent is self.parent
            and self.scope==recompile_scope(self.template,self.creation.scope,self.scope) and digest(self.scope)==self.scope_hash,
            'PROVIDER_ISSUER_SCOPE_DRIFT')
        installation=self.creation.component.get('installation',{})
        require(self.creation.component.get('schema') in {'ouf.discovery-composed-provider-installation-scope.v1',
            'ouf.discovery-composed-provider-installation-scope.v2'}
            and (installation==self.scope or installation.get('profiles')==self.scope),
            'EXPLICIT_PARENT_REVIEW_OF_PROVIDER_PROFILE_AND_KEY_SCOPE_REQUIRED')
        with directory(self.root) as fd:require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
            and inode(self.root)==self.root_pin,'PROVIDER_ISSUER_PRIVATE_DIRECTORY_DRIFT')
        for path,pin in self.directory_pins.items():
            with directory(path) as fd:require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700
                and inode(path)[:5]==pin,'PROVIDER_PROFILE_SOURCE_SIGNATURE_OR_REGISTRY_DIRECTORY_DRIFT')
        verifier=self.parent.verifier;crypto=self.scope['crypto']
        require(verifier.policy_binding==crypto['policyBinding'] and str(verifier.signature_directory)==crypto['signatureDirectory']
            and verifier.openssl_binding==crypto['opensslBinding'],'SAME_CURRENT_PROVIDER_PARENT_PUBLIC_VERIFIER_REQUIRED')
        for name,(role,key,signing_key) in ROLES.items():
            signer=self.signers[name];require(type(signer) is ExistingEd25519Signer and id(signer)==self.signer_ids[name]
                and signer.verifier is verifier and signer.key==self.scope['keys'][signing_key]
                and signer.key_ref==self.scope['keyRefs'][signing_key]
                and signer.scope=={'role':role,'issuerRef':self.parent.context[key],
                    **{k:self.parent.context[k] for k in ('installationRef','entityRef')}},
                'EXACT_PROVIDER_EXISTING_KEY_AND_ROLE_SCOPE_REQUIRED')
        self.creation.sealed();validate_registry_recipe(self.scope['registryRecipe'],self.creation.window)
    def sources(self):
        values={k:protected_file(Path(self.scope['sourceRoot'])/k,131072,expected=v,modes=(0o600,))
            for k,v in self.scope['sourceHashes'].items()}
        for entry in (BROKER,NODE,INSTALLER):source_closure(values,entry)
        raw=protected_file(self.scope['priorRuntimeConfigurationBinding']['path'],131072,
            expected=self.scope['priorRuntimeConfigurationBinding']['sha256'],modes=(0o600,))
        require(decode(raw)==self.scope['priorRuntimeConfiguration'],'CURRENT_PRIOR_PROVIDER_RUNTIME_CONFIGURATION_DRIFT')
        protected_file(self.scope['frameSourceBinding']['path'],131072,expected=FRAME_SOURCE_SHA,modes=(0o600,))
        return values
    def current(self,signing=False):
        self.check_scope();self.parent.guard('providerInstallation',self.creation.component)
        if signing:
            self.creation.current();require(self.creation.observe()[0]=='APPLIED','EXACT_NEW_UNSTARTED_PROVIDER_REQUIRED_BEFORE_MANDATES')
        return self.creation.owned_id(),registry_identity(self.creation,self.scope),self.sources()
    def material(self,claim):
        cid,registry,sources=self.current()
        result=compile_material(self.template,self.scope,sources,cid,registry,self.parent.context,claim['issuedAt'],claim['expiresAt'])
        require(claim==self.claim(result),'EXACT_RETAINED_PROVIDER_PAYLOADS_AND_SCOPE_REQUIRED');return result
    def claim(self,material):
        times=material['payloads']['intent']
        return {'schema':'ouf.discovery-provider-initial-issuance-claim.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.parent.sha,'creationScopeHash':self.creation.scope_hash,
            'containerId':material['materialized']['containerId'],'registryIdentity':material['materialized']['registryIdentity'],
            'issuedAt':times['issuedAt'],'expiresAt':times['expiresAt'],
            'payloadHashes':{k:digest(v) for k,v in material['payloads'].items()},'maximumSignatures':3,'automaticReplayAllowed':False}
    def issue_once(self):
        cid,registry,sources=self.current(signing=True);now=int(self.parent.clock())
        parent=decode(self.parent.raw);child=decode(self.creation.window.raw)
        left=int(self.creation.window.retained()['deadlineMonotonic']-time.monotonic())
        until=min(now+self.scope['maximumSeconds'],parent['expiresAt'],child['expiresAt'],now+left)
        material=compile_material(self.template,self.scope,sources,cid,registry,self.parent.context,now,until)
        claim=self.claim(material)
        with directory(self.root) as journal:
            new_file(journal,'issuance-claim.json',encoded(claim))
            for name in PAYLOADS:
                self.current(signing=True);require(private_json(self.root/'issuance-claim.json')==claim,'PROVIDER_ISSUANCE_CLAIM_DRIFT')
                payload=encoded(material['payloads'][name]);role=ROLES[name][0]
                new_file(journal,name+'-dispatch.json',encoded({'payloadHash':hashlib.sha256(payload).hexdigest(),'attempt':1}))
                self.current(signing=True)
                require(private_json(self.root/'issuance-claim.json')==claim,'PROVIDER_ISSUANCE_CLAIM_CHANGED_BEFORE_KEY')
                signature=self.signers[name].sign(payload)
                with directory(self.scope['crypto']['signatureDirectory']) as signatures:
                    signature_name=hashlib.sha256(payload).hexdigest()+'.'+role+'.json'
                    new_file(signatures,signature_name,signature)
                new_file(journal,name+'.json',payload)
                new_file(journal,name+'-owned.json',encoded({'payload':inode(self.root/(name+'.json')),
                    'signature':inode(Path(self.scope['crypto']['signatureDirectory'])/signature_name)}))
            self.current(signing=True);new_file(journal,'issuance-complete.json',encoded(claim))
    def observe(self):
        self.check_scope()
        if not os.path.lexists(self.root/'issuance-claim.json'):
            return 'UNKNOWN',{'ownedIssuanceClaimPresent':False,'automaticReplayAllowed':False}
        claim=private_json(self.root/'issuance-claim.json');material=self.material(claim);ctx=self.parent.context
        for name,(role,key,_) in ROLES.items():
            if not os.path.lexists(self.root/(name+'-owned.json')):return 'UNKNOWN',{'partialIssuancePreserved':True,'automaticReplayAllowed':False}
            raw=private_bytes(self.root/(name+'.json'))
            require(raw==encoded(material['payloads'][name]) and private_json(self.root/(name+'-dispatch.json'))==
                {'payloadHash':hashlib.sha256(raw).hexdigest(),'attempt':1},'EXACT_PROVIDER_ISSUANCE_PAYLOAD_AND_DISPATCH_REQUIRED')
            require(self.parent.verifier(raw,role,ctx[key],ctx['installationRef'],ctx['entityRef']) is True,'CURRENT_PROVIDER_INITIAL_MANDATE_SIGNATURE_REQUIRED')
            require(private_json(self.root/(name+'-owned.json'))=={'payload':inode(self.root/(name+'.json')),
                'signature':inode(Path(self.scope['crypto']['signatureDirectory'])/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json'))},
                'PROVIDER_INITIAL_MANDATE_OWNED_INODE_DRIFT')
            window(material['payloads'][name],self.parent.clock())
        validate_intent(encoded(material['payloads']['intent']),ctx,self.parent.verifier,self.parent.clock)
        if os.path.lexists(self.root/'issuance-complete.json'):
            require(private_json(self.root/'issuance-complete.json')==claim,'PROVIDER_ISSUANCE_COMPLETION_DRIFT')
        self.current();return 'APPLIED',{'schema':'ouf.discovery-provider-initial-mandates-issued.v1',
            'scopeHash':self.scope_hash,'claimHash':digest(claim),'signaturesIssued':3,'nativeAdmissionGranted':False,
            'runtimeSwitchOrStartPerformed':False,'automaticReplayAllowed':False}
