"""Read-only complete OCI + four immutable files + configtree + renewable token.

Separate v1 six-mount path; original four-mount observer remains unchanged.
Owner admission and expected OCI are independently supplied, never issued here.

Uses pinned existing owner primitives in an isolated module namespace. Policy
must be prepared/authenticated independently; observed OCI is never a policy
input. No signature, key, native mutation or approval is issued here.
"""
import ast,copy,hashlib,json,os,stat,sys,types,time
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation as token_generation
from tools.semantic_policy_token_owner.producer import DomainOwner
from paused_workload_binding import PausedWorkloadBinding
from pathlib import Path
from transition_journal import require,digest,hash_value
from configtree_mount_observation import ConfigtreeMountObservation
from tools.semantic_provider_deployment_authentication import private_bytes,decode,ancestors,attributes

OWNER_HASHES={'review_semantic_oci_policy':'d35123954e91fc463a3ad78cedeeb2284c0106c22de48780e1128178c72a4eb6',
              'observe_semantic_mount_view':'6d2f00ffcf1159bde6a2bbf9744e62f2c6b6760d8af12d8647d911336a059201',
              'observe_semantic_creation_frame':'9e259ed7874c4eed3516d0d05ab31eb960d17f8af43626caa2386038ad81b201',
              'semantic_oci_shape_schema.json':'d8f2196b2f0e22c448942d46e25a775d4ffc7284b72435e04633ec9cb08b5368'}

class SixMountFrameObservation:
    def __init__(self,configured,budget,owner_gate,paused_binding):
        require(isinstance(owner_gate,DomainOwner) and type(paused_binding) is PausedWorkloadBinding,"EXISTING_TOKEN_OWNER_AND_ENGINE_PAUSE_BINDING_REQUIRED")
        self.token_owner,self.pause_binding=owner_gate,paused_binding
        require(os.geteuid()==0 and type(configured) is dict and set(configured)=={'source','configuration','bundleParents'},'EXACT_ROOT_PROJECTED_FRAME_BINDINGS_REQUIRED')
        require(all(type(configured[k]) is dict and set(configured[k])=={'path','sha256'} and Path(configured[k]['path']).is_absolute() and hash_value(configured[k]['sha256']) for k in ('source','configuration')),'EXACT_PINNED_PROJECTED_FRAME_SOURCE_AND_POLICY_REQUIRED')
        require(type(configured['bundleParents']) is list and 1<=len(configured['bundleParents'])<=8
                and all(type(p) is str and Path(p).is_absolute() and '..' not in Path(p).parts and p!='/' for p in configured['bundleParents']),
                'EXPLICIT_OWNED_PROJECTED_BUNDLE_PARENTS_REQUIRED')
        self.configured=copy.deepcopy(configured);self.configuration_hash=digest(configured);self.budget=budget
    def pinned(self):
        require(digest(self.configured)==self.configuration_hash,'PROJECTED_FRAME_BINDINGS_DRIFT');values={}
        for name in ('source','configuration'):
            binding=self.configured[name]
            self.budget.check();raw=private_bytes(Path(binding['path']),131072)
            require(hashlib.sha256(raw).hexdigest()==binding['sha256'],'PROJECTED_FRAME_SOURCE_OR_POLICY_DRIFT');values[name]=raw
        return values
    def bundle(self,path):
        path=Path(path);require(path.name=='config.json' and path.is_absolute()
                               and any(Path(p) in path.parent.parents for p in self.configured['bundleParents']),
                               'PROJECTED_RUNTIME_BUNDLE_OUTSIDE_APPROVAL')
        ancestors(path);self.budget.check();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                    and stat.S_IMODE(before.st_mode) in (0o600,0o644) and 0<before.st_size<=131072,
                    'ROOT_OWNED_RUNTIME_BUNDLE_CUSTODY_REQUIRED')
            raw=os.read(fd,131073)
            require(len(raw)==before.st_size and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat()),
                    'PROJECTED_RUNTIME_BUNDLE_CHANGED')
            self.budget.check();return raw
        finally:os.close(fd)
    def owner(self,raw):
        # Parse only literal embedded source/schema assignments; never execute
        # the wrapper or an unpinned import from the current Python namespace.
        literals={}
        for item in ast.parse(raw).body:
            if isinstance(item,ast.Assign) and len(item.targets)==1 and isinstance(item.targets[0],ast.Name) and item.targets[0].id in {'SOURCES','SOURCE_HASHES','SCHEMA_BYTES'}:
                require(item.targets[0].id not in literals,'DUPLICATE_OWNER_SOURCE_LITERAL');literals[item.targets[0].id]=ast.literal_eval(item.value)
        require(set(literals)=={'SOURCES','SOURCE_HASHES','SCHEMA_BYTES'} and literals['SOURCE_HASHES']==OWNER_HASHES
                and set(literals['SOURCES'])==set(OWNER_HASHES)-{'semantic_oci_shape_schema.json'},'EXACT_RETAINED_OWNER_PRIMITIVES_REQUIRED')
        for name,source in literals['SOURCES'].items():require(hashlib.sha256(source.encode()).hexdigest()==OWNER_HASHES[name],'EMBEDDED_OWNER_SOURCE_DRIFT')
        require(type(literals['SCHEMA_BYTES']) is bytes and hashlib.sha256(literals['SCHEMA_BYTES']).hexdigest()==OWNER_HASHES['semantic_oci_shape_schema.json'],'EMBEDDED_OWNER_SCHEMA_DRIFT')
        namespace='_ouf_projected_'+hashlib.sha256(raw).hexdigest();package=types.ModuleType(namespace);package.__path__=[];sys.modules[namespace]=package;modules={}
        try:
            for name,source in literals['SOURCES'].items():
                module=types.ModuleType(namespace+'.'+name);module.__package__=namespace;module.__file__='<pinned-ouf-owner-primitive>'
                sys.modules[module.__name__]=module;setattr(package,name,module);modules[name]=module
                scoped=source.replace('from tools.', 'from '+namespace+'.').replace('from tools import ', 'from '+namespace+' import ')
                exec(compile(scoped,module.__file__,'exec'),module.__dict__)
            schema=modules['review_semantic_oci_policy'].schema_from_source_closure(literals['SCHEMA_BYTES'])
            return modules,schema
        finally:
            for name in list(modules):sys.modules.pop(namespace+'.'+name,None)
            sys.modules.pop(namespace,None)
    def observe(self,generation,bundle_path,application_hash,artifact_hash):
        require(artifact_hash==self.configured['configuration']['sha256'] and hash_value(application_hash),'EXACT_PROJECTED_FRAME_POLICY_AND_APPLICATION_REQUIRED')
        private=self.pinned();policy=decode(private['configuration'],131072)
        fields={'schema','expectedOci','manifest','startup','approvedHooks','sources','configtree','renewableToken','delegationKeyTarget'}
        require(set(policy)==fields and policy['schema']=='ouf.semantic-configured-six-mount-frame-policy.v1'
                and type(policy['sources']) is list and len(policy['sources'])==4,'EXACT_FOUR_FILES_CONFIGTREE_AND_TOKEN_POLICY_REQUIRED')
        bundle_path=Path(bundle_path);raw=self.bundle(bundle_path);bundle=decode(raw,131072)
        require(digest(bundle)==application_hash,'PROJECTED_FRAME_OBSERVED_OCI_DRIFT')
        modules,schema=self.owner(private['source']);review=modules['review_semantic_oci_policy'];mounts=modules['observe_semantic_mount_view'];frame=modules['observe_semantic_creation_frame']
        configtree=ConfigtreeMountObservation(policy['configtree'],self.budget)
        bindings=[{k:item[k] for k in ('source','target','readOnly')} for item in policy['sources']]
        bindings.append({k:policy['configtree'][k] for k in ('source','target','readOnly')})
        bindings.append({k:policy['renewableToken'][k] for k in ('source','target')}|{'readOnly':True})
        key=policy['sources'][3]
        require(policy['delegationKeyTarget']==key['target'] and key['uid']==key['gid']==10001 and key['mode']==0o400 and key['readOnly'] is True, 'STATIC_ORIGINAL_DELEGATION_KEY_CUSTODY_REQUIRED')
        require(len({v['source'] for v in bindings})==6 and not any(a['target'].startswith(b['target']+'/') for a in bindings for b in bindings if a is not b), 'DISTINCT_NONSHADOWING_SIX_MOUNTS_REQUIRED')
        require(bindings==policy['manifest']['mounts'] and len({v['target'] for v in bindings})==6,'EXACT_SIX_PRIVATE_INPUT_BINDINGS_REQUIRED')
        require(digest(policy['expectedOci'])==application_hash,'INDEPENDENT_PROJECTED_FRAME_EXPECTATION_DRIFT')
        approved=review.configured_profile(bundle,policy['expectedOci'],policy['manifest'],policy['startup'],policy['approvedHooks'],schema)
        current=mounts.generation(generation['pid'],self.budget)
        require({k:current[k] for k in ('pid','startTicks')}=={k:generation[k] for k in ('pid','startTicks')}
                and current['networkNamespaceInode']==generation['namespaceInode'],'PROJECTED_FRAME_PROCESS_GENERATION_DRIFT')
        files=frame.source_mount_frame(generation['pid'],current,bundle,policy['sources'],self.budget)
        directory=configtree.observe(generation)
        token=RenewableTokenMountObservation(policy['renewableToken'],self.token_owner,time.monotonic()+self.budget.remaining(30),pause_binding=self.pause_binding).observe(token_generation(generation['pid'],allow_frozen=True))
        require(self.pinned()==private and self.bundle(bundle_path)==raw
                and mounts.generation(generation['pid'],self.budget)==current,'PROJECTED_FRAME_CHANGED_DURING_OBSERVATION')
        self.budget.check()
        result={'schema':'ouf.semantic-configured-paused-six-mount-frame.v1','configuredPolicy':approved,
                'sourceMountFrame':files,'configtreeMountFrame':directory,'renewableTokenMountFrame':token,'sixMountShapeObserved':True,'policyAuthenticationProven':False,
                'rootfsSealProven':False,'imagePublisherProvenanceVerified':False,'completeCreationAccepted':False,
                'acceptanceGranted':False,'signaturesIssued':0,'startAuthorized':False}
        return digest(result),{Path(self.configured[k]['path']):v for k,v in private.items()}

