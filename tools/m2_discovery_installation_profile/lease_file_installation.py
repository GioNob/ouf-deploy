"""Create-only publication of already attested discovery worker material.

No signer, manager, Engine mutation, DNS or kernel writer is available here.
The parent controller must obtain current independent admissions and the three
detached attestations first. This component cannot manufacture those admissions.
An interrupted publication is inspected, never completed or overwritten by replay.
"""
import copy,hashlib,os,stat,time
from pathlib import Path
from .custody_capture import digest,encoded,require
from .lease_installation_template import recompile,materialize,parent_scope
from .lease_unit import path,beneath
from .lease_worker import DiscoveryRecovery
from .lease_service import existing_kernel_lock
from .installed_lease_guard import boot_id
from .native_generation_probe import NativeLeaseGenerationProbe
from bounded_recovery import Policy,fingerprint,number
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import protected_file,private_json

ROLE='CREATION_ATTESTATION'


def inode(name):
    s=Path(name).lstat()
    return [getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')]


def publication_scope(template,start,directory):
    t=recompile(template);root=path(directory)
    roots=[t['installationRoot'],t['configurationTemplate']['ledgerRoot'],t['sandboxRoot'],start['journalDirectory']]
    require(len(Path(root).parts)>=4 and all(not beneath(root,p) and not beneath(p,root) for p in roots),
        'SEPARATE_DISCOVERY_FILE_TRANSACTION_DIRECTORY_REQUIRED')
    require(start.get('installation')==parent_scope(t),'SAME_DISCOVERY_TEMPLATE_AND_START_REVIEW_REQUIRED')
    return {'schema':'ouf.discovery-lease-files-and-start-scope.v1','start':copy.deepcopy(start),
        'publication':{'template':parent_scope(t),'journalDirectory':root,
            'maximumPublicationAttempts':1,'preAttestedMaterialRequired':True,
            'partialInstallationReplayAllowed':False,'existingLedgerAdoptionAllowed':False}}


def compile_material(template,proposal,capsule,*,initial_time,installation_sources):
    """Pure exact bytes and attestation payloads. The result grants nothing."""
    t=recompile(template);p=copy.deepcopy(proposal)
    require(p==materialize(t,p['nativeObservation'],p['configuration']['commonLockIdentity']),
        'EXACT_RECOMPILED_DISCOVERY_FILE_PROPOSAL_REQUIRED')
    require(type(capsule) is bytes and len(capsule)==t['capsuleBytes']
        and hashlib.sha256(capsule).hexdigest()==t['capsuleSha256'],
        'EXACT_QUALIFIED_DISCOVERY_CAPSULE_BYTES_REQUIRED')
    require(type(initial_time) in (tuple,list) and len(initial_time)==2
        and all(number(v) for v in initial_time),'EXACT_INITIAL_DISCOVERY_CLOCKS_REQUIRED')
    c,r,s=p['configuration'],p['recipe'],p['nativeObservation']
    install,ledger,sandbox=t['installationRoot'],c['ledgerRoot'],t['sandboxRoot']
    policy=copy.deepcopy(r['policy']);policy['delays']=tuple(policy['delays']);policy=Policy(**policy)
    recovery=DiscoveryRecovery(None,None,policy,r['scope']['contextRef'],s['generationRef'],lambda:initial_time,lambda:.5)
    initial={**recovery.initial(),'discoveryLeaseScopeHash':fingerprint(r['scope'])}
    receipt={'schema':'ouf.discovery-operational-lease-installation-receipt.v1','complete':True,
        'configurationHash':digest(c),'installationInputsHash':c['installationInputsHash'],
        'desiredProfileHash':c['desiredProfileHash'],'sourceManifestHash':digest(c['sourceManifest']),
        'serviceUnitHash':c['serviceUnitHash'],'scopePolicyHash':c['scopePolicyHash'],
        'finiteApprovalAuthorizesInstallationOnly':True,
        'operationalLifetime':'UNTIL_DISABLE_CUSTODY_OR_INSTALLATION_TRUST_REVOCATION',
        'runtimeSigningKeyAccessAllowed':False,'containerLifecycleOperationsAllowed':False}
    generation={'schema':'ouf.discovery-operational-lease-generation-receipt.v1','configurationHash':digest(c),
        'desiredProfileHash':c['desiredProfileHash'],'scopePolicyHash':c['scopePolicyHash'],
        'scopeHash':fingerprint(r['scope']),'generationRef':s['generationRef'],'bootId':s['bootId'],
        'nativeObservationHash':digest(s),'nativeProfileHash':s['nativeProfileHash'],'ledgerRoot':ledger,
        'state':'NATIVE_GENERATION_ADMITTED','containerStartAuthorized':False}
    files={install+'/capsule.py':(0o400,capsule),install+'/worker-recipe.json':(0o600,encoded(r)),
        install+'/configuration.json':(0o600,encoded(c)),c['serviceUnitPath']:(0o644,p['serviceUnit']['unitBody'].encode('ascii')),
        install+'/current-generation.json':(0o600,encoded(generation)),
        c['hostBootIdPath']:(0o600,(s['bootId']+'\n').encode('ascii')),
        install+'/observations/'+digest(s)+'.json':(0o600,encoded(s)),
        ledger+'/coordination.json':(0o600,encoded({'schema':'ouf.semantic-lease-coordination.v1',**r['binding'],
            'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,
            'leaseAddresses':[[] for _ in r['kernel']['providerFlows']]})),
        ledger+'/recovery.json':(0o600,encoded(initial)),ledger+'/recovery.lock':(0o600,b''),
        ledger+'/invocation.lock':(0o600,b'')}
    refs={v['path']:v for v in c['sources'] if beneath(v['path'],install)}
    trust=c['verification']['trustPolicy']
    if beneath(trust['path'],install):refs[trust['path']]={**trust,'maximumBytes':65536}
    needed=set(refs)-set(files)
    require(type(installation_sources) is dict and set(installation_sources)==needed,
        'EXACT_ADDITIONAL_REVIEWED_DISCOVERY_INSTALLATION_SOURCES_REQUIRED')
    for name,raw in installation_sources.items():
        require(type(raw) is bytes and name not in files,'EXACT_BOUND_DISCOVERY_SOURCE_BYTES_REQUIRED')
        files[name]=(0o600,bytes(raw))
    for name,ref in refs.items():
        require(len(files[name][1])<=ref['maximumBytes']
            and hashlib.sha256(files[name][1]).hexdigest()==ref['sha256'],
            'REVIEWED_DISCOVERY_INSTALLATION_SOURCE_HASH_CHANGED')
    dirs={install,ledger,sandbox,install+'/observations',install+'/receipt-signatures'}
    for name in files:
        path(name)
        require(any(beneath(name,root) and name!=root for root in (install,ledger)),
            'DISCOVERY_FILE_OUTSIDE_REVIEWED_ROOTS')
        parent=str(Path(name).parent)
        while parent not in (install,ledger):
            dirs.add(parent);parent=str(Path(parent).parent)
    require(not set(files)&dirs and install+'/installed.json' not in files,
        'DISCOVERY_FILE_DIRECTORY_OR_COMMIT_MARKER_COLLISION')
    seal={'schema':'ouf.discovery-worker-file-publication-seal.v1','templateHash':digest(t),
        'proposalHash':digest(p),'initialRecoveryHash':digest(initial),
        'directories':sorted(dirs),
        'files':{k:{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'mode':mode}
            for k,(mode,raw) in sorted(files.items())},
        'installationReceiptHash':digest(receipt),'generationReceiptHash':digest(generation),
        'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False}
    require(len(files)<=96 and sum(len(v[1]) for v in files.values())<=8388608
        and len(encoded(seal))<=65536,'BOUNDED_DISCOVERY_INSTALLATION_MATERIAL_REQUIRED')
    return {'template':t,'proposal':p,'initialTime':list(initial_time),
        'installationSources':copy.deepcopy(installation_sources),'files':files,
        'receipt':receipt,'generation':generation,'seal':seal}


class LeaseFileInstallation:
    def __init__(self,start,material,*,verifier,probe):
        from .lease_start_owner import LeaseStartAdapter
        require(type(start) is LeaseStartAdapter and start.publication_directory is not None
            and type(verifier) is DetachedAuthenticator and type(probe) is NativeLeaseGenerationProbe,
            'TYPED_PARENT_START_PUBLIC_VERIFIER_AND_NATIVE_PROBE_REQUIRED')
        self.start,self.verifier,self.probe=start,verifier,probe
        self.material=copy.deepcopy(material);self.validate_material()
        c=material['proposal']['configuration'];v=c['verification']
        require(verifier.policy_binding['sha256']==v['trustPolicy']['sha256']
            and (beneath(v['trustPolicy']['path'],start.template['installationRoot'])
                or verifier.policy_binding==v['trustPolicy']) and verifier.openssl_binding==v['openssl'],
            'EXACT_REVIEWED_DISCOVERY_RECEIPT_VERIFIER_REQUIRED')
        self.root=Path(start.publication_directory)
        self.context=copy.deepcopy(v['context']);self.seal_hash=digest(material['seal'])
        self.policy=v['trustPolicy'];self.signatures={}
        require(all(not beneath(str(probe.root),p) and not beneath(str(verifier.signature_directory),p)
            for p in (start.template['installationRoot'],c['ledgerRoot'],start.template['sandboxRoot'])),
            'PREEXISTING_SEPARATE_DISCOVERY_ATTESTATION_STAGING_REQUIRED')

    def validate_material(self):
        m=self.material
        require(m==compile_material(m['template'],m['proposal'],m['files'][m['template']['installationRoot']+'/capsule.py'][1],
            initial_time=m['initialTime'],installation_sources=m['installationSources'])
            and m['template']==self.start.template and m['proposal']==self.start.proposal,
            'DISCOVERY_FILE_MATERIAL_DRIFT')

    def current(self,intent):
        self.validate_material();self.start.current(intent)
        m=self.material;c=m['proposal']['configuration']
        require(type(self.verifier) is DetachedAuthenticator and type(self.probe) is NativeLeaseGenerationProbe
            and self.context==c['verification']['context']
            and self.verifier.policy_binding['sha256']==c['verification']['trustPolicy']['sha256']
            and self.verifier.openssl_binding==c['verification']['openssl'],
            'CURRENT_TYPED_DISCOVERY_INSTALLATION_VERIFIERS_REQUIRED')
        require(self.start.installation_component==publication_scope(self.start.template,self.start.scope,str(self.root))
            and digest(m['seal'])==self.seal_hash,'EXACT_REVIEWED_DISCOVERY_FILE_PUBLICATION_REQUIRED')
        require(set(self.signatures)<={digest(m[k])+'.'+ROLE+'.json' for k in ('seal','receipt','generation')},
            'EXACT_DISCOVERY_ATTESTATION_FILE_SET_REQUIRED')
        for payload in (m['seal'],m['receipt'],m['generation']):
            raw=encoded(payload)
            require(self.verifier(raw,ROLE,self.context['attestorRef'],self.context['installationRef'],
                self.context['entityRef']) is True,'CURRENT_DISCOVERY_MATERIAL_ATTESTATIONS_REQUIRED')
            name=digest(payload)+'.'+ROLE+'.json'
            signature=private_bytes(self.verifier.signature_directory/name)
            require(name not in self.signatures or self.signatures[name]==signature,
                'DISCOVERY_ATTESTATION_BYTES_CHANGED')
            self.signatures[name]=signature
        require(boot_id('/proc/sys/kernel/random/boot_id')==m['generation']['bootId'],
            'CURRENT_DISCOVERY_INSTALLATION_BOOT_REQUIRED')
        observed=self.probe(copy.deepcopy(m['generation']))
        require(observed=={k:m['generation'][k] for k in
            ('nativeObservationHash','nativeProfileHash','generationRef','bootId')},
            'CURRENT_PREATTESTED_TWO_PEER_GENERATION_REQUIRED')
        for ref in c['sources']:
            if not beneath(ref['path'],m['template']['installationRoot']):
                protected_file(ref['path'],ref['maximumBytes'],expected=ref['sha256'],modes=(0o400,0o600,0o644,0o755))
        wall,mono=time.time(),time.monotonic();initial=m['initialTime']
        require(initial[0]<=wall and initial[1]<=mono
            and max(wall-initial[0],mono-initial[1])<m['proposal']['recipe']['policy']['max_elapsed'],
            'INITIAL_DISCOVERY_RECOVERY_BUDGET_ALREADY_CONSUMED_OR_CLOCK_REGRESSED')
        self.start.current(intent)

    def claim(self):
        return {'schema':'ouf.discovery-worker-file-publication-claim.v1','sealHash':self.seal_hash,
            'parentAuthorityHash':self.start.parent_hash,'childAuthorityHash':self.start.authority_hash,
            'transitionContextHash':self.start.transition.context,'intentHash':self.start.intent_hash,
            'publicationAttempts':1,'automaticReplayAllowed':False,'budgetReset':False}

    def put(self,name,raw,mode=0o600):
        with directory(Path(name).parent) as fd:new_file(fd,Path(name).name,raw,mode)

    def apply(self,intent):
        self.current(intent);c=self.material['proposal']['configuration']
        with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root) as journal:
            require(stat.S_IMODE(os.fstat(journal).st_mode)==0o700,'PRIVATE_DISCOVERY_FILE_TRANSACTION_REQUIRED')
            # O_EXCL consumes this stable parent-reviewed transaction before any
            # destination write. Every failure leaves this claim and all bytes.
            new_file(journal,'claim.json',encoded(self.claim()))
            self.current(intent)
            roots=(self.start.template['installationRoot'],c['ledgerRoot'],self.start.template['sandboxRoot'])
            require(all(not os.path.lexists(p) for p in roots),'EXISTING_DISCOVERY_INSTALLATION_OR_LEDGER_PRESERVED')
            for name in sorted(self.material['seal']['directories'],key=lambda p:(len(Path(p).parts),p)):
                with directory(Path(name).parent) as parent:
                    os.mkdir(Path(name).name,0o700,dir_fd=parent);os.fsync(parent)
            for name,(mode,raw) in sorted(self.material['files'].items()):self.put(name,raw,mode)
            install=self.start.template['installationRoot']
            for name,raw in sorted(self.signatures.items()):self.put(install+'/receipt-signatures/'+name,raw)
            self.put(install+'/publication-seal.json',encoded(self.material['seal']))
            owned={name:inode(name) for name in self.material['seal']['directories']}
            owned.update({name:inode(name) for name in self.material['files']})
            owned.update({install+'/receipt-signatures/'+name:inode(install+'/receipt-signatures/'+name)
                for name in self.signatures})
            owned[install+'/publication-seal.json']=inode(install+'/publication-seal.json')
            new_file(journal,'owned-inodes.json',encoded(owned))
            self.current(intent)
            # installed.json is the last runtime-visible commit marker. A crash
            # after it is reconciled from exact byte/custody readback, not replay.
            self.put(install+'/installed.json',encoded(self.material['receipt']))
            new_file(journal,'commit-inode.json',encoded({'inode':inode(install+'/installed.json')}))
            self.current(intent)
            new_file(journal,'complete.json',encoded(self.claim()))

    def observe(self,intent):
        """Strict read-only reconciliation, including partial and lost commits."""
        self.current(intent);c=self.material['proposal']['configuration']
        with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root):
            claim=self.root/'claim.json'
            if not os.path.lexists(claim):return 'UNKNOWN',{'ownedClaimPresent':False,'automaticReplayAllowed':False}
            require(private_json(claim)==self.claim(),'FOREIGN_DISCOVERY_FILE_PUBLICATION_CLAIM')
            install=self.start.template['installationRoot']
            files={**self.material['files'],install+'/publication-seal.json':(0o600,encoded(self.material['seal'])),
                install+'/installed.json':(0o600,encoded(self.material['receipt'])),
                **{install+'/receipt-signatures/'+name:(0o600,raw) for name,raw in self.signatures.items()}}
            try:
                owned=private_json(self.root/'owned-inodes.json')
                commit_inode=private_json(self.root/'commit-inode.json')
                require(set(owned)==set(self.material['seal']['directories'])|set(files)-{install+'/installed.json'},
                    'EXACT_OWNED_DISCOVERY_INSTALLATION_INODE_SET_REQUIRED')
                require(all(inode(name)==pin for name,pin in owned.items())
                    and commit_inode=={'inode':inode(install+'/installed.json')},'DISCOVERY_INSTALLED_INODE_DRIFT')
                for name in self.material['seal']['directories']:
                    with directory(name) as fd:
                        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'DISCOVERY_INSTALLATION_DIRECTORY_DRIFT')
                for name,(mode,raw) in files.items():
                    actual=(private_bytes(Path(name),1) if not raw
                        else protected_file(name,len(raw),modes=(mode,)))
                    require(actual==raw,
                        'DISCOVERY_INSTALLED_FILE_BYTES_DRIFT')
            except FileNotFoundError:
                return 'UNKNOWN',{'ownedClaimPresent':True,'partialInstallationPreserved':True,'automaticReplayAllowed':False}
            if os.path.lexists(self.root/'complete.json'):
                require(private_json(self.root/'complete.json')==self.claim(),'FOREIGN_DISCOVERY_FILE_COMMIT_RECORD')
            self.current(intent)
            return 'APPLIED',{'schema':'ouf.discovery-worker-files-installed.v1','sealHash':self.seal_hash,
                'claimHash':digest(self.claim()),'exactInitialLedgerReadback':True,
                'managerStartPerformed':False,'signaturesIssued':0,'automaticReplayAllowed':False,
                'runtimeAuthorityIssued':False,'applicationE2EProven':False,'releaseAcceptance':False}
