"""Finite, one-use issuance for an independently admitted discovery generation.

The provider reader never starts/adopts a provider; the Registry owner independently
rechecks its paused OCI/rootfs acceptance. Native observation alone cannot reach
the signer. Partial or lost signing outcomes are reconciled without re-signing.
No command-line or target-delivery entry point is provided.
"""
import copy,os,stat,time
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .lease_installation_template import recompile,hashed
from .lease_unit import path,beneath
from .lease_file_installation import LeaseFileInstallation,inode,ROLE
from .provider_admission import RetainedProviderAdmission
from .native_generation_probe import NativeLeaseGenerationProbe
from .lease_service import existing_kernel_lock
from .installed_lease_guard import boot_id
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes
from tools.semantic_provider_deployment_protocol import identity
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json

PAYLOADS=('seal','generation','receipt')


def issuance_scope(template,provider_scope,*,directory,signature_directory,observation_root,key_binding,key_ref):
    t=recompile(template);c=t['configurationTemplate']
    require(type(provider_scope) is dict and provider_scope.get('schema')=='ouf.discovery-retained-provider-admission-scope.v1'
        and provider_scope.get('templateHash')==digest(t)
        and provider_scope.get('nodeRecipeHash')==t['expectedNodeProfiles']['provider']['nodeRecipeHash'],
        'SAME_REVIEWED_INDEPENDENT_PROVIDER_ADMISSION_SCOPE_REQUIRED')
    require(type(key_binding) is dict and set(key_binding)=={'path','sha256'}
        and key_binding['path'] in t['signingKeyPaths'] and hashed(key_binding['sha256'])
        and identity(key_ref),'EXACT_REVIEWED_ISOLATED_EXISTING_ATTESTOR_KEY_REQUIRED')
    selected=[path(p) for p in (directory,signature_directory,observation_root)]
    protected=(t['installationRoot'],c['ledgerRoot'],t['sandboxRoot'])
    require(all(len(Path(p).parts)>=4 and all(not beneath(p,r) and not beneath(r,p) for r in protected)
        for p in selected) and all(not beneath(p,q) and not beneath(q,p)
            for i,p in enumerate(selected) for q in selected[i+1:])
        and all(not beneath(key_binding['path'],p) for p in selected),
        'DISTINCT_PRIVATE_ISSUANCE_SIGNATURE_AND_OBSERVATION_DIRECTORIES_REQUIRED')
    return {'schema':'ouf.discovery-worker-attestation-issuance-scope.v1','templateHash':digest(t),
        'providerAdmission':copy.deepcopy(provider_scope),'journalDirectory':selected[0],
        'signatureDirectory':selected[1],'observationRoot':selected[2],
        'keyBinding':copy.deepcopy(key_binding),'keyRef':key_ref,'maximumSignatures':3,
        'payloads':list(PAYLOADS),'partialIssuanceReplayAllowed':False,'runtimeKeyAccessAllowed':False}


def attested_component(template,installation,issuance):
    require(type(installation) is dict and installation.get('schema')=='ouf.discovery-lease-files-and-start-scope.v1',
        'FILE_PUBLICATION_AND_START_SCOPE_REQUIRED_BEFORE_ISSUANCE')
    expected=issuance_scope(template,issuance['providerAdmission'],directory=issuance['journalDirectory'],
        signature_directory=issuance['signatureDirectory'],observation_root=issuance['observationRoot'],
        key_binding=issuance['keyBinding'],key_ref=issuance['keyRef'])
    require(issuance==expected,'DISCOVERY_ISSUANCE_SCOPE_CHANGED')
    roots=(installation['start']['journalDirectory'],installation['publication']['journalDirectory'])
    require(all(not beneath(issuance['journalDirectory'],p) and not beneath(p,issuance['journalDirectory']) for p in roots),
        'SEPARATE_SIGNING_PUBLICATION_AND_START_TRANSACTIONS_REQUIRED')
    return {'schema':'ouf.discovery-worker-attested-installation-and-start-scope.v1',
        'installation':copy.deepcopy(installation),'issuance':copy.deepcopy(issuance)}


class LeaseAttestationIssuer:
    def __init__(self,*,installation,provider,signer):
        require(type(installation) is LeaseFileInstallation and type(provider) is RetainedProviderAdmission
            and type(signer) is ExistingEd25519Signer and provider.parent is installation.start.parent
            and provider.template==installation.start.template and signer.verifier is installation.verifier,
            'SHARED_TYPED_WORKER_INSTALLATION_PROVIDER_AND_ATTESTOR_REQUIRED')
        self.installation,self.provider,self.signer=installation,provider,signer
        self.start=installation.start;self.scope=copy.deepcopy(self.start.attestation_scope)
        require(type(self.scope) is dict,'EXPLICIT_PARENT_REVIEWED_WORKER_ISSUANCE_REQUIRED')
        self.scope_hash=digest(self.scope);self.root=Path(self.scope['journalDirectory'])
        self.material_hash=digest(installation.material['seal'])
        self.directory_pins={p:inode(p) for p in (str(self.root),self.scope['signatureDirectory'])}
        self.check_scope()

    def check_scope(self):
        i=self.installation;s=self.start;scope=self.scope
        require(type(i) is LeaseFileInstallation and type(self.provider) is RetainedProviderAdmission
            and type(self.signer) is ExistingEd25519Signer and type(i.verifier) is DetachedAuthenticator
            and type(i.probe) is NativeLeaseGenerationProbe and self.signer.verifier is i.verifier
            and i.start is s and self.provider.parent is s.parent and self.provider.template==s.template
            and scope==s.attestation_scope and digest(scope)==self.scope_hash
            and s.parent_component==attested_component(s.template,s.installation_component,scope)
            and scope['providerAdmission']==self.provider.scope
            and self.signer.key==scope['keyBinding'] and self.signer.key_ref==scope['keyRef']
            and self.signer.scope=={'role':ROLE,'issuerRef':s.parent.context['attestorRef'],
                'installationRef':s.parent.context['installationRef'],'entityRef':s.parent.context['entityRef']}
            and str(i.verifier.signature_directory)==scope['signatureDirectory']
            and str(i.probe.root)==scope['observationRoot'] and str(self.root)==scope['journalDirectory'],
            'EXACT_CURRENT_REVIEWED_ISSUER_KEY_CONTEXT_AND_COMPONENTS_REQUIRED')
        for p in (str(self.root),scope['signatureDirectory']):
            with directory(p) as fd:
                require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and inode(p)==self.directory_pins[p],
                    'CURRENT_PRIVATE_ISSUANCE_DIRECTORY_CUSTODY_REQUIRED')
        i.validate_material();require(digest(i.material['seal'])==self.material_hash,'ATTESTATION_MATERIAL_CHANGED')

    def current(self,intent):
        self.check_scope();self.start.current(intent)
        material=self.installation.material;snapshot=material['proposal']['nativeObservation']
        provider=self.provider.current(copy.deepcopy(snapshot))
        require(boot_id('/proc/sys/kernel/random/boot_id')==snapshot['bootId'],
            'SAME_CURRENT_WORKER_ATTESTATION_BOOT_REQUIRED')
        observed=self.installation.probe(copy.deepcopy(material['generation']))
        require(observed=={k:material['generation'][k] for k in
            ('nativeObservationHash','nativeProfileHash','generationRef','bootId')},
            'CURRENT_INDEPENDENT_TWO_PEER_PROBE_REQUIRED_BEFORE_SIGNING')
        initial=material['initialTime'];wall,mono=time.time(),time.monotonic()
        require(initial[0]<=wall and initial[1]<=mono
            and max(wall-initial[0],mono-initial[1])<material['proposal']['recipe']['policy']['max_elapsed'],
            'INITIAL_WORKER_ATTESTATION_BUDGET_EXPIRED_OR_CLOCK_REGRESSED')
        self.check_scope();self.start.current(intent)
        return provider

    def claim(self,provider):
        return {'schema':'ouf.discovery-worker-attestation-issuance-claim.v1','scopeHash':self.scope_hash,
            'sealHash':self.material_hash,'parentAuthorityHash':self.start.parent_hash,
            'childAuthorityHash':self.start.authority_hash,'transitionContextHash':self.start.transition.context,
            'intentHash':self.start.intent_hash,'providerProofHash':digest(provider),
            'payloadHashes':{k:digest(self.installation.material[k]) for k in PAYLOADS},
            'maximumSignatures':3,'automaticReplayAllowed':False,'budgetReset':False}

    def issue(self,intent):
        provider=self.current(intent);c=self.installation.material['proposal']['configuration']
        with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root) as journal:
            require(stat.S_IMODE(os.fstat(journal).st_mode)==0o700,'ROOT_PRIVATE_ATTESTATION_ISSUANCE_JOURNAL_REQUIRED')
            new_file(journal,'claim.json',encoded(self.claim(provider)))
            require(self.current(intent)==provider,'PROVIDER_ADMISSION_CHANGED_BEFORE_ISSUANCE')
            with directory(self.scope['signatureDirectory']) as signatures:
                require(all(not os.path.lexists(Path(self.scope['signatureDirectory'])/
                    (digest(self.installation.material[k])+'.'+ROLE+'.json')) for k in PAYLOADS),
                    'PREEXISTING_WORKER_SIGNATURES_PRESERVED_NO_RESIGNING')
                for k in PAYLOADS:
                    require(self.current(intent)==provider,'PROVIDER_ADMISSION_CHANGED_DURING_ISSUANCE')
                    payload=encoded(self.installation.material[k]);name=digest(self.installation.material[k])+'.'+ROLE+'.json'
                    # Persist before calling the private-key primitive. A crash
                    # or lost result here is never permission to call it again.
                    new_file(journal,k+'-dispatch.json',encoded({'payloadHash':digest(self.installation.material[k]),'signAttempts':1}))
                    envelope=self.signer.sign(payload)
                    require(self.current(intent)==provider,'PROVIDER_ADMISSION_CHANGED_AFTER_SIGNATURE')
                    require(self.installation.verifier.verify_detached(payload,envelope,ROLE,
                        self.start.parent.context['attestorRef'],self.start.parent.context['installationRef'],
                        self.start.parent.context['entityRef']) is True,'SCOPED_WORKER_SIGNATURE_READBACK_REQUIRED')
                    new_file(signatures,name,envelope)
                    new_file(journal,k+'-owned.json',encoded({'inode':inode(Path(self.scope['signatureDirectory'])/name)}))
                require(self.current(intent)==provider,'PROVIDER_ADMISSION_CHANGED_BEFORE_ISSUANCE_COMMIT')
                new_file(journal,'complete.json',encoded(self.claim(provider)))

    def observe(self,intent):
        """Read only; missing signatures remain unknown with attempts consumed."""
        provider=self.current(intent);c=self.installation.material['proposal']['configuration']
        with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root):
            claim=self.root/'claim.json'
            if not os.path.lexists(claim):return 'UNKNOWN',{'ownedIssuanceClaimPresent':False,'automaticReplayAllowed':False}
            require(private_json(claim)==self.claim(provider),'EXACT_RETAINED_WORKER_ISSUANCE_CLAIM_REQUIRED')
            try:
                for k in PAYLOADS:
                    payload=encoded(self.installation.material[k]);sha=digest(self.installation.material[k])
                    require(private_json(self.root/(k+'-dispatch.json'))=={'payloadHash':sha,'signAttempts':1},
                        'EXACT_ONE_USE_WORKER_SIGN_DISPATCH_REQUIRED')
                    name=Path(self.scope['signatureDirectory'])/(sha+'.'+ROLE+'.json')
                    require(private_json(self.root/(k+'-owned.json'))=={'inode':inode(name)},'WORKER_SIGNATURE_INODE_DRIFT')
                    signature=private_bytes(name)
                    require(self.installation.verifier.verify_detached(payload,signature,ROLE,
                        self.start.parent.context['attestorRef'],self.start.parent.context['installationRef'],
                        self.start.parent.context['entityRef']) is True,'RETAINED_WORKER_SIGNATURE_REQUIRED')
            except FileNotFoundError:
                return 'UNKNOWN',{'ownedIssuanceClaimPresent':True,'partialIssuancePreserved':True,'automaticReplayAllowed':False}
            if os.path.lexists(self.root/'complete.json'):
                require(private_json(self.root/'complete.json')==self.claim(provider),'WORKER_ISSUANCE_COMMIT_DRIFT')
            require(self.current(intent)==provider,'PROVIDER_ADMISSION_CHANGED_DURING_ISSUANCE_RECONCILIATION')
            return 'APPLIED',{'schema':'ouf.discovery-worker-attestations-issued.v1','scopeHash':self.scope_hash,
                'claimHash':digest(self.claim(provider)),'signaturesIssued':3,'automaticReplayAllowed':False,
                'providerStartPerformed':False,'runtimeAuthorityIssued':False,'applicationE2EProven':False,'releaseAcceptance':False}
