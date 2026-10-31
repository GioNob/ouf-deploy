"""Disposable native worker-sequence setup; provider application claims synthetic.

Only CI seed directories are moved. They have never run a worker and are not an
operational predecessor. The production publisher creates new destinations and
new initial records; no installed or live journal is overwritten/adopted.
"""
import copy,hashlib,os,time
from pathlib import Path
from tools.m2_discovery_installation_profile import lease_installation_template as templates
from tools.m2_discovery_installation_profile import lease_file_installation as files
from tools.m2_discovery_installation_profile import provider_admission as admission
from tools.m2_discovery_installation_profile import lease_registration as registration
from tools.m2_discovery_installation_profile import lease_attestation as attestation
from tools.m2_discovery_installation_profile import lease_installation_phase as sequence
from tools.m2_discovery_installation_profile import lease_start_owner as starts
from tools.m2_discovery_installation_profile.lease_materialization import WorkerMaterialization
from tools.m2_discovery_installation_profile.native_generation_probe import NativeLeaseGenerationProbe,generation_reference
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_deployment_protocol import validate_final

encoded=files.encoded;digest=files.digest


def prepare(base,auth,private,install,ledger,sandbox,link,checkpoint,command,create):
    require=files.require
    require(os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_NATIVE_CI_ONLY')
    original=base.proposal;old=original['configuration']
    require(files.private_json(ledger/'recovery.json')['attempts']==0,'UNUSED_CI_SEED_REQUIRED')
    capsule=(install/'capsule.py').read_bytes();trust=(install/'public-trust/policy.json').read_bytes()
    readonly=(install/'readonly-probe').read_bytes()
    # The manual fixture seed is retained for diagnosis, before any parent
    # sequence is authorized or attempted. This is not target recovery code.
    seed=private/'unused-seed';seed.mkdir(mode=0o700)
    link.unlink();command('systemctl','daemon-reload')
    for p,name in ((install,'installation'),(ledger,'ledger'),(sandbox,'sandbox')):p.rename(seed/name)
    for name in ('signatures','observations','provider-admission','registration','issuance','sequence','file-publication'):
        (private/name).mkdir(mode=0o700)
    provider_recipe={'schema':'ouf.discovery-provider-independent-node-recipe.v1','sourceClosureHash':base.template['sourceClosureHash'],
        'qualifiedPackageHash':'7'*64,'imageConfigurationHash':'2'*64,
        'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'2'*64,'entries':1,'bytes':0},
        'expectedImageId':base.template['expectedImages']['provider'],'artifactHash':'8'*64,
        'deploymentConstraintsHash':'9'*64,'transportHash':'a'*64,'runtimeExecutableHash':'b'*64}
    snapshot=copy.deepcopy(original['nativeObservation'])
    snapshot['profiles']['provider']={'nodeRecipeHash':digest(provider_recipe),'applicationHash':'2'*64,
        'imageConfigurationHash':provider_recipe['imageConfigurationHash'],'rootfsSealHash':digest(provider_recipe['expectedRootfsSeal'])}
    snapshot['nativeProfileHash']=digest(snapshot['profiles']);snapshot['generationRef']=generation_reference(snapshot)
    static=copy.deepcopy(base.template['configurationTemplate']);recipe=copy.deepcopy(base.template['recipeTemplate'])
    options={k:copy.deepcopy(base.template[k]) for k in ('signingKeyPaths','engineUnit','sandboxRoot')}
    template=templates.template(static,recipe,base.template['python'],source_closure_hash=base.template['sourceClosureHash'],
        expected_images=base.template['expectedImages'],expected_node_profiles={role:{k:v[k] for k in templates.INDEPENDENT_FIELDS}
            for role,v in snapshot['profiles'].items()},installation_root=str(install),signing_key_paths=options['signingKeyPaths'],
        engine_unit=options['engineUnit'],sandbox_root=options['sandboxRoot'])
    materialized=templates.materialize(template,snapshot,old['commonLockIdentity'])
    records={name:str(private/'provider-admission'/(name+'.json')) for name in admission.RECORDS}
    provider_scope=admission.admission_scope(template,provider_recipe,records,'c'*64)
    start_scope=starts.start_scope(template,unit_name=base.scope['unitName'],manager=base.scope['manager'],directory=str(base.root))
    bare=files.publication_scope(template,start_scope,str(private/'file-publication'))
    manager_scope=registration.registration_scope(template,start_scope,unit_directory=str(link.parent),journal_directory=str(private/'registration'))
    managed=registration.registered_component(template,bare,manager_scope)
    native_key=private/'native.pem';public_policy=seed/'installation/public-trust/policy.json'
    crypto=materialized['configuration']['verification']
    verifier=DetachedAuthenticator({'path':str(public_policy),'sha256':hashlib.sha256(trust).hexdigest()},
        str(private/'signatures'),crypto['openssl'])
    signer=ExistingEd25519Signer({'path':str(native_key),'sha256':hashlib.sha256(native_key.read_bytes()).hexdigest()},
        'synthetic-ci-key',verifier,{'role':'CREATION_ATTESTATION','issuerRef':auth.context['attestorRef'],
            'installationRef':auth.context['installationRef'],'entityRef':auth.context['entityRef']})
    issue_scope=attestation.issuance_scope(template,provider_scope,directory=str(private/'issuance'),
        signature_directory=str(private/'signatures'),observation_root=str(private/'observations'),
        key_binding=signer.key,key_ref=signer.key_ref)
    component=attestation.attested_component(template,managed,issue_scope)
    seq_scope=sequence.sequence_scope(template,component,directory=str(private/'sequence'))
    intent={**base.intent,'leaseInstallationScopeHash':digest(start_scope)}
    auth.now=int(time.time());auth.review.update(sourceClosureHash=template['sourceClosureHash'],
        installationInputsHash=old['installationInputsHash'],desiredProfileHash=old['desiredProfileHash'])
    phase_hashes={phase:digest(base.node_owner.request) if phase=='CREATE_REPLACEMENT' else digest(intent)
        if phase==base.phase else '4'*64 for phase in starts.PHASES}
    child,raw=auth.child(creation_request_hash=digest(base.node_owner.request),phase_intent_hashes=phase_hashes)
    auth.review['components']['operationalLeaseInstallation']=sequence.sequenced_component(template,component,seq_scope)
    auth.review['components']['providerInstallation']=provider_scope;parent=auth.fixture()
    authority_hash=hashlib.sha256(raw).hexdigest();checkpoint['transitionAuthorityEvidenceHash']=authority_hash
    for effect in checkpoint['effects']:
        effect.update(authorityEvidenceHash=authority_hash,intentHash=phase_hashes[effect['phase']])
    node=base.node_owner;node.authority=child;node.raw=raw
    start=starts.LeaseStartAdapter(parent=parent,authority=child,authority_raw=raw,transition=base.transition,store=base.store,
        node_owner=node,template=template,proposal=materialized,scope=start_scope,intent=intent,
        publication_directory=str(private/'file-publication'),registration_scope=manager_scope,
        attestation_scope=issue_scope,sequence_scope=seq_scope)
    provider=admission.RetainedProviderAdmission(parent=parent,template=template,recipe=provider_recipe,records=records,configuration_hash='c'*64)
    # Signed synthetic application admission records; real peer generation and
    # independent native probe are used. No real provider admission is claimed.
    def signed(value,role):
        issuer=auth.context['attestorRef'] if role=='CREATION_ATTESTATION' else auth.context['intentIssuerRef']
        key_ref='synthetic-attestor-key' if role=='CREATION_ATTESTATION' else 'synthetic-installer-key'
        actor=ExistingEd25519Signer(auth.binding(auth.key),key_ref,auth.verifier,
            {'role':role,'issuerRef':issuer,'installationRef':auth.context['installationRef'],'entityRef':auth.context['entityRef']})
        payload=encoded(value);envelope=actor.sign(payload)
        create(auth.signatures/(digest(value)+'.'+role+'.json'),envelope)
        return payload
    peer=snapshot['peers']['provider'];ctx=auth.context
    generation={'pid':peer['pid'],'startTicks':peer['startTicks'],'namespaceInode':peer['namespace']['identity'][1]}
    request={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':ctx['intentIssuerRef'],
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'containerId':peer['containerId'],'transactionId':'d'*64,
        **{k:provider_recipe[k] for k in ('artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
        'issuedAt':auth.now,'expiresAt':auth.now+85,'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
    request_raw=signed(request,'DEPLOYMENT_INTENT')
    acceptance={'schema':'ouf.semantic-container-creation-acceptance.v2','containerId':peer['containerId'],
        'applicationHash':'2'*64,'transportHash':request['transportHash'],'accepted':True,'artifactHash':request['artifactHash'],
        'creationFrameHash':'e'*64}
    attested={'schema':'ouf.semantic-created-candidate-attestation.v2','attestorRef':ctx['attestorRef'],
        **{k:request[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
            'deploymentConstraintsHash','transportHash','runtimeExecutableHash')},'applicationHash':'2'*64,'generation':generation,
        'intentHash':hashlib.sha256(request_raw).hexdigest(),'observedAt':auth.now,'creationAcceptance':acceptance}
    attested_raw=signed(attested,'CREATION_ATTESTATION')
    approval={'schema':'ouf.semantic-deployment-admission-approval.v1','issuerRef':ctx['approvalIssuerRef'],
        **{k:request[k] for k in ('installationRef','entityRef','containerId','transactionId','transportHash')},
        'applicationHash':'2'*64,'approvalRef':'SYNTHETIC_NATIVE_WORKER_CI','creationAcceptanceHash':digest(acceptance),
        'issuedAt':auth.now,'expiresAt':auth.now+85,'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}
    approval_raw=signed(approval,'FINAL_DEPLOYMENT_APPROVAL')
    mandate={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1','issuerRef':ctx['attestorRef'],
        **{k:attested[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
            'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation')},
        'rootfsSeal':provider_recipe['expectedRootfsSeal'],'issuedAt':auth.now,'expiresAt':auth.now+85,
        'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
    mandate_raw=signed(mandate,'CREATION_ATTESTATION')
    evidence=validate_final(request_raw,attested_raw,approval_raw,ctx,auth.verifier,parent.clock)
    consumption={'schema':'ouf.semantic-deployment-consumption.v1',
        **{k:request[k] for k in ('installationRef','entityRef','containerId','transactionId')},'intentHash':attested['intentHash'],
        'configurationHash':'c'*64,'state':'STARTED','bundleHash':'2'*64,'generation':generation,
        'evidenceHash':digest(evidence),'approvalHash':evidence['approvalHash'],'driverHash':'f'*64}
    for name,payload in [('intent',request_raw),('attestation',attested_raw),('approval',approval_raw),
        ('acceptanceMandate',mandate_raw),('consumption',encoded(consumption))]:create(Path(records[name]),payload)
    # Preserve only this never-used CI seed fence. The production owner must
    # create one new inode itself and capture both actual Docker generations.
    Path(static['commonInvocationLock']).rename(seed/'logical-fence')
    owner=WorkerMaterialization(node_owner=node,provider=provider,signer=signer,capsule=capsule,
        installation_sources={str(install/'public-trust/policy.json'):trust,str(install/'readonly-probe'):readonly})
    phase=owner.prepare_once(intent)
    assert owner.prepared(intent).files.material==phase.files.material
    return phase,phase.start,template,phase.start.proposal,intent
