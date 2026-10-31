"""Disposable Registry node/transport + installed token owner composition.

Only CI may construct the synthetic HUMAN/IAM realm/image/package predecessors.
All production owner, Ed25519, TLS, mount, OCI/rootfs/NIC, nft and systemd readers
remain real. No production source/guard or consumed runtime scope is modified.
"""
import copy,hashlib,json,os,time
from pathlib import Path
from tools.m2_discovery_installation_profile import node_owner as nodes,transport_owner as transports
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,LegacyWriterFence
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery,RenewalWorker
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_lease_recovery.bounded_recovery import Permanent

digest=nodes.digest


class TokenFixture:
    def __init__(self,run):
        assert os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0
        from test_installed_token_owner import InstalledOwnerTest
        self.run=run;self.masks=[];self.case=InstalledOwnerTest()
        try:
            # Dedicated disposable host only. Refuse to adopt any existing unit.
            for unit in LegacyWriterFence.UNITS:
                path=Path('/etc/systemd/system')/unit
                assert not os.path.lexists(path),'CI_LEGACY_UNIT_ALREADY_PRESENT'
                path.symlink_to('/dev/null');self.masks.append(path)
            run('systemctl','daemon-reload');assert LegacyWriterFence().guard()
            f,server,owner,recovery,_,output=self.case.fixture(scheduled=True,
                authority_seconds=300,real_authority_clock=True,iam_lifetime=600)
            self.auth,self.server,self.owner,self.output=f,server,owner,output
            scheduled=ScheduledRecovery(recovery.journal,recovery.adapter,recovery.policy,
                recovery.context,recovery.generation,recovery.clock,lambda:.5,interval_seconds=60)
            first=RenewalWorker(scheduled).tick();assert first['state']=='ACTIVE' and first['attempts']==1
            self.reader=InstalledTokenOwner(owner.binding,owner.credential,owner.admission,owner.journal,
                owner.context,owner.generation,owner.manifest,f.gate(),f.authority,observer=True)
            self.files={p:p.read_bytes() for p in (owner.journal.record,owner.journal.root/'owner-admission.json',output/'token.jwt')}
            self.initial_grants=self.grants();assert self.initial_grants==1
        except BaseException:
            self.close();raise

    def grants(self):return sum(path.endswith('/token') for path,_ in self.server.calls)
    def unchanged(self):
        assert self.grants()==self.initial_grants==1
        assert all(p.read_bytes()==raw for p,raw in self.files.items())
    def close(self):
        self.case.doCleanups()
        for path in self.masks:
            if path.is_symlink() and os.readlink(path)=='/dev/null':path.unlink()
        if self.masks:self.run('systemctl','daemon-reload',check=False)
        self.masks=[]


def configure_recipe(auth,root,options,commands,registry_rootfs):
    """Complete independently prepared inputs before parent/child review."""
    prep=options['preparer_template'];recipe=options['registry_recipe']
    binding={'interface':'eth0','bridge':'brfixture','mac':'02:00:00:00:01:02','ipv4':'10.77.0.3',
        'workloadRef':'registry-fixture','bindingRef':'registry-nic',
        'leaseGuard':{'configurationHash':digest(prep['kernel']),'tableName':prep['kernel']['tableName']}}
    command=lambda name:{'path':commands[name],'sha256':hashlib.sha256(Path(commands[name]).read_bytes()).hexdigest()}
    candidate={'networkBindings':[binding],'tableName':'ci_registry_shared',
        'transport':[{'purpose':'GATEWAY_ADAPTER','authorityRef':'synthetic-ci-registry-host-transport',
            'source':'10.77.0.3','destination':'192.0.2.53','protocol':'tcp','port':9443,
            'peerIngress':{'kind':'HOST','ifindex':0}}]}
    recipe.update(expectedRootfsSeal=copy.deepcopy(registry_rootfs),observationSeconds=60,
        frameSourceBinding=copy.deepcopy(options['frame_source_binding']),
        observationConfiguration={'runtimeBinding':command('runc'),'runtimeRootParents':options['runtime_root_parents'],
            'bundleParents':[recipe['dockerContext']['bundleParent']],
            'commands':{k:command(k) for k in ('ip','nsenter')},'candidate':candidate,
            'rootfsLimits':copy.deepcopy(options['rootfs_limits'])})
    node_root=root/'registry-node';transport_root=root/'registry-transport'
    node_root.mkdir(mode=0o700);transport_root.mkdir(mode=0o700)
    transport={'schema':'ouf.semantic-discovery-transport-recipe.v1','sourceClosureHash':recipe['sourceClosureHash'],
        'nodeRecipeHash':digest(recipe),'coordinatorBindingHash':digest(prep['coordinationBinding']),
        'leaseConfigurationHash':digest(prep['kernel']),'leaseStructureHash':prep['coordinationBinding']['leaseStructureHash'],
        'commands':{k:command(k) for k in ('ip','nsenter','nft')},'nativeBudgetSeconds':5,'isolationSeconds':15}
    return {'nodeRoot':node_root,'transportRoot':transport_root,'transportRecipe':transport,
        'transportIntent':{'creationRequestHash':auth.review['components']['registryCutover']['creationRequestHash'],
            'nodeRecipeHash':digest(recipe),'transportRecipeHash':digest(transport),'priorEvidencePhase':'ATTEST_NEW_OCI_PEER'}}


def enter(boundary,phase,raw):
    index=nodes.DISCOVERY_PHASES.index(phase);signed=json.loads(raw)
    assert boundary['state']=='READY' and boundary['nextPhase']==index
    assert len(boundary['effects'])==index and all(e['state']=='APPLIED' for e in boundary['effects'])
    boundary.update(state='IN_FLIGHT',nextPhase=index)
    boundary['effects'].append({'phase':phase,'state':'IN_FLIGHT','intentHash':signed['phaseIntentHashes'][phase],
        'authorityEvidenceHash':hashlib.sha256(raw).hexdigest(),'nativeEvidenceHash':None})


def applied(boundary,evidence):
    assert boundary['effects'][-1]['state']=='IN_FLIGHT'
    boundary['effects'][-1].update(state='APPLIED',nativeEvidenceHash=digest(evidence))
    boundary.update(state='READY',nextPhase=boundary['nextPhase']+1)


def attest_and_install(provider_phase,auth,setup,boundary,token):
    owner=provider_phase.runtime;window=owner.creation.window;recipe=owner.issuer.scope['registryRecipe']
    signer=ExistingEd25519Signer(auth.binding(auth.key),'synthetic-attestor-key',auth.verifier,
        {'role':'CREATION_ATTESTATION','issuerRef':auth.context['attestorRef'],
            'installationRef':auth.context['installationRef'],'entityRef':auth.context['entityRef']})
    intent={'creationRequestHash':window.request_hash,
        **{k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')},'nodeRecipeHash':digest(recipe)}
    assert window.transition.phases==nodes.DISCOVERY_PHASES
    node=nodes.DiscoveryNodeOwner(window.engine,window.transition,window.request,intent,window.store,window.profile,
        token.reader,window.child,window.raw,auth.verifier,signer,recipe,setup['nodeRoot'])
    enter(boundary,'ATTEST_NEW_OCI_PEER',window.raw)
    node.apply(intent);outcome,proof=node.observe(intent);assert outcome=='APPLIED'
    assert proof['completeNativeObservationPerformed'] and proof['currentScopedAcceptanceSignatureVerified']
    applied(boundary,proof);token.unchanged()
    enter(boundary,'INSTALL_AUTHENTICATED_TRANSPORT',window.raw)
    transport=transports.TransportInstallationAdapter(transition=window.transition,store=window.store,
        authority=window.child,authority_raw=window.raw,node_owner=node,coordinator=owner.coordinator,
        recipe=setup['transportRecipe'],directory=setup['transportRoot'],intent=setup['transportIntent'])
    try:
        transport.apply(setup['transportIntent']);outcome,proof=transport.observe(setup['transportIntent']);assert outcome=='APPLIED'
    except Exception:
        observer=node.adapter.observer;profile=observer.transport_profile
        ns=Path(profile['namespacePath'])
        def metadata(p):
            try:
                s=p.lstat();return {'path':str(p),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(s.st_mode),
                    'inode':s.st_ino,'symlink':p.is_symlink()}
            except OSError:return {'path':str(p),'unavailable':True}
        print('CI_REGISTRY_TRANSPORT_NAMESPACE='+json.dumps({'origin':profile.get('namespaceOrigin'),
            'path':str(ns),'expectedInode':profile['namespaceInode'],'generation':observer.transport_generation,
            'dockerSandboxKey':window.engine.inspect(window.transition)['NetworkSettings']['SandboxKey'],
            'metadata':[metadata(ns),*[metadata(p) for p in ns.parents]]},sort_keys=True),flush=True)
        raise
    assert not proof['applicationStartAuthorized'] and not proof['applyReplayAllowed']
    applied(boundary,proof);token.unchanged()
    return node


def final_read(node,token):
    token.unchanged();token.server.active=lambda:{'active':False}
    try:node.verify_retained();raise AssertionError('CI_REVOKED_IAM_TOKEN_ADMITTED_REGISTRY')
    except Permanent as error:assert error.code=='AUTHORITY_REVOKED'
    token.unchanged()
    return {'schema':'ouf.m2-registry-node-transport-token-ci.v1','actualRegistryNodeAttestationAndRetainedRead':True,
        'actualFiveFilesDbConfigtreeAndRenewableTokenMount':True,'actualInstalledTokenOwnerSourceCustodyAndJournal':True,
        'actualMaskedLegacyWriterUnitReadback':True,'actualTlsDiscoveryIntrospectionAndOneInitialGrant':True,
        'noGrantRenewalOrJournalResetDuringNativeReads':True,'iamRevocationDeniesFinalRegistryRead':True,
        'actualAuthenticatedTransportNftApplyAndReadback':True,'registryJavaStarted':False,
        'syntheticIamRealmHumanImagesPackagesAndEarlierTransitionPrefix':True,
        'currentTargetCohortProven':False,'applicationE2EProven':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
