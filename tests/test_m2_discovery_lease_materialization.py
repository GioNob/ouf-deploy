"""Actual signed scopes/files/claims; native generation and admissions modeled.

No native provider, manager or target operation is dispatched by these fixtures.
"""
import copy,hashlib,os,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_attestation as attest
from tools.m2_discovery_installation_profile import lease_materialization as m


class Materialization(unittest.TestCase):
    def fixture(self):
        f=attest.Attest();issuer,intent,auth,_,_=f.fixture(registration=True,sequence=True)
        self.addCleanup(f.doCleanups);material=issuer.installation.material
        template=material['template'];snapshot=copy.deepcopy(material['proposal']['nativeObservation'])
        # Remove only the disposable fixture's preseeded worker fence/snapshot.
        # Production materialization never deletes/adopts an existing fence.
        Path(template['configurationTemplate']['commonInvocationLock']).unlink()
        (issuer.installation.probe.root/(m.digest(snapshot)+'.json')).unlink()
        capsule=material['files'][template['installationRoot']+'/capsule.py'][1]
        owner=m.WorkerMaterialization(node_owner=issuer.start.node_owner,provider=issuer.provider,
            signer=issuer.signer,capsule=capsule,installation_sources=material['installationSources'])
        for selected in (patch.object(owner,'capture_native',return_value=snapshot),
                patch.object(m,'boot_id',return_value=snapshot['bootId'])):
            selected.start();self.addCleanup(selected.stop)
        return owner,intent,auth,snapshot

    def test_prepares_current_peers_once_without_signing_and_retains_original_clocks(self):
        owner,intent,auth,snapshot=self.fixture()
        with patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')):
            phase=owner.prepare_once(intent);again=owner.prepared(intent)
        self.assertIs(type(phase),m.WorkerInstallationPhase)
        self.assertEqual(phase.files.material,again.files.material)
        self.assertEqual(phase.files.material['proposal']['nativeObservation'],snapshot)
        self.assertEqual(phase.files.material['initialTime'],m.private_json(owner.root/'materialization-claim.json')['initialTime'])
        self.assertFalse((owner.root/'claim.json').exists())
        with self.assertRaises(FileExistsError):owner.prepare_once(intent)

    def test_lost_owned_commit_reply_reconciles_without_any_write_or_resigning(self):
        owner,intent,auth,_=self.fixture();original=m.new_file
        def lost(fd,name,raw,mode=0o600):
            result=original(fd,name,raw,mode)
            if name=='materialization-owned.json':raise TimeoutError('SYNTHETIC_LOST_OWNED_REPLY')
            return result
        with patch.object(m,'new_file',side_effect=lost),self.assertRaises(TimeoutError):owner.prepare_once(intent)
        with (patch.object(m,'new_file',side_effect=AssertionError('NO_RECONCILIATION_WRITES')),
                patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS'))):
            self.assertIsNotNone(owner.prepared(intent))

    def test_partial_materialization_preserves_claim_and_fence_without_recreation(self):
        owner,intent,auth,_=self.fixture()
        with (patch.object(owner,'capture_native',side_effect=TimeoutError('SYNTHETIC_LOST_CAPTURE')),
                self.assertRaises(TimeoutError)):owner.prepare_once(intent)
        lock=Path(owner.template['configurationTemplate']['commonInvocationLock']);identity=m.inode(lock)
        self.assertIsNone(owner.prepared(intent));self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.prepare_once(intent)
        self.assertEqual(m.inode(lock),identity)
        with self.assertRaisesRegex(ValueError,'NO_REPREPARATION'):owner.continue_installation(intent)

    def test_native_generation_mismatch_cannot_commit_owned_material(self):
        owner,intent,auth,_=self.fixture()
        with patch.object(m.NativeLeaseGenerationProbe,'__call__',return_value={}),self.assertRaisesRegex(ValueError,'EXACT_CURRENT'):
            owner.prepare_once(intent)
        self.assertFalse((owner.root/'materialization-owned.json').exists())

    def test_new_boot_cannot_reconstruct_or_rearm_the_retained_material(self):
        owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
        with patch.object(m,'boot_id',return_value='new-boot'),self.assertRaisesRegex(ValueError,'NO_REARM'):
            owner.prepared(intent)

    def test_provider_and_worker_must_share_independent_recipe_and_actual_kernel_contract(self):
        owner,_,_,_=self.fixture();t=owner.template;r=t['recipeTemplate'];recipe=copy.deepcopy(owner.node.recipe)
        # Pure cross-input checks only. This partial profile is never an issuer
        # input, native admission or substitute for recompile_scope/check_scope.
        profile={'schema':'ouf.discovery-provider-profile-installation-scope.v1','registryRecipe':{
            **recipe,'sourceClosureHash':t['sourceClosureHash']},'preparerTemplate':{
            'kernel':r['kernel'],'dns':r['dns'],'coordinationBinding':r['binding'],
            'coordinationJournal':str(owner.root/'retained-provider-coordination.json'),'lockFile':r['leaseCommonLock'],
            'commands':{'nft':r['nft']['path']},'commandHashes':{'nft':r['nft']['sha256']}}}
        profile['keys']={role:{'path':t['signingKeyPaths'][0]} for role in ('installer','attestor')}
        # The Registry recipe must be the exact independent one fixed in t.
        profile['registryRecipe']=recipe
        recipe['sourceClosureHash']=t['sourceClosureHash']
        from tools.m2_discovery_installation_profile import lease_installation_template as templates
        options={k:t[k] for k in ('sourceClosureHash','expectedImages','expectedNodeProfiles','installationRoot','signingKeyPaths','engineUnit','sandboxRoot')}
        options['expectedNodeProfiles']=copy.deepcopy(options['expectedNodeProfiles'])
        options['expectedNodeProfiles']['registry']['nodeRecipeHash']=m.digest(recipe)
        t=templates.template(t['configurationTemplate'],r,t['python'],**{
            'source_closure_hash':options['sourceClosureHash'],'expected_images':options['expectedImages'],
            'expected_node_profiles':options['expectedNodeProfiles'],'installation_root':options['installationRoot'],
            'signing_key_paths':options['signingKeyPaths'],'engine_unit':options['engineUnit'],'sandbox_root':options['sandboxRoot']})
        lock=[*r['leaseCommonLockIdentity'],0,1,1];request={'Image':t['expectedImages']['registry']}
        m.paired_native_inputs(t,profile,request,lock)
        for field in ('kernel','dns','coordinationBinding','lockFile','commands','commandHashes'):
            wrong=copy.deepcopy(profile);wrong['preparerTemplate'][field]={} if type(wrong['preparerTemplate'][field]) is dict else '/other'
            with self.assertRaises((ValueError,KeyError)):m.paired_native_inputs(t,wrong,request,lock)
        with self.assertRaises(ValueError):m.paired_native_inputs(t,profile,request,[*lock[:1],lock[1]+1,*lock[2:]])
        with self.assertRaises(ValueError):m.paired_native_inputs(t,profile,{'Image':'sha256:'+'f'*64},lock)
        wrong=copy.deepcopy(profile);wrong['preparerTemplate']['coordinationJournal']=r['coordinationJournal']
        with self.assertRaisesRegex(ValueError,'PRESERVED_PROVIDER_JOURNAL'):m.paired_native_inputs(t,wrong,request,lock)
        wrong=copy.deepcopy(profile);wrong['keys']['installer']['path']='/unlisted-private-key'
        with self.assertRaisesRegex(ValueError,'ALL_PROVIDER_SIGNING_KEYS'):m.paired_native_inputs(t,wrong,request,lock)

    def test_replaced_snapshot_and_invalid_reference_are_not_adopted(self):
        for change in ('inode','path'):
            owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
            record=owner.root/'materialization-owned.json';owned=m.private_json(record)
            if change=='inode':
                selected=owner.probe.root/(owned['snapshotHash']+'.json');replacement=owner.probe.root/'replacement.json'
                auth.write(replacement,selected.read_bytes());replacement.replace(selected)
            else:
                owned['snapshotHash']='../other';auth.write(record,m.encoded(owned))
            with (patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')),
                    self.assertRaises(ValueError)):owner.prepared(intent)

    def test_original_clock_tamper_or_revoked_admission_blocks_reconstruction(self):
        for change in ('clock','admission'):
            owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
            if change=='clock':
                path=owner.root/'materialization-claim.json';claim=m.private_json(path)
                claim['initialTime'][0]+=1;auth.write(path,m.encoded(claim))
                selected=patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS'))
            else:selected=patch.object(owner.provider,'current',side_effect=ValueError('SYNTHETIC_ADMISSION_REVOKED'))
            with selected,self.assertRaises(ValueError):owner.prepared(intent)

    def test_late_material_drives_real_signatures_and_files_before_modeled_manager_boundary(self):
        owner,intent,auth,_=self.fixture()
        with (patch.object(m.LeaseRegistration,'apply',side_effect=TimeoutError('MODELED_MANAGER_UNAVAILABLE')),
                self.assertRaises(TimeoutError)):owner.apply(intent)
        phase=owner.prepared(intent)
        from tools.m2_discovery_installation_profile.lease_installation_phase import checked_row
        self.assertEqual(checked_row(phase.start)['stageIndex'],2)
        self.assertEqual(phase.issuer.observe(intent)[0],'APPLIED')
        self.assertEqual(phase.files.observe(intent)[0],'APPLIED')
        with (patch.object(owner.signer,'sign',side_effect=AssertionError('NO_RESIGNING')),
                patch.object(m.LeaseRegistration,'apply',side_effect=AssertionError('NO_MANAGER_REPLAY'))):
            self.assertEqual(owner.observe(intent)[0],'UNKNOWN')

    def test_materialized_v2_provider_and_worker_preserve_separate_journals_under_one_parent(self):
        # Real constructors, signing, CAS and publication; Engine/kernel/node
        # admission leaves remain modeled. No real provider/manager is started.
        import test_m2_provider_runtime_installation as native
        from tools.m2_discovery_installation_profile import lease_installation_template as templates
        from tools.m2_discovery_installation_profile import lease_attestation as issue,lease_registration as reg
        from tools.m2_discovery_installation_profile import lease_installation_phase as sequence
        from tools.m2_discovery_installation_profile.provider_installation_phase import ProviderInstallationPhase
        from tools.m2_discovery_installation_profile.provider_materialized_admission import admission_scope
        from tools.m2_discovery_installation_profile.native_generation_probe import generation_reference
        case=native.Runtime();prior,w,auth,state,calls,*_=case.fixture(sequenced=True)
        self.addCleanup(case.doCleanups)
        worker_case=attest.Attest();seed,_,_,_,_=worker_case.fixture(registration=True,sequence=True)
        self.addCleanup(worker_case.doCleanups)
        old=seed.installation.material;t=old['template'];c=copy.deepcopy(t['configurationTemplate']);r=copy.deepcopy(t['recipeTemplate'])
        ps=copy.deepcopy(prior.issuer.scope);prep=ps['preparerTemplate']
        prep['coordinationBinding']['configurationHash']=m.digest(prep['kernel'])
        kernel_directory=auth.root/'shared-worker-kernel';kernel_directory.mkdir(mode=0o700)
        prep['lockFile']=str(kernel_directory/'kernel.lock');auth.write(Path(prep['lockFile']),b'')
        prep['coordinationJournal']=str(kernel_directory/'provider-coordination.json')
        # Disposable unattempted CI seeds only, before the new parent review.
        auth.write(Path(prep['coordinationJournal']),m.encoded({'schema':'ouf.semantic-lease-coordination.v1',
            **prep['coordinationBinding'],'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]}))
        c['installationInputsHash']=auth.review['installationInputsHash'];c['desiredProfileHash']=auth.review['desiredProfileHash']
        public_policy={'path':t['installationRoot']+'/public-trust/policy.json','sha256':auth.binding(auth.policy)['sha256']}
        c['verification']={'trustPolicy':public_policy,'openssl':ps['crypto']['opensslBinding'],
            'context':{k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}}
        r.update(kernel=prep['kernel'],dns=prep['dns'],binding=prep['coordinationBinding'],
            leaseCommonLock=prep['lockFile'],leaseCommonLockIdentity=list(native.m.custody(prep['lockFile'],0o600)[1])[:6],
            coordinationJournal=c['ledgerRoot']+'/coordination.json',nft={'path':prep['commands']['nft'],
                'sha256':prep['commandHashes']['nft'],'maximumBytes':67108864})
        r['scope'].update(installationInputsHash=c['installationInputsHash'],contextRef=w.transition.context,
            coordinatorBindingHash=m.digest(r['binding']),configurationHash=m.digest(r['kernel']),
            dnsProfileHash=m.digest(r['dns']),leaseStructureHash=r['binding']['leaseStructureHash'])
        rr=ps['registryRecipe'];profiles={'registry':{'nodeRecipeHash':m.digest(rr),
            'imageConfigurationHash':rr['imageConfigurationHash'],'rootfsSealHash':m.digest(rr['expectedRootfsSeal'])},
            'provider':prior.admission.template['expectedNodeProfiles']['provider']}
        lease=templates.template(c,r,t['python'],source_closure_hash=prior.creation.template['sourceClosureHash'],
            expected_images={'registry':w.request['Image'],'provider':prior.creation.template['expectedImageId']},
            expected_node_profiles=profiles,installation_root=t['installationRoot'],signing_key_paths=[str(auth.key)],
            engine_unit=t['engineUnit'],sandbox_root=t['sandboxRoot'])
        rs=native.m.runtime_scope(ps,wrapper_binding=prior.scope['wrapperBinding'],
            common_lock_identity=list(native.m.custody(prep['lockFile'],0o600)[1]))
        adm=admission_scope(lease,prior.creation.template,prior.creation.scope,ps)
        component={'schema':'ouf.discovery-composed-provider-installation-scope.v2','creation':prior.creation.scope,
            'installation':rs,'admission':adm}
        from tools.m2_discovery_installation_profile.provider_creation import provider_sequence_scope
        component['sequence']=provider_sequence_scope(prior.creation.scope,rs,adm,
            journal_directory=prior.creation.component['sequence']['journalDirectory'])
        start=m.start_scope(lease,unit_name=seed.start.scope['unitName'],manager=seed.start.scope['manager'],directory=str(seed.start.root))
        bare=m.publication_scope(lease,start,str(seed.installation.root))
        managed=reg.registered_component(lease,bare,reg.registration_scope(lease,start,
            unit_directory=seed.start.registration_scope['unitDirectory'],journal_directory=seed.start.registration_scope['journalDirectory']))
        issuance=issue.issuance_scope(lease,adm,directory=str(seed.root),signature_directory=str(auth.signatures),
            observation_root=str(seed.installation.probe.root),key_binding=auth.binding(auth.key),key_ref='synthetic-attestor-key')
        attested=issue.attested_component(lease,managed,issuance)
        scope=sequence.sequence_scope(lease,attested,directory=seed.start.sequence_scope['journalDirectory'])
        intent={'creationRequestHash':w.request_hash,'nodeRecipeHash':m.digest(rr),
            'leaseInstallationScopeHash':m.digest(start),'priorEvidencePhase':'INSTALL_AUTHENTICATED_TRANSPORT'}
        phases=m.decode(w.raw)['phaseIntentHashes'];phases[m.PHASE]=m.digest(intent)
        child,raw=auth.child(creation_request_hash=w.request_hash,phase_intent_hashes=phases)
        w.child,w.raw,w.child_hash=child,raw,hashlib.sha256(raw).hexdigest()
        row=w.transition.read();row['transitionAuthorityEvidenceHash']=w.child_hash
        for effect in row['effects']:effect.update(authorityEvidenceHash=w.child_hash,intentHash=phases[effect['phase']])
        w.transition.read=lambda:copy.deepcopy(row)
        auth.review['components'].update(providerInstallation=component,
            operationalLeaseInstallation=sequence.sequenced_component(lease,attested,scope))
        parent=auth.fixture();w.parent=parent;w.parent_hash=parent.sha
        creation=native.m.ProviderCreation(parent=parent,window=w,template=prior.creation.template,
            journal_directory=prior.creation.root,installation_component=component)
        issuer=native.m.ProviderInitialIssuer(creation=creation,scope=ps,signers=prior.issuer.signers)
        publication=native.m.ProviderProfilePublication(issuer)
        reader=native.m.MaterializedProviderAdmission(publication=publication,lease_template=lease)
        journal=native.m.PrivateJournal(Path(prep['coordinationJournal']))
        coordinator=native.m.Coordinator(native.m.LeaseOwner(prep['kernel'],prep['dns'],prior.coordinator.owner.backend),
            prep['coordinationBinding'],lambda:native.m.hold_common_lock(Path(prep['lockFile'])),journal.read,journal.write)
        runtime=native.m.ProviderRuntimeInstallation(publication=publication,admission=reader,scope=rs,coordinator=coordinator)
        node=object.__new__(m.DiscoveryNodeOwner);node.engine=creation.engine;node.request=w.request;node.recipe=rr
        node.signer=issuer.signers['live'];node.authority=child;node.raw=raw;node.transition=w.transition;node.store=w.store
        node.adapter=None;node.verify_retained=lambda:{'syntheticCurrentRegistryAdmission':True}
        Path(c['commonInvocationLock']).unlink()
        capsule=old['files'][t['installationRoot']+'/capsule.py'][1]
        factory=m.WorkerMaterialization(node_owner=node,provider=reader,signer=issuer.signers['live'],capsule=capsule,
            installation_sources={public_policy['path']:auth.policy.read_bytes()})
        self.assertFalse(os.path.lexists(creation.journal.record))
        self.assertFalse((factory.root/'materialization-claim.json').exists())
        original=creation.engine.request
        def dispatch(method,path,body=None):
            if method=='POST' and path.endswith('/start'):
                calls.append((method,path,None));state['native']['State'].update(Status='running',Running=True,Pid=os.getpid())
                native.admissions.Admission().admit(reader,auth,native.m.NativeBackend.generation(None,os.getpid()))
                return 204,None
            return original(method,path,body)
        creation.engine.request=dispatch
        provider_phase=ProviderInstallationPhase(runtime)
        try:provider_phase.apply()
        except Exception as error:
            tb=error.__traceback__
            while tb is not None:
                if tb.tb_frame.f_code.co_name=='drive':
                    left=tb.tb_frame.f_locals.get('expected');right=tb.tb_frame.f_locals.get('row')
                    def changed(a,b,path=''):
                        if type(a) is dict and type(b) is dict:
                            return [v for key in sorted(set(a)|set(b)) for v in changed(a.get(key),b.get(key),path+'/'+str(key))]
                        if type(a) is list and type(b) is list:
                            return [v for i in range(max(len(a),len(b))) for v in changed(a[i] if i<len(a) else None,b[i] if i<len(b) else None,path+'/'+str(i))]
                        return [] if a==b else [path]
                    print('CI_PROVIDER_SEQUENCE_DIFFERING_FIELDS='+repr(changed(left,right)),flush=True)
                    def summary(value):
                        return {k:value[k] for k in ('version','state','stageIndex')}|{'effects':len(value['effects'])}
                    print('CI_PROVIDER_SEQUENCE_RECORD_PROGRESS='+repr({'expected':summary(left),
                        'observed':summary(right),'retained':summary(provider_phase.read())}),flush=True)
                tb=tb.tb_next
            raise
        retained=Path(prep['coordinationJournal']).read_bytes()
        material=publication.material();registry=creation.engine.inspect(w.transition)
        # Complete the explicitly modeled Registry metadata for the later
        # worker adapter. The preceding gate fixture intentionally used only
        # its minimal process/binding fields; no native fact is inferred.
        registry.update(Id=registry['binding']['containerId'],Image=w.request['Image'],
            Config={'syntheticRegistryConfiguration':True},HostConfig={'synthetic':True},Mounts=[],NetworkSettings={})
        registry['State'].update(Pid=registry['binding']['pid'],StartedAt='synthetic-registry-generation')
        creation.engine.inspect=lambda _:copy.deepcopy(registry)
        snapshot=copy.deepcopy(old['proposal']['nativeObservation']);snapshot['desiredProfileHash']=c['desiredProfileHash']
        registry_hash=native.profiles.m.registry_identity(creation,ps)['applicationHash']
        snapshot['profiles']={'registry':{**profiles['registry'],'applicationHash':registry_hash},
            'provider':{**profiles['provider'],'applicationHash':material['materialized']['applicationHash']}}
        snapshot['peers']['registry'].update(containerId=registry['Id'],imageId=registry['Image'],
            dockerBindingHash=m.digest({k:registry[k] for k in m.DOCKER_FIELDS}),pid=registry['State']['Pid'],startedAt=registry['State']['StartedAt'])
        generation=native.m.NativeBackend.generation(None,os.getpid())
        snapshot['peers']['provider'].update(containerId=creation.owned_id(),imageId=creation.template['expectedImageId'],
            pid=generation['pid'],startTicks=generation['startTicks'],namespace={'path':'/run/docker/netns/synthetic','identity':[1,generation['namespaceInode']]})
        snapshot['nativeProfileHash']=m.digest(snapshot['profiles']);snapshot['generationRef']=generation_reference(snapshot)
        row.update(state='IN_FLIGHT',nextPhase=8,effects=[{'phase':p,'state':'APPLIED' if i<8 else 'IN_FLIGHT',
            'intentHash':phases[p],'authorityEvidenceHash':w.child_hash,'nativeEvidenceHash':'9'*64} for i,p in enumerate(m.PHASES[:9])])
        node.adapter=types.SimpleNamespace(request={'applicationHash':registry_hash})
        with (patch.object(factory,'capture_native',return_value=snapshot),patch.object(m,'boot_id',return_value=snapshot['bootId']),
                patch.object(m.LeaseRegistration,'apply',side_effect=TimeoutError('MODELED_MANAGER_BOUNDARY')),
                self.assertRaises(TimeoutError)):
            factory.apply(intent)
        self.assertEqual(Path(prep['coordinationJournal']).read_bytes(),retained)
        self.assertNotEqual(Path(r['coordinationJournal']),Path(prep['coordinationJournal']))
        self.assertEqual(m.private_json(r['coordinationJournal'])['state'],'QUIESCED')
        self.assertEqual(sum(method=='POST' and path.endswith('/start') for method,path,_ in calls),1)

if __name__=='__main__':unittest.main()
