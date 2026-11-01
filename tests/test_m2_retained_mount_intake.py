"""Consume actual frozen producer outputs, never a hand-written lookalike.

Real protected metadata/FIFO and create-once corrective capture; unit Engine
and process pins modeled. Native suite separately uses real Docker/proc/socket.
"""
import copy,json,os,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from contextlib import ExitStack
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_selected_runtime # retained dependency import setup
import test_m2_retained_mount_role_correction as capture_fixture
from tools.m2_discovery_installation_profile import retained_mount_role_correction as producer
from tools.m2_discovery_installation_profile import retained_mount_intake as m
from tools.m2_discovery_installation_profile import current_retained_mounts as current

COMMON=dict(zip(m.COMMON,('a'*64,'b'*64,'c'*64,'d'*64)))


class Intake(unittest.TestCase):
    def prepared(self,*,before_capture=None,seed_transform=None):
        case=capture_fixture.RoleCorrection();self.addCleanup(case.doCleanups)
        c,args,seed,root,mounted,reads,aliases=case.prepared()
        seed['bootId']='11111111-1111-1111-1111-111111111111';args['boot_path'].write_text(seed['bootId'])
        for role,alias in aliases.items():
            row=seed['observations'][alias]
            row['Name']='/ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role)
            if role=='semantic':row['Name']='/ouf-semantic-cutover-'+'a'*64
        if before_capture is not None:before_capture(root,mounted)
        if seed_transform is not None:seed_transform(seed)
        args['seed_path'].write_bytes(m.encoded(seed));args['seed_hash']=m.digest(seed)
        args['roster']=capture_fixture.roster_for(seed,aliases)
        result=producer.collect(c,**args);c.put('result.json',result)
        candidate=json.loads((c.scope/'retained-mounts.private.json').read_bytes())
        bindings={'candidate_hash':m.digest(candidate),'result_hash':m.digest(result),
            'seed_hash':m.digest(seed),'roster':copy.deepcopy(args['roster'])}
        return c,args,seed,root,mounted,reads,candidate,result,bindings,aliases

    def observer(self):
        c,args,seed,root,mounted,reads,candidate,result,bindings,aliases=self.prepared()
        proposal=m.runtime_proposal(candidate,result,seed,COMMON,**bindings)
        runtime=object.__new__(current.CurrentCohortRuntime);runtime.inputs=proposal['runtimeInputs']
        runtime.input_hash=m.digest(runtime.inputs);runtime.guard=Mock()
        row={'state':'READY','nextPhase':12,'version':42}
        def held(expected=None):
            if expected is not None and expected!=row:raise ValueError('HELD_HISTORY_CHANGED')
            return copy.deepcopy(row)
        class Selected:pass
        runtime.selected=Selected();runtime.selected.held=held
        # Fixture-only module patch: production constructor exposes no path,
        # hash, roster or callback override for the accepted target capture.
        for name,value in {'CANDIDATE':c.scope/'retained-mounts.private.json',
            'SEED':args['seed_path'],'CANDIDATE_HASH':bindings['candidate_hash'],
            'RESULT_HASH':bindings['result_hash'],'SEED_HASH':bindings['seed_hash'],
            'ROSTER':bindings['roster']}.items():
            context=patch.object(current,name,value);context.start();self.addCleanup(context.stop)
        observer=current.CurrentRetainedMountMetadata(runtime)
        reads.clear()
        return observer,args,root,mounted,reads,seed,candidate,result,bindings,aliases

    def run_observer(self,observer,args,engine_factory=None):
        with ExitStack() as context:
            context.enter_context(patch.object(current,'RetainedEngine',engine_factory or args['engine_factory']))
            context.enter_context(patch.object(current,'process_pin',args['pin']))
            context.enter_context(patch.object(current,'BOOT_PATH',args['boot_path']))
            return observer.observe()

    def test_production_observer_exposes_no_input_or_engine_callback_override(self):
        observer,args,*_=self.observer()
        with self.assertRaises(TypeError):current.CurrentRetainedMountMetadata(observer.runtime,candidate_hash='f'*64)
        with self.assertRaises(TypeError):observer.observe(engine_factory=args['engine_factory'])

    def test_actual_producer_record_is_intaken_with_explicit_independent_review_hashes(self):
        _,_,seed,_,_,_,candidate,result,bindings,aliases=self.prepared()
        fragment=m.runtime_proposal(candidate,result,seed,COMMON,**bindings)
        self.assertEqual(fragment['runtimeInputs']['sourceClosureHash'],COMMON['sourceClosureHash'])
        self.assertEqual(set(fragment['runtimeInputs']['peers']),m.ROLES)
        self.assertEqual(m.validate_capture(candidate,result,seed,**bindings),aliases)
        for role,alias in aliases.items():
            self.assertEqual(fragment['runtimeInputs']['peers'][role]['runtimeBinding']['containerId'],seed['observations'][alias]['Id'])
        for key in ('expectedMountPolicyEstablished','completeParentReview','completePrivateCustodyProven',
            'runtimeAuthorityIssued','targetApplyAuthorized','applicationE2EProven','releaseAcceptance'):
            self.assertIs(fragment[key],False)

    def test_runtime_binding_preserves_engine_mount_order_and_does_not_reuse_sorted_historical_digest(self):
        _,_,seed,_,_,_,candidate,result,bindings,aliases=self.prepared()
        fragment=m.runtime_proposal(candidate,result,seed,COMMON,**bindings)
        from engine_creation import Engine
        row=seed['observations'][aliases['onboarding']]
        binding=fragment['runtimeInputs']['peers']['onboarding']['runtimeBinding']
        self.assertEqual(binding,Engine.runtime_binding(row))
        self.assertNotEqual(binding['mountsHash'],producer.stable_binding(row)['mountsHash'])
        self.assertEqual(producer.stable_binding(row)['mountsHash'],m.digest(sorted(row['Mounts'],key=lambda v:v['Destination'])))

    def test_missing_inferred_or_unknown_common_review_bindings_deny(self):
        _,_,seed,_,_,_,candidate,result,bindings,_=self.prepared()
        for common in ({}, {**COMMON,'sourceClosureHash':None}, {**COMMON,'implicitPolicy':True}):
            with self.assertRaises(ValueError):m.runtime_proposal(candidate,result,seed,common,**bindings)

    def test_hash_count_role_pin_mount_and_policy_forgery_denied(self):
        for kind in ('hash','count','alias','pin','mount','policy'):
            _,_,seed,_,_,_,candidate,result,bindings,_=self.prepared()
            if kind=='hash':bindings['candidate_hash']='0'*64
            elif kind=='count':result['counts']['staticEntries']+=1
            elif kind=='alias':candidate['inventoryRoleMap']['onboarding']='invented'
            elif kind=='pin':candidate['peers']['onboarding']['processPin']['startTicks']+=1
            elif kind=='mount':candidate['peers']['onboarding']['mounts'][0]['destination']='/other'
            else:candidate['observedMetadataIsExpectedPolicy']=True
            # Shape/lineage checks remain meaningful independently of hashes.
            if kind!='hash':bindings.update(candidate_hash=m.digest(candidate),result_hash=m.digest(result))
            if kind in ('alias','pin','mount','policy'):
                result['candidateHash']=m.digest(candidate);bindings['result_hash']=m.digest(result)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.runtime_proposal(candidate,result,seed,COMMON,**bindings)

    def test_public_target_receipt_is_pinned_and_separate_from_source_fixture_evidence(self):
        evidence=json.loads((ROOT/'evidence/m2-retained-mount-role-correction-target-20261101.json').read_text())
        self.assertEqual(m.digest(evidence['receipt']),m.RESULT_HASH)
        self.assertEqual(evidence['receipt']['candidateHash'],m.CANDIDATE_HASH)
        self.assertFalse(evidence['privateCandidateReadByAgent'])
        self.assertTrue(evidence['receipt']['predecessorPreserved'])
        self.assertEqual(evidence['receipt']['counts']['readonlyMounts'],25)
        self.assertEqual(evidence['receipt']['counts']['mutableMounts'],4)

    def test_current_observer_reads_twenty_exact_gets_metadata_only_without_new_scope(self):
        observer,args,root,mounted,reads,*_=self.observer()
        before={str(p.relative_to(root)) for p in root.rglob('*')}
        original_open=os.open;opened_paths={}
        allowed={str(observer.candidate_path),str(observer.candidate_path.parent/'result.json'),str(observer.seed_path)}
        def no_contents(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened_paths[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened_paths else None)
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):self.assertIn(resolved,allowed)
            fd=original_open(path,flags,*a,**kw)
            if resolved is not None:opened_paths[fd]=resolved
            return fd
        with patch.object(os,'open',side_effect=no_contents):
            result=self.run_observer(observer,args)
        self.assertEqual(len(reads),20);self.assertEqual(result['directRetainedEngineGets'],20)
        self.assertTrue(result['currentRetainedMetadataMatchesCapturedCandidate'])
        self.assertFalse(result['newCaptureScopeCreated']);self.assertEqual(result['mountedFileContentBytesRead'],0)
        self.assertFalse(result['expectedMountPolicyEstablished']);self.assertFalse(result['completePrivateCustodyProven'])
        self.assertEqual(before,{str(p.relative_to(root)) for p in root.rglob('*')})
        self.assertNotIn(str(mounted),json.dumps(result));self.assertNotIn('NEVER_READ',json.dumps(result))

    def test_mutable_size_times_or_new_children_are_unobserved_but_inode_or_mode_drift_denied(self):
        observer,args,root,_,_,*_=self.observer()
        (root/'mutable/private-data').write_bytes(b'CHANGED_MUTABLE_DATA')
        (root/'mutable/new-file').write_text('UNOBSERVED')
        result=self.run_observer(observer,args)
        self.assertTrue(result['currentRetainedMetadataMatchesCapturedCandidate'])
        for kind in ('inode','mode'):
            observer,args,root,_,reads,*_=self.observer()
            if kind=='inode':(root/'mutable').rename(root/'old-mutable');(root/'mutable').mkdir(mode=0o700)
            else:(root/'mutable').chmod(0o750)
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'METADATA_DIFFERS'):
                self.run_observer(observer,args)
            self.assertEqual(len(reads),1)

    def test_readonly_static_metadata_change_denied_before_positive_witness(self):
        for kind in ('before','during','new-child','link'):
            observer,args,root,mounted,reads,*_=self.observer();original=args['engine_factory']
            if kind=='before':(mounted/'credential').chmod(0o400)
            elif kind=='new-child':(mounted/'extra').write_text('EXTRA')
            elif kind=='link':(mounted/'credential').unlink();(mounted/'credential').symlink_to(root/'mutable/private-data')
            class Changed(original):
                def get(engine,cid):
                    value=super().get(cid)
                    if kind=='during' and engine.c.counts['engineGets']==11:(mounted/'credential').chmod(0o400)
                    return value
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):
                self.run_observer(observer,args,Changed)
            self.assertLessEqual(len(reads),20)

    def test_parent_runtime_capture_or_reference_drift_denied_without_engine_contact(self):
        for kind in ('runtime','config','input','reference','root'):
            observer,args,_,_,reads,*_=self.observer()
            if kind=='runtime':observer.runtime_id+=1
            elif kind=='config':observer.runtime.inputs['peers']['onboarding']['runtimeBinding']['mountsHash']='0'*64
            elif kind=='input':observer.candidate_path.write_bytes(b'{}')
            elif kind=='reference':observer.bindings['candidate_hash']='0'*64
            else:observer.runtime.inputs['rootProcessPins']['engine']['startTicks']+=1
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):
                self.run_observer(observer,args)
            self.assertFalse(reads)

    def test_process_drift_socket_failure_and_configuration_drift_never_retry_or_repair(self):
        for kind in ('pin','network','config'):
            observer,args,_,_,reads,*_=self.observer();original=args['engine_factory']
            if kind=='pin':args['pin']=lambda pid:{'pid':pid,'changed':True}
            class Changed(original):
                def get(engine,cid):
                    if kind=='network':reads.append(cid);raise TimeoutError('fixture')
                    value=super().get(cid)
                    if kind=='config':value['Config']['Env']=['CHANGED']
                    return value
            with self.subTest(kind=kind),self.assertRaises((ValueError,TimeoutError)):
                self.run_observer(observer,args,Changed)
            self.assertLessEqual(len(reads),1)


if __name__=='__main__':unittest.main()
