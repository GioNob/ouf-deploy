"""Real old capture, failed hash and reconciliation feed the new static input.

Unit Engine and process pins are modeled. Actual 25/4/33 filesystem shape,
token replacement, SQLite WAL writer, FD allowlist and adversarial custody.
"""
import copy,json,os,sqlite3,sys,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
import test_m2_retained_mount_intake as fixture
from retained_lifecycle_layout import layout,rotate
from tools.m2_discovery_installation_profile import retained_static_custody as m
from tools.m2_discovery_installation_profile import retained_readonly_hashes as old
from tools.m2_discovery_installation_profile import retained_hash_reconciliation as recon
from tools.m2_discovery_installation_profile import retained_mount_lifecycle as life
from tools.m2_discovery_installation_profile import current_retained_mounts as current


class StaticInput(unittest.TestCase):
    def prepared(self,change_layout=None):
        case=fixture.Intake();self.addCleanup(case.doCleanups);box={}
        def ready(root,mounted):box['layout']=layout(root)
        def select(seed):
            mounts,*_=box['layout']
            for row in seed['observations'].values():
                role=row['Name'].removeprefix('/ouf-')
                if role=='gateway-operational-owner':role='gateway-owner'
                if role in mounts:row['Mounts']=copy.deepcopy(mounts[role])
            if change_layout:change_layout(seed,box['layout'])
        capture,args,seed,root,_,reads,candidate,receipt,bindings,_=case.prepared(before_capture=ready,seed_transform=select)
        selected={'candidatePath':str(capture.scope/'retained-mounts.private.json'),
            'resultPath':str(capture.scope/'result.json'),'seedPath':str(args['seed_path']),
            'candidateHash':bindings['candidate_hash'],'resultHash':bindings['result_hash'],
            'seedHash':bindings['seed_hash'],'failedScope':str(args['predecessor_root'])}
        mounts,auth,database,keys=box['layout']
        for name,value in {'CASE':selected,'ROSTER':bindings['roster'],'RetainedEngine':args['engine_factory'],
            'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}.items():
            context=patch.object(old,name,value);context.start();self.addCleanup(context.stop)
        failed=old.ReadonlyHashPreparation(root/'failed-hashes');rotate(auth['gateway'])
        db=sqlite3.connect(database);db.execute('update fixture set value=value+1');db.commit();db.close()
        with self.assertRaisesRegex(ValueError,'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE'):old.collect(failed)
        self.assertEqual(failed.counts['engineGets'],2);self.assertFalse(failed.hashes)
        failure={'schema':'ouf.retained-readonly-hash-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE','scopeConsumed':True,
            'counts':{k:failed.counts[k] for k in old.PUBLIC_COUNTS},'automaticReplayAllowed':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        failed.put('result.json',failure)
        values={'CASE':selected,'ROSTER':bindings['roster'],'FAILED_SCOPE':failed.scope,'FAILED_HASH':m.digest(failure),
            'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}
        with ExitStack() as contexts:
            for name,value in values.items():contexts.enter_context(patch.object(recon,name,value))
            reconciler=recon.Reconciliation(root/'reconciliation');result=recon.collect(reconciler);reconciler.put('result.json',result)
        record=json.loads((reconciler.scope/'reconciliation.private.json').read_bytes())
        newcase={**selected,'reconciliationScope':str(reconciler.scope),'reconciliationCandidateHash':m.digest(record),
            'reconciliationResultHash':m.digest(result),'failedHashScope':str(failed.scope),'failedHashResultHash':m.digest(failure)}
        for name,value in {'CASE':newcase,'ROSTER':bindings['roster'],'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}.items():
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        reads.clear();return m.StaticCustody(root/'static-custody'),root,auth,database,keys,reads,newcase,candidate,args

    def test_target_shape_rotations_and_live_sqlite_writes_do_not_read_live_members_or_engine(self):
        c,root,auth,database,keys,reads,case,candidate,_=self.prepared()
        self.assertEqual(life.plan(candidate['peers'],exact_static_input=True)[1],
            {'readonly':25,'mutable':4,'tokens':7,'stores':1,'staticRegularMounts':17,'nodes':33})
        for path in auth.values():rotate(path)
        db=sqlite3.connect(database);self.addCleanup(db.close);db.execute('update fixture set value=value+1');db.commit()
        history={str(p):p.read_bytes() for d in (Path(case['failedScope']),Path(case['candidatePath']).parent,
            Path(case['failedHashScope']),Path(case['reconciliationScope'])) for p in d.iterdir()}
        opened={};original_open=os.open;original_dup=os.dup;content=[]
        allowed={str(p) for p in keys.values()}|{case['candidatePath'],case['resultPath'],case['seedPath'],
            str(Path(case['failedScope'])/'result.json'),str(Path(case['failedHashScope'])/'result.json'),
            str(Path(case['failedHashScope'])/'readonly-hash-preparation.claim.json'),
            str(Path(case['reconciliationScope'])/'result.json'),str(Path(case['reconciliationScope'])/'reconciliation.private.json')}
        def closed(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened else None)
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):self.assertIn(resolved,allowed);content.append(resolved)
            fd=original_open(path,flags,*a,**kw)
            if resolved is not None:opened[fd]=resolved
            return fd
        def duplicate(fd):
            value=original_dup(fd)
            if fd in opened:opened[value]=opened[fd]
            return value
        with patch.object(os,'open',side_effect=closed),patch.object(os,'dup',side_effect=duplicate),\
             patch.object(old,'RetainedEngine',side_effect=AssertionError('NO_ENGINE')),\
             patch.object(sqlite3,'connect',side_effect=AssertionError('NO_SQLITE_IN_COLLECTOR')):
            result=m.collect(c)
        self.assertFalse(reads);self.assertEqual(result['counts']['engineGets'],0)
        self.assertEqual(result['cumulativeDirectEngineGets'],22);self.assertEqual(result['cumulativeControlAttempts'],5)
        self.assertEqual(result['counts']['readonlyRegularFilesHashed'],13)
        self.assertEqual(set(c.hashes),{str(p) for p in keys.values()})
        self.assertTrue(result['allFourPriorScopesPreserved']);self.assertFalse(result['currentContainerConfigurationFreshlyObserved'])
        self.assertFalse(result['liveMembersObservedOrAdmitted']);self.assertFalse(result['expectedPermissionOrContentPolicyEstablished'])
        self.assertFalse(result['completePrivateCustodyProven']);self.assertFalse(result['targetApplyAuthorized'])
        self.assertEqual(history,{p:Path(p).read_bytes() for p in history})
        raw=(c.scope/'static-custody.private.json').read_text()+json.dumps(result)
        for value in ('SYNTHETIC_STATIC_PRIVATE_VALUE','SYNTHETIC_LIVE_TOKEN','SYNTHETIC_MUTABLE_DATA'):self.assertNotIn(value,raw)
        self.assertNotIn(str(root),json.dumps(result).replace(str(c.scope),''))

    def test_static_replacement_mode_content_link_and_hardlink_fail_before_hash_candidate(self):
        for kind in ('replace','mode','content','link','hardlink'):
            c,root,_,_,keys,*_=self.prepared();path=keys['gateway-key']
            if kind=='replace':
                temp=root/'replacement';temp.write_bytes(path.read_bytes());temp.chmod(0o600);temp.replace(path)
            elif kind=='mode':path.chmod(0o400)
            elif kind=='content':path.write_bytes(b'CHANGED_STATIC')
            elif kind=='link':path.unlink();path.symlink_to(root/'must-not-read')
            else:os.link(path,root/'hardlink')
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):m.collect(c)
            self.assertFalse(c.hashes);self.assertFalse((c.scope/'static-custody.private.json').exists())

    def test_live_root_custody_change_is_not_accepted_as_token_renewal(self):
        for kind in ('mode','inode','symlink'):
            c,root,auth,*_=self.prepared();path=auth['gateway']
            if kind=='mode':path.chmod(0o700)
            elif kind=='inode':path.rename(root/'old-auth');path.mkdir(mode=0o750);os.chown(path,0,0)
            else:path.rename(root/'old-auth');path.symlink_to(root/'old-auth')
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):m.collect(c)
            self.assertFalse(c.hashes)

    def test_unknown_directory_and_live_or_mutable_alias_are_refused_before_content(self):
        def unknown(seed,layout):
            for row in seed['observations'].values():
                if row['Name']=='/ouf-keycloak':row['Mounts']=[{'Type':'bind','Source':str(layout[1]['gateway']),'Destination':'/unclassified','RW':False}]
        c,*_=self.prepared(unknown)
        with self.assertRaisesRegex(ValueError,'UNCLASSIFIED_READONLY_DIRECTORY'):m.collect(c)
        self.assertFalse(c.hashes)
        def live_alias(seed,layout):
            for row in seed['observations'].values():
                if row['Name']=='/ouf-onboarding':row['Mounts'][-1]['Source']=str(layout[1]['gateway']/'token')
        c,*_=self.prepared(live_alias)
        with self.assertRaisesRegex(ValueError,'OVERLAPS_CAPTURED_MUTABLE_SOURCE'):m.collect(c)
        self.assertFalse(c.hashes)
        for kind in ('live','mutable'):
            c,_,auth,_,keys,*_=self.prepared()
            excluded=auth['gateway'] if kind=='live' else keys['gateway-key'].parent
            c.mutable_sources=[(excluded,m.attrs(excluded.stat()))]
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'OVERLAPS_CAPTURED_MUTABLE_SOURCE'):
                c.hash_file(auth['gateway']/'token' if kind=='live' else keys['gateway-key'],
                    m.attrs((auth['gateway']/'token' if kind=='live' else keys['gateway-key']).stat()))
            self.assertFalse(c.hashes)

    def test_changed_history_process_scope_or_binding_denies_without_content_or_replay(self):
        for kind in ('receipt','private','history','pin','case'):
            c,_,_,_,_,reads,case,_,_=self.prepared()
            if kind in ('receipt','private'):
                (Path(case['reconciliationScope'])/('result.json' if kind=='receipt' else 'reconciliation.private.json')).write_text('{}')
            elif kind=='history':(Path(case['failedHashScope'])/'extra').touch()
            elif kind=='pin':
                context=patch.object(m,'process_pin',lambda pid:{'pid':pid,'changed':True});context.start();self.addCleanup(context.stop)
            else:m.CASE['reconciliationCandidateHash']='0'*64
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):m.collect(c)
            self.assertFalse(c.hashes);self.assertFalse(reads)
            with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.StaticCustody(c.scope)
        with self.assertRaises(TypeError):m.collect(c,engine_factory=lambda:None)

    def test_current_metadata_witness_excludes_live_descendants_but_keeps_static_and_root_guards(self):
        c,_,auth,database,_,_,_,candidate,_=self.prepared()
        def observe():
            from tools.m2_discovery_installation_profile.node_owner import ObservationBudget
            scanner=current.MetadataObservation(ObservationBudget(90))
            return {role:life.observe_mounts(scanner,role,peer['mounts']) for role,peer in sorted(candidate['peers'].items())}
        before=observe()
        for path in auth.values():rotate(path)
        db=sqlite3.connect(database);db.execute('update fixture set value=value+1');db.commit();db.close()
        self.assertEqual(before,observe())
        # An unsafe live member is deliberately UNOBSERVED here, not admitted.
        (auth['gateway']/'token').chmod(0o666)
        self.assertEqual(before,observe())


if __name__=='__main__':unittest.main()
