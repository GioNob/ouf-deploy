"""Actual five-stage producer records feed static intake/current byte continuity.

FS/hash/rotation/WAL are real; parent authority, Engine and process pins are
fixtures. No test calls a positive flag a complete native/target admission.
"""
import copy,json,os,sqlite3,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from contextlib import ExitStack
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_static_custody as fixture
from retained_lifecycle_layout import rotate
from tools.m2_discovery_installation_profile import retained_static_intake as intake
from tools.m2_discovery_installation_profile import retained_static_custody as prep
from tools.m2_discovery_installation_profile import retained_mount_intake as old
from tools.m2_discovery_installation_profile import current_retained_mounts as metadata
from tools.m2_discovery_installation_profile import current_retained_static as m


class StaticIntake(unittest.TestCase):
    def prepared(self):
        case=fixture.StaticInput();self.addCleanup(case.doCleanups)
        c,root,auth,database,keys,reads,selected,capture,args=case.prepared()
        result=prep.collect(c);c.put('result.json',result)
        record=json.loads((c.scope/'static-custody.private.json').read_bytes())
        seed=json.loads(Path(selected['seedPath']).read_bytes());receipt=json.loads(Path(selected['resultPath']).read_bytes())
        proposal=old.runtime_proposal(capture,receipt,seed,dict(zip(old.COMMON,('a'*64,'b'*64,'c'*64,'d'*64))),
            candidate_hash=selected['candidateHash'],result_hash=selected['resultHash'],seed_hash=selected['seedHash'],roster=prep.ROSTER)
        runtime=object.__new__(metadata.CurrentCohortRuntime);runtime.inputs=proposal['runtimeInputs']
        runtime.input_hash=m.digest(runtime.inputs);runtime.guard=Mock()
        row={'state':'READY','nextPhase':12,'version':42}
        class Selected:
            def held(self,expected=None):
                if expected is not None and expected!=row:raise ValueError('HELD_HISTORY_CHANGED')
                return copy.deepcopy(row)
        runtime.selected=Selected()
        for mod,values in ((metadata,{'CANDIDATE':Path(selected['candidatePath']),'SEED':Path(selected['seedPath']),
            'CANDIDATE_HASH':selected['candidateHash'],'RESULT_HASH':selected['resultHash'],
            'SEED_HASH':selected['seedHash'],'ROSTER':prep.ROSTER}),
            (m,{'CANDIDATE':c.scope/'static-custody.private.json','CANDIDATE_HASH':m.digest(record),
                'RESULT_HASH':m.digest(result),'CASE':selected,'BOOT_PATH':args['boot_path'],'process_pin':args['pin']})):
            for name,value in values.items():
                context=patch.object(mod,name,value);context.start();self.addCleanup(context.stop)
        mounts=metadata.CurrentRetainedMountMetadata(runtime);observer=m.CurrentRetainedStaticBytes(mounts)
        reads.clear();return observer,record,result,capture,root,auth,database,keys,reads,selected,args,row

    def test_real_producer_input_exact_allowlist_and_current_bytes_without_engine_new_scope_or_live_reads(self):
        observer,record,result,capture,root,auth,database,keys,reads,case,_,_=self.prepared()
        classes,files=intake.validate_static(record,result,capture,candidate_hash=m.digest(record),result_hash=m.digest(result),case=case)
        self.assertEqual(set(files),{str(p) for p in keys.values()})
        for path in auth.values():rotate(path)
        db=sqlite3.connect(database);self.addCleanup(db.close);db.execute('update fixture set value=value+1');db.commit()
        before={str(p):p.stat().st_ino for p in root.rglob('*')}
        opened={};original_open=os.open;original_dup=os.dup
        allowed={str(p) for p in keys.values()}|{case['candidatePath'],case['resultPath'],case['seedPath'],
            str(observer.path),str(observer.path.parent/'result.json'),str(observer.path.parent/'static-custody.claim.json')}
        def closed(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened else None)
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):self.assertIn(resolved,allowed)
            fd=original_open(path,flags,*a,**kw)
            if resolved is not None:opened[fd]=resolved
            return fd
        def duplicate(fd):
            value=original_dup(fd)
            if fd in opened:opened[value]=opened[fd]
            return value
        with patch.object(os,'open',side_effect=closed),patch.object(os,'dup',side_effect=duplicate),\
             patch.object(fixture.old,'RetainedEngine',side_effect=AssertionError('NO_ENGINE')):
            proof=observer.observe()
        self.assertEqual(proof['staticFileCount'],13);self.assertTrue(proof['currentStaticFileBytesMatchCapturedCandidate'])
        self.assertEqual(proof['staticFileBytesRead'],sum(p.stat().st_size for p in keys.values()))
        self.assertEqual(proof['directEngineGets'],0);self.assertFalse(reads);self.assertFalse(proof['newCaptureScopeCreated'])
        for field in ('liveMembersObservedOrAdmitted','expectedPermissionOrContentPolicyEstablished','completePrivateCustodyProven',
            'fullCohortProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(proof[field],False)
        self.assertEqual(before,{str(p):p.stat().st_ino for p in root.rglob('*')})
        text=json.dumps(proof)
        for value in ('SYNTHETIC_',str(root),next(iter(files.values()))['sha256']):self.assertNotIn(value,text)

    def test_no_constructor_path_hash_callback_or_engine_override_and_foreign_metadata_rejected(self):
        observer,*_=self.prepared()
        with self.assertRaises(TypeError):m.CurrentRetainedStaticBytes(observer.mounts,candidate_hash='a'*64)
        with self.assertRaises(TypeError):observer.observe(engine_factory=lambda:None)
        with self.assertRaises(ValueError):m.CurrentRetainedStaticBytes(Mock())
        observer.mounts=Mock()
        with self.assertRaises(ValueError):observer.observe()

    def test_shape_lineage_counts_allowlist_permissions_and_live_claim_forgery_denied_even_with_rehashed_fixture(self):
        for kind in ('files','metadata','profile','case','counts','policy','live','boot','lineage'):
            _,record,result,capture,_,_,_,_,_,case,*_=self.prepared()
            if kind=='files':record['files']['/extra']=copy.deepcopy(next(iter(record['files'].values())))
            elif kind=='metadata':next(iter(record['files'].values()))['metadata'][4]+=1
            elif kind=='profile':record['profile']['maximumEngineGets']=1
            elif kind=='case':record['caseHash']='f'*64
            elif kind=='counts':result['counts']['readonlyFileBytesHashed']+=1
            elif kind=='policy':record['expectedPermissionOrContentPolicyEstablished']=True
            elif kind=='live':result['liveMembersObservedOrAdmitted']=True
            elif kind=='boot':record['bootId']='different'
            else:record['rootAndStaticMetadataHash']='f'*64
            result['candidateHash']=m.digest(record)
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):
                intake.validate_static(record,result,capture,candidate_hash=m.digest(record),result_hash=m.digest(result),case=case)

    def test_current_static_content_inode_mode_symlink_hardlink_and_accepted_hash_difference_deny(self):
        for kind in ('content','inode','mode','symlink','hardlink','hash'):
            observer,record,result,_,root,_,_,keys,*_=self.prepared();file=keys['gateway-key']
            if kind=='content':file.write_bytes(b'CHANGED_STATIC')
            elif kind=='inode':
                temp=root/'replacement';temp.write_bytes(file.read_bytes());temp.chmod(0o600);temp.replace(file)
            elif kind=='mode':file.chmod(0o400)
            elif kind=='symlink':file.unlink();file.symlink_to(root/'must-not-read')
            elif kind=='hardlink':os.link(file,root/'alias')
            else:
                record['files'][str(file)]['sha256']='f'*64;observer.path.write_bytes(old.encoded(record))
                result['candidateHash']=m.digest(record);(observer.path.parent/'result.json').write_bytes(old.encoded(result))
                observer.bindings.update(candidateHash=m.digest(record),resultHash=m.digest(result))
                observer.reference_hash=m.digest({'path':str(observer.path),'case':observer.case,**observer.bindings})
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):observer.observe()

    def test_changed_inputs_boot_process_held_history_and_live_root_denied(self):
        for kind in ('input','claim','scope','boot','pin','held','root'):
            observer,_,_,_,_,auth,_,_,_,_,args,row=self.prepared()
            if kind=='input':observer.path.write_text('{}')
            elif kind=='claim':(observer.path.parent/'static-custody.claim.json').write_text('{}')
            elif kind=='scope':(observer.path.parent/'unexpected').touch()
            elif kind=='boot':args['boot_path'].write_text('new-boot')
            elif kind=='pin':
                context=patch.object(m,'process_pin',lambda pid:{'pid':pid});context.start();self.addCleanup(context.stop)
            elif kind=='root':auth['gateway'].chmod(0o700)
            else:
                original=observer.runtime.selected.held;calls=[]
                def changed(expected=None):
                    calls.append(1)
                    if len(calls)==4:row['version']+=1
                    return original(expected)
                observer.runtime.selected.held=changed
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):observer.observe()

    def test_changed_during_actual_content_read_never_returns_positive_proof(self):
        observer,_,_,_,_,_,_,keys,*_=self.prepared();file=keys['gateway-key'];inode=file.stat().st_ino
        original=os.read;changed=[]
        def mutate(fd,amount):
            raw=original(fd,amount)
            if os.fstat(fd).st_ino==inode and not changed:changed.append(True);file.write_bytes(b'CHANGED_WHILE_READING')
            return raw
        with patch.object(os,'read',side_effect=mutate),self.assertRaisesRegex(ValueError,'CHANGED_DURING_HASH_READ'):observer.observe()

    def test_actual_target_receipt_hash_is_pinned_and_not_claimed_as_current_admission(self):
        v=json.loads((ROOT/'evidence/m2-retained-static-custody-target-20261101.json').read_text())
        self.assertEqual(m.digest(v['receipt']),intake.RESULT_HASH);self.assertEqual(v['receipt']['candidateHash'],intake.CANDIDATE_HASH)
        self.assertEqual(v['receipt']['counts']['readonlyRegularFilesHashed'],13)
        self.assertEqual(v['receipt']['counts']['readonlyFileBytesHashed'],3937)
        self.assertFalse(v['privateRecordReadByAgent']);self.assertFalse(v['receipt']['liveMembersObservedOrAdmitted'])


if __name__=='__main__':unittest.main()
