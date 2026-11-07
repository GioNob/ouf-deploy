"""Reproduce actual old failure before reconciling; no mocked successor success.

Protected FS metadata are real. Initial unit Engine and process pins modeled;
production reconciliation has no Engine call or file-content path.
"""
import copy,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_mount_intake as fixture
from tools.m2_discovery_installation_profile import retained_readonly_hashes as previous
from tools.m2_discovery_installation_profile import retained_hash_reconciliation as m


class Reconcile(unittest.TestCase):
    def prepared(self,change='write'):
        case=fixture.Intake();self.addCleanup(case.doCleanups);box={}
        def ready(root,mounted):
            (mounted/'credential').chmod(0o600)
            folder=root/'gateway-source';folder.mkdir(mode=0o700)
            (folder/'credential').write_bytes(b'OLD_PRIVATE_TOKEN_VALUE');(folder/'credential').chmod(0o600)
            box['folder']=folder;box['root']=root
        def select(seed):
            row=next(row for row in seed['observations'].values() if row['Name']=='/ouf-gateway-operational-owner')
            row['Mounts'][0]['Source']=str(box['folder'])
            row['Config']['Env'].append('OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/run/input/credential')
        capture,args,seed,root,_,reads,candidate,receipt,bindings,_=case.prepared(before_capture=ready,seed_transform=select)
        selected={'candidatePath':str(capture.scope/'retained-mounts.private.json'),
            'resultPath':str(capture.scope/'result.json'),'seedPath':str(args['seed_path']),
            'candidateHash':bindings['candidate_hash'],'resultHash':bindings['result_hash'],
            'seedHash':bindings['seed_hash'],'failedScope':str(args['predecessor_root'])}
        for mod,values in ((previous,{'CASE':selected,'ROSTER':bindings['roster'],
            'RetainedEngine':args['engine_factory'],'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}),):
            for name,value in values.items():
                context=patch.object(mod,name,value);context.start();self.addCleanup(context.stop)
        failed_scope=root/'failed-hashes';c=previous.ReadonlyHashPreparation(failed_scope)
        file=box['folder']/'credential'
        if change=='rotate':
            replace=root/'replacement';replace.write_bytes(b'NEW_PRIVATE_TOKEN_VALUE');replace.chmod(0o600);replace.replace(file)
        elif change=='mode':file.chmod(0o400)
        else:file.write_bytes(b'NEW_PRIVATE_TOKEN_VALUE_LONGER')
        with self.assertRaisesRegex(ValueError,'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE'):previous.collect(c)
        self.assertEqual(c.counts['engineGets'],2);self.assertEqual(c.counts['readonlyFileBytesHashed'],0)
        failed={'schema':'ouf.retained-readonly-hash-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE','scopeConsumed':True,
            'counts':{k:c.counts[k] for k in previous.PUBLIC_COUNTS},'automaticReplayAllowed':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        c.put('result.json',failed)
        for name,value in {'CASE':selected,'ROSTER':bindings['roster'],'FAILED_SCOPE':failed_scope,
            'FAILED_HASH':m.digest(failed),'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}.items():
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        reconciler=m.Reconciliation(root/'reconciliation');reads.clear()
        return reconciler,root,box['folder'],reads,selected,failed_scope,args

    def test_exact_frozen_failure_then_redacted_metadata_only_deltas_no_engine_or_contents(self):
        c,_,folder,reads,selected,failed_scope,_=self.prepared()
        history={str(p):p.read_bytes() for d in (failed_scope,Path(selected['candidatePath']).parent,Path(selected['failedScope'])) for p in d.iterdir()}
        opened={};original_open=os.open;original_dup=os.dup
        allowed={str(failed_scope/'result.json'),str(failed_scope/'readonly-hash-preparation.claim.json'),
            selected['candidatePath'],selected['resultPath'],selected['seedPath']}
        def closed(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened else None)
            if not flags&(os.O_PATH|os.O_DIRECTORY|os.O_WRONLY|os.O_RDWR):self.assertIn(resolved,allowed)
            fd=original_open(path,flags,*a,**kw)
            if resolved is not None:opened[fd]=resolved
            return fd
        def duplicate(fd):
            result=original_dup(fd)
            if fd in opened:opened[result]=opened[fd]
            return result
        with patch.object(os,'open',side_effect=closed),patch.object(os,'dup',side_effect=duplicate),\
             patch.object(previous,'RetainedEngine',side_effect=AssertionError('NO_ENGINE_IN_RECONCILIATION')):
            result=m.collect(c)
        self.assertFalse(reads);self.assertEqual(result['counts']['engineGets'],0)
        self.assertEqual(result['counts']['mountedFileContentBytesRead'],0);self.assertEqual(result['cumulativeDirectEngineGets'],22)
        self.assertEqual(result['role'],'gateway-owner');self.assertFalse(result['currentContainerConfigurationFreshlyObserved'])
        token=[d for d in result['differences'] if d['configuredReferenceClass']=='EXPLICIT_TOKEN_PATH_REFERENCE']
        self.assertEqual(len(token),1);self.assertEqual(token[0]['category'],'SIZE_OR_TIME_CHANGED')
        self.assertIn('mtimeNs',token[0]['changedMetadataFields'])
        text=json.dumps(result)
        for sentinel in (str(folder),'credential','PRIVATE_TOKEN_VALUE','NEVER_READ','relativePath'):
            self.assertNotIn(sentinel,text)
        self.assertTrue(result['currentDiffIsNotHistoricalFailureTrace']);self.assertFalse(result['hashPreparationRearmed'])
        self.assertEqual(history,{p:Path(p).read_bytes() for p in history})
        self.assertEqual((c.scope/'reconciliation.private.json').stat().st_mode&0o777,0o600)

    def test_rotation_and_permission_drift_reported_without_accepting_new_custody(self):
        for change in ('rotate','mode'):
            c,_,_,_,_,_,_=self.prepared(change);result=m.collect(c)
            leaf=[d for d in result['differences'] if d['configuredReferenceClass']=='EXPLICIT_TOKEN_PATH_REFERENCE'][0]
            self.assertEqual(leaf['category'],'KIND_OR_CUSTODY_CHANGED')
            self.assertIn('inode' if change=='rotate' else 'typeAndMode',leaf['changedMetadataFields'])
            self.assertFalse(result['permissionOrContentPolicyEstablished']);self.assertFalse(result['targetApplyAuthorized'])

    def test_deleted_added_symlink_and_hardlink_metadata_are_reported_without_following(self):
        for change in ('delete','add','symlink','hardlink'):
            c,root,folder,_,_,_,_=self.prepared();leaf=folder/'credential'
            if change=='delete':leaf.unlink()
            elif change=='add':(folder/'new').write_text('NEVER_READ_NEW')
            elif change=='symlink':leaf.unlink();leaf.symlink_to(root/'must-not-follow')
            else:os.link(leaf,folder/'alias')
            result=m.collect(c);self.assertGreater(result['changedNodes'],0)
            private=json.loads((c.scope/'reconciliation.private.json').read_bytes())
            raw=json.dumps(private)
            self.assertNotIn('NEVER_READ_NEW',raw)
            if change=='symlink':self.assertTrue(any(d['currentKind']=='SYMLINK' for d in result['differences']))
            if change=='hardlink':self.assertTrue(any('linkCount' in d['changedMetadataFields'] for d in result['differences']))

    def test_changed_or_missing_predecessor_unknown_output_and_hash_mismatch_deny(self):
        for change in ('result','claim','extra','candidate'):
            c,_,_,_,selected,failed_scope,_=self.prepared()
            if change=='result':(failed_scope/'result.json').write_bytes(b'{}')
            elif change=='claim':(failed_scope/'readonly-hash-preparation.claim.json').write_bytes(b'{}')
            elif change=='extra':(failed_scope/'readonly-content-hashes.private.json').write_text('{}')
            else:Path(selected['candidatePath']).write_bytes(b'{}')
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):m.collect(c)
            self.assertFalse((c.scope/'reconciliation.private.json').exists())

    def test_process_or_boot_change_and_consumed_diagnostic_cannot_rearm_hashing(self):
        for change in ('pin','boot'):
            c,_,_,_,_,_,args=self.prepared()
            if change=='pin':
                context=patch.object(m,'process_pin',lambda pid:{'pid':pid,'changed':True});context.start();self.addCleanup(context.stop)
            else:args['boot_path'].write_text('changed-boot')
            with self.assertRaises(ValueError):m.collect(c)
            with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.Reconciliation(c.scope)

    def test_limits_and_mutable_roots_are_never_enumerated_as_readonly_trees(self):
        c,root,_,_,_,_,_=self.prepared()
        (root/'mutable/unread').write_text('NEVER_READ_MUTABLE')
        tree=c.current_node(root/'mutable',walk=False)
        self.assertNotIn('children',tree)
        with patch.dict(m.PROFILE,maximumNodes=c.counts['reconciliationNodes']),self.assertRaises(ValueError):m.collect(c)
        self.assertFalse((c.scope/'reconciliation.private.json').exists())

    def test_default_public_failure_case_is_exact_and_production_has_no_override(self):
        data=json.loads((ROOT/'evidence/m2-retained-readonly-hashes-target-stop-20261101.json').read_text())
        self.assertEqual(m.digest(data['receipt']),'a7a7601c5f78dd55ad43839c588cddaded3a61471517dbf6b7917ffbfd9f4319')
        c,*_=self.prepared()
        with self.assertRaises(TypeError):m.collect(c,role='other')
        with self.assertRaises(TypeError):m.collect(c,engine_factory=lambda:None)


if __name__=='__main__':unittest.main()
