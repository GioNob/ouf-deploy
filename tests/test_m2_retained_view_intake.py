"""Actual six-stage producer records; real file metadata, modeled kernel/proc.

Only the low-level kernel surface and parent authority are modeled. The real
capture writes the private record; native Docker suite separately owns the
actual process namespace/descriptor checks, not these unit fixtures.
"""
import copy,json,os,sqlite3,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_static_intake as fixture
from retained_lifecycle_layout import rotate
from tools.m2_discovery_installation_profile import retained_view_capture as producer
from tools.m2_discovery_installation_profile import retained_view_intake as intake
from tools.m2_discovery_installation_profile import retained_static_custody as static
from tools.m2_discovery_installation_profile import current_retained_views as m


class ViewIntake(unittest.TestCase):
    def prepared(self):
        case=fixture.StaticIntake();self.addCleanup(case.doCleanups)
        static_owner,_,_,capture,root,auth,database,keys,reads,oldcase,args,history=case.prepared()
        selected={**oldcase,'staticCandidatePath':str(static_owner.path),
            'staticCandidateHash':static_owner.bindings['candidateHash'],'staticResultHash':static_owner.bindings['resultHash']}
        peers=capture['peers'];roots={};inodes={};context={'role':None}
        for role,peer in peers.items():
            folder=root/('kernel-root-'+role);folder.mkdir(mode=0o700)
            roots[peer['processPin']['pid']]=folder;inodes[(folder.stat().st_dev,folder.stat().st_ino)]=role
        def mount_id(role,index):return 1000+sorted(peers).index(role)*100+index
        raw_open=os.open
        def kernel_root(path,flags,*a,**kw):
            value=str(path)
            if value.startswith('/proc/') and value.endswith('/root'):
                return raw_open(roots[int(value.split('/')[2])],flags,*a,**kw)
            return raw_open(path,flags,*a,**kw)
        def view(root_fd,target):
            info=os.fstat(root_fd);identity=(info.st_dev,info.st_ino)
            if identity in inodes:
                role=inodes[identity];mount=next(row for row in peers[role]['mounts'] if row['destination']==target)
                return static.RetainedCapture.node(c,Path(mount['source']))
            for peer in peers.values():
                for mount in peer['mounts']:
                    if mount['kind']=='READONLY_METADATA_CANDIDATE' and mount['metadataTree']['kind']=='DIRECTORY':
                        row=mount['metadataTree']['metadata']
                        if tuple(row[:2])==identity:return static.RetainedCapture.node(c,Path(mount['source'])/target.lstrip('/'))
            raise AssertionError('MODELED_KERNEL_VIEW_NOT_DECLARED')
        def read_kernel(path,maximum,budget):
            budget.check();path=str(path)
            if path.endswith('/mountinfo'):
                pid=int(path.split('/')[2]);role=next(r for r,p in peers.items() if p['processPin']['pid']==pid)
                context['role']=role
                lines=['1 1 0:1 / / ro - tmpfs none rw\n']
                for index,mount in enumerate(peers[role]['mounts']):
                    lines.append(f"{mount_id(role,index)} 1 0:2 / {mount['destination']} {'ro' if mount['readOnly'] else 'rw'} - tmpfs none rw\n")
                return ''.join(lines).encode()
            if '/fdinfo/' in path:
                info=os.fstat(int(path.rsplit('/',1)[1]));identity=(info.st_dev,info.st_ino);role=context['role']
                for index,mount in enumerate(peers[role]['mounts']):
                    row=(mount['metadataTree']['metadata'] if mount['kind']=='READONLY_METADATA_CANDIDATE' else mount['metadata'])
                    selected=[row]
                    if mount.get('metadataTree',{}).get('kind')=='DIRECTORY':
                        selected.extend(m.attrs((Path(mount['source'])/name).lstat()) for name in mount['metadataTree']['children'])
                    if any(tuple(frame[:2])==identity for frame in selected):
                        return ('mnt_id:\t'+str(mount_id(role,index))+'\n').encode()
            raise AssertionError('CLOSED_MODELED_KERNEL_FILE_SET_REQUIRED')
        for mod,values in ((producer,{'CASE':selected,'ROSTER':static.ROSTER,'BOOT_PATH':args['boot_path'],'process_pin':args['pin']}),
            (m,{'BOOT_PATH':args['boot_path'],'process_pin':args['pin']})):
            for name,value in values.items():
                p=patch.object(mod,name,value);p.start();self.addCleanup(p.stop)
        for p in (patch.object(os,'open',side_effect=kernel_root),patch.object(producer.kernel,'view_node',side_effect=view),
                  patch.object(m,'view_node',side_effect=view),patch.object(m,'kernel_read',side_effect=read_kernel),
                  patch.object(producer.kernel,'kernel_read',side_effect=read_kernel)):
            p.start();self.addCleanup(p.stop)
        c=producer.ViewCapture(root/'kernel-view-capture');result=producer.collect(c);c.put('result.json',result)
        record=json.loads((c.scope/'effective-views.private.json').read_bytes())
        for name,value in {'VIEW_CASE':selected,'VIEW_CANDIDATE':c.scope/'effective-views.private.json',
            'VIEW_CANDIDATE_HASH':m.digest(record),'VIEW_RESULT_HASH':m.digest(result)}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)
        observer=m.CurrentRetainedMountViews(static_owner);reads.clear()
        return observer,record,result,capture,selected,auth,database,keys,root,args,reads,history

    def test_actual_six_stage_producer_shape_and_zero_content_current_live_custody_continuity(self):
        observer,record,result,capture,case,auth,database,_,_,_,reads,_=self.prepared()
        intake.validate_views(record,result,capture,candidate_hash=m.digest(record),result_hash=m.digest(result),case=case)
        first=observer.observe()
        for path in auth.values():rotate(path)
        db=sqlite3.connect(database);db.execute('update fixture set value=value+1');db.commit();db.close()
        second=observer.observe();self.assertEqual(first,second)
        self.assertTrue(second['currentMountDeclarationsMatchEffectiveViews'])
        self.assertTrue(second['currentLiveLeafCustodyMatchesCapturedMetadata']);self.assertEqual(second['liveLeafMetadataNodes'],8)
        self.assertFalse(second['liveOwnerAuthenticated']);self.assertFalse(second['liveDirectoryMembershipObserved'])
        self.assertEqual(second['directEngineGets'],0);self.assertEqual(second['mountedFileContentBytesRead'],0);self.assertFalse(reads)
        for key in ('expectedPermissionOrContentPolicyEstablished','completePrivateCustodyProven','fullCohortProven',
            'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):self.assertFalse(second[key])

    def test_intake_rejects_rehashed_role_source_mountid_leaf_policy_count_and_membership_forgery(self):
        for kind in ('role','source','mount','leaf','policy','count','membership','lineage'):
            _,record,result,capture,case,*_=self.prepared();row=record['peers']['gateway-owner']['mounts'][0]
            if kind=='role':record['peers']['gateway-owner']['processPin']['startTicks']+=1
            elif kind=='source':row['mount']['source']='/foreign-source'
            elif kind=='mount':row['effectiveMountId']=0
            elif kind=='leaf':row['liveLeafMetadata']['currentEffectiveView'][4]+=1
            elif kind=='policy':row['liveLeafMetadata']['expectedPolicyEstablished']=True
            elif kind=='count':result['counts']['liveLeafMetadataNodes']=7
            elif kind=='membership':record['liveOwnerAuthenticated']=True
            else:record['staticCandidateHash']='f'*64
            result['candidateHash']=m.digest(record)
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):
                intake.validate_views(record,result,capture,candidate_hash=m.digest(record),result_hash=m.digest(result),case=case)

    def test_current_token_or_database_custody_drift_is_not_a_permitted_renewal(self):
        for kind in ('mode','hardlink','inode','symlink'):
            observer,_,_,_,_,auth,database,_,root,*_=self.prepared()
            if kind=='mode':(auth['gateway']/'token').chmod(0o400)
            elif kind=='hardlink':os.link(auth['gateway']/'token',root/'alias')
            elif kind=='inode':
                replace=root/'db-replacement';replace.write_bytes(database.read_bytes());replace.chmod(database.stat().st_mode&0o777);replace.replace(database)
            else:
                path=auth['gateway']/'token';path.unlink();path.symlink_to(root/'must-not-read')
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):observer.observe()

    def test_no_public_path_hash_engine_callback_or_foreign_static_owner_override(self):
        observer,*_=self.prepared()
        with self.assertRaises(TypeError):m.CurrentRetainedMountViews(observer.static_bytes,view_hash='f'*64)
        with self.assertRaises(TypeError):observer.observe(engine=lambda:True)
        observer.view_bindings['candidateHash']='f'*64
        with self.assertRaises(ValueError):observer.observe()

    def test_changed_view_receipt_claim_scope_or_parent_runtime_denies(self):
        for kind in ('record','receipt','claim','scope','runtime'):
            observer,*_=self.prepared()
            if kind=='record':observer.view_path.write_text('{}')
            elif kind=='receipt':(observer.view_path.parent/'result.json').write_text('{}')
            elif kind=='claim':(observer.view_path.parent/'effective-view.claim.json').write_text('{}')
            elif kind=='scope':(observer.view_path.parent/'extra').touch()
            else:observer.static_bytes.runtime=object()
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):observer.observe()

    def test_public_target_receipt_is_pinned_and_does_not_claim_private_readback_or_admission(self):
        row=json.loads((ROOT/'evidence/m2-retained-view-capture-target-20261101.json').read_text())
        self.assertEqual(m.digest(row['receipt']),intake.RESULT_HASH)
        self.assertEqual(row['receipt']['candidateHash'],intake.CANDIDATE_HASH)
        self.assertFalse(row['privateRecordReadByAgent']);self.assertFalse(row['receipt']['liveOwnerAuthenticated'])
        self.assertEqual(row['receipt']['counts']['liveCustodyContinuityDifferences'],0)


if __name__=='__main__':unittest.main()
