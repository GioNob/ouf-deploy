"""Complete independent CI entries and private-safe exact target difference."""
import base64,contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_chatbot_paused_node_readback as prior
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rootfs_entry_reader',ROOT/'scripts/read-chatbot-rootfs-entry-diff-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
SEAL={'schema':'ouf.semantic-rootfs-seal.v1','entries':9301,'bytes':1719645735,'sha256':'510f56436da3e36b700b244e5e2476db9d4984216866e412b0484f951bfdb8a2'}
POLICY={'sources':[{'target':'/run/ouf/delegation.key'},{'target':'/run/ouf/proposal.key'}],
    'configtree':{'target':'/run/ouf/database'},'renewableToken':{'target':'/run/ouf/policy'}}

class RootfsEntryReadback(unittest.TestCase):
    def test_all_ci_entries_reproduce_exact_original_package_seal(self):
        rows=r.ci_image_entries(SEAL)
        self.assertEqual(len(rows),9301);self.assertIn('app/application.jar',rows)
        self.assertEqual(rows['run/ouf/delegation.key']['size'],0)
        self.assertEqual(r.rootfs_differences(rows,rows,POLICY)['differentEntryCount'],0)
    def test_changed_baseline_binding_and_corrupt_compression_are_rejected(self):
        changed={**SEAL,'entries':9302}
        with self.assertRaisesRegex(r.ReadDenied,'CI_ENTRIES_MUST_REPRODUCE_RETAINED_QUALIFIED_SEAL'):r.ci_image_entries(changed)
        with patch.object(r,'CI_ENTRIES_SHA','0'*64),self.assertRaisesRegex(r.ReadDenied,'CI_IMAGE_MANIFEST_HASH_DRIFT'):r.ci_image_entries(SEAL)
    def test_extra_empty_entry_and_other_drift_are_reported_without_normalization(self):
        left=r.ci_image_entries(SEAL);right=copy.deepcopy(left)
        right['run/ouf/extra']={'path':'run/ouf/extra','kind':'directory','mode':0o755,'uid':0,'gid':0,'links':2,'xattrs':{}}
        right['app/application.jar']['sha256']='PRIVATE_HASH_DO_NOT_PRINT'
        result=r.rootfs_differences(left,right,POLICY)
        self.assertEqual(result['differentEntryCount'],2);self.assertEqual(result['fieldCounts'],{'sha256':1,'UNEXPECTED_ENTRY':1})
        self.assertNotIn('PRIVATE_HASH',json.dumps(result));self.assertFalse(result['acceptanceGranted'])
    def test_metadata_changes_count_every_entry_and_limit_samples_only(self):
        left=r.ci_image_entries(SEAL);right=copy.deepcopy(left)
        for item in right.values():item['uid']+=1
        result=r.rootfs_differences(left,right,POLICY,maximum=3)
        self.assertEqual(result['differentEntryCount'],9301);self.assertEqual(result['fieldCounts'],{'uid':9301})
        self.assertEqual(len(result['samples']),3);self.assertTrue(result['samplesTruncated'])
    def test_private_xattrs_and_symlink_targets_are_not_printed(self):
        left={'p':{'path':'p','kind':'symlink','mode':0o777,'uid':0,'gid':0,'links':1,'target':'old','xattrs':{}}}
        right=copy.deepcopy(left);right['p'].update(target='SECRET_LINK_TARGET',xattrs={'secret':'SECRET_VALUE'})
        result=r.rootfs_differences(left,right,POLICY)
        self.assertEqual(result['fieldCounts'],{'target':1,'xattrs':1});self.assertNotIn('SECRET',json.dumps(result))
    def test_complete_readback_main_preserves_control_flow_through_rootfs_handoff(self):
        owner=prior.Reader();self.addCleanup(owner.doCleanups)
        with patch.object(prior,'r',r),patch.object(r,'bridge_proposal',return_value={'syntheticControlFlowOnly':True}),patch.object(r,'image_rootfs_preflight',return_value=False):
            owner.complete_entrypoint(drift=True)
    def test_real_frozen_sealer_capture_and_private_bind_guard(self):
        sources={name:base64.b64encode((ROOT/'tools/semantic_cohort_admission/cohort-draft/tools'/(name.rsplit('.',1)[1]+'.py')).read_bytes()).decode()for name in r.SEAL_SOURCE_PINS}
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);image=root/'image';image.mkdir(mode=0o755);(image/'regular').write_bytes(b'fixture image file')
            outside=root/'outside';outside.mkdir();(outside/'secret').write_bytes(b'DO_NOT_READ_PRIVATE_BYTES')
            policy={'expectedOci':{'root':{'path':str(image)}},'sources':[{'source':str(outside/'secret'),'target':'/missing/file'}],
                'configtree':{'source':str(outside),'target':'/missing/db'},'renewableToken':{'source':str(outside),'target':'/missing/token'}}
            limits={'maxEntries':100,'maxBytes':4096,'maxDepth':8}
            prepared={'registry':{'nodeRecipe':{'observationConfiguration':{'rootfsLimits':limits},'expectedRootfsSeal':SEAL}}}
            output=io.StringIO()
            # procfs is unavailable in this workspace; mountinfo denial has a
            # separate parser case. Original sealer/capture use real files.
            with contextlib.redirect_stdout(output),patch.object(r,'proc_generation',return_value={'stable':True}),patch.object(r,'host_image_mount_guard'),patch.object(r,'ci_image_entries',return_value={}):
                result=r.image_rootfs_preflight(policy,prepared,{'State':{'Pid':123}},sources)
            self.assertFalse(result);rows=[json.loads(x)for x in output.getvalue().splitlines()]
            diff=next(x for x in rows if x['check']=='ROOTFS_ENTRY_DIFFERENCES')
            self.assertEqual(diff['differentEntryCount'],2);self.assertEqual(diff['fieldCounts'],{'UNEXPECTED_ENTRY':2})
            self.assertNotIn('DO_NOT_READ',output.getvalue())
            (image/'missing').mkdir();(image/'missing'/'file').symlink_to(outside/'secret')
            with patch.object(r,'proc_generation',return_value={'stable':True}),patch.object(r,'host_image_mount_guard'),patch.object(r,'ci_image_entries',return_value={}):
                with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BIND_VISIBLE_IN_IMAGE_SCAN_DENIED'):
                    r.image_rootfs_preflight(policy,prepared,{'State':{'Pid':123}},sources)
    def test_host_private_submount_is_refused_before_content_scan(self):
        with patch('builtins.open',return_value=io.BytesIO(b'1 0 1:1 / /image/private ro - ext4 /dev/none ro\n')):
            with self.assertRaisesRegex(r.ReadDenied,'PRIVATE_SUBMOUNT_IN_IMAGE_SCAN_DENIED'):r.host_image_mount_guard(Path('/image'))

if __name__=='__main__':unittest.main()
