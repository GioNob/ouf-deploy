"""Candidate expectation over immutable launch inputs; no target acceptance."""
import base64,contextlib,copy,hashlib,importlib.util,io,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import test_chatbot_paused_node_readback as prior
from test_file_only_preparation import Preparation
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bridge_proposal_reader',ROOT/'scripts/read-chatbot-bridge-proposal-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class CandidateReadback(unittest.TestCase):
    def fixture(self):
        template,launch,context,args,request=Preparation().gated_frame()
        # This fixture now models the same signed named bridge, rather than the
        # older independent unit fixture's inconsistent host/network names.
        request['HostConfig']['NetworkMode']='ouf-backend'
        original_env=request['Env']+['HOSTNAME=$OUF_HOSTNAME']
        template['expectedOci']['process']['env']=copy.deepcopy(original_env);launch['startup']['env']=copy.deepcopy(original_env)
        parent=context['networkNamespaceParent'];storage=context['storageParent']
        recipe_context={k:v for k,v in context.items()if k not in('containerId','networkNamespaceName','rootfsPath')}
        recipe_context['rootfsLayout']='docker-containerd-overlayfs-v1'
        recipe={'template':template,'launch':launch,'dockerContext':recipe_context,'renewableToken':args['renewable_token'],
            'delegationKeyMetadataHash':args['delegation_key_metadata_hash'],'proposalReceiptKey':args['proposal_receipt_key']}
        prepared={'registry':{'creationRequest':request,'configtree':args['execution_profile'].configtree,'nodeRecipe':recipe}}
        native={'State':{'Pid':123},'NetworkSettings':{'SandboxKey':parent+'/'+'b'*12}}
        runtime={'bundle':context['bundleParent']+'/'+r.CID}
        compiler,profile=r.candidate_compiler();new_t,new_l=compiler.recompile_bridge_proposal(template,launch,request)
        new_context={**recipe_context,'containerId':r.CID,'networkNamespaceName':None,'rootfsPath':storage+'/rootfs/overlayfs/'+r.CID}
        new_context.pop('rootfsLayout')
        policy=compiler.compile_policy(new_t,new_l,new_context,execution_profile=profile.FileOnlyProfile(request,prepared['registry']['configtree']),
            renewable_token=recipe['renewableToken'],delegation_key_metadata_hash=recipe['delegationKeyMetadataHash'],proposal_receipt_key=recipe['proposalReceiptKey'])
        return prepared,native,runtime,policy
    def run_probe(self,prepared,native,runtime,oci):
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(r,'proc_generation',return_value={'networkNamespaceInode':99}),patch.object(Path,'stat',return_value=type('Stat',(),{'st_ino':99})()):
            policy=r.bridge_proposal(prepared,native,oci,runtime)
        return policy,[json.loads(x)for x in output.getvalue().splitlines()]
    def test_unchanged_signed_inputs_derive_exact_candidate_without_using_observed_oci(self):
        p,n,rt,expected=self.fixture();before=copy.deepcopy(p)
        policy,rows=self.run_probe(p,n,rt,copy.deepcopy(expected['expectedOci']))
        self.assertEqual(policy,expected);self.assertEqual(p,before)
        self.assertTrue(rows[0]['candidateExactFullOci']);self.assertTrue(rows[0]['sameEnvironmentValues']);self.assertFalse(rows[0]['applyAuthorized'])
    def test_an_extra_native_change_is_not_normalized_or_silently_accepted(self):
        p,n,rt,expected=self.fixture();native=copy.deepcopy(expected['expectedOci']);native['process']['env'][2]='LANG=PRIVATE_VALUE_DRIFT'
        policy,rows=self.run_probe(p,n,rt,native)
        self.assertIsNone(policy);self.assertFalse(rows[0]['candidateExactFullOci']);self.assertFalse(rows[0]['sameEnvironmentValues'])
        self.assertNotIn('PRIVATE_VALUE_DRIFT',json.dumps(rows));self.assertEqual(rows[1]['check'],'CANDIDATE_OCI_DIFFERENCE')
    def test_tampered_embedded_compiler_is_refused_before_execution(self):
        sources=copy.deepcopy(r.CANDIDATE_SOURCES);sources['file_only_profile']['body']=base64.b64encode(b'raise Exception("DO_NOT_EXECUTE")').decode()
        with patch.object(r,'CANDIDATE_SOURCES',sources),self.assertRaisesRegex(r.ReadDenied,'CANDIDATE_COMPILER_SOURCE_DRIFT'):r.candidate_compiler()
    @unittest.skipUnless(os.geteuid()==0,'sealed root-owned entrypoint fixture')
    def test_complete_entrypoint_reaches_end_including_proposal_and_rootfs_handoff(self):
        # Prior test helper writes actual sealed records/mount views and runs
        # the complete main function. Compiler/rootfs bodies have separate tests;
        # only their two new handoff calls are isolated in this control-flow test.
        owner=prior.Reader();self.addCleanup(owner.doCleanups)
        with patch.object(prior,'r',r),patch.object(r,'bridge_proposal',return_value={'syntheticControlFlowOnly':True}),patch.object(r,'image_rootfs_preflight',return_value=True):
            owner.complete_entrypoint(drift=True)
    def test_frozen_real_rootfs_sealer_reports_drift_without_reading_private_bind_views(self):
        sources={name:base64.b64encode((ROOT/'tools/semantic_cohort_admission/cohort-draft/tools'/(name.rsplit('.',1)[1]+'.py')).read_bytes()).decode()for name in r.SEAL_SOURCE_PINS}
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);image=root/'image';image.mkdir(mode=0o755);(image/'regular').write_bytes(b'fixture image file')
            outside=root/'outside';outside.mkdir();(outside/'secret').write_bytes(b'DO_NOT_READ_PRIVATE_BYTES')
            policy={'expectedOci':{'root':{'path':str(image)}},'sources':[{'source':str(outside/'secret'),'target':'/missing/file'}],
                'configtree':{'source':str(outside),'target':'/missing/db'},'renewableToken':{'source':str(outside),'target':'/missing/token'}}
            limits={'maxEntries':100,'maxBytes':4096,'maxDepth':8}
            prepared={'registry':{'nodeRecipe':{'observationConfiguration':{'rootfsLimits':limits},'expectedRootfsSeal':{'different':'seal'}}}}
            output=io.StringIO()
            with contextlib.redirect_stdout(output),patch.object(r,'proc_generation',return_value={'stable':True}):
                result=r.image_rootfs_preflight(policy,prepared,{'State':{'Pid':123}},sources)
            self.assertFalse(result);row=json.loads(output.getvalue().splitlines()[-1]);self.assertFalse(row['sameAsQualifiedImageSeal']);self.assertFalse(row['credentialOrTokenFilesRead'])
            self.assertNotIn('DO_NOT_READ',output.getvalue())
            (image/'missing').mkdir();(image/'missing'/'file').symlink_to(outside/'secret')
            with patch.object(r,'proc_generation',return_value={'stable':True}),self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BIND_VISIBLE_IN_IMAGE_SCAN_DENIED'):
                r.image_rootfs_preflight(policy,prepared,{'State':{'Pid':123}},sources)

if __name__=='__main__':unittest.main()
