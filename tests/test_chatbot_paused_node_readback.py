"""Real pure compiler bodies, byte custody and diagnostic privacy; no VPS I/O."""
import base64, contextlib, copy, hashlib, importlib.util, io, json, os
from pathlib import Path
import tempfile, unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('paused_node_reader',ROOT/'scripts/read-chatbot-paused-node-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Reader(unittest.TestCase):
    def sources(self):
        return {name:base64.b64encode((ROOT/'tools/semantic_cohort_admission/cohort-draft/tools'/(name.split('.')[-1]+'.py')).read_bytes()).decode()for name in r.PINS}
    def fixture(self):
        cfg={'commands':{'ip':{'path':'/pinned/ip'},'nsenter':{'path':'/pinned/nsenter'}},'candidate':{'networkBindings':[
            {'interface':'eth0','bridge':'br-fixture','mac':'02:42:aa:bb:cc:07','ipv4':'10.44.0.7','workloadRef':'fixture','bindingRef':'fixture-binding'}],
            'transport':[{'purpose':'IDENTITY','authorityRef':'fixture-authority','source':'10.44.0.7','destination':'10.55.0.9','protocol':'tcp','port':443,'peerIngress':{'kind':'HOST','ifindex':0}}],
            'tableName':'fixture_registry'}}
        p={'registry':{'nodeRecipe':{'observationConfiguration':cfg,'transactionId':'a'*64}}}
        child={'ifname':'eth0','ifindex':2,'link_index':55,'address':'02:42:aa:bb:cc:07','addr_info':[{'family':'inet','local':'10.44.0.7'}]}
        host={'ifindex':55,'ifname':'vethfixture','link_index':2,'master':'br-fixture'}
        oci={'linux':{'namespaces':[{'type':'network'}]}}
        def command(binding,args):return copy.deepcopy([host]if'link'in args else[child])
        return p,{'State':{'Pid':123}},oci,command
    def probe(self,p,n,oci,cmd):
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(r,'proc_generation',return_value={'networkNamespaceInode':99}),patch.object(r,'command',side_effect=cmd),patch.object(r.socket,'if_indextoname',return_value='vethfixture'):
            result=r.network_probe(p,n,oci,'/approved/bundle',self.sources())
        return result,[json.loads(line)for line in output.getvalue().splitlines()]
    def test_actual_frozen_pure_admission_and_materializer_pass(self):
        p,n,oci,cmd=self.fixture();before=copy.deepcopy(p)
        result,rows=self.probe(p,n,oci,cmd)
        self.assertIsNone(result);self.assertEqual(rows[0]['status'],'PASS');self.assertEqual(p,before)
    def test_value_error_static_literal_is_visible_without_runtime_values(self):
        p,n,oci,cmd=self.fixture();p['registry']['nodeRecipe']['observationConfiguration']['candidate']['tableName']='DO_NOT_PRINT_PRIVATE_VALUE!'
        result,rows=self.probe(p,n,oci,cmd)
        self.assertEqual(result,'safe explicit kernel binding required');self.assertEqual(rows[0]['errorClass'],'ValueError')
        self.assertNotIn('DO_NOT_PRINT',json.dumps(rows));self.assertTrue(rows[0]['locations'])
    def test_changed_pinned_source_is_denied_before_execution(self):
        sources=self.sources();key=next(iter(sources));sources[key]=base64.b64encode(b'raise RuntimeError("MUST_NOT_EXECUTE")').decode()
        with self.assertRaisesRegex(r.ReadDenied,'PURE_SOURCE_PIN_DRIFT'):r.pure_network(sources)
    def test_namespace_or_link_drift_at_end_is_denied(self):
        p,n,oci,cmd=self.fixture();count=0
        def changed(binding,args):
            nonlocal count
            count+=1;value=cmd(binding,args)
            if count>2:value[0]['ifindex']=9876
            return value
        with self.assertRaisesRegex(r.ReadDenied,'NETWORK_PROBE_INPUT_OR_GENERATION_DRIFT'):self.probe(p,n,oci,changed)
    def test_dynamic_native_exception_message_is_never_printed(self):
        p,n,oci,cmd=self.fixture()
        def secret(*a):raise ValueError('DO_NOT_PRINT_PRIVATE_VALUE')
        ns,allow=r.pure_network(self.sources());ns['live_profile']=secret
        with patch.object(r,'pure_network',return_value=(ns,allow)):
            result,rows=self.probe(p,n,oci,cmd)
        self.assertIsNone(result);self.assertIsNone(rows[0]['sourceLiteralReason']);self.assertNotIn('DO_NOT_PRINT',json.dumps(rows))
    @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
    def test_real_private_file_bound_symlink_and_hardlink_denial(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            path=Path(d)/'record.json';path.write_bytes(b'{"state":"CANCELLED"}');path.chmod(0o600)
            self.assertEqual(r.read(path),{'state':'CANCELLED'})
            with self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BOUNDED_RECORD_REQUIRED'):r.read(path,1)
            other=Path(d)/'link';os.link(path,other)
            with self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BOUNDED_RECORD_REQUIRED'):r.read(path)
            other.unlink();other.symlink_to(path)
            with self.assertRaisesRegex(r.ReadDenied,'EXACT_READ_PATH_REQUIRED'):r.read(other)
    def test_projection_rejects_arbitrary_text(self):
        self.assertEqual(r.projection({'state':'CANCELLED','attempts':1,'secret':'HIDDEN'}),{'state':'CANCELLED','attempts':1})
        with self.assertRaises(r.ReadDenied):r.projection({'state':'secret value'})

    def test_reserved_protocol_fields_cannot_be_overridden(self):
        for field,value in (('readOnly',False),('budgetReset',True)):
            with self.assertRaisesRegex(r.ReadDenied,'RESERVED_DIAGNOSTIC_FIELD'):r.emit('PROBE',**{field:value})

    def test_oci_paths_hide_environment_values_and_dynamic_annotation_keys(self):
        expected={'process':{'env':['TOKEN=PRIVATE_EXPECTED']},'annotations':{'PRIVATE_KEY':1}}
        native={'process':{'env':['TOKEN=PRIVATE_OBSERVED']},'annotations':{'OTHER_PRIVATE_KEY':2}}
        result=r.oci_difference(expected,native)
        self.assertFalse(result['exactMatch']);self.assertGreater(result['differenceCount'],0)
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertFalse(result['dynamicMapKeysPrinted'])
        self.assertEqual(r.oci_difference(expected,expected)['differenceCount'],0)

    @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
    def test_complete_reader_entrypoint_reaches_end_with_four_real_mount_metadata_rows(self):
        self.complete_entrypoint(drift=False)

    @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
    def test_complete_reader_entrypoint_keeps_oci_denial_observable_without_type_error(self):
        self.complete_entrypoint(drift=True)

    def complete_entrypoint(self,drift):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);context=root/'context';context.mkdir(mode=0o700)
            def write(path,value,mode=0o600):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=r.encoded(value);path.write_bytes(raw);path.chmod(mode);return hashlib.sha256(raw).hexdigest()
            prepared,native,oci,nic_command=self.fixture();prepared['engine']={'syntheticReadOnlyEngine':True}
            paths={k:str(root/k)for k in('transition','node')};prepared['registry']['directoryPlan']=paths
            bundle_parent=root/'bundles';bundle_path=bundle_parent/r.CID;bundle_path.mkdir(mode=0o700,parents=True)
            cfg=bundle_path/'config.json';oci['ociVersion']='1.3.0';oci['process']={'env':['OUF_TEST=PRIVATE_OBSERVED']}
            write(cfg,oci,0o644);expected=copy.deepcopy(oci)
            if drift:expected['process']['env']=['OUF_TEST=PRIVATE_EXPECTED']
            fake_proc=root/'fake-proc';process_root=fake_proc/'123'/'root';process_root.mkdir(mode=0o700,parents=True)
            bindings=[];lines=[]
            for index in range(4):
                source=root/('source'+str(index));target='/run/slot'+str(index)
                if index<2:source.write_bytes(b'DO_NOT_READ_SECRET_FILE');source.chmod(0o600)
                else:source.mkdir(mode=0o700)
                view=process_root/target.lstrip('/');view.parent.mkdir(mode=0o700,parents=True,exist_ok=True);view.symlink_to(source,target_is_directory=index>=2)
                bindings.append({'source':str(source),'target':target});lines.append(str(index+10)+' 1 0:1 / '+target+' ro - tmpfs none ro')
            (fake_proc/'123'/'mountinfo').write_text('\n'.join(lines)+'\n')
            policy={'expectedOci':expected,'sources':bindings[:2],'configtree':bindings[2],'renewableToken':bindings[3]}
            write(Path(paths['node'])/'frame-policy.json',policy)
            recipe=prepared['registry']['nodeRecipe'];recipe.update(runtimeRoot='/approved/runc',dockerContext={'bundleParent':str(bundle_parent)})
            recipe['observationConfiguration']['runtimeBinding']={'path':'/pinned/runc'}
            sources=self.sources();sources['paused_node_observation']=base64.b64encode((ROOT/'tools/semantic_application_cutover/paused_node_observation.py').read_bytes()).decode()
            declaration={'sourceCommit':r.SOURCE};bundle={'declaration':declaration,'prepared':prepared,'sources':sources}
            bundle_file=root/'bundle.json';bundle_sha=write(bundle_file,bundle)
            directories={name:str(root/name)for name in('containers','databases','gateway','authorization')}
            for directory in directories.values():write(Path(directory)/'recovery.json',{'version':1,'effects':[]})
            owner=root/'owner'
            for name in ('recovery.json','owner-session.json','owner-admission.json'):write(owner/name,{'state':'CANCELLED','attempts':1,'controlledCumulativeGrantAttempts':2})
            scope={'finiteActionProcess':{'unit':r.UNIT,'authorityDirectory':str(context),'bundle':{'path':str(bundle_file),'sha256':bundle_sha},'directoryPlan':directories},
                'policyTokenOwnerInstallation':{'journalPath':str(owner)}}
            authority_sha=write(context/'authority.json',scope)
            review={'scopes':scope,'sourceClosure':{'declaration':declaration},'privateInputHashes':{'preparedInputs':r.digest(prepared)}}
            review_sha=write(context/'review.json',review)
            write(context/'delivery-status.json',{'authorityHash':authority_sha,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'ValueError'})
            write(root/'chatbot-file-cohort-postgrant-7db9ea82ed6fbbdc88cfdbd8e7315404e6c958e841731d1d12b22482f8fa8f30.claim.json',{'authorityHash':authority_sha,'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'})
            write(Path(paths['transition'])/'recovery.json',{'state':'IN_FLIGHT','version':13,'nextPhase':6,'effects':[{'phase':phase,'state':'APPLIED'if i<6 else'IN_FLIGHT'}for i,phase in enumerate(('STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT','CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER'))]})
            native.update(RestartCount=0);native['State'].update(Running=True,Paused=True,Status='paused')
            def command(binding,args):
                if binding['path']=='/pinned/runc':return {'id':r.CID,'pid':123,'status':'paused','bundle':str(bundle_path)}
                return nic_command(binding,args)
            def path(value):return fake_proc if str(value)=='/proc'else Path(value)
            output=io.StringIO();r.ERRORS.clear()
            with contextlib.ExitStack()as stack:
                for obj,name,value in ((r,'CONTEXT',context),(r,'REVIEW',review_sha),(r,'AUTHORITY',authority_sha),(r,'Path',path)):
                    stack.enter_context(patch.object(obj,name,value))
                stack.enter_context(patch.object(r,'inspect',return_value=native));stack.enter_context(patch.object(r,'command',side_effect=command))
                stack.enter_context(patch.object(r,'proc_generation',return_value={'networkNamespaceInode':99}))
                stack.enter_context(patch.object(r.socket,'if_indextoname',return_value='vethfixture'))
                stack.enter_context(patch.object(r.signal,'alarm',return_value=0))
                stack.enter_context(patch.object(r.subprocess,'run',return_value=type('Result',(),{'returncode':0,'stdout':b'ActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n'})()))
                stack.enter_context(contextlib.redirect_stdout(output));r.main()
            rows=[json.loads(line)for line in output.getvalue().splitlines()]
            self.assertEqual(rows[-1]['check'],'END');self.assertTrue(rows[-1]['complete']);self.assertEqual(rows[-1]['unavailableChecks'],[])
            mounts=[row for row in rows if row['check']=='MOUNT_METADATA'];self.assertEqual(len(mounts),4)
            self.assertTrue(all(x['readOnly']and x['mountReadOnly']and x['sameSourceInode']for x in mounts))
            gate=next(row for row in rows if row['check']=='ORIGINAL_FULL_OCI_GATE')
            self.assertEqual(gate['status'],'DENIED'if drift else'PASS')
            if drift:self.assertEqual(gate['sourceReason'],'PAUSED_NODE_FULL_OCI_DRIFT')
            self.assertNotIn('PRIVATE',output.getvalue());self.assertNotIn('DO_NOT_READ_SECRET_FILE',output.getvalue())

if __name__=='__main__':unittest.main()
