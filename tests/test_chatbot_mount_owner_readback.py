"""Bounded metadata reader custody, complete entrypoint and closed projections."""
import base64,contextlib,hashlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixed_mount_owner_reader',ROOT/'scripts/read-chatbot-mount-owner-failure-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Readback(unittest.TestCase):
    def setUp(self):r.READS.clear();r.ERRORS.clear()
    def test_protocol_and_projection_reject_reserved_or_dynamic_values(self):
        with self.assertRaises(r.ReadDenied):r.emit('PROBE',readOnly=False)
        with self.assertRaises(r.ReadDenied):r.projection({'state':'PRIVATE VALUE'})
        self.assertEqual(r.projection({'state':'CANCELLED','attempts':1,'private':'SECRET'}),{'state':'CANCELLED','attempts':1})
    def test_exact_failure_and_source_pins_are_frozen(self):
        self.assertEqual(r.SOURCE,'b7d24c57d6e45e71994ac3f99f56f249d83cde22')
        self.assertEqual(r.REVIEW,'2380132af8e47de185894fde156470e162dab784942c8615778e7620e7f8fc60')
        self.assertEqual(r.SOURCE_PINS['tools.semantic_policy_token_owner.mount_observation'],'f02137f9b2af62ddcfec9aad554ea572a0440870dfc065a23a21de2e58eff5b8')
        with self.assertRaises(r.ReadDenied):r.source_check({'declaration':{'sourceHashes':{}},'sources':{}})
    def test_lifetime_mismatch_is_calculated_from_reviewed_metadata_not_bearer(self):
        out=io.StringIO();p={'owner':{'iamProfile':{'minimum_remaining':90},'binding':{'minimum_remaining':90}}}
        with contextlib.redirect_stdout(out):r.lifetime_check(p,{'renewableToken':{'minimumRemainingSeconds':30}}, {})
        rows=[json.loads(s)for s in out.getvalue().splitlines()]
        self.assertTrue(rows[0]['oldCallerAlwaysBelowOwnerMinimum']);self.assertEqual(rows[0]['oldCallerMaximumValiditySeconds'],60)
        self.assertIsNone(rows[1]['tokenExpiresWallRemainingSeconds']);self.assertFalse(rows[1]['currentTokenOrCredentialRead'])
    @unittest.skipUnless(os.geteuid()==0,'native root private file custody')
    def test_private_read_detects_link_mode_bound_and_later_record_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            p=Path(d)/'record.json';p.write_bytes(b'{"state":"CANCELLED"}');p.chmod(0o600)
            self.assertEqual(r.read(p),{'state':'CANCELLED'})
            with self.assertRaises(r.ReadDenied):r.read(p,1)
            p.chmod(0o644)
            with self.assertRaises(r.ReadDenied):r.read(p)
            p.chmod(0o600);q=Path(d)/'hardlink';os.link(p,q)
            with self.assertRaises(r.ReadDenied):r.read(p)
            q.unlink();q.symlink_to(p)
            with self.assertRaises(r.ReadDenied):r.read(q)
            p.write_bytes(b'{"state":"ACTIVE"}')
            with self.assertRaisesRegex(r.ReadDenied,'CHANGED_DURING_DIAGNOSIS'):r.read(p)
    @unittest.skipUnless(os.geteuid()==0,'native root private metadata fixture')
    def test_complete_entrypoint_reports_latest_history_and_never_opens_secret_or_executes_source(self):
        self.complete()
    @unittest.skipUnless(os.geteuid()==0,'native root private metadata fixture')
    def test_unavailable_native_get_still_reports_all_metadata_and_complete_false(self):
        self.complete(native_failure=True)
    def complete(self,native_failure=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);context=root/'context';context.mkdir(mode=0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=r.encoded(value);path.write_bytes(raw);path.chmod(0o600)
                return hashlib.sha256(raw).hexdigest()
            owner=root/'owner';owner.mkdir(mode=0o700)
            paths={k:str(root/'registry'/k)for k in('transition','node','evidence')}
            session={'schema':'ouf.policy-token-new-finite-worker-session.v2','predecessorGrantAttempts':2}
            worker={'state':'CANCELLED','attempts':1,'controlledPredecessorGrantAttempts':2,'controlledCumulativeGrantAttempts':3,
                'publicationCount':1,'workerSessionHash':r.digest(session),'firstGrantReceiptHash':'4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a'}
            for name,value in(('recovery.json',worker),('owner-session.json',session),('owner-admission.json',{'state':'BLOCKED','version':3})):
                write(owner/name,value)
            effects=[{'phase':n,'state':'APPLIED'if i<6 else'IN_FLIGHT'}for i,n in enumerate(r.PHASES[:7])]
            write(Path(paths['transition'])/'recovery.json',{'version':15,'state':'IN_FLIGHT','nextPhase':6,'effects':effects,'governedUnsignedReprocessing':{'predecessorJournalHash':r.OLD_TRANSITION}})
            write(Path(paths['node'])/'frame-policy.json',{'renewableToken':{'minimumRemainingSeconds':30},'private':'DO_NOT_PRINT_SECRET_METADATA'})
            directories={k:str(root/k)for k in('authorization','containers','databases','gateway')}
            for path in directories.values():write(Path(path)/'recovery.json',{'version':1,'effects':[]})
            sources={k:base64.b64encode(b'raise RuntimeError("SOURCE_MUST_NEVER_EXECUTE")').decode()for k in r.SOURCE_PINS}
            pins={k:hashlib.sha256(base64.b64decode(v)).hexdigest()for k,v in sources.items()}
            declaration={'sourceCommit':r.SOURCE,'sourceHashes':pins}
            prepared={'owner':{'iamProfile':{'minimum_remaining':90},'binding':{'minimum_remaining':90}},
                'registry':{'directoryPlan':paths},'engine':{'syntheticReadOnlyEngine':True}}
            bundle={'declaration':declaration,'prepared':prepared,'sources':sources};bundle_path=root/'bundle.json';bundle_hash=write(bundle_path,bundle)
            process={'unit':r.UNIT,'authorityDirectory':str(context),'bundle':{'path':str(bundle_path),'sha256':bundle_hash},'directoryPlan':directories}
            scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':str(owner)},'policyTokenFiniteWorkerSession':session}
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{'syntheticPinned':True}}},'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(prepared)}}
            review_hash=write(context/'review.json',review);authority={**scopes,'expiresAt':0};authority_hash=write(context/'authority.json',authority)
            write(context/'delivery-status.json',{'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'Permanent','authorityHash':authority_hash})
            write(context/'decision.json',{'approvedReviewHash':review_hash});write(root/r.CLAIM,{'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY','authorityHash':authority_hash})
            secret=root/'client-secret';secret.write_text('MUST_NEVER_READ');secret.chmod(0o400)
            token=root/'token.jwt';token.write_text('MUST_NEVER_READ');token.chmod(0o440)
            out=io.StringIO();real_read=r.read;opened=[]
            def observed_read(path,*args,**kwargs):
                opened.append(Path(path));self.assertNotIn(Path(path).name,{'client-secret','token.jwt'});return real_read(path,*args,**kwargs)
            native={'Id':r.CID,'State':{'Status':'paused','Running':True,'Paused':True,'Pid':123},'RestartCount':0}
            with (patch.object(r,'CONTEXT',context),patch.object(r,'REVIEW',review_hash),patch.object(r,'AUTHORITY',authority_hash),
                patch.object(r,'SOURCE_PINS',pins),patch.object(r,'systemd',return_value={'stopped':True}),
                patch.object(r,'inspect',side_effect=OSError('DO_NOT_PRINT_EXCEPTION')if native_failure else None,return_value=native),
                patch.object(r,'read',side_effect=observed_read),patch.object(r.signal,'alarm'),contextlib.redirect_stdout(out)):
                r.main()
            rows=[json.loads(line)for line in out.getvalue().splitlines()];self.assertEqual(rows[-1]['check'],'END')
            self.assertEqual(rows[-1]['complete'],not native_failure);self.assertFalse(rows[-1]['sourceBodiesExecuted'])
            self.assertEqual(next(x for x in rows if x['check']=='WORKER_HISTORY')['cumulativeAttempts'],3)
            self.assertTrue(next(x for x in rows if x['check']=='UNSIGNED_NODE_BOUNDARY')['nodeContainsOnlyFramePolicy'])
            self.assertEqual(len([x for x in rows if x['check'].startswith('LATER_EFFECTS_')]),4)
            self.assertTrue(all(x['readOnly']and not x['budgetReset']for x in rows));self.assertGreater(len(opened),15)
            for private in('DO_NOT_PRINT','SOURCE_MUST_NEVER_EXECUTE','MUST_NEVER_READ',str(secret),str(token)):
                self.assertNotIn(private,out.getvalue())

if __name__=='__main__':unittest.main()
