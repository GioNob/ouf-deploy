"""Exact five-stage real producer inputs; no modeled positive kernel admission.

Kernel-positive capture and adverse namespace changes run in the native suite.
These tests exercise private lineage, closed preconditions and no replay.
"""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_static_intake as fixture
from tools.m2_discovery_installation_profile import retained_view_capture as m
from tools.m2_discovery_installation_profile import retained_static_custody as previous


class ViewInput(unittest.TestCase):
    def prepared(self):
        fixture_case=fixture.StaticIntake();self.addCleanup(fixture_case.doCleanups)
        observer,record,result,capture,root,auth,database,keys,reads,case,args,row=fixture_case.prepared()
        selected={**case,'staticCandidatePath':str(observer.path),'staticCandidateHash':m.digest(record),
            'staticResultHash':m.digest(result)}
        for name,value in {'CASE':selected,'ROSTER':previous.ROSTER,'BOOT_PATH':args['boot_path'],'process_pin':args['pin']}.items():
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        c=m.ViewCapture(root/'view-input');return c,selected,args,root

    def test_valid_original_inputs_reach_kernel_step_without_engine_or_content_or_old_scope_changes(self):
        c,case,_,_=self.prepared();history={str(p):p.read_bytes() for root in
            (case['failedScope'],str(Path(case['candidatePath']).parent),case['failedHashScope'],case['reconciliationScope'],
             str(Path(case['staticCandidatePath']).parent)) for p in Path(root).iterdir()}
        with patch.object(c,'kernel_read',side_effect=RuntimeError('ACTUAL_KERNEL_STEP_REQUIRED')) as kernel,\
            self.assertRaisesRegex(RuntimeError,'ACTUAL_KERNEL_STEP_REQUIRED'):m.collect(c)
        kernel.assert_called_once();self.assertEqual(c.counts['metadataReads'],6)
        self.assertEqual(c.counts['engineGets'],0);self.assertEqual(c.counts['mountFileContentBytesRead'],0)
        self.assertEqual(history,{p:Path(p).read_bytes() for p in history})
        self.assertFalse((c.scope/'effective-views.private.json').exists())

    def test_mutated_static_or_capture_record_receipt_claim_and_scope_fail_before_kernel(self):
        for kind in ('static','static-result','claim','capture','seed','old-scope'):
            c,case,_,_=self.prepared()
            if kind=='static':path=Path(case['staticCandidatePath'])
            elif kind=='static-result':path=Path(case['staticCandidatePath']).parent/'result.json'
            elif kind=='claim':path=Path(case['staticCandidatePath']).parent/'static-custody.claim.json'
            elif kind=='capture':path=Path(case['candidatePath'])
            elif kind=='seed':path=Path(case['seedPath'])
            else:path=Path(case['failedScope'])/'extra'
            path.write_text('{}')
            with patch.object(c,'kernel_read') as kernel,self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):
                m.collect(c)
            kernel.assert_not_called();self.assertFalse((c.scope/'effective-views.private.json').exists())

    def test_current_boot_and_all_processes_required_and_scope_never_rearms(self):
        for kind in ('boot','process'):
            c,_,args,_=self.prepared()
            if kind=='boot':args['boot_path'].write_text('different-boot')
            else:
                context=patch.object(m,'process_pin',lambda pid:{'pid':pid});context.start();self.addCleanup(context.stop)
            with patch.object(c,'kernel_read') as kernel,self.subTest(kind=kind),self.assertRaises(ValueError):m.collect(c)
            kernel.assert_not_called()
            with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.ViewCapture(c.scope)

    def test_source_entrypoint_has_no_caller_selected_paths_engine_or_positive_callback(self):
        c,*_=self.prepared()
        with self.assertRaises(TypeError):m.collect(c,engine_factory=lambda:None)
        with self.assertRaises(TypeError):m.collect(c,case={})
        with self.assertRaises(TypeError):m.collect(c,kernel_observer=lambda:True)

    def test_kernel_attempt_and_byte_limits_fail_closed_without_private_candidate(self):
        c,*_=self.prepared()
        with patch.dict(m.PROFILE,maximumKernelReads=0),self.assertRaisesRegex(ValueError,'KERNEL_METADATA_READ_SET'):
            c.kernel_read('/must-not-open',1)
        with patch.object(m.kernel,'kernel_read',return_value=b'12345'),patch.dict(m.PROFILE,maximumKernelMetadataBytes=4),\
            self.assertRaisesRegex(ValueError,'KERNEL_METADATA_BYTES'):c.kernel_read('/fixture-kernel',10)
        self.assertFalse((c.scope/'effective-views.private.json').exists())


if __name__=='__main__':unittest.main()
