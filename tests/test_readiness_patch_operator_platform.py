"""Whole exact controller capsule on real disposable Docker/APISIX/JVM/PG17.

Synthetic HUMAN/Owner/provider qualification inputs are explicit. The production
139-source native core and new controller are not patched in the child.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_platform as native_fixture
import test_readiness_patch_operator_delivery as delivery_fixture
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_readiness_patch_execution import operator_delivery as d,entry as e,operator_control as op

@unittest.skipUnless(os.environ.get('OUF_ISOLATED_NATIVE_PLATFORM')=='1','explicit disposable platform required')
class WholeControllerPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_class=type('_WholeControllerFixture',(native_fixture.NativePlatform,),{})
        cls.addClassCleanup(cls.fixture_class.doClassCleanups);cls.fixture_class.setUpClass()
    def setUp(self):
        self.native=self.fixture_class();self.native.report_progress=lambda:None
        self.addCleanup(self.native.doCleanups)
        # Reuse only fixture setup. No old/direct native journal is initialized.
        with patch.object(native_fixture.Runner,'initialize',return_value=None):self.native.setUp()
        self.native.ports.close();n=self.native;self.root=n.root
        self.addCleanup(self.cleanup_replacement)
        bundle=copy.deepcopy(n.review['preparedInputs']);bundle['nativeArchivePreparation']={'parentNativeInputsHash':'a'*64}
        q=n.crypto
        installed={'schema':'ouf.semantic-existing-installation-authority-bindings.v1',
            'authorities':q.context,'policyBinding':q.binding(q.policy),
            'keyRefs':{'installer':q.grant['keyRef'],'attestor':'synthetic-fixture-attestor-key'},
            'keyBindings':{'installer':q.binding(q.key),'attestor':q.binding(q.key)}}
        existing=self.root/'issuer.json';q.write(existing,e.c.encoded(installed))
        issuer={'schema':'ouf.ingestion-rollout-existing-issuer-profile.v1','installationAuthority':binding(existing),
            'policy':binding(q.policy),'authorityContext':q.context}
        bundle['retainedIssuerProfile']=issuer
        bundle['historicalSourceClosure']={'executables':{'openssl':q.verifier.openssl_binding}}
        folder=self.root/'archive-successor';folder.mkdir(mode=0o700)
        inputs=folder/'native-inputs.json';inputs.write_bytes(e.c.encoded(bundle));inputs.chmod(0o400)
        receipt={'schema':'ouf.ingestion-readiness-native-archive-result.v1','status':'NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY',
            'complete':True,'bundleHash':e.c.digest(bundle),'parentInputsHash':'a'*64,
            'logicalOperationRef':bundle['finiteIntentContract']['logicalOperationRef'],
            'configurationImageId':bundle['candidate']['Id'],'nativeImageId':bundle['nativeArchiveAudit']['nativeIdentity']['nativeImageId'],
            'nativeArchiveSha256':bundle['nativeArchiveAudit']['archiveSha256'],
            'plannedStages':len(bundle['finiteIntentContract']['stages']),'contextPath':str(folder),
            **dict.fromkeys(('automaticReplayAllowed','budgetReset','runtimeAuthorityIssued','nativeRuntimeExecutorQualified',
                'targetApplyAuthorized','releaseAcceptance','imageRebuilt','liveRuntimeReverified'),False),
            **dict.fromkeys(('imagesImported','engineRequests','oauthRequests','credentialFilesOpened','runtimeEffectsDispatched'),0)}
        path=folder/'complete.json';path.write_bytes(e.c.encoded(receipt));path.chmod(0o400)
        _,manifest=d.core(ROOT)
        qualification={'schema':'ouf.ingestion-readiness-patch-native-qualification.v1',
            'sourceCommit':manifest['sourceCommit'],'sourceHashes':manifest['sourceHashes'],
            'candidateNativeImageId':receipt['nativeImageId'],'candidateSourceCommit':n.candidate['sourceCommit'],
            'results':dict.fromkeys(e.authority.QUALIFICATION,'PASS'),'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
            'evidenceRefs':{k:{'repository':'synthetic/fixture-only','runId':1,'jobId':1,'sourceCommit':'1'*40}for k in e.authority.QUALIFICATION}}
        control_hash=hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/operator_control.py').read_bytes()).hexdigest()
        self.case={'schema':op.SCHEMA,'snapshotRoot':str(self.root),'nativeInputsPath':str(inputs),
            'nativeInputsHash':e.c.digest(bundle),'nativeReceiptHash':e.c.digest(receipt),'parentInputsHash':'a'*64,
            'logicalOperationRef':receipt['logicalOperationRef'],'configurationImageId':receipt['configurationImageId'],
            'nativeImageId':receipt['nativeImageId'],'nativeArchiveSha256':receipt['nativeArchiveSha256'],
            'candidateSourceCommit':n.candidate['sourceCommit'],'plannedStages':receipt['plannedStages'],
            'nativeDeclarationHash':e.c.digest(manifest),'qualification':qualification,
            'requiredCumulativeOAuthAttempts':296,'maximumRuntimeSeconds':900,'controlSourceHash':control_hash}
        h=n.human;row=h.journal.read();b=copy.deepcopy(row['binding'])
        b['retryProfile']={**b['retryProfile'],'maximumAttempts':296,'maximumElapsedSeconds':7200,'automaticBudgetRenewalAllowed':False}
        review={'maximumCumulativeOAuthAttempts':296,'priorOAuthAttempts':292,'requestedScopes':b['scopes'],
            'budgetReset':False,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,'freshIssuerAuthenticationRequired':True,
            'operationBinding':{'runtimeCaseHash':e.c.digest(self.case),'nativeInputsHash':self.case['nativeInputsHash'],
                'logicalOperationRef':self.case['logicalOperationRef'],'controlSourceHash':control_hash}}
        renewal={'review':review,'decision':{'reviewHash':e.c.digest(review),'approvedAt':b['createdAt'],'expiresAt':b['expiresAt']}}
        h.journal.compare_and_save(row,{**row,'binding':b,'attempts':296,'governedWindowRenewal':renewal,'version':row['version']+1})
        profile={'schema':e.human_reader.SCHEMA,'selection':h.selection,'expectedBinding':b,'journal':binding(h.journal.record),
            'minimumCumulativeAttempts':296,'maximumCumulativeAttempts':296,'expectedBootId':row['bootId'],
            'expectedMonotonicDeadline':row['monotonicDeadline'],'governedWindowReceiptHash':e.c.digest(renewal),
            'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        self.profile=self.root/'human-read-profile.json';self.profile.write_bytes(e.c.encoded(profile));self.profile.chmod(0o400)
        self.path=self.root/'whole-operator.py';raw,_=d.generate(ROOT,self.case);self.path.write_bytes(raw);self.path.chmod(0o400)
        self.target=self.root/('ingestion-readiness-execution-'+e.c.digest(self.case))
    def call(self,*args):
        result=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(self.path),*args],capture_output=True,text=True,timeout=190)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);return json.loads(result.stdout)
    def cleanup_replacement(self):
        if not hasattr(self,'target')or not (self.target/'recovery.json').exists():return
        row=json.loads((self.target/'recovery.json').read_bytes())
        for effect in row.get('effects',[]):
            if effect['stage']=='ingestion.CREATE_REPLACEMENT':
                cid=effect.get('nativeResource',{}).get('containerId')
                if cid:self.native.names.append(cid)
    def test_whole_capsule_through_real_tty_and_every_native_stage(self):
        self.assertEqual(self.call('preflight')['status'],'PATCH_RUNTIME_PREFLIGHT_NO_AUTHORITY')
        self.call('review',str(self.profile));review=json.loads((self.target/'review.json').read_bytes())
        delivery_fixture.OperatorDelivery.tty_approve(self,'APPROVO '+e.c.digest(review))
        self.assertTrue(self.call('initialize')['initialized'])
        for _ in range(self.case['plannedStages']):self.call('step')
        self.assertTrue(self.call('step')['complete']);status=self.call('status')
        self.assertEqual(status['nextStage'],self.case['plannedStages']);self.assertEqual(status['state'],'COMPLETE')
        row=json.loads((self.target/'recovery.json').read_bytes())
        self.assertEqual(row['nativeDirectEnginePosts'],8)
        self.assertFalse(any(effect.get('nativeGatewayPutAttempted')for effect in row['effects']))
        self.assertEqual(self.native.admin(self.native.before['gateway']['Id'],'GET','/apisix/admin/routes')['status'],200)
        created=next(effect['nativeResource']['containerId']for effect in row['effects']if effect['stage']=='ingestion.CREATE_REPLACEMENT')
        actual=self.native.inspect(created)
        self.assertEqual(actual['HostConfig']['RestartPolicy'],self.native.packet['frames']['ingestion']['restoreRestartPolicy'])
        self.assertFalse(self.native.inspect(self.native.before['ingestion']['Id'])['State']['Running'])
        print('OUF_WHOLE_PATCH_CONTROLLER_PROOF='+json.dumps({'complete':True,'stages':self.case['plannedStages'],
            'enginePosts':8,'gatewayWrites':0,'newKeys':0,'realTtyConsent':True,'newControllerAnd139CoreUnmodifiedInChild':True,
            'syntheticHumanAndOwner':True,'targetEvidence':False,'notReleaseAcceptance':True}),flush=True)

if __name__=='__main__':unittest.main()
