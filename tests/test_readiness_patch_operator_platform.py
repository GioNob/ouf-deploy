"""Whole exact controller capsule on real disposable Docker/APISIX/JVM/PG17.

Synthetic HUMAN/Owner/provider qualification inputs are explicit. The production
139-source native core and new controller are not patched in the child.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_platform as native_fixture
import test_readiness_patch_operator_delivery as delivery_fixture
import test_readiness_patch_human_governance as human_fixture
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_readiness_patch_execution import operator_delivery as d,entry as e,operator_control as op,custody
from tools.ingestion_readiness_patch_execution import human_delivery as hd,human_governance as g
from tools.ingestion_readiness_patch_execution import release_delivery as release
from tools.governed_human_successor import operator
from tools.governed_human_successor.session import ExplicitFreshSession

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
    def tty_mode(self,path,mode,prefix):
        import fcntl
        import termios
        master,slave=os.openpty()
        def setup():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        command=['bash',str(path),mode]if path.suffix=='.sh'else['/usr/bin/python3','-I','-B','-S',str(path),mode]
        child=subprocess.Popen(command,
            stdin=slave,stdout=slave,stderr=slave,preexec_fn=setup,close_fds=True)
        os.close(slave);output=bytearray();sent=False;deadline=time.monotonic()+250
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],.1)
                if ready:
                    try:raw=os.read(master,65536)
                    except OSError:break
                    if not raw:break
                    output.extend(raw)
                    if not sent and b'> 'in output:
                        match=re.search(rb'Scrivi esattamente: ([^\r\n]+)\r?\n> ',output)
                        self.assertIsNotNone(match,output.decode(errors='replace'))
                        phrase=match.group(1);self.assertTrue(phrase.decode().startswith(prefix))
                        os.write(master,phrase+b'\n');sent=True
                if child.poll()is not None and not ready:break
            self.assertTrue(sent,'real controlling-terminal prompt not reached')
            self.assertEqual(child.wait(timeout=5),0,output.decode(errors='replace'))
            return next(json.loads(line)for line in reversed(output.decode().splitlines())if line.startswith('{'))
        finally:
            if child.poll()is None:child.kill();child.wait(timeout=5)
            os.close(master)
    def fresh_human_governance(self):
        """Real capsule/TTY/generation probes; only four provider replies mocked."""
        config=human_fixture.expired_previous(self);_,manifest=d.core(ROOT)
        case={'schema':g.SCHEMA,'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'runtimeCase':self.case,'nativeDeclaration':manifest,'predecessorControlPath':str(self.oldcontrol),
            'predecessorReviewHash':e.c.digest(config['review']),'humanOperatorTransportProfile':dict(operator.TRANSPORT),
            'governanceSourceHash':d.sha((ROOT/'tools/ingestion_readiness_patch_execution/human_governance.py').read_bytes())}
        raw,declaration=hd.generate(ROOT,case);path=self.root/'human-operator.py';path.write_bytes(raw);path.chmod(0o400)
        launcher=self.root/'human.sh';launcher.write_bytes(release.launcher('human',raw));launcher.chmod(0o600)
        cache=Path(str(launcher)+'.operator.py');cache.write_bytes(raw);cache.chmod(0o600)
        closure=d.sha(d.encoded(declaration))
        def call(*args):
            value=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(path),*args],capture_output=True,text=True,timeout=250)
            self.assertEqual(value.returncode,0,value.stdout+value.stderr);return json.loads(value.stdout)
        prepared=call('prepare');self.assertEqual(prepared['engineRequests'],12)
        self.assertFalse(prepared['newBudgetGranted']);self.assertFalse(prepared['newHumanWindowOpened'])
        grant=self.tty_mode(launcher,'grant-budget','CONCEDO BUDGET OAUTH 292->296 ')
        self.assertEqual(grant['additionalOAuthAttemptsGranted'],4)
        self.assertEqual(call('budget-status')['decisionHash'],grant['decisionHash'])
        opened=self.tty_mode(launcher,'open-window','APRO FINESTRA HUMAN ');control=opened['controlPath']
        self.assertEqual(call('status',control)['attempts'],292)
        issuer=self.old.selection['issuer'];responses=[
            (200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
                ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE','device_code':'PRIVATE','expires_in':600,'interval':5},0),
            (200,{'access_token':self.old.token(),'refresh_token':'PRIVATE_FRESH_REFRESH','token_type':'Bearer'},0),
            (200,{'sub':self.old.selection['subject']},0)]
        # The actual child used unchanged verified-memory sources above. Parent
        # annotations identify those same bytes only for synthetic HTTP replies;
        # no production implementation is changed in any isolated child.
        annotations=[(g,case['governanceSourceHash']),(op,self.case['controlSourceHash']),
            (e,manifest['sourceHashes'][e.__name__]),(custody,manifest['sourceHashes'][custody.__name__])]
        from contextlib import ExitStack
        with ExitStack()as stack:
            for module,digest in annotations:stack.enter_context(patch.object(module,'__qualified_source_sha256__',digest,create=True))
            stack.enter_context(patch.object(operator,'terminal_confirm',return_value=True))
            stack.enter_context(patch.object(operator,'terminal_notice'))
            http=stack.enter_context(patch.object(ExplicitFreshSession,'_http',side_effect=responses))
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],293)
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],294)
            _,cfg,b=g.load(control,case,closure);journal=e.Journal(b['sessionDirectory']);row=journal.read()
            journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],295)
            ready=g.execute('step',control,case,{},closure);self.assertEqual(ready['attempts'],296)
            self.assertEqual(http.call_count,4)
        self.profile=Path(ready['privateHumanReadProfilePath'])
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
        # Fixture server accepts exactly the fresh synthetic bearer. Its Owner
        # payload/revision/generation and all real runtime frames remain fixed.
        data=json.loads(self.native.owner_data.read_bytes());data['bearer']=responses[2][1]['access_token']
        self.native.owner_data.chmod(0o600);self.native.owner_data.write_bytes(e.c.encoded(data));self.native.owner_data.chmod(0o400)
        return {'realBudgetAndWindowTty':True,'cachedHashCheckedForegroundLaunchers':True,
            'preLoginExactEngineGets':12,'syntheticProviderRequests':4,
            'priorOAuthAttempts':292,'readyOAuthAttempts':296,'oldSessionBytesUnchanged':True}
    def test_whole_capsule_through_real_tty_and_every_native_stage(self):
        launcher=self.root/'runtime.sh';launcher.write_bytes(release.launcher('runtime',self.path.read_bytes()));launcher.chmod(0o600)
        cache=Path(str(launcher)+'.operator.py');cache.write_bytes(self.path.read_bytes());cache.chmod(0o600)
        wrapped=subprocess.run(['bash',str(launcher),'preflight'],capture_output=True,text=True,timeout=190)
        self.assertEqual(wrapped.returncode,0,wrapped.stdout+wrapped.stderr)
        self.assertIn('PATCH_RUNTIME_PREFLIGHT_NO_AUTHORITY',wrapped.stdout)
        human_proof=self.fresh_human_governance()
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
            'syntheticHumanAndOwner':True,'targetEvidence':False,'notReleaseAcceptance':True,
            'freshHumanGovernance':human_proof}),flush=True)

if __name__=='__main__':unittest.main()
