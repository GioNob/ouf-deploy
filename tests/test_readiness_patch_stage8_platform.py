"""Whole four-stage continuation on real Docker/APISIX/JVM/Postgres.

Only provider replies, Owner identity and modeled predecessor expiry are
synthetic. Isolated new runtime/HUMAN capsules are never patched in the child.
"""
import copy,hashlib,json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_successor_platform as base
import test_readiness_patch_stage8_governance as human_fixture
import test_readiness_patch_operator_delivery as delivery_fixture
from tools.ingestion_readiness_patch_execution import stage8_delivery as d,stage8_human as g,stage8_continuation as op
from tools.ingestion_readiness_patch_execution import operator_delivery_v2 as old_delivery,release_delivery_v2 as release
from tools.ingestion_readiness_patch_execution import stage8_live_delivery as capture_delivery,stage8_live_inputs as live
from tools.ingestion_readiness_patch_execution import stopped_patch_snapshot as snap,entry_v2 as e,custody
from tools.governed_human_successor import operator
from tools.governed_human_successor.session import ExplicitFreshSession

@unittest.skipUnless(os.environ.get('OUF_ISOLATED_NATIVE_PLATFORM')=='1','disposable platform required')
class Stage8ContinuationPlatform(base.WholeControllerPlatform):
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
                        # sudo's own PTY can translate the outer PTY newline
                        # twice. Accept CR/LF framing only; phrase bytes stay exact.
                        match=re.search(rb'Scrivi(?: esattamente)?: ([^\r\n]+)[\r\n]+> ',output)
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
        config=human_fixture.expired_previous(self);manifest=self.stage8_manifest
        case={'schema':g.SCHEMA,'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'runtimeCase':self.case,'nativeDeclaration':manifest,'predecessorControlPath':str(self.oldcontrol),
            'predecessorReviewHash':e.c.digest(config['review']),'humanOperatorTransportProfile':dict(operator.TRANSPORT),
            'governanceSourceHash':old_delivery.sha((ROOT/'tools/ingestion_readiness_patch_execution/stage8_human.py').read_bytes())}
        raw,declaration=d.human_generate(ROOT,case);path=self.root/'human-operator.py';path.write_bytes(raw);path.chmod(0o400)
        launcher=self.root/'human.sh';launcher.write_bytes(release.launcher('human',raw));launcher.chmod(0o600)
        cache=Path(str(launcher)+'.operator.py');cache.write_bytes(raw);cache.chmod(0o600)
        closure=e.c.digest(declaration)
        def call(*args):
            value=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(path),*args],capture_output=True,text=True,timeout=250)
            self.assertEqual(value.returncode,0,value.stdout+value.stderr);return json.loads(value.stdout)
        prepared=call('prepare');self.assertEqual(prepared['engineRequests'],14)
        self.assertFalse(prepared['newBudgetGranted']);self.assertFalse(prepared['newHumanWindowOpened'])
        grant=self.tty_mode(launcher,'grant-budget','CONCEDO BUDGET OAUTH 300->304 ')
        self.assertEqual(grant['additionalOAuthAttemptsGranted'],4)
        self.assertEqual(call('budget-status')['decisionHash'],grant['decisionHash'])
        opened=self.tty_mode(launcher,'open-window','APRO FINESTRA HUMAN ');control=opened['controlPath']
        self.assertEqual(call('status',control)['attempts'],300)
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
            (e,manifest['sourceHashes'][e.__name__]),(custody,manifest['sourceHashes'][custody.__name__]),
            (live,manifest['sourceHashes'][live.__name__])]
        from contextlib import ExitStack
        with ExitStack()as stack:
            for module,digest in annotations:stack.enter_context(patch.object(module,'__qualified_source_sha256__',digest,create=True))
            stack.enter_context(patch.object(operator,'terminal_confirm',return_value=True))
            stack.enter_context(patch.object(operator,'terminal_notice'))
            http=stack.enter_context(patch.object(ExplicitFreshSession,'_http',side_effect=responses))
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],301)
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],302)
            _,cfg,b=g.load(control,case,closure);journal=e.Journal(b['sessionDirectory']);row=journal.read()
            journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
            self.assertEqual(g.execute('step',control,case,{},closure)['attempts'],303)
            ready=g.execute('step',control,case,{},closure);self.assertEqual(ready['attempts'],304)
            self.assertEqual(http.call_count,4)
        self.profile=Path(ready['privateHumanReadProfilePath'])
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
        # Fixture server accepts exactly the fresh synthetic bearer. Its Owner
        # payload/revision/generation and all real runtime frames remain fixed.
        data=json.loads(self.native.owner_data.read_bytes());data['bearer']=responses[2][1]['access_token']
        self.native.owner_data.chmod(0o600);self.native.owner_data.write_bytes(e.c.encoded(data));self.native.owner_data.chmod(0o400)
        return {'realBudgetAndWindowTty':True,'cachedHashCheckedForegroundLaunchers':True,
            'preLoginExactEngineGets':14,'syntheticProviderRequests':4,
            'priorOAuthAttempts':300,'readyOAuthAttempts':304,'oldSessionBytesUnchanged':True}
    def test_whole_capsule_through_real_tty_and_every_native_stage(self):
        self.call('review',str(self.profile));review=json.loads((self.target/'review.json').read_bytes())
        delivery_fixture.OperatorDelivery.tty_approve(self,'APPROVO '+e.c.digest(review));self.call('initialize')
        n=next(i+1 for i,s in enumerate(review['executionReview']['stages'])if s['name']=='ingestion.START_REPLACEMENT')
        for _ in range(n):self.call('step')
        previous=self.target;native=e.Journal(previous);row=native.read();expired=time.time()-10
        native.compare_and_save(row,{**row,'expiresAt':expired,'expiresMonotonic':time.monotonic()-10})
        ctl=e.Journal(previous/'operator-control');r=ctl.read();ctl.compare_and_save(r,{**r,'state':'RECONCILE_REQUIRED'})
        sc={'contextPath':str(previous),'runtimeCaseHash':e.c.digest(self.case),'nextStage':n,
            'readAttempts':native.read()['readAttempts'],'recordedExpiresAt':expired}
        capturecase={'schema':live.SCHEMA,'snapshotCase':sc,'expectedSnapshot':snap.inspect(sc),
            'readerSourceHash':old_delivery.sha((ROOT/'tools/ingestion_readiness_patch_execution/stage8_live_inputs.py').read_bytes())}
        raw,_=capture_delivery.generate(ROOT,capturecase);p=self.root/'capture.py';p.write_bytes(raw)
        result=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(p),'prepare'],capture_output=True,text=True,timeout=250)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);receipt=json.loads(result.stdout)
        oldrow=native.read();oldbytes={str(p):p.read_bytes()for p in previous.rglob('*')if p.is_file()}
        _,oldmanifest=base.successor_manifest()
        _,manifest=d.core(ROOT,oldmanifest['sourceCommit'],oldmanifest['sourcePins']);self.stage8_manifest=manifest
        qualification=copy.deepcopy(self.case['qualification']);qualification['sourceHashes']=manifest['sourceHashes']
        self.case={'schema':op.SCHEMA,'capturePath':receipt['contextPath'],'captureHash':receipt['privateCaptureHash'],
            'expectedCaptureReceipt':receipt,'nativeDeclarationHash':e.c.digest(manifest),
            'controlSourceHash':manifest['sourceHashes'][op.__name__],'qualification':qualification,
            'requiredCumulativeOAuthAttempts':304,'maximumRuntimeSeconds':900}
        self.path=self.root/'stage8-runtime.py';raw,_=d.generate(ROOT,self.case,manifest);self.path.write_bytes(raw)
        self.target=op.context(self.case)
        self.assertTrue(self.call('preflight')['complete'])
        human_proof=self.fresh_human_governance()
        self.call('review',str(self.profile));selected=json.loads((self.target/'review.json').read_bytes())
        launcher=self.root/'runtime-stage8.sh';launcher.write_bytes(d.launcher(raw));launcher.chmod(0o600)
        cache=Path(str(launcher)+'.operator.py');cache.write_bytes(raw);cache.chmod(0o600)
        self.tty_mode(launcher,'approve','APPROVO ')
        imported=self.call('import-prefix');self.assertEqual(imported['nextStage'],n)
        initial=e.Journal(self.target).read()
        self.assertEqual(initial['effects'],oldrow['effects']);self.assertEqual(initial['readAttempts'],oldrow['readAttempts'])
        self.assertEqual(initial['nativeDirectEnginePosts'],oldrow['nativeDirectEnginePosts'])
        for _ in range(4):self.call('step')
        self.assertTrue(self.call('step')['complete']);final=e.Journal(self.target).read()
        self.assertEqual(final['nextStage'],n+4)
        self.assertEqual(final['nativeDirectEnginePosts']-oldrow['nativeDirectEnginePosts'],1)
        self.assertEqual(final['readAttempts'],oldrow['readAttempts']+4)
        self.assertEqual(oldbytes,{str(p):p.read_bytes()for p in previous.rglob('*')if p.is_file()})
        created=next(v['nativeResource']['containerId']for v in oldrow['effects']if v['stage']=='ingestion.CREATE_REPLACEMENT')
        self.assertEqual(self.native.inspect(created)['HostConfig']['RestartPolicy'],self.native.packet['frames']['ingestion']['restoreRestartPolicy'])
        print('OUF_STAGE8_CONTINUATION_PROOF='+json.dumps({'complete':True,'sealedNativeModules':len(manifest['sourceHashes']),
            'prefixImportedWithoutReplay':True,'oldPrefixBytesUnchanged':True,'nativeCountersPreserved':True,
            'remainingStagesExecuted':4,'additionalEnginePosts':1,'newImagesOrKeys':0,'gatewayWrites':0,
            'syntheticStopAndExpiry':True,'syntheticHumanAndOwner':True,'targetEvidence':False,'humanGovernance':human_proof}),flush=True)

if __name__=='__main__':unittest.main()
