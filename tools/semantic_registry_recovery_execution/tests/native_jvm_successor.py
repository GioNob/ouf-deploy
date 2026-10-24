"""Real expired-epoch/current-boot owner handoff from stopped Registry to GET200.

All native owners, Engine/process/OCI/rootfs/database/TLS/crypto/fence checks run
unchanged. Only disposable IAM/HUMAN, forwarding proxy, seeded read data and
absent legacy systemd units are fixtures, as in native_jvm_postboot.py. Six
explicit empty directories inject the actual seal failure; only these are
removed. This does not establish VPS health or production renewal/acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_jvm_postboot as j
from tools.semantic_registry_recovery_execution import bootstrap,resumption_install
from tools.semantic_registry_recovery_execution import core as c,resumption
from tools.semantic_registry_recovery_execution.postboot_scopes import compile_scopes
from tools.semantic_registry_recovery_execution.postboot_factory import build_on_bootstrap
from tools.semantic_registry_recovery_execution.postboot_controller import ColdStartWait
from tools.semantic_registry_recovery_execution.semantic_request import OriginalSemanticRequest
from tools.semantic_registry_postboot_owner import contract as owner_contract,installer as owner_installer
from cutover_authority import CutoverAuthority
from file_only_profile import PROFILE


class NativeJvmSuccessor(j.NativeJvmPostboot):
    test_full_native_pause_owner_oci_database_release_and_same_service_get=None
    authority_window_seconds=150
    journal_window_seconds=120
    human_window_seconds=180

    def setUp(self):
        super().setUp()
        # Disposable trust keys must outlive both real finite authority epochs
        # and the deliberate expiry wait. This changes only fixture key policy,
        # never an authority/journal/token clock or any production trust input.
        policy=json.loads(self.policy.read_bytes())
        expires=int(time.time())+1200
        for key in policy['keys']:key['expiresAt']=expires
        self.grant['expiresAt']=expires
        self.write(self.policy,c.encoded(policy));self.verifier.policy_binding=self.binding(self.policy)

    def image_root(self):
        actual=self.inspect();recipe=self.recipe['dockerContext']
        if recipe.get('rootfsLayout')=='docker-containerd-overlayfs-v1':
            root=Path(recipe['storageParent'])/'rootfs/overlayfs'/self.cid
        else:root=Path(actual['GraphDriver']['Data']['MergedDir'])
        self.assertTrue(root.is_absolute() and root.is_relative_to(self.daemon_root))
        return root

    def test_real_expiry_failed_seal_cancelled_owner_handoff_and_original_get_200(self):
        # The preceding independent JVM case proves the original GET502. This
        # exact target-scope replay must start with semanticGets==0; performing
        # another preliminary SERVICE GET here would consume a real request
        # and change the inherited ledger. Never decrement or bypass it.
        self.assertEqual(self.inspect()['State']['Status'],'exited')
        self.assertFalse(self.inspect()['State']['Running'])
        self.install_owner()
        worker,coordination,stop,thread,statuses=self.run_worker()
        self.assertEqual(statuses[-1]['state'],'ACTIVE',statuses[-1])
        self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],320)
        root=self.image_root();residue=[]
        parent=root/'tmp'
        self.assertTrue(parent.is_dir())
        for index in range(6):
            parent=parent/('ouf-explicit-successor-residue-'+str(index))
            parent.mkdir(mode=0o700);os.chown(parent,10001,10001);residue.append(parent)
        with coordination:
            runner=build_on_bootstrap(self.runner,self.native_context,self.owner_context,
                self.current_authority,self.authority,self.verifier,self.node_signer)
            with self.assertRaisesRegex(c.RecoveryDenied,'INDEPENDENT_IMAGE_ROOTFS_SEAL_MISMATCH'):
                runner.step()
            failed=self.store.read()
            self.assertEqual(failed['nextStage'],4);self.assertEqual(failed['readAttempts'],5)
        stop.set();thread.join(35);self.assertFalse(thread.is_alive())
        old_owner=worker.r.journal.read()
        self.assertEqual(old_owner['state'],'CANCELLED')
        self.assertEqual(old_owner['controlledCumulativeGrantAttempts'],320)
        for path in reversed(residue):
            self.assertEqual(list(path.iterdir()),[]);path.rmdir()
        self.assertEqual(j.rootfs_seal(str(root),j.LIMITS,j.Budget()),self.recipe['expectedRootfsSeal'])
        old=self.store.read();reads=self.budget.read()
        self.assertEqual(reads['counts'],{'databaseSessions':1,'gatewayAdminGets':6,'semanticGets':0})
        old_scope=owner_contract.compile_scope(self.owner_context)
        predecessor=Path(old_scope['journalPath'])
        names=('owner-session.json','owner-admission.json','owner-first-grant.json')
        records={name:json.loads((predecessor/name).read_bytes()) for name in names}
        before_records={name:(predecessor/name).read_bytes() for name in (*names,'recovery.json')}
        maintenance={'status':'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED','complete':True,
            'originalIndependentRootfsSealMatches':True,'expectedRootfsSealUnchanged':True,
            'samePausedGenerationBeforeAndAfter':True,'directoryRemovalAttempts':6,
            'directoryRemovalsConfirmed':6,'retainedControlledGrantAttempts':320,'javaReleased':False}
        value={'schema':'ouf.semantic-registry-resumption-inputs.v1','newGrantAllowance':0,
            'retainedControlledGrantAttempts':320,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'retainedNativeJournal':old,'retainedNativeReads':reads,'retainedOwnerJournal':old_owner,
            'retainedOwnerRecords':records,'retainedFence':old_scope['fenceBinding'],'maintenanceResult':maintenance,
            'identity':{'nativeJournalHash':c.digest(old),'ownerJournalHash':c.digest(old_owner),
                'maintenanceResultHash':c.digest(maintenance),'priorAuthorityHash':old['authorityHash'],'bootId':self.boot}}
        snapshot=self.root/'native-successor-inputs.json';self.write(snapshot,c.encoded(value));snapshot.chmod(0o400)
        following=copy.deepcopy(self.owner_context)
        following.update(schema='ouf.semantic-registry-postboot-successor-owner-context.v1',
            predecessorContext=copy.deepcopy(self.owner_context),resumptionInputs=value,
            resumptionBinding={'path':str(snapshot),'sha256':c.digest(value)},
            predecessorJournalPath=str(predecessor),retainedRecords={**records,'recovery.json':old_owner},
            budget={'maximumGrantAttempts':1,'maximumSeconds':300,'attemptTimeoutSeconds':30,'intervalSeconds':60})
        owner_contract.compile_scope(following)
        raw=json.loads(self.authority);old_authority=self.current_authority;old_raw=self.authority
        print(json.dumps({'schema':'ouf.native-successor-qualification-progress.v1',
            'status':'WAITING_FOR_REAL_PREDECESSOR_AUTHORITY_EXPIRY','retainedControlledGrantAttempts':320,
            'nativeCheckpoint':4,'maximumRemainingSeconds':max(0,raw['expiresAt']-time.time())}),flush=True)
        while time.time()<=raw['expiresAt']:
            time.sleep(min(1,max(.01,raw['expiresAt']-time.time()+.01)))
        with self.assertRaises(Exception):old_authority(old_raw)
        with self.assertRaises(c.RecoveryDenied):self.runner.current()
        self.assertEqual(self.store.read(),old)
        now=int(time.time());raw.update(issuedAt=now,expiresAt=now+300)
        history=json.loads(Path(self.native_context['retainedInputs']['path']).read_bytes())
        raw.update(compile_scopes(self.native_context,following,history['registryInputs'],self.profile,self.boot))
        self.authority=c.encoded(raw)
        self.approval.update(issuedAt=now,expiresAt=now+360,approvalRef='native-successor-'+uuid.uuid4().hex,
            executionAuthorityHash=hashlib.sha256(self.authority).hexdigest())
        self.write(self.mandate,c.encoded(self.approval));self.approved=hashlib.sha256(self.mandate.read_bytes()).hexdigest()
        for role in self.grant['roles']:self.sign(role)
        self.current_authority=CutoverAuthority(self.verifier,self.binding(self.mandate),self.approved,
            self.context,self.expected,self.clock,execution_profile=self.profile)
        self.assertTrue(self.current_authority(self.authority))
        installed=resumption_install.install(self.native_context,following,self.current_authority,self.authority)
        self.assertEqual(installed['lifecycleEffectsDispatched'],0)
        self.assertEqual(self.store.read()['effects'],old['effects'])
        self.assertEqual(resumption_install.read_counts(self.store.root)['counts'],reads['counts'])
        self.assertEqual(self.inspect()['State']['Pid'],old['newGeneration']['pid'])
        self.assertTrue(self.inspect()['State']['Paused'])
        self.owner_context=following
        self.runner=bootstrap.build(self.native_context,self.current_authority,self.authority)
        self.ports=self.runner.ports;self.lifecycle=self.ports.lifecycle
        self.gateway=self.ports.gateway;self.budget=self.gateway.budget
        owner_installer.install(following,self.current_authority,self.authority,self.ports.witness)
        worker,coordination,_,_,statuses=self.run_worker()
        self.assertEqual(statuses[-1]['state'],'ACTIVE',statuses[-1])
        self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'],321)
        with coordination:
            runner=build_on_bootstrap(self.runner,self.native_context,following,self.current_authority,
                self.authority,self.verifier,self.node_signer)
        deadline=time.monotonic()+180;cold=ColdStartWait()
        while True:
            delay=None
            with coordination:
                cold.before_poll(runner,self.ports.witness);before=runner.current()
                if before['nextStage']==12:break
                try:row=runner.step()
                except Exception:self.diagnose_native();raise
                if row['nextStage']==before['nextStage']:delay=cold.defer(runner,before,row,self.ports.witness)
                self.assertLess(time.monotonic(),deadline,'Finite successor JVM recovery did not settle')
            if delay is not None:time.sleep(delay)
        row=runner.current()
        self.assertTrue(row['originalSemanticGetSucceeded'])
        self.assertEqual(row['effects'][-1]['nativeEvidence']['httpStatus'],200)
        self.assertEqual(row['effects'][:4],old['effects'][:4])
        self.assertEqual(row['resumption']['predecessorJournal'],old)
        self.assertEqual(row['effects'][4]['completionAuthorityHash'],hashlib.sha256(self.authority).hexdigest())
        self.assertEqual(self.iam_app.grant_count,2)
        self.assertEqual(before_records,{name:(predecessor/name).read_bytes() for name in before_records})
        self.assertEqual([e['stage'] for e in row['effects'] if e.get('nativeRequestAttempted')],
            ['START_NEW_WAIT_GATE','PAUSE_NEW_WAIT_GATE','UNPAUSE_ATTESTED_GENERATION','RELEASE_SAME_GENERATION_SIGUSR1'])
        with self.assertRaises(c.RecoveryDenied):
            resumption_install.install(self.native_context,following,self.current_authority,self.authority)
        print(json.dumps({'schema':'ouf.native-successor-qualification-result.v1','status':'ORIGINAL_SERVICE_GET_200_AFTER_REAL_AUTHORITY_SUCCESSION',
            'initialRuntimeState':'EXITED','initialHttpStatusObservedInThisScope':False,
            'finalHttpStatus':200,'samePausedGenerationImported':True,
            'originalPrefixEffectsPreserved':True,'predecessorGrantAttempts':320,'controlledGrantAttempts':321,
            'newServiceGrantAttempts':1,'predecessorAuthorityReallyExpired':True,'readCountersPreserved':True,
            'targetExecutionPerformed':False,'permanentRenewalProven':False,'releaseAcceptance':False}),flush=True)

if __name__=='__main__':unittest.main()
