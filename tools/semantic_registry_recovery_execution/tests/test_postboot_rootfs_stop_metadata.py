"""Retained-only metadata observation using actual protected fixture files."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('rootfs_stop', ROOT/'scripts/inspect-registry-rootfs-stop-20261023.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class RootfsStop(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup); self.root = Path(tmp.name)
        self.boot = '00000000-1111-2222-3333-444444444444'; self.bootfile = self.root/'boot'; self.bootfile.write_text(self.boot)
        self.prep = self.root/'prepared'; self.prep.mkdir(mode=0o700); (self.prep/'authority').mkdir(mode=0o700)
        self.execution = self.root/('semantic-registry-recovery-'+'a'*64); self.execution.mkdir(mode=0o700); (self.execution/'node').mkdir(mode=0o700)
        self.ownerroot = self.root/'owner'; self.ownerroot.mkdir(mode=0o700)
        self.manifest = {'fixture':True}; self.scope = {'maximumRequests':{'databaseSessions':128,'gatewayAdminGets':64,'semanticGets':64}}
        self.seal = {'schema':'ouf.semantic-rootfs-seal.v1','sha256':'c'*64,'entries':10,'bytes':99}
        self.context = {'executionRoot':str(self.execution),'nodeRecipe':{'expectedRootfsSeal':self.seal},'plan':{
            'logicalOperationRef':'a'*64,'stages':[{'name': 'stage'+str(i)} for i in range(12)]}}
        self.refresh()
        self.write(self.prep/'authority/receipt.json',{'schema':'ouf.semantic-registry-postboot-issued-authority.v1','authorityHash':m.AUTHORITY_HASH,'reviewHash':m.REVIEW_HASH,'runtimeAuthorityIssued':True})
        self.journal = {'logicalOperationRef':'a'*64,'authorityHash':m.AUTHORITY_HASH,'bootId':self.boot,'nextStage':5,
            'effects':[{'stage':'stage'+str(i),'state':'APPLIED' if i<5 else 'CLAIMED'} for i in range(6)],
            'state':'IN_FLIGHT','readAttempts':47,'newGeneration':{'private':'not printed'},'expiresUnix':1}
        self.write(self.execution/'recovery.json',self.journal)
        self.owner = {'contextRef':'a','generationRef':'b','attempts':1,'controlledPredecessorGrantAttempts':319,
            'controlledCumulativeGrantAttempts':320,'state':'BLOCKED','reason':'private reason must not print'}
        self.write(self.ownerroot/'recovery.json',self.owner)
        self.write(self.execution/'native-reads.json',{'scopeHash':m.digest(self.scope),'authorityHash':m.AUTHORITY_HASH,'counts':dict.fromkeys(self.scope['maximumRequests'],0)})
        self.write(self.execution/'node/frame-policy.json',{'private':'do not print'})
        for key,value in {'PARENT':str(self.root),'PREPARATION_ROOT':str(self.prep)}.items():
            p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)
        real=Path;p=patch.object(m,'Path',side_effect=lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v));p.start();self.addCleanup(p.stop)

    def write(self,path,value): path.write_bytes(m.encoded(value));path.chmod(0o600)

    def refresh(self):
        prepared={'nativeContext':self.context,'ownerContext':{'fixture':True},'sourceClosure':self.manifest}
        review={'currentContext':self.context,'ownerContext':prepared['ownerContext'],'sourceClosure':self.manifest,
            'sourceClosureHash':m.digest(self.manifest),'bootId':self.boot,'scopes':{
                'semanticRegistryPostbootOwner':{'journalPath':str(self.ownerroot),'contextRef':'a','generationRef':'b'},
                'semanticRegistryRecoveryReads':self.scope}}
        self.write(self.prep/'prepared.json',prepared);self.write(self.prep/'review.json',review)
        case={'fixture':True};decl={'nativeDeclaration':self.manifest,'caseHash':m.digest(case)}
        cap=self.root/'capsule.py';cap.write_text('CASE='+repr(case)+'\nDELIVERY='+repr(decl)+'\nDELIVERY_HASH='+repr(m.digest(decl))+"\nPACKED=''\nBOOTSTRAP='raise AssertionError(\"must not execute\")'\n");cap.chmod(0o600)
        for key,value in {'CAPSULE':str(cap),'CAPSULE_HASH':hashlib.sha256(cap.read_bytes()).hexdigest(),
            'CLOSURE_HASH':m.digest(self.manifest),'DECLARATION_HASH':m.digest(decl),
            'PREPARATION_HASH':m.digest(prepared),'REVIEW_HASH':m.digest(review)}.items():
            p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)
        if (self.prep/'authority/receipt.json').exists():
            self.write(self.prep/'authority/receipt.json',{'schema':'ouf.semantic-registry-postboot-issued-authority.v1','authorityHash':m.AUTHORITY_HASH,'reviewHash':m.REVIEW_HASH,'runtimeAuthorityIssued':True})

    def test_consumed_grant_and_claimed_effect_retained_without_any_effect_or_secret_output(self):
        before={p:(p.read_bytes(),p.stat()) for p in self.root.rglob('*.json')}
        result=m.inspect(m.Reader());self.assertEqual(result['checkpoint'],5);self.assertEqual(result['retainedControlledGrantAttempts'],320)
        self.assertFalse(result['effects'][5]['nativeAttestationAttempted']);self.assertFalse(result['currentRootfsRead'])
        self.assertFalse(result['pausedObservationRetained']);self.assertEqual(result['expectedSealShape']['entries'],10)
        self.assertEqual(before,{p:(p.read_bytes(),p.stat()) for p in before})
        self.assertNotIn(str(self.root),json.dumps(result));self.assertNotIn('private',json.dumps(result));self.assertEqual(result['oauthRequests'],0)

    def test_string_expected_seal_is_observable_without_accepting_it(self):
        self.context['nodeRecipe']['expectedRootfsSeal']='c'*64;self.refresh()
        result=m.inspect(m.Reader());self.assertTrue(result['expectedSealShape']['string']);self.assertFalse(result['expectedSealShape']['exactKeys'])

    def test_retained_mismatching_observation_is_reported_without_becoming_authority(self):
        self.write(self.execution/'node/paused-observation.json',{'rootfsSeal':dict(self.seal,bytes=100)})
        result=m.inspect(m.Reader());self.assertFalse(result['retainedSealMatchesExpected']);self.assertFalse(result['runtimeAuthorityIssued'])

    def test_tampered_preparation_rejected(self):
        self.write(self.prep/'prepared.json',{'tamper':True})
        with self.assertRaisesRegex(ValueError,'METADATA_HASH_OR_BYTE_BOUND'):m.inspect(m.Reader())

    def test_invalid_owner_budget_or_scope_rejected(self):
        for key,value in [('attempts',2),('controlledCumulativeGrantAttempts',319),('contextRef','wrong')]:
            with self.subTest(key=key):
                self.write(self.ownerroot/'recovery.json',dict(self.owner,**{key:value}))
                with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_OWNER_ACCOUNTING'):m.inspect(m.Reader())

    def test_linked_journal_rejected(self):
        p=self.execution/'recovery.json';p.unlink();p.symlink_to(self.ownerroot/'recovery.json')
        with self.assertRaises(OSError):m.inspect(m.Reader())

    def test_concurrent_journal_movement_rejected_without_lock_or_write(self):
        class Moving(m.Reader):
            def __init__(self):super().__init__();self.n=0
            def json(inner,path,*args,**kwargs):
                row=super(Moving,inner).json(path,*args,**kwargs)
                if path==str(self.execution/'recovery.json'):
                    inner.n+=1
                    if inner.n==2:row['nextStage']=6
                return row
        with self.assertRaisesRegex(ValueError,'STOP_METADATA_CHANGED_DURING_OBSERVATION'):m.inspect(Moving())


if __name__=='__main__':unittest.main()
