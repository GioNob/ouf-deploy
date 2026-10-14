"""Terminal witness delivery checks; actual IAM signer/action is qualified separately."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('approved_delivery',ROOT/'scripts/apply-policy-token-exact-reviewed-iam.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

class ApprovedDeliveryTest(unittest.TestCase):
    def test_portable_cli_pinned_capsule_and_exact_root_target_binding(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            home=Path(directory);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
            gh.parent.mkdir(parents=True);gh.write_text('SYNTHETIC');gh.chmod(0o700)
            raw=(ROOT/'releases/policy-token-iam-action-source-capsule-20261013.json').read_bytes();calls=[]
            def run(args,**kw):
                calls.append(args)
                if args[0]=='sudo':
                    self.assertEqual(args[:6],['sudo','--','/usr/bin/python3','-I','-B','-S'])
                    self.assertIn(repr(delivery.REVIEW_HASH),args[-1]);self.assertIn(repr(delivery.CLOSURE_HASH),args[-1])
                    self.assertEqual(kw['input'],raw);self.assertEqual(kw['timeout'],440)
                    return subprocess.CompletedProcess(args,0)
                self.assertEqual(args[0],str(gh));self.assertIn(delivery.CAPSULE_COMMIT,args[2])
                return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(raw))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),patch.object(delivery.subprocess,'run',side_effect=run):
                self.assertEqual(delivery.main(),0)
            self.assertEqual(len(calls),2)
    def test_capsule_drift_denies_before_privileged_launch(self):
        calls=[]
        def changed(args,**kw):calls.append(args);return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(b'CHANGED'))
        with patch.object(delivery.shutil,'which',return_value='/fixture/gh'),patch.object(delivery.subprocess,'run',side_effect=changed):
            with self.assertRaisesRegex(SystemExit,'HASH_MISMATCH'):delivery.main()
        self.assertFalse(any(c[0]=='sudo' for c in calls))
    def fixture(self,directory,drift=False,cli_deny=False):
        # Deliberately synthetic entry. This verifies the real isolated launcher
        # and terminal/witness boundary, not provider semantics or source closure.
        declaration={'syntheticFixture':True}
        closure={'declaration':declaration}
        closure_hash=hashlib.sha256(json.dumps(closure,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        review={'schema':'ouf.policy-token-iam-owner-action-review.v1','sourceClosureHash':closure_hash,
            'sourceClosure':closure,'maximumIamPostAttempts':1,'maximumExistingRoleSignatures':2,
            'authorityLifetimeSeconds':240,'requiredFirstInvocationWindowSeconds':900,
            'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'policyTokenIamPreparation':{'resource':'clients/11111111-1111-1111-1111-111111111111/protocol-mappers/models'}}
        raw=json.dumps(review,sort_keys=True,separators=(',',':')).encode();review_hash=hashlib.sha256(raw).hexdigest()
        (Path(directory)/('policy-token-iam-action-review-'+review_hash+'.private.json')).write_bytes(raw if not drift else b'CHANGED')
        loader='''
import contextlib,hashlib,json,os,pathlib,time,types,subprocess
PARENT=pathlib.Path(DIRECTORY)
class Denied(Exception):pass
def require(value,reason):
    if not value:raise Denied(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
@contextlib.contextmanager
def protected_parent():yield PARENT
binding=types.SimpleNamespace(PARENT=PARENT,CandidateDenied=Denied,require=require,encoded=encoded,
    decode=json.loads,sha=lambda raw:hashlib.sha256(raw).hexdigest(),protected_parent=protected_parent,
    read_member=lambda directory,name:(directory/name).read_bytes())
def publish(directory,name,raw):
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return True
def main(manifest,**kw):
    require(kw['mode']=='apply','FIXTURE_WRONG_MODE')
    decision=kw['decision'];require(decision['approvedAt']<=int(time.time())<decision['firstInvocationBefore'],'FIXTURE_EXPIRED')
    witness=list(PARENT.glob('policy-token-iam-human-witness-*.private.json'))
    require(len(witness)==1,'FIXTURE_WITNESS_MISSING')
    body=witness[0].read_bytes();require(decision['approvalRef']=='human-iam-'+binding.sha(body),'FIXTURE_WITNESS_HASH_DRIFT')
    require((witness[0].stat().st_mode&0o777)==0o600,'FIXTURE_WITNESS_CUSTODY')
    print(encoded({'status':'SYNTHETIC_ENTRY_CALLED','decision':decision,'witness':json.loads(body)}).decode());return 0
def fake_cli(args,**kw):
    require(args==['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh','get',
        'clients/11111111-1111-1111-1111-111111111111','--server','http://localhost:8080','-r','ouf','--fields','id'],'FIXTURE_UNEXPECTED_CLI')
    if CLI_DENY:
        kw['stderr'].write(b'Session has expired: SYNTHETIC_PRIVATE_TEXT');return types.SimpleNamespace(returncode=1)
    kw['stdout'].write(encoded({'id':'11111111-1111-1111-1111-111111111111'}));return types.SimpleNamespace(returncode=0)
def load_entry(*args):
    subprocess.run=fake_cli
    return types.SimpleNamespace(binding=binding,publish=publish,main=main,inputs=lambda directory:None),DECLARATION
'''
        loader='DIRECTORY='+repr(directory)+'\nDECLARATION='+repr(declaration)+'\nCLI_DENY='+repr(cli_deny)+'\n'+loader
        capsule={'schema':'ouf.policy-token-iam-action-memory-capsule.v1','sourceCommit':'a'*40,
            'loader':base64.b64encode(loader.encode()).decode(),'sources':{},'declarationHash':'b'*64}
        raw=json.dumps(capsule).encode()
        code='CAPSULE_SHA='+repr(hashlib.sha256(raw).hexdigest())+'\nREVIEW_HASH='+repr(review_hash)+'\nCLOSURE_HASH='+repr(closure_hash)+'\n'+delivery.ROOT_BODY
        return raw,code,review_hash
    def isolated(self,directory,answer=None,drift=False,cli_deny=False):
        raw,code,review_hash=self.fixture(directory,drift,cli_deny)
        master=slave=None;setup=None
        if answer is not None:
            import fcntl,termios
            master,slave=os.openpty()
            def setup():os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
        proc=subprocess.Popen([sys.executable,'-I','-B','-S','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            preexec_fn=setup,pass_fds=(() if slave is None else (slave,)),start_new_session=answer is None)
        try:
            if master is not None:os.write(master,('APPROVO IAM '+review_hash+'\n' if answer=='APPROVE' else answer+'\n').encode())
            out,err=proc.communicate(raw,timeout=8)
            self.assertEqual(err,b'');return proc.returncode,json.loads(out)
        finally:
            if proc.poll()is None:proc.kill();proc.communicate()
            if master is not None:os.close(master);os.close(slave)
    def test_actual_isolated_terminal_approval_publishes_hash_bound_witness(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            code,report=self.isolated(directory,'APPROVE')
            self.assertEqual(code,0);self.assertEqual(report['status'],'SYNTHETIC_ENTRY_CALLED')
            self.assertEqual(report['witness']['approvedReviewHash'],report['decision']['approvedReviewHash'])
            self.assertEqual(report['witness']['approvedSourceClosureHash'],report['decision']['approvedSourceClosureHash'])
            self.assertEqual(report['decision']['firstInvocationBefore']-report['decision']['approvedAt'],900)
    def test_no_terminal_refusal_and_review_drift_never_call_action(self):
        for answer,drift,reason in [(None,False,'OSError'),('NO',False,'APPROVAL_NOT_GIVEN'),('APPROVE',True,'REVIEW_HASH_DRIFT')]:
            with tempfile.TemporaryDirectory(dir=ROOT)as directory:
                code,report=self.isolated(directory,answer,drift)
                self.assertEqual(code,1);self.assertEqual(report['status'],'BLOCKED');self.assertIn(reason,report['reason'])
                self.assertFalse(report['installationKeyAccessAttempted']);self.assertEqual(report['iamMutations'],0)
                self.assertEqual(list(Path(directory).glob('policy-token-iam-human-witness-*')),[])

    def test_expired_session_is_diagnosed_before_approval_witness_or_issuance(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            code,report=self.isolated(directory,'APPROVE',cli_deny=True)
            self.assertEqual(code,1);self.assertEqual(report['reason'],'EXISTING_IAM_SESSION_PREFLIGHT_FAILED')
            self.assertEqual(report['diagnosticCategories'],['SESSION_AUTH_FAILURE_TEXT_OBSERVED'])
            self.assertEqual(report['iamMetadataGetAttempts'],1)
            self.assertNotIn('SYNTHETIC_PRIVATE_TEXT',json.dumps(report))
            self.assertEqual(list(Path(directory).glob('policy-token-iam-human-witness-*')),[])

if __name__=='__main__':unittest.main()
