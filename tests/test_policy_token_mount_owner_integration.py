"""Real read-only mount + installed signed owner + native TLS introspection.

Only the existing HUMAN/legacy-unit fixture is synthetic. Admission, durable
publication lifetime, mount custody and token rotation are not mocked.
"""
import json,os,select,signal,subprocess,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_installed_token_owner as fixture_module
from test_renewable_token_mount import HELPER
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,LegacyWriterFence
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery,RenewalWorker
from tools.semantic_lease_recovery.bounded_recovery import Permanent

class MountedOwnerIntegration(unittest.TestCase):
    def setUp(self):
        if os.environ.get('OUF_NATIVE_MOUNTS')!='1':self.skipTest('Hosted root mount namespace is mandatory for this suite')
        fixture=fixture_module.InstalledOwnerTest();self.addCleanup(fixture.doCleanups)
        self.f,self.server,self.owner,recovery,self.source,self.output=fixture.fixture(scheduled=True)
        fence=patch.object(LegacyWriterFence,'guard',return_value=True);fence.start();self.addCleanup(fence.stop)
        r=ScheduledRecovery(recovery.journal,recovery.adapter,recovery.policy,recovery.context,recovery.generation,
            recovery.clock,lambda:.5,interval_seconds=60)
        self.worker=RenewalWorker(r);self.assertEqual(self.worker.tick()['state'],'ACTIVE')
        o=self.owner
        self.reader=InstalledTokenOwner(o.binding,o.credential,o.admission,o.journal,o.context,o.generation,
            o.manifest,self.f.gate(),self.f.authority,observer=True)
        self.target=self.f.root/'token-mount';self.target.mkdir(mode=0o700)
        process=subprocess.Popen(['/usr/bin/unshare','--mount','--propagation','private',
            '/usr/bin/python3','-I','-B','-c',HELPER,str(self.output),str(self.target),'yes'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if process.poll()is None:process.kill()
            process.wait(timeout=5);process.stdout.close();process.stderr.close()
        self.addCleanup(cleanup)
        self.assertTrue(select.select([process.stdout],[],[],10)[0])
        line=process.stdout.readline();self.assertTrue(line,process.stderr.read(4096).decode()if not line else '')
        pid=int(line);self.assertEqual(pid,process.pid);os.kill(pid,signal.SIGSTOP)
        _,status=os.waitpid(pid,os.WUNTRACED);self.assertTrue(os.WIFSTOPPED(status));self.generation=generation(pid)
        s=self.output.stat();self.policy={'source':str(self.output),'target':str(self.target),'fileName':'token.jwt',
            'gid':10001,'directoryDevice':s.st_dev,'directoryInode':s.st_ino,'ownerBindingHash':o.binding.digest(),
            'maxBytes':16384,'minimumRemainingSeconds':30}
        self.before_grants=self.grants();self.token=(self.output/'token.jwt').read_bytes()
        self.row=o.journal.read();self.marker=o.store.read()
    def grants(self):return sum(p.endswith('/token')for p,_ in self.server.calls)
    def observe(self):
        return RenewableTokenMountObservation(self.policy,self.reader,time.monotonic()+20).observe(self.generation)
    def unchanged(self):
        self.assertEqual(self.grants(),self.before_grants);self.assertEqual(self.owner.journal.read(),self.row)
        self.assertEqual(self.owner.store.read(),self.marker);self.assertEqual((self.output/'token.jwt').read_bytes(),self.token)
    def test_original_sixty_second_ceiling_reproduces_denial_but_real_publication_window_passes(self):
        self.assertEqual(self.owner.binding.minimum_remaining,90)
        with self.assertRaises(Permanent)as error:
            self.reader.admit(self.token.decode(),time.monotonic()+60,self.owner.binding.digest(),time.monotonic()+10)
        self.assertEqual(error.exception.code,'AUTHORITY_EXPIRED')
        result=self.observe();self.assertTrue(result['currentOwnerAdmissionObserved']);self.unchanged()
        for secret in ('FIXTURE_TOKEN','DISPOSABLE_FIXTURE_SECRET',str(self.output),'tokenExpires'):
            self.assertNotIn(secret,json.dumps(result))
    def test_short_durable_window_denies_even_if_issuer_token_is_still_valid(self):
        wall,mono=time.time(),time.monotonic();r=self.owner.journal
        r.compare_and_save(self.row,{**self.row,'tokenExpiresWall':wall+60,'tokenExpiresMonotonic':mono+60})
        self.row=r.read();before=len(self.server.calls)
        with self.assertRaises(Permanent)as error:self.observe()
        self.assertEqual(error.exception.code,'AUTHORITY_EXPIRED');self.assertEqual(len(self.server.calls),before);self.unchanged()
    def test_mount_minimum_is_enforced_without_lowering_owner_minimum(self):
        self.policy['minimumRemainingSeconds']=310
        with self.assertRaises(Permanent)as error:self.observe()
        self.assertEqual(error.exception.code,'AUTHORITY_EXPIRED');self.unchanged()
    def test_inactive_or_short_issuer_lifetime_is_never_admitted(self):
        original=self.server.active
        for expired in (False,True):
            self.server.active=(lambda:{**original(),'exp':int(time.time())+60})if expired else(lambda:{'active':False})
            with self.subTest(expired=expired),self.assertRaises(Permanent):self.observe()
        self.unchanged()
    def test_rotation_during_real_introspection_denies_mount_acceptance(self):
        def rotate():
            replacement=self.f.root/'replacement';replacement.write_bytes(self.token);replacement.chmod(0o440)
            os.chown(replacement,0,10001);os.replace(replacement,self.output/'token.jwt');self.server.after=None
        self.server.after=rotate
        with self.assertRaisesRegex(ValueError,'TOKEN_ROTATED_OR_MOUNT_CHANGED'):self.observe()
        self.unchanged()
    def test_human_revocation_during_real_introspection_denies_acceptance(self):
        def revoke():
            self.f.approval['state']='REVOKED';self.f.write(self.f.mandate,json.dumps(self.f.approval,sort_keys=True,separators=(',',':')).encode())
        self.server.after=revoke
        with self.assertRaises(Exception):self.observe()
        self.unchanged()
    def test_publication_window_change_during_introspection_cannot_mix_generations(self):
        def change():
            r=self.owner.journal;row=r.read();r.compare_and_save(row,{**row,'tokenExpiresMonotonic':row['tokenExpiresMonotonic']-1})
            self.server.after=None
        self.server.after=change
        with self.assertRaises(Permanent):self.observe()
        self.row=self.owner.journal.read();self.unchanged()

if __name__=='__main__':unittest.main()
