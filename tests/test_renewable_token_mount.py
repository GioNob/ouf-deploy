import json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.semantic_policy_token_owner.producer import DomainOwner
from tools.semantic_policy_token_owner.mount_observation import RenewableTokenMountObservation,generation

class FixtureOwner(DomainOwner):
    # Synthetic admission ONLY. Native tests prove mount/byte custody, not IAM.
    def __init__(self):self.accept=True;self.callback=None;self.calls=0
    def guard(self,binding_hash):pass
    def prepare(self,binding_hash,deadline):pass
    def pause(self):pass
    def admit_mounted(self,token,*args):
        self.calls+=1
        if self.callback:self.callback()
        return self.accept

HELPER='''import os,subprocess,sys,signal
source,target,readonly=sys.argv[1:]
subprocess.run(['/usr/bin/mount','--bind',source,target],check=True)
if readonly=='yes':subprocess.run(['/usr/bin/mount','-o','remount,bind,ro',target],check=True)
print(os.getpid(),flush=True)
while True:signal.pause()
'''

class RenewableMount(unittest.TestCase):
    def fixture(self,readonly=True):
        if os.environ.get('OUF_NATIVE_MOUNTS')!='1':self.skipTest('Private mount namespace requires native root CI')
        temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup)
        root=Path(temp.name);root.chmod(0o700)
        source=root/'source';source.mkdir(mode=0o750);source.chmod(0o750);os.chown(source,0,10001)
        leaf=source/'token.jwt';leaf.write_text('FIXTURE_PRIVATE_TOKEN');leaf.chmod(0o440);os.chown(leaf,0,10001)
        target=root/'target';target.mkdir(mode=0o700)
        process=subprocess.Popen(['/usr/bin/unshare','--mount','--propagation','private',
            '/usr/bin/python3','-I','-B','-c',HELPER,str(source),str(target),'yes' if readonly else 'no'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:process.kill()
            process.wait(timeout=5);process.stdout.close();process.stderr.close()
        self.addCleanup(cleanup)
        import select
        self.assertTrue(select.select([process.stdout],[],[],10)[0],'Native mount helper did not become ready')
        line=process.stdout.readline()
        if not line:self.fail(process.stderr.read(4096).decode())
        pid=int(line);os.kill(pid,signal.SIGSTOP)
        self.assertEqual(pid,process.pid)
        _,status=os.waitpid(pid,os.WUNTRACED);self.assertTrue(os.WIFSTOPPED(status))
        current=generation(pid)
        info=source.stat();owner=FixtureOwner()
        policy={'source':str(source),'target':str(target),'fileName':'token.jwt','gid':10001,
                'directoryDevice':info.st_dev,'directoryInode':info.st_ino,'ownerBindingHash':'a'*64,
                'maxBytes':16384,'minimumRemainingSeconds':30}
        observer=RenewableTokenMountObservation(policy,owner,time.monotonic()+10)
        return source,leaf,owner,observer,current
    def rotate(self,leaf):
        replacement=leaf.parent.parent/'replacement';replacement.write_text('FIXTURE_NEW_TOKEN')
        replacement.chmod(0o440);os.chown(replacement,0,10001);os.replace(replacement,leaf)
    def test_real_readonly_mount_and_rotation_between_fresh_observations(self):
        source,leaf,owner,observer,current=self.fixture()
        first=observer.observe(current);self.rotate(leaf);second=observer.observe(current)
        self.assertEqual(owner.calls,2);self.assertEqual(first['bindingHash'],second['bindingHash'])
        self.assertTrue(second['sameSourceFileInMountedView'])
        for private in ('FIXTURE_PRIVATE_TOKEN','FIXTURE_NEW_TOKEN',str(source),'sha256'):
            self.assertNotIn(private,json.dumps(first)+json.dumps(second))
        self.assertFalse(second['completeSixMountClosureProven']);self.assertFalse(second['runtimeAuthorityIssued'])
    def test_rotation_during_admission_is_not_promoted(self):
        source,leaf,owner,observer,current=self.fixture();owner.callback=lambda:self.rotate(leaf)
        with self.assertRaisesRegex(ValueError,'TOKEN_ROTATED_OR_MOUNT_CHANGED'):observer.observe(current)
    def test_actual_rw_mount_denied_before_owner_admission(self):
        source,leaf,owner,observer,current=self.fixture(False)
        with self.assertRaisesRegex(ValueError,'READONLY_SINGLETON_TOKEN_MOUNT_REQUIRED'):observer.observe(current)
        self.assertEqual(owner.calls,0)
    def test_extra_member_and_symlink_are_denied_before_admission(self):
        source,leaf,owner,observer,current=self.fixture();extra=source/'foreign';extra.write_text('FIXTURE')
        with self.assertRaises(ValueError):observer.observe(current)
        extra.unlink();original=leaf.parent.parent/'original';leaf.rename(original);leaf.symlink_to(original)
        with self.assertRaises(OSError):observer.observe(current)
        self.assertEqual(owner.calls,0)
    def test_owner_denial_and_changed_process_generation_block(self):
        source,leaf,owner,observer,current=self.fixture();owner.accept=False
        with self.assertRaisesRegex(ValueError,'CURRENT_TOKEN_OWNER_ADMISSION_REQUIRED'):observer.observe(current)
        changed={**current,'startTicks':current['startTicks']+1}
        with self.assertRaisesRegex(ValueError,'PAUSED_MOUNT_PROCESS_DRIFT'):observer.observe(changed)
    def test_approved_directory_identity_cannot_be_refreshed_from_observation(self):
        source,leaf,owner,observer,current=self.fixture()
        policy={**observer.expected,'directoryInode':observer.expected['directoryInode']+1}
        different=RenewableTokenMountObservation(policy,owner,time.monotonic()+10)
        with self.assertRaisesRegex(ValueError,'APPROVED_RENEWABLE_ROOT'):different.observe(current)
        self.assertEqual(owner.calls,0)

if __name__=='__main__':unittest.main()

