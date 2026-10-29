"""Real frozen rootfs sealer and custody; explicit synthetic target API receipts."""
import base64,contextlib,copy,hashlib,importlib.util,io,json,os,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('running_rootfs_reader',ROOT/'scripts/read-chatbot-running-rootfs-diff-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Diagnostic(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
        self.image=self.root/'image';self.image.mkdir();(self.image/'tmp').mkdir();(self.image/'app').mkdir()
        (self.image/'app/application.jar').write_bytes(b'fixture public package')
        self.sources={n:base64.b64encode((ROOT/'tools/semantic_cohort_admission/cohort-draft'/Path(*n.split('.')).with_suffix('.py')).read_bytes()).decode()for n in r.SEAL_SOURCE_PINS}
        self.limits={'maxEntries':100,'maxBytes':1048576,'maxDepth':8}
    def scan(self):return r.scan(self.image,self.limits,self.sources,r.Budget())
    def test_independent_manifest_reproduces_exact_retained_seal(self):
        entries=r.ci_image_entries(r.ORIGINAL_ROOTFS_SEAL)
        self.assertEqual(len(entries),9302);self.assertEqual(r.replay_entry_stream(list(entries.values())),r.RETAINED_MOUNT_ROOTFS_SEAL)
        with patch.object(r,'CI_ENTRIES_SHA','f'*64),self.assertRaises(r.ReadDenied):r.ci_image_entries(r.ORIGINAL_ROOTFS_SEAL)
    def test_post_start_files_are_differences_not_automatically_accepted(self):
        first,left=self.scan();(self.image/'tmp/PRIVATE_RUNTIME_NAME').write_bytes(b'PRIVATE_RUNTIME_VALUE')
        second,right=self.scan();self.assertNotEqual(first,second)
        delta=r.differences(left,right);self.assertEqual(delta['differentEntryCount'],1)
        self.assertEqual(delta['samples'][0]['imagePath'],'tmp');self.assertTrue(delta['samples'][0]['unlistedDescendant'])
        self.assertNotIn('PRIVATE',json.dumps(delta));self.assertFalse(delta['fileContentsPrinted'])
    def test_content_mode_and_link_changes_are_all_counted(self):
        _,left=self.scan();p=self.image/'app/application.jar';p.write_bytes(b'changed');p.chmod(0o600)
        (self.image/'app/link').symlink_to('/PRIVATE_TARGET')
        _,right=self.scan();d=r.differences(left,right)
        self.assertIn('sha256',d['fieldCounts']);self.assertIn('mode',d['fieldCounts']);self.assertNotIn('PRIVATE',json.dumps(d))
    def test_second_scan_redacts_names_not_in_independent_manifest(self):
        _,baseline=self.scan();p=self.image/'tmp/PRIVATE_NEW_NAME';p.write_bytes(b'one');_,left=self.scan()
        p.write_bytes(b'two');_,right=self.scan()
        delta=r.differences(left,right,public_paths=set(baseline));self.assertNotIn('PRIVATE',json.dumps(delta))
        self.assertEqual(delta['samples'][0]['imagePath'],'tmp')
    def test_source_substitution_denied_before_scanning(self):
        self.sources['tools.semantic_provider_node_observation']=base64.b64encode(b'raise RuntimeError("PRIVATE")').decode()
        with patch.object(r.os,'scandir',side_effect=AssertionError('must not scan')),self.assertRaisesRegex(r.ReadDenied,'FROZEN_SEAL_SOURCE_DRIFT'):self.scan()
    def test_special_file_and_bounds_fail_closed(self):
        os.mkfifo(self.image/'fifo')
        with self.assertRaisesRegex(r.ReadDenied,'SPECIAL_ENTRY'):self.scan()
        (self.image/'fifo').unlink();self.limits['maxBytes']=1
        with self.assertRaisesRegex(r.ReadDenied,'BYTES_UNBOUNDED'):self.scan()
        with self.assertRaisesRegex(r.ReadDenied,'TIME_BOUND'):r.scan(self.image,{'maxEntries':100,'maxBytes':1024,'maxDepth':8},self.sources,r.Budget(-1))
    def test_mutation_during_file_read_is_not_silently_adopted(self):
        actual=r.os.read;changed=[False];path=self.image/'app/application.jar'
        def changing(fd,size):
            data=actual(fd,size)
            if data and not changed[0]:changed[0]=True;path.write_bytes(b'changed during read')
            return data
        with patch.object(r.os,'read',side_effect=changing),self.assertRaises(r.ReadDenied):self.scan()
    def test_private_bind_alias_blocks_before_image_content_read(self):
        source=self.root/'private';source.write_bytes(b'PRIVATE')
        (self.image/'private').symlink_to(source)
        binding={'source':str(source),'target':'/private'}
        policy={'sources':[binding],'configtree':binding,'renewableToken':binding}
        with patch.object(r,'host_image_mount_guard'),self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BIND_VISIBLE'):r.image_guard(self.image,policy)
    def test_custody_rejects_symlink_mode_and_changed_hash(self):
        path=self.root/'record';path.write_bytes(b'{}');path.chmod(0o600);pin=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(r.read(path,expected=pin),{})
        path.write_bytes(b'{"private":1}')
        with self.assertRaises(r.ReadDenied):r.read(path,expected=pin)
        path.chmod(0o644)
        with self.assertRaises(r.ReadDenied):r.read(path)
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(r.ReadDenied):r.read(link)
    def test_difference_output_is_bounded_without_hiding_count(self):
        _,baseline=self.scan();right=copy.deepcopy(baseline)
        for i in range(80):right['tmp/PRIVATE_'+str(i)]={'path':'tmp/PRIVATE_'+str(i),'kind':'file','size':1,'sha256':'PRIVATE'}
        d=r.differences(baseline,right);self.assertEqual(d['differentEntryCount'],80);self.assertEqual(len(d['samples']),60)
        self.assertTrue(d['samplesTruncated']);self.assertNotIn('PRIVATE',json.dumps(d))
    def fixture_main(self,*,drift=False):
        root=self.root/'rootfs/overlayfs'/r.CID;root.parent.mkdir(parents=True);self.image.rename(root);self.image=root
        seal,entries=self.scan();private=self.root/'secret';private.write_bytes(b'PRIVATE_VALUE')
        binding={'source':str(private),'target':'/not-present'}
        config=self.root/'bundle'/r.CID/'config.json';config.parent.mkdir(parents=True)
        oci={'root':{'path':str(root)}};raw=r.encoded(oci);config.write_bytes(raw)
        policy={'expectedOci':oci,'sources':[binding],'configtree':binding,'renewableToken':binding}
        recipe={'expectedRootfsSeal':r.RETAINED_MOUNT_ROOTFS_SEAL,'observationConfiguration':{'rootfsLimits':self.limits,'runtimeBinding':{}},
            'runtimeRoot':'/fixture-runtime','dockerContext':{'bundleParent':str(config.parent.parent),'storageParent':str(self.root)}}
        p={'registry':{'nodeRecipe':recipe,'creationRequest':{'Cmd':['fixture-app']}},'engine':{}}
        native={'Id':r.CID,'Image':'sha256:'+'a'*64,'RestartCount':0,'State':{'Pid':123,'StartedAt':'start','Running':True,'Paused':False,'Status':'running'},
            'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
        generation={'pid':123,'startTicks':10,'namespaceInode':20,'mountNamespaceInode':30}
        effects={'START_REPLACEMENT':{'runtimeBinding':r.runtime_pin(native),'generation':{k:v for k,v in generation.items()if k!='mountNamespaceInode'}},
            'VERIFY_APPLICATION':{'runtimeBinding':r.runtime_pin(native)}}
        checked=[];out=io.StringIO()
        with contextlib.ExitStack()as stack:
            for name,value in [('read_checkpoint',(p,self.sources,policy,effects,lambda:checked.append(True))),('ci_image_entries',entries),
                ('app_generation',generation),('command',{'id':r.CID,'pid':123,'status':'running','bundle':str(config.parent)}),('runtime_config',raw)]:
                stack.enter_context(patch.object(r,name,return_value=value))
            get=stack.enter_context(patch.object(r,'inspect',side_effect=[native,{**native,'RestartCount':1}if drift else native]))
            stack.enter_context(patch.object(r,'host_image_mount_guard'));stack.enter_context(patch.object(r.signal,'alarm'))
            stack.enter_context(contextlib.redirect_stdout(out))
            if drift:
                with self.assertRaisesRegex(r.ReadDenied,'NATIVE_GENERATION_CHANGED'):r.main()
            else:r.main()
            self.assertEqual(get.call_count,2)
        self.assertNotIn('PRIVATE',out.getvalue());return [json.loads(l)for l in out.getvalue().splitlines()],checked
    def test_complete_reader_uses_real_sealer_and_no_acceptance(self):
        rows,checked=self.fixture_main();self.assertEqual(checked,[True]);end=rows[-1]
        self.assertEqual(end['check'],'END');self.assertTrue(end['stableDoubleScan']);self.assertFalse(end['runtimeAuthorityIssued'])
        self.assertEqual(end['dumpProbes'],0);self.assertEqual(end['grantRequests'],0)
        self.assertTrue(all(x['readOnly']and not x['acceptanceGranted']for x in rows))
    def test_generation_change_prevents_end_unchanged_assertion(self):
        rows,checked=self.fixture_main(drift=True);self.assertEqual(checked,[]);self.assertNotEqual(rows[-1]['check'],'END')
    def test_checkpoint_checks_real_private_records_archives_and_raw_byte_drift(self):
        context=self.root/'retained';context.mkdir(mode=0o700)
        def write(path,value):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=r.encoded(value);path.write_bytes(raw);path.chmod(0o600)
            return hashlib.sha256(raw).hexdigest()
        directories={name:str(context/name)for name in ('containers','authorization','gateway','databases','backups')}
        paths={name:str(context/name)for name in ('transition','node','evidence')}
        p={'registry':{'directoryPlan':paths}};declaration={'sourceCommit':r.SOURCE}
        bundle={'prepared':p,'sources':self.sources,'declaration':declaration};bh=write(context/'bundle.json',bundle)
        process={'unit':r.UNIT,'authorityDirectory':str(context),'directoryPlan':directories,'bundle':{'path':str(context/'bundle.json'),'sha256':bh}}
        scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':str(context/'owner')}}
        review={'scopes':scopes,'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{}}},'privateInputHashes':{'preparedInputs':r.digest(p)}}
        rh=write(context/'review.json',review);ah=write(context/'authority.json',scopes)
        write(context/'delivery-status.json',{'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'COHORT_DATABASE_DUMP_FAILED'})
        effects=[{'phase':'SYNTHETIC_'+str(i),'state':'APPLIED'}for i in range(8)]
        for phase in ('START_REPLACEMENT','VERIFY_APPLICATION'):
            h=write(context/'evidence'/(phase+'.json'),{'syntheticEvidence':phase})
            effects.append({'phase':phase,'state':'APPLIED','nativeEvidenceHash':h})
        th=write(context/'transition/recovery.json',{'state':'READY','version':29,'nextPhase':10,'effects':effects})
        wh=write(context/'owner/recovery.json',{'state':'CANCELLED','controlledCumulativeGrantAttempts':5})
        sh=write(context/'owner/owner-session.json',{});ad=write(context/'owner/owner-admission.json',{})
        later={k:write(Path(directories[k])/'recovery.json',{})for k in ('containers','authorization','gateway')}
        dh=write(context/'databases/recovery.json',{});nh=write(context/'node/frame-policy.json',{})
        archives={};Path(directories['backups']).mkdir(mode=0o700)
        for m in r.ARCHIVES:
            raw=b''if m=='mcp'else b'PGDMP-fixture';path=Path(directories['backups'])/(m+'.dump');path.write_bytes(raw);path.chmod(0o600)
            archives[m]=(len(raw),hashlib.sha256(raw).hexdigest())
        with contextlib.ExitStack()as stack:
            for name,value in {'CONTEXT':context,'REVIEW':rh,'AUTHORITY':ah,'TRANSITION_HASH':th,'WORKER_HASH':wh,'SESSION_HASH':sh,
                'ADMISSION_HASH':ad,'LATER_HASHES':later,'DATABASE_JOURNAL':dh,'NODE_POLICY_HASH':nh,'ARCHIVES':archives}.items():
                stack.enter_context(patch.object(r,name,value))
            stack.enter_context(patch.object(r,'stopped'))
            prepared,sources,policy,observed,unchanged=r.read_checkpoint();self.assertEqual(prepared,p);unchanged()
            path=context/'owner/recovery.json';path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(r.ReadDenied,'READ_HASH_DRIFT'):unchanged()
    @unittest.skipUnless(os.environ.get('OUF_NATIVE_PROCESS')=='1','requires native /proc and setpriv')
    def test_real_hardened_running_process_and_wrong_argv_denial(self):
        binary=shutil.which('setpriv');sleep=shutil.which('sleep');self.assertIsNotNone(binary);self.assertIsNotNone(sleep)
        child=subprocess.Popen([binary,'--reuid=10001','--regid=10001','--clear-groups','--bounding-set=-all','--inh-caps=-all',
            '--ambient-caps=-all','--no-new-privs',sleep,'30'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda:child.wait()if child.poll()is not None else(child.terminate(),child.wait()))
        # Fixture process startup only; the delivered reader never waits/retries.
        for _ in range(100):
            try:first=r.app_generation(child.pid,[sleep,'30']);break
            except r.ReadDenied:time.sleep(0.01)
        else:self.fail('native fixture did not enter reviewed process')
        self.assertEqual(first,r.app_generation(child.pid,[sleep,'30']))
        with self.assertRaisesRegex(r.ReadDenied,'ARGUMENTS'):r.app_generation(child.pid,[sleep,'31'])

if __name__=='__main__':unittest.main()
