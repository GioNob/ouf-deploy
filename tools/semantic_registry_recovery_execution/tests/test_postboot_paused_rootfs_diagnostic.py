"""Actual sealed rootfs primitive/files; explicit Engine/kernel cohort substitutes."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch
import test_postboot_rootfs_stop_metadata as fixture

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('paused_rootfs_diagnostic',ROOT/'scripts/observe-registry-paused-rootfs-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def primitives():
    b=m.base_module()
    with patch.object(b,'CAPSULE',str(ROOT/'releases/semantic-registry-postboot-byte-20261023.py')):
        return m.primitives(b,b.Reader())


class Primitive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.ns=primitives();cls.b=m.base_module()

    def setUp(self):
        tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)

    def test_exact_native_primitive_transcript_and_fixed_directory_only_variants(self):
        (self.root/'sub').mkdir();(self.root/'sub'/'app').write_bytes(b'image payload')
        limits={'maxEntries':100,'maxBytes':1024,'maxDepth':8}
        seal,rows=m.sealed_rows(dict(self.ns),self.b,self.root,limits,m.Budget(5))
        self.assertEqual(m.transcript_seal(self.b,rows),seal['sha256']);self.assertEqual(seal['entries'],3)
        modified=copy.deepcopy(rows)
        for row in modified:
            if row['kind']=='directory':row['links']=1
        expected=m.transcript_seal(self.b,modified)
        self.assertEqual(m.transcript_seal(self.b,rows,'one'),expected)
        self.assertEqual([r for r in modified if r['kind']=='file'],[r for r in rows if r['kind']=='file'])
        (self.root/'sub'/'app').write_bytes(b'changed payload')
        after,_=m.sealed_rows(dict(self.ns),self.b,self.root,limits,m.Budget(5))
        self.assertNotEqual(after['sha256'],seal['sha256'])

    def test_symlink_target_never_opened_and_special_files_denied(self):
        outer=self.root/'outside';outer.write_bytes(b'credential projection must not read')
        image=self.root/'image';image.mkdir();(image/'link').symlink_to(outer)
        limits={'maxEntries':100,'maxBytes':1024,'maxDepth':8}
        seal,rows=m.sealed_rows(dict(self.ns),self.b,image,limits,m.Budget(5))
        self.assertEqual(seal['bytes'],0);self.assertEqual(rows[1]['kind'],'symlink')
        os.mkfifo(image/'fifo')
        with self.assertRaisesRegex(ValueError,'ROOTFS_SPECIAL_ENTRY_UNSUPPORTED'):m.sealed_rows(dict(self.ns),self.b,image,limits,m.Budget(5))

    def test_host_projection_mount_rejected_and_root_mount_identity_retained(self):
        root=Path('/reviewed/image')
        raw=b'1 0 0:1 / /reviewed/image rw - overlay overlay rw\n'
        self.assertEqual(len(m.mount_guard(root,raw)),1)
        with self.assertRaisesRegex(ValueError,'HOST_ROOTFS_CONTAINS_MOUNTED_PROJECTIONS'):
            m.mount_guard(root,raw+b'2 1 0:2 / /reviewed/image/credential rw - ext4 source rw\n')

    def test_limits_deadline_and_custody_rejected(self):
        (self.root/'file').write_bytes(b'123')
        with self.assertRaisesRegex(ValueError,'ROOTFS_BYTES_UNBOUNDED'):
            m.sealed_rows(dict(self.ns),self.b,self.root,{'maxEntries':100,'maxBytes':1,'maxDepth':8},m.Budget(5))
        with self.assertRaisesRegex(ValueError,'ROOTFS_DIAGNOSTIC_DEADLINE'):
            m.sealed_rows(dict(self.ns),self.b,self.root,{'maxEntries':100,'maxBytes':100,'maxDepth':8},m.Budget(-1))
        (self.root/'alias').symlink_to(self.root)
        with self.assertRaises(OSError):m.open_parent(self.root/'alias')

    def test_kernel_generation_checks_real_ticks_and_network_namespace_when_available(self):
        pid=os.getpid()
        try:
            raw=m.kernel_file('/proc/'+str(pid)+'/stat',8192)
            info=os.stat('/proc/'+str(pid)+'/ns/net')
        except (FileNotFoundError,PermissionError):
            # The local managed sandbox has no proc access. Native component
            # CI explicitly requires the actual kernel path instead.
            self.assertNotEqual(os.environ.get('OUF_NATIVE_UIDS'),'1')
            return
        ticks=int(raw[raw.rfind(b')')+2:].split()[19])
        pin={'pid':pid,'startTicks':ticks,'namespaceDevice':info.st_dev,'namespaceInode':info.st_ino}
        self.assertEqual(m.generation(pin),[pid,ticks,info.st_dev,info.st_ino])
        with self.assertRaisesRegex(ValueError,'RETAINED_PROCESS_GENERATION_CHANGED'):
            m.generation(dict(pin,startTicks=ticks+1))
        self.assertIsInstance(m.mount_guard(self.root),list)

    def test_exact_sealed_engine_class_actual_unix_get_transport(self):
        import http.server
        requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(inner):
                requests.append((inner.command,inner.path));raw=b'{"observed":true}'
                inner.send_response(200);inner.send_header('Content-Length',str(len(raw)));inner.end_headers();inner.wfile.write(raw)
            def log_message(*args):pass
        class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
        path=self.root/'engine.sock';server=Server(str(path),Handler);path.chmod(0o600)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            info=path.lstat();binding=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
            engine=self.ns['Engine'](str(path),binding)
            self.assertEqual(engine.request('GET','/v1.44/containers/exact/json'),(200,{'observed':True}))
            self.assertEqual(requests,[('GET','/v1.44/containers/exact/json')])
        finally:server.shutdown();server.server_close();thread.join(timeout=2)


class Cohort(unittest.TestCase):
    write=fixture.RootfsStop.write
    refresh=fixture.RootfsStop.refresh

    def setUp(self):
        fixture.RootfsStop.setUp(self)
        self.ns=primitives();self.calls=[];self.mode='normal';cid='1'*64;image='sha256:'+'d'*64
        storage=self.root/'engine';actual=storage/'rootfs'/'overlayfs'/cid;actual.mkdir(parents=True)
        (actual/'app.jar').write_bytes(b'public image payload')
        bundle=self.root/'bundles'/cid;bundle.mkdir(parents=True);oci={'root':{'path':str(actual),'readonly':True}}
        self.write(bundle/'config.json',oci)
        limits={'maxEntries':100,'maxBytes':1024,'maxDepth':8}
        expected,_=m.sealed_rows(dict(self.ns),fixture.m,actual,limits,m.Budget(5))
        self.context['nodeRecipe']={'expectedRootfsSeal':expected,'observationSeconds':180,
            'observationConfiguration':{'rootfsLimits':limits},'dockerContext':{'storageParent':str(storage),
                'bundleParent':str(self.root/'bundles'),'rootfsLayout':'docker-containerd-overlayfs-v1'}}
        for stage in self.context['plan']['stages']:stage['intent']={'registryId':cid}
        self.context['engineBinding']={'socketPath':'/explicit-fixture','socketBinding':[]}
        self.journal.update(nextStage=4,readAttempts=5,effects=self.journal['effects'][:5],newGeneration={
            'containerId':cid,'bootId':self.boot,'pid':123,'startTicks':10,'namespaceDevice':4,'namespaceInode':5})
        self.journal['effects'][4]['state']='CLAIMED';self.owner['state']='CANCELLED'
        self.refresh()
        p=self.prep/'prepared.json';prepared=json.loads(p.read_bytes());prepared['registryInputs']={
            'creationRequest':{'Image':image,'HostConfig':{'ReadonlyRootfs':True}},'imageAudit':{'imageId':image,'layers':[{'diffId':'sha256:'+'e'*64}]}}
        self.write(p,prepared);p=patch.object(fixture.m,'PREPARATION_HASH',fixture.m.digest(prepared));p.start();self.addCleanup(p.stop)
        self.write(self.execution/'recovery.json',self.journal);self.write(self.ownerroot/'recovery.json',self.owner)
        self.write(self.execution/'native-reads.json',{'scopeHash':fixture.m.digest(self.scope),'authorityHash':fixture.m.AUTHORITY_HASH,
            'counts':{'databaseSessions':1,'gatewayAdminGets':6,'semanticGets':0}})
        self.write(self.execution/'node/frame-policy.json',{'expectedOci':oci})
        case=self
        class Engine:
            def __init__(inner,*args):pass
            def request(inner,method,path):
                case.calls.append((method,path));case.assertEqual(method,'GET')
                if '/images/' in path:return 200,{'Id':image,'RootFS':{'Layers':['sha256:'+'e'*64]}}
                return 200,{'Id':cid,'Image':image,'State':{'Pid':123,'Running':True,'Paused':case.mode!='unpaused',
                    'Restarting':False,'Dead':False,'StartedAt':'one' if len(case.calls)<3 or case.mode!='changed' else 'changed'},
                    'HostConfig':{'ReadonlyRootfs':True},'RestartCount':0}
        ns=dict(self.ns);ns['Engine']=Engine
        real_path=Path
        p=patch.object(m,'Path',side_effect=lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real_path(v));p.start();self.addCleanup(p.stop)
        for name,value in {'base_module':lambda:fixture.m,'primitives':lambda b,r:dict(ns),'generation':lambda pin:[123,10,4,5],
            'mount_guard':lambda root:[]}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def test_full_claimed_observation_writes_only_private_diagnostics_and_never_replays(self):
        before={p:(p.read_bytes(),p.stat()) for p in [self.execution/'recovery.json',self.execution/'native-reads.json',self.ownerroot/'recovery.json']}
        result=m.observe();self.assertTrue(result['rootfsSealMatchesExpected']);self.assertEqual(result['engineGets'],3)
        self.assertEqual(result['retainedControlledGrantAttempts'],320);self.assertEqual(result['oauthRequests'],0)
        self.assertEqual(before,{p:(p.read_bytes(),p.stat()) for p in before})
        manifest=Path(result['privateManifestPath']);self.assertEqual(stat.S_IMODE(manifest.stat().st_mode),0o400)
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(),result['privateManifestHash'])
        with self.assertRaisesRegex(ValueError,'ROOTFS_DIAGNOSTIC_ALREADY_CONSUMED'):m.observe()
        self.assertEqual(len(self.calls),3)

    def test_unpaused_container_stops_before_full_rootfs_read(self):
        self.mode='unpaused'
        with self.assertRaisesRegex(ValueError,'EXACT_PAUSED_READONLY_IMAGE_GENERATION'):m.observe()
        self.assertEqual(len(self.calls),1)
        self.assertFalse(list(self.root.glob('semantic-registry-rootfs-diagnostic-*/rootfs-manifest.json')))

    def test_changed_generation_after_scan_stops_without_success_or_native_changes(self):
        self.mode='changed'
        with self.assertRaisesRegex(ValueError,'PAUSED_CONTAINER_CHANGED_DURING_ROOTFS_READ'):m.observe()
        self.assertEqual(len(self.calls),3)
        self.assertFalse(list(self.root.glob('semantic-registry-rootfs-diagnostic-*/observation.json')))


if __name__=='__main__':unittest.main()
