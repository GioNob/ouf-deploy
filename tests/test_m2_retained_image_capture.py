"""Real Unix socket/peer credentials and private bounded create-only archives."""
import hashlib,io,json,os,socket,stat,struct,sys,tarfile,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT)]
from tools.m2_discovery_installation_profile import retained_image_capture as m


class PrivateImageInput(unittest.TestCase):
    def prepared(self,*,body=None,header=None,peer=None):
        temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup)
        root=Path(temp.name);root.chmod(0o700)
        space=patch.object(m.shutil,'disk_usage',return_value=type('Space',(),{'free':12*1024**3})())
        space.start();self.addCleanup(space.stop)
        c=m.ImageCapture(root/'output');endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(endpoint.close);path=root/'engine.sock';endpoint.bind(str(path));path.chmod(0o600);endpoint.listen(1);endpoint.settimeout(2)
        if body is None:
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:
                content=b'PRIVATE_IMAGE_ENV_VALUE';member=tarfile.TarInfo('config.json');member.size=len(content);archive.addfile(member,io.BytesIO(content))
            body=data.getvalue()
        requests=[];errors=[]
        def server():
            try:
                channel,_=endpoint.accept()
                with channel:
                    channel.settimeout(2);request=b''
                    while b'\r\n\r\n' not in request:
                        block=channel.recv(4096)
                        if not block:return
                        request+=block
                    requests.append(request)
                    response=header or ('HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n\r\n').encode()
                    channel.sendall(response+body)
            except (TimeoutError,BrokenPipeError,ConnectionResetError):pass
            except Exception as error:errors.append(error)
        thread=threading.Thread(target=server);thread.start()
        def finish():thread.join(3);self.assertFalse(thread.is_alive());self.assertFalse(errors)
        self.addCleanup(finish)
        s=path.lstat();binding={'socketPath':str(path),'socketBinding':[s.st_dev,s.st_ino,0,0,0o600],
            'peerCredentials':peer or [os.getpid(),0,0]}
        images=['sha256:'+format(i,'064x') for i in range(1,14)]
        return c,m.ImageEngine(c,binding,images),images,body,requests

    def test_actual_unix_get_keeps_archive_private_and_never_executes_or_admits_it(self):
        c,engine,images,body,requests=self.prepared();row=engine.export(images[0],'mcp')
        file=c.scope/row['filename'];self.assertEqual(file.read_bytes(),body)
        self.assertEqual(row['sha256'],hashlib.sha256(body).hexdigest());self.assertEqual(row['bytes'],len(body))
        self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o400)
        self.assertEqual(requests[0].split(b'\r\n')[0],('GET /v1.44/images/'+images[0]+'/get HTTP/1.1').encode())
        self.assertFalse(row['nativeIdentityAndSourceAdmissionEstablished']);self.assertNotIn('PRIVATE_IMAGE_ENV_VALUE',json.dumps(row))
        self.assertEqual(c.counts['engineGets'],1);self.assertEqual(c.counts['imageArchivesCaptured'],1)
        self.assertEqual(c.counts['credentialFileReads'],0);self.assertEqual(c.counts['mountFileContentBytesRead'],0)
        with self.assertRaisesRegex(ValueError,'CLOSED_SINGLE_PASS'):engine.export(images[0],'mcp')
        with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.ImageCapture(c.scope)
        self.assertEqual(c.counts['engineGets'],1)

    def test_arbitrary_path_role_or_budget_denies_before_connection(self):
        c,engine,images,_,requests=self.prepared()
        for image,role in (('sha256:'+('f'*64),'mcp'),(images[0],'../../escape')):
            with self.assertRaisesRegex(ValueError,'CLOSED_SINGLE_PASS'):engine.export(image,role)
        c.counts['engineGets']=13
        with self.assertRaisesRegex(ValueError,'CLOSED_SINGLE_PASS'):engine.export(images[0],'mcp')
        self.assertFalse(requests);self.assertEqual(c.counts['imageArchiveBytes'],0)

    def test_wrong_peer_wrong_content_type_incomplete_or_oversized_reply_never_produces_candidate(self):
        cases=({'peer':[os.getpid()+1,0,0]},
            {'header':b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n'},
            {'header':b'HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nContent-Length: 10240\r\nConnection: close\r\n\r\n','body':b'x'*512},
            {'body':b'x'*10241})
        for args in cases:
            c,engine,images,_,_=self.prepared(**args)
            with self.subTest(args=sorted(args)),self.assertRaises((ValueError,OSError)):engine.export(images[0],'mcp')
            self.assertEqual(c.counts['imageArchivesCaptured'],0);self.assertTrue((c.scope/'native-image-archive.claim.json').exists())
            self.assertFalse((c.scope/'native-image-archives.private.json').exists());self.assertEqual(c.counts['engineGets'],1)
        c,engine,images,_,_=self.prepared(header=b'HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nConnection: close\r\n\r\n')
        with patch.dict(m.PROFILE,maximumImageBytes=512),self.assertRaisesRegex(ValueError,'BOUNDED_NATIVE_IMAGE_ARCHIVE_BYTES'):
            engine.export(images[0],'mcp')
        self.assertEqual(c.counts['imageArchivesCaptured'],0)

    def test_insufficient_disk_space_denies_before_claim_or_engine_and_entrypoint_has_no_overrides(self):
        c,_,_,_,_=self.prepared();scope=c.scope.parent/'no-space'
        with patch.object(m.shutil,'disk_usage',return_value=type('Space',(),{'free':0})()),\
            self.assertRaisesRegex(ValueError,'NINE_GIB_FREE'):m.ImageCapture(scope)
        self.assertFalse(scope.exists())
        with self.assertRaises(TypeError):m.collect(c,engine_factory=lambda:True)
        with self.assertRaises(TypeError):m.collect(c,case={})


if __name__=='__main__':unittest.main()
