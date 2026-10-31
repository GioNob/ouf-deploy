"""Real AF_UNIX/root peer and root copier; all application/history data synthetic."""
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import subprocess
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('redaction_tests',ROOT/'tests/test_acquisition_redaction_update_capture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m

class NativeCaptureTests(f.RedactionCaptureTests):
    def test_actual_unix_transport_root_peer_and_finite_allowlist(self):
        self.assertEqual(os.geteuid(),0)
        requests=[];observations=self.observations
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(server):
                requests.append(server.path)
                value={'Driver':'synthetic-ci'} if server.path=='/v1.44/info' else observations[server.path.split('/')[3]]
                body=m.encoded(value);server.send_response(200);server.send_header('Content-Length',str(len(body)));server.end_headers();server.wfile.write(body)
            def log_message(*args):pass
        class UnixHttp(socketserver.UnixStreamServer):allow_reuse_address=False
        selected=self.base/'engine.sock';server=UnixHttp(str(selected),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            info=selected.lstat()
            binding={'socketPath':str(selected),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],'peerCredentials':[os.getpid(),0,0]}
            c=m.Capture(self.base/'unix-capture');engine=m.Engine(c,binding,list(self.ids.values()))
            for _ in range(10):self.assertEqual(engine.get('/v1.44/info'),{'Driver':'synthetic-ci'})
            with self.assertRaises(m.Stop):engine.get('/v1.44/info')
            self.assertEqual(len(requests),10)
            bad=dict(binding,peerCredentials=[os.getpid()+1,0,0])
            other=m.Engine(m.Capture(self.base/'wrong-peer'),bad,list(self.ids.values()))
            with self.assertRaises(m.Stop):other.get('/v1.44/info')
            self.assertEqual(len(requests),10)
            # Use a real process/namespace observation, not synthetic PID metadata.
            pin=m.process_pin(os.getpid());self.assertEqual(pin['pid'],os.getpid());self.assertGreater(pin['startTicks'],0)
        finally:server.shutdown();server.server_close();worker.join(timeout=2)
    def test_root_copier_exact_public_source_root0400_and_nonroot_denial(self):
        self.assertEqual(os.geteuid(),0)
        wrapper=(ROOT/'releases/prepare-acquisition-redaction-update-inputs-20261026.sh').read_text()
        marker="<<'PY' 2>&1 | tee -a \"$delivery_log\"\n"
        copier=wrapper.split(marker,1)[1].split('\nPY\n',1)[0]
        raw=(ROOT/'scripts/prepare-acquisition-redaction-update-inputs-20261026.py').read_bytes()
        expected=hashlib.sha256(raw).hexdigest();self.assertIn('code_sha='+expected,wrapper)
        self.assertRegex(wrapper,r'code_commit=[a-f0-9]{40}\n')
        protected=self.base/'protected-lib';protected.mkdir(mode=0o700)
        # Only CI destination roots are substituted, never custody checks or source bytes.
        copier=copier.replace('/usr/local/lib',str(protected)).replace('/etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1',str(self.base/'fresh-scope'))
        source=self.base/'download.py';source.write_bytes(raw);source.chmod(0o600);os.chown(source,65534,65534)
        result=subprocess.run(['/usr/bin/python3','-I','-S','-B','-',str(source),expected,'65534'],input=copier,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        target=protected/('ouf-acquisition-redaction-inputs-'+expected[:16])/'prepare.py'
        self.assertEqual(target.read_bytes(),raw);self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o400)
        self.assertEqual(target.stat().st_uid,0)
        def unprivileged():os.setgid(65534);os.setuid(65534)
        denial=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(target)],capture_output=True,preexec_fn=unprivileged)
        self.assertNotEqual(denial.returncode,0)
        self.assertIn(b'Permission denied',denial.stderr)
        duplicate=subprocess.run(['/usr/bin/python3','-I','-S','-B','-',str(source),expected,'65534'],input=copier,text=True,capture_output=True)
        self.assertNotEqual(duplicate.returncode,0)
        self.assertEqual(target.read_bytes(),raw)


if __name__=='__main__':
    names=[n for n in NativeCaptureTests.__dict__ if n.startswith('test_')]
    outcome=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(NativeCaptureTests(n) for n in names))
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
