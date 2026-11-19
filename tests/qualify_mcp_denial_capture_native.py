"""Actual Docker GETs/root peer and private files; synthetic installed history."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('capture_fixtures',ROOT/'tests/test_mcp_denial_update_capture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m


def docker(*args):
    return subprocess.check_output(['docker',*args],text=True).strip()


class NativeTests(f.CaptureTests):
    # Native entry executes only its two explicit methods below, not inherited
    # fixture unit tests. No skips, Docker/root availability mandatory.
    def test_actual_engine_gets_and_no_target_effects(self):
        self.assertEqual(os.geteuid(),0)
        names=[]
        try:
            tag='ouf-capture-ci:'+self.base.name
            built=subprocess.run(['docker','build','-q','-t',tag,'-'],input='FROM busybox:1.37\nENTRYPOINT ["/bin/sh","-c","exec sleep 300","--"]\nCMD ["server"]\n',text=True,capture_output=True,check=True)
            image=docker('image','inspect','--format','{{.Id}}',tag)
            for index,role in enumerate(self.ids):
                name='ouf-capture-ci-'+self.base.name+'-'+str(index);names.append(name)
                cid=docker('run','-d','--name',name,'--restart=no',image)
                self.ids[role]=cid
            self.observations={}
            for role,cid in self.ids.items():
                body=json.loads(docker('inspect',cid))[0]
                # v1.44 and CLI inspect can have different API projections.
                # Capture fixtures below use the exact API version under test.
                self.observations[cid]=body
            selected=Path('/var/run/docker.sock').resolve();info=selected.stat()
            conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);conn.connect(str(selected))
            peer=list(struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));conn.close()
            binding={'socketPath':str(selected),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],'peerCredentials':peer}
            probe=m.Capture(self.base/'transport-fixture');engine=m.Engine(probe,binding,list(self.ids.values()))
            self.observations={cid:engine.get('/v1.44/containers/'+cid+'/json') for cid in self.ids.values()}
            self.plan['existingApplications']={role:m.stable_binding(self.observations[self.ids[role]]) for role in ('gateway','postgres','ingestion','udp')}
            self.plan['engineBinding']=binding
            # Synthetic manager semantics only; real process is the fixture's
            # sleep process. Main entry/actual OUF application is not claimed.
            self.plan['mcpReplacement']['name']=self.observations[self.ids['mcp']]['Name'].removeprefix('/')
            self.captured['currentProcessPins']={role:m.process_pin(self.observations[self.ids[role]]['State']['Pid']) for role in self.plan['existingApplications']}
            self.native['candidateFacts']={r:{'nativeImageId':self.observations[self.ids[r if r=='mcp' else r+'-read']]['Image']} for r in ('mcp','ingestion','udp')}
            boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();self.native['bootId']=self.captured['bootId']=boot
            self.native['nativeProposal']['capturedInputsHash']=m.digest(self.captured);self.native['nativeProposalHash']=m.digest(self.native['nativeProposal'])
            self.review['nativePlan']['proposal']=self.plan
            self.result['reviewHash']=m.digest(self.review);self.journal['reviewHash']=self.result['reviewHash']
            for role in self.journal['candidates']:
                cid=self.ids[role if role=='mcp' else role+'-read'];self.journal['candidates'][role].update(id=cid,generation=m.process_pin(self.observations[cid]['State']['Pid']))
            for path,value in [(self.paths['native'],self.native),(self.paths['captured'],self.captured),(self.installed/'review.json',self.review),(self.installed/'result.json',self.result),(self.installed/'recovery.json',self.journal)]:
                path.write_bytes(m.encoded(value))
            with patch.multiple(m,NATIVE_HASH=m.digest(self.native),INSTALLED_REVIEW_HASH=m.digest(self.review),INSTALLED_RESULT_HASH=m.digest(self.result)):
                capture=m.Capture(self.base/'actual-engine-capture')
                output=m.prepare(capture,native_path=self.paths['native'],captured_path=self.paths['captured'],installed=self.installed,
                    engine_factory=m.Engine,boot_path=Path('/proc/sys/kernel/random/boot_id'))
            self.assertTrue(output['complete']);self.assertEqual(output['counts']['engineGets'],9)
            self.assertEqual(output['containerWrites'],0)
            for role,cid in self.ids.items():
                body=json.loads(docker('inspect',cid))[0]
                self.assertTrue(body['State']['Running']);self.assertEqual(body['RestartCount'],0)
                self.assertEqual(m.process_pin(body['State']['Pid']),self.journal['candidates'][role.removesuffix('-read')]['generation'] if role in ('mcp','ingestion-read','udp-read') else self.captured['currentProcessPins'][role])
            bad=dict(binding,peerCredentials=[peer[0]+1,*peer[1:]])
            e=m.Engine(m.Capture(self.base/'wrong-peer'),bad,list(self.ids.values()))
            with self.assertRaises(m.Stop):e.get('/v1.44/info')
            print('NATIVE_ROOT_ENGINE_GET_CAPTURE_PASS_NO_WRITES',flush=True)
        finally:
            for name in names:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)

    def test_root_copier_mode_and_nonroot_denial(self):
        wrapper=(ROOT/'releases/prepare-mcp-denial-update-inputs-20261026.sh').read_text()
        marker="<<'PY' 2>&1 | tee -a \"$delivery_log\"\n"
        copier=wrapper.split(marker,1)[1].split('\nPY\n',1)[0]
        raw=(ROOT/'scripts/prepare-mcp-denial-update-inputs-20261026.py').read_bytes();expected=hashlib.sha256(raw).hexdigest()
        self.assertIn('code_sha='+expected,wrapper)
        src=self.base/'download.py';src.write_bytes(raw);src.chmod(0o600);os.chown(src,65534,65534)
        target=Path('/usr/local/lib/ouf-mcp-denial-update-inputs-'+expected[:16]);self.assertFalse(target.exists())
        before=os.umask(0o077)
        try:
            r=subprocess.run(['/usr/bin/python3','-I','-S','-B','-',str(src),expected,'65534'],input=copier,text=True,capture_output=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            code=target/'prepare.py';self.assertEqual(code.stat().st_mode&0o777,0o400)
            self.assertEqual(target.stat().st_mode&0o777,0o700)
            self.assertEqual(hashlib.sha256(code.read_bytes()).hexdigest(),expected)
            denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code)],capture_output=True)
            self.assertNotEqual(denied.returncode,0)
            denied=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(code)],capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','SUDO_UID':'0'})
            self.assertEqual(denied.returncode,2)
            self.assertFalse(json.loads(denied.stdout)['runtimeAuthorityIssued'])
        finally:
            os.umask(before)
            if target.exists():shutil.rmtree(target)


if __name__=='__main__':
    suite=unittest.TestSuite(NativeTests(name) for name in ('test_actual_engine_gets_and_no_target_effects','test_root_copier_mode_and_nonroot_denial'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
