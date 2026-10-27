#!/usr/bin/env python3
"""CI-only native Engine/file-custody fixture, never a target entrypoint."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    assert os.geteuid()==os.getegid()==0
    repository=Path(__file__).resolve().parents[1]
    source=repository/'scripts/capture-onboarding-profile-recovery-inputs-20261027.py'
    root=Path('/usr/local/lib/ouf-profile-recovery-capture-ci-'+str(os.getpid()));root.mkdir(mode=0o700)
    protected=root/'read.py';raw=source.read_bytes();protected.write_bytes(raw);protected.chmod(0o400)
    assert hashlib.sha256(protected.read_bytes()).hexdigest()==hashlib.sha256(raw).hexdigest() and stat.S_IMODE(protected.stat().st_mode)==0o400
    m=load('sealed_profile_capture',protected)
    helper=load('profile_capture_fixture',repository/'tests/test_onboarding_profile_recovery_current_inputs.py')
    actual=json.loads(subprocess.check_output(['docker','inspect','ouf-ci-profile-recovery-capture'],text=True))[0]
    generation=m.process_pin(actual['State']['Pid']);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    selected=Path('/var/run/docker.sock').resolve();s=selected.lstat()
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
    binding={'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':peer}
    history=root/'history';history.mkdir(mode=0o700)
    values,_,_,reviewed,native=helper.fixture(actual,generation,binding,boot,history)
    for name,value in values.items():
        path=history/name;path.write_bytes(m.encoded(value));path.chmod(0o400)
    # Fixture-only historical metadata. No alternate values are exposed by the production main/CLI.
    m.INPUTS_HASH=hashlib.sha256((history/'inputs.json').read_bytes()).hexdigest();m.REVIEW_HASH=reviewed
    m.INSTALLED_NATIVE_BINDING_HASH=native;m.INSTALLED_NATIVE_IMAGE=actual['Image']
    c=m.Capture(root/'capture');result=m.prepare(c,inputs_path=history/'inputs.json',installed=history)
    assert result['complete'] is True and c.counts['engineGets']==3 and c.counts['privateMetadataReads']==4
    assert result['containerWrites']==result['sqlSessions']==result['oauthRequests']==result['credentialFileReads']==0
    assert result['runtimeAuthorityIssued'] is False and result['currentJobOrBudgetStateObserved'] is False
    assert len(c.seals)==4 and 'CAPTURE_PRIVATE_CANARY' not in json.dumps(result)
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in c.root.iterdir())
    try:m.Engine(c,binding,[actual['Id']]).get('/v1.44/info');raise AssertionError('fourth GET allowed')
    except m.Stop:pass
    try:m.Capture(c.root);raise AssertionError('consumed scope recreated')
    except m.Stop:pass
    # Exact peer tuple, including a possible PID1, is retained rather than normalized or guessed.
    wrong=dict(binding,peerCredentials=[peer[0]+1,*peer[1:]])
    c2=m.Capture(root/'wrong-peer')
    try:m.Engine(c2,wrong,[actual['Id']]).get('/v1.44/info');raise AssertionError('peer drift allowed')
    except m.Stop as e:assert str(e)=='EXACT_CAPTURE_ROOT_ENGINE_PEER_REQUIRED'
    print(json.dumps({'status':'NATIVE_SEALED_PROFILE_CAPTURE_FIXTURE_PASS','metadataReads':4,'engineGets':3,'rootSource0400':True,
        'oldFilesWritten':0,'runtimeEffects':0,'fixtureHistoryNotTargetProof':True,'applicationE2EProven':False},sort_keys=True))


if __name__=='__main__':main()
