"""Actual session/TTY -> sudo -> Python -> tee, including phone-like CR/paste.

Normal operator UID, actual sudo (no mock), synthetic reviews only. CI requires
root escalation through sudo; local test may explicitly set CI_NO_SUDO=1 and
does not count as sudo qualification. No production controller or account used.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import time

ROOT=Path(__file__).resolve().parents[1]
no_sudo=os.environ.get('CI_NO_SUDO')=='1'
if not no_sudo:
    assert os.geteuid()!=0,'run as actual unprivileged CI runner'
    subprocess.run(['sudo','-n','/usr/bin/true'],check=True)


def run(mode,case):
    with tempfile.TemporaryDirectory() as tmp:
        report=Path(tmp)/'report.json';log=Path(tmp)/'pipeline.log'
        command=([] if no_sudo else ['sudo','-n'])+['/usr/bin/python3','-I','-S','-B',str(ROOT/'tests/fixtures/human_terminal_pipeline_probe.py'),mode,case,str(report)]
        shell='set -o pipefail\n'+shlex.join(command)+' 2>&1 | tee '+shlex.quote(str(log))
        master,slave=os.openpty()
        def session():
            os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc','-c',shell],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session)
        os.close(slave);buffer=bytearray();sent=False;deadline=time.monotonic()+8
        try:
            while proc.poll() is None and time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],.05)
                if ready:
                    try:raw=os.read(master,65536)
                    except OSError:break
                    if not raw:break
                    buffer.extend(raw)
                if not sent and b'CI_PROMPT_READY' in buffer:
                    match=re.search(rb'CI_HASH=([a-f0-9]{64})',buffer);assert match
                    line=b'APPROVO '+match[1]
                    if case=='lf':os.write(master,line+b'\n')
                    elif case=='cr':os.write(master,line+b'\r')
                    elif case=='crlf':os.write(master,line+b'\r\n')
                    elif case=='paste-no-enter':os.write(master,line)
                    elif case=='fragmented':
                        os.write(master,line[:16]);time.sleep(.05);os.write(master,line[16:]);time.sleep(.05);os.write(master,b'\r')
                    elif case=='wrong':os.write(master,line[:-1]+b'z\n')
                    elif case!='no-input':raise AssertionError(case)
                    sent=True
            assert proc.poll() is not None or proc.wait(timeout=3) is not None
            assert report.exists(),bytes(buffer).decode(errors='replace')
            result=json.loads(report.read_text())
            assert result['stdinIsTTY'] and result['terminalRestored'],result
            if not no_sudo:assert result['root'],result
            reproduced_legacy=mode=='legacy' and os.environ.get('CI_SUDO_PTY')=='use_pty' and case in ('lf','crlf')
            if reproduced_legacy:
                assert result['accepted'] is False and result['reason']=='FINITE_HUMAN_WINDOW_EXPIRED',result
                print('REPRODUCED_LEGACY_SUDO_PTY_TIMEOUT_WITH_ENTER '+json.dumps(result),flush=True)
            else:
                assert result['accepted']==(case in ('lf','cr','crlf','fragmented')),result
            if mode=='new' and case=='paste-no-enter':
                assert any(s['state']=='WAITING_ENTER' and s['receivedBytes']==72 and not s['enterReceived'] for s in result['states']),result
                assert 'Input ricevuto' in log.read_text() and 'Attendo Invio' in log.read_text()
            if mode=='new' and result['accepted']:
                assert result['states'][-1]['enterReceived'] is True
            print('PIPELINE_'+('LOCAL_NO_SUDO_' if no_sudo else 'ACTUAL_SUDO_')+mode+'_'+case+'_PASS',flush=True)
        finally:
            if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL)
            proc.wait(timeout=3);os.close(master)


for mode,cases in [('legacy',('lf','crlf','paste-no-enter')),('new',('lf','cr','crlf','fragmented','paste-no-enter','wrong','no-input'))]:
    for case in cases:run(mode,case)
