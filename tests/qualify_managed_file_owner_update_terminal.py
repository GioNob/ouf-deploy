"""Unprivileged real sudo/TTY through the exact new CONTROL prompt and logger."""
import fcntl,json,os,re,select,shlex,signal,subprocess,tempfile,termios,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()!=0
subprocess.run(['sudo','-n','/usr/bin/true'],check=True)
cases=('lf','cr','crlf','fragmented','paste-no-enter','wrong','no-input','duplicate-clear','bad-line-recover','backspace','long-clear')
for case in cases:
    with tempfile.TemporaryDirectory()as directory:
        report=Path(directory)/'report.json';master,slave=os.openpty()
        def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
        command=['sudo','-n','/usr/bin/python3','-I','-S','-B',str(BASE/'tests/fixtures/managed_file_owner_update_terminal_probe.py'),case,str(report)]
        proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc','-c',shlex.join(command)],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session);os.close(slave);output=bytearray();sent=False;deadline=time.monotonic()+10
        try:
            while proc.poll()is None and time.monotonic()<deadline:
                if select.select([master],[],[],.05)[0]:
                    try:raw=os.read(master,65536)
                    except OSError:break
                    output.extend(raw)
                match=re.search(rb'APPROVO ([a-f0-9]{64})\r?\n',output)
                if not sent and match:
                    line=b'APPROVO '+match[1]
                    if case=='lf':os.write(master,line+b'\n')
                    elif case=='cr':os.write(master,line+b'\r')
                    elif case=='crlf':os.write(master,line+b'\r\n')
                    elif case=='fragmented':os.write(master,line[:16]);time.sleep(.05);os.write(master,line[16:]+b'\n')
                    elif case=='paste-no-enter':os.write(master,line)
                    elif case=='wrong':os.write(master,line+b' EXTRA\n')
                    elif case=='duplicate-clear':os.write(master,line+line);time.sleep(.05);os.write(master,b'\x15'+line+b'\r')
                    elif case=='bad-line-recover':os.write(master,line+line+b'\n');time.sleep(.05);os.write(master,line+b'\n')
                    elif case=='backspace':os.write(master,line[:-1]+b'z\x7f'+line[-1:]+b'\n')
                    elif case=='long-clear':os.write(master,b'x'*1000);time.sleep(.05);os.write(master,b'\x15'+line+b'\n')
                    sent=True
            proc.wait(timeout=3);assert report.exists(),output.decode(errors='replace');result=json.loads(report.read_text())
            assert result['accepted']==(case not in('paste-no-enter','wrong','no-input')),result
            assert all(result[k]for k in('root','stdinIsTTY','foreground','terminalRestored','operatorLogPrivate','operatorLogHasPrompt','privateReviewAndCountsUnchanged')),result
            assert result['productionAuthorityIssued']is False
            if result['accepted']:assert result['states'][-1]['enterReceived']is True
            if case=='bad-line-recover':assert result['states'][-1]['rejectedLines']==1
            print('ACTUAL_SUDO_OWNER_V38_PROMPT_'+case+'_PASS '+json.dumps({k:v for k,v in result.items()if k!='states'}),flush=True)
        finally:
            if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
            proc.wait(timeout=3);os.close(master)

