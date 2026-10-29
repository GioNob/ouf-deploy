"""Exact HUMAN approval with visible native terminal line editing.

Wrong lines are input mistakes, not authority claims. They may be corrected only
inside the original finite review window. No grant, counter or deadline reset.
Only counts/states are persisted. Terminal echo stays on the actual TTY, not logs.
"""
import os
import re
import select
import stat
import termios
import time

class TerminalReviewError(Exception): pass

def require(value, code):
    if not value: raise TerminalReviewError(code)

def read_exact(review_hash, guard, *, emit, progress, fd=None, clock=time.monotonic, heartbeat=10):
    require(isinstance(review_hash,str) and re.fullmatch('[a-f0-9]{64}',review_hash),'EXACT_REVIEW_HASH_REQUIRED')
    require(0 < heartbeat <= 10,'FINITE_TERMINAL_HEARTBEAT_REQUIRED')
    owned=fd is None
    if owned:fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_CLOEXEC|os.O_NOFOLLOW)
    previous=None
    try:
        require(os.isatty(fd) and stat.S_ISCHR(os.fstat(fd).st_mode),'CONTROLLING_REVIEW_TTY_REQUIRED')
        if owned:require(os.tcgetpgrp(fd)==os.getpgrp(),'FOREGROUND_REVIEW_TERMINAL_REQUIRED')
        previous=termios.tcgetattr(fd)
        selected=[list(x) if isinstance(x,list) else x for x in previous]
        selected[0]=(selected[0]|termios.ICRNL)&~(termios.INLCR|termios.IGNCR)
        selected[3]|=termios.ICANON|termios.ECHO|termios.ECHOE|termios.ECHOK|termios.ISIG
        selected[6][termios.VERASE]=b'\x7f';selected[6][termios.VKILL]=b'\x15'
        # TCSANOW does not discard input already pasted at the prompt.
        termios.tcsetattr(fd,termios.TCSANOW,selected)
        expected=('APPROVO '+review_hash).encode('ascii')
        buf=bytearray();oversized=False;last=clock();rejected=0
        def state(name,n=0,enter=False):
            progress({'state':name,'receivedBytes':n,'enterReceived':enter,'rejectedLines':rejected})
        state('WAITING_INPUT')
        emit('Input visibile. Incolla la riga APPROVO e premi Invio. Backspace cancella; Ctrl+U svuota la riga.')
        emit('Una riga errata resta correggibile qui entro la stessa scadenza; non rilanciare il comando.')
        while True:
            guard()
            ready,_,_=select.select([fd],[],[],.2)
            if ready:
                raw=os.read(fd,4096)
                require(bool(raw),'REVIEW_TERMINAL_EOF')
                # Canonical mode delivers a completed line, with native editing
                # already applied. Never decide on a partially pasted line.
                newline=raw.find(b'\n')
                content=raw if newline<0 else raw[:newline]
                if len(buf)+len(content)>4096:oversized=True
                if not oversized:buf.extend(content)
                if newline>=0:
                    guard()
                    if not oversized and bytes(buf)==expected and raw[newline+1:] in (b'',b'\n'):
                        state('LINE_RECEIVED',len(buf),True)
                        emit('Riga esatta ricevuta con Invio. Verifico la revisione privata.')
                        return
                    if buf or oversized:
                        rejected+=1
                        state('LINE_REJECTED',min(4097,len(buf)+(4097 if oversized else 0)),True)
                        emit('Riga non valida: nessuna approvazione acquisita. Incolla nuovamente la sola riga APPROVO e premi Invio.')
                    buf.clear();oversized=False;state('WAITING_INPUT')
            if clock()-last>=heartbeat:
                guard()
                emit('Attendo la riga APPROVO e Invio; puoi modificarla con Backspace o cancellarla con Ctrl+U. Scadenza invariata.')
                last=clock()
    finally:
        if previous is not None:termios.tcsetattr(fd,termios.TCSANOW,previous)
        if owned:os.close(fd)
