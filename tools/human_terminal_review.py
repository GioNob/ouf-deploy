"""Bounded exact HUMAN line from the controlling terminal, never a pipe.

No approval is inferred from echo/paste/time. Enter and exact bytes are required.
Only byte counts/states are observable; terminal settings always restored.
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
        if owned:
            require(os.tcgetpgrp(fd)==os.getpgrp(),'FOREGROUND_REVIEW_TERMINAL_REQUIRED')
        previous=termios.tcgetattr(fd)
        selected=[list(x) if isinstance(x,list) else x for x in previous]
        selected[0]&=~(termios.ICRNL|termios.INLCR|termios.IGNCR)
        selected[3]&=~(termios.ICANON|termios.ECHO)
        selected[6][termios.VMIN]=1;selected[6][termios.VTIME]=0
        # TCSANOW preserves input already pasted between prompt and setup.
        termios.tcsetattr(fd,termios.TCSANOW,selected)
        expected=('APPROVO '+review_hash).encode('ascii')
        buf=bytearray();last=clock();first=True
        progress({'state':'WAITING_INPUT','receivedBytes':0,'enterReceived':False})
        emit('Incolla la riga APPROVO e premi Invio (↵). Il solo incolla non conferma. Input nascosto; ricezione segnalata.')
        while True:
            guard()
            ready,_,_=select.select([fd],[],[],.2)
            if ready:
                raw=os.read(fd,128)
                require(bool(raw),'REVIEW_TERMINAL_EOF')
                if first:
                    emit('Input ricevuto dal terminale. Premi Invio (↵) per confermare la riga.')
                    first=False
                for i,value in enumerate(raw):
                    if value in (10,13):
                        tail=raw[i+1:]
                        require(not tail or value==13 and tail==b'\n','ONE_EXACT_REVIEW_LINE_ONLY')
                        progress({'state':'LINE_RECEIVED','receivedBytes':len(buf),'enterReceived':True})
                        require(bytes(buf)==expected,'EXACT_TERMINAL_REVIEW_NOT_APPROVED')
                        emit('Riga esatta ricevuta con Invio. Verifico la revisione privata.')
                        return
                    if value in (8,127):
                        if buf:buf.pop()
                    else:
                        require(32 <= value <= 126,'REVIEW_CONTROL_CHARACTER_DENIED')
                        buf.append(value)
                    require(len(buf)<=len(expected),'EXACT_TERMINAL_REVIEW_LENGTH_EXCEEDED')
                progress({'state':'WAITING_ENTER','receivedBytes':len(buf),'enterReceived':False})
            if clock()-last>=heartbeat:
                guard()
                emit('Attendo Invio (↵) sulla riga ricevuta; pubblicazione non autorizzata.' if buf else
                     'Attendo la riga APPROVO e Invio (↵); pubblicazione non autorizzata.')
                last=clock()
    finally:
        if previous is not None:termios.tcsetattr(fd,termios.TCSANOW,previous)
        if owned:os.close(fd)
